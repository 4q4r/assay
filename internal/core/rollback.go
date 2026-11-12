package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"assay/internal/config"
	"assay/internal/store"
)

// StateFileName is the D8 health-state file inside the data dir — the
// status core block's cross-process observable (T7): the strike counter
// lives in the daemon's manager memory, and `assay status` runs as a
// separate process, so the counter persists here on every RecordHealth
// transition.
const StateFileName = "core-state.json"

// HealthState is the persisted D8 strike/rollback mirror. Strikes mirror
// the in-memory counter under its DISPLAY clamp (a refused streak reads
// K/K — T2 review M-1) and reset with it: a fresh manager resets the file
// (NewManager), because the streak lives in the process that counts it.
// The rollback record is DISK truth — the restore really happened — and
// survives restarts. The Binary* fields are the core-binary RESOLUTION
// provenance (owner ruling 2026-11-11): written on every resolution change
// by the core lifecycle, read cross-process by the status block.
type HealthState struct {
	Strikes            int       `json:"strikes"`
	LastCheckAt        time.Time `json:"last_check_at,omitzero"`
	LastHealthy        bool      `json:"last_healthy,omitempty"`
	LastError          string    `json:"last_error,omitempty"`
	LastRollbackAt     time.Time `json:"last_rollback_at,omitzero"`
	LastRollbackBackup string    `json:"last_rollback_backup,omitempty"`
	// BinarySource is the resolution provenance: "override" (an explicit
	// [core].xray_bin), "user-local" (~/.local/bin/xray — assay's own
	// binary), or "system-preexisting" (a system xray bound as found).
	BinarySource string `json:"binary_source,omitempty"`
	// BinaryPath is the bound binary's absolute path.
	BinaryPath string `json:"binary_path,omitempty"`
	// BinaryVersion is the bound binary's parsed `xray version` ("" when
	// the binary cannot answer).
	BinaryVersion string `json:"binary_version,omitempty"`
}

// writeHealthStateFile persists the state atomically (the store's
// atomic-write convention; the file sits in the data dir, 0600-class).
func writeHealthStateFile(dataDir string, s *HealthState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode health state: %w", err)
	}
	return store.WriteFileAtomic(filepath.Join(dataDir, StateFileName), func(f *os.File) error {
		_, werr := f.Write(b)
		return werr
	})
}

// writeHealthStateLocked persists the mirror under the manager lock. The
// state file is observability, not control flow: a write failure warns
// loud and never breaks health handling (the stats-accounting precedent).
func (m *Manager) writeHealthStateLocked(s *HealthState) {
	if err := writeHealthStateFile(m.dataDir, s); err != nil {
		_, _ = fmt.Fprintf(m.log, "WARNING: core: persist health state: %v\n", err)
	}
}

// ReadHealthState reads the persisted D8 state for the status core block
// (cross-process). A missing file is the no-evidence state (nil, nil —
// no post-activation health check has ever run); a corrupt file errors —
// silent zero rows would mask damage (the corrupt-artifact discipline).
func ReadHealthState(dataDir string) (*HealthState, error) {
	//nolint:gosec // G703: the data dir comes from the owner's config, which is
	// the trust root by construction — the same suppression the manager's
	// pidfile/lock paths carry; there is no fixed path to fall back to.
	raw, err := os.ReadFile(filepath.Join(dataDir, StateFileName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("core: read health state: %w", err)
	}
	var s HealthState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("core: decode health state: %w", err)
	}
	return &s, nil
}

// writeCoreProvenance merges the resolution provenance into the persisted
// core-state.json (read-modify-write — the D8 health mirror and the
// rollback record are preserved). Called by the core lifecycle on every
// RESOLUTION CHANGE; an identical provenance skips the write (no churn).
// The state file is observability, not control flow: a write failure warns
// loud and never breaks the resolution.
func writeCoreProvenance(dataDir string, src BinarySource, path, version string, log io.Writer) {
	state, err := ReadHealthState(dataDir)
	switch {
	case err != nil:
		// F9 honesty precedent: a corrupt artifact is named loud, never
		// swallowed — this rewrite LOSES whatever disk history (e.g. the
		// rollback record) the corrupt file carried.
		_, _ = fmt.Fprintf(log, "WARNING: core: persisted %s is corrupt (%v) — rewriting it; "+
			"any rollback record in it is lost\n", StateFileName, err)
		state = &HealthState{}
	case state == nil:
		state = &HealthState{}
	}
	if state.BinarySource == string(src) && state.BinaryPath == path && state.BinaryVersion == version {
		return
	}
	state.BinarySource = string(src)
	state.BinaryPath = path
	state.BinaryVersion = version
	if err := writeHealthStateFile(dataDir, state); err != nil {
		_, _ = fmt.Fprintf(log, "WARNING: core: persist resolution provenance: %v\n", err)
	}
}

// RecordHealth feeds the D8 strike counter. A nil error is a healthy check:
// the counter resets (loudly, when it was non-zero) and false is returned.
// A non-nil error increments the counter; at K = [core].rollback_strikes
// consecutive failures the D8 rollback runs — restore the NEWEST
// <data>/backups/config.json.bak-<ts>, gate it with `run -test` on the
// managed binary, restart the core, log the loud line — and true is
// returned. A REFUSED rollback (no backup, failed gate, failed restore or
// failed restart) leaves the streak at K so the next failure re-attempts
// (loud refusals keep surfacing; a healthy check still resets). The failure
// line's DISPLAY clamps at K — a refused streak reads "K/K" on every line,
// never "K+1/K" (T2 review M-1).
//
// Every transition persists the mirror (StateFileName) for the status core
// block; the write is observability and never changes the verdict.
//
// mu is held across the whole call: a rollback forks a gate child and
// restarts the core, and a concurrent spawn/stop mid-rollback would race
// the same child state.
func (m *Manager) RecordHealth(err error) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.readHealthStateLocked()
	if err == nil {
		if m.strikes > 0 {
			_, _ = fmt.Fprintf(m.log, "core: healthy — strike counter reset (was %d)\n", m.strikes)
			m.strikes = 0
		}
		state.Strikes = 0
		state.LastCheckAt = time.Now()
		state.LastHealthy = true
		state.LastError = ""
		m.writeHealthStateLocked(state)
		return false
	}
	m.strikes++
	// The display clamps at K (T2 review M-1): a REFUSED rollback keeps the
	// streak attempting on every further failure, and the line reads "K/K"
	// for the whole refused streak — never "K+1/K, K+2/K…". The mirror
	// persists the same clamped value.
	shown := min(m.strikes, m.strikeK)
	_, _ = fmt.Fprintf(m.log, "core: health failure %d/%d: %v\n", shown, m.strikeK, err)
	state.Strikes = shown
	state.LastCheckAt = time.Now()
	state.LastHealthy = false
	state.LastError = err.Error()
	m.writeHealthStateLocked(state)
	if m.strikes < m.strikeK {
		return false
	}
	if m.rollbackLocked() {
		m.strikes = 0
		// Re-read before the reset write: rollbackLocked just persisted the
		// rollback record (disk truth) — the reset must keep it, only
		// zeroing the streak.
		state = m.readHealthStateLocked()
		state.Strikes = 0
		state.LastHealthy = true
		state.LastError = ""
		m.writeHealthStateLocked(state)
		return true
	}
	return false
}

// readHealthStateLocked loads the persisted mirror as the base for the
// next transition write — the rollback record (disk truth) must survive
// strike updates that rewrite the file. A corrupt/missing file degrades to
// a fresh mirror here (the loud read error path belongs to the status
// reader; the next write replaces damaged content either way).
func (m *Manager) readHealthStateLocked() *HealthState {
	state, err := ReadHealthState(m.dataDir)
	if err != nil || state == nil {
		return &HealthState{}
	}
	return state
}

// userLocalPreviousBin is the binary-level rollback artifact: the copy of
// ~/.local/bin/xray as it was BEFORE the latest update's atomic swap. Kept
// through the swap (graceful-migration contract), restored by the D8
// strike trigger — the binary-level mirror of the config-level rollback.
func userLocalPreviousBin() string {
	user := config.UserLocalXrayBin()
	if user == "" {
		return ""
	}
	return user + ".previous"
}

// restorePreviousBinaryLocked performs the binary-level rollback when one
// is possible: the bound binary is assay's own user-local install AND the
// .previous copy exists. The restore is the atomic same-directory rename —
// the swap's own mechanism, run in reverse. Reports whether a restore
// happened (the caller's log line names it).
func (m *Manager) restorePreviousBinaryLocked() bool {
	prev := userLocalPreviousBin()
	if prev == "" || m.source != SourceUserLocal {
		return false
	}
	if _, err := os.Stat(prev); err != nil {
		return false
	}
	user := config.UserLocalXrayBin()
	if err := os.Rename(prev, user); err != nil {
		_, _ = fmt.Fprintf(m.log, "WARNING: core: binary rollback failed — the previous binary stays at %s: %v\n",
			prev, err)
		return false
	}
	_, _ = fmt.Fprintf(m.log, "core: binary-level rollback — restored the previous core binary over %s\n", user)
	// The resolution CHANGED (a different binary now sits at the bound path)
	// — re-probe its version and rewrite the provenance record (the
	// "provenance on every resolution change" contract); the record must
	// never keep describing the failed update.
	version := probeBoundVersion(context.Background(), user, m.log)
	warnBelowFloor(binarySourceKind(m.source), user, version, m.log)
	writeCoreProvenance(m.dataDir, m.source, user, version, m.log)
	return true
}

// rollbackLocked performs the D8 sequence on the already-struck manager:
// (binary-level restore first, when one is possible — the -test gate and
// the respawn must run the known-good binary) → newest backup → `-test`
// gate → atomic restore of live.json → core restart → loud line. Every
// refusal keeps the previous state untouched and is logged loud.
func (m *Manager) rollbackLocked() bool {
	m.restorePreviousBinaryLocked()
	bak, err := newestBackup(m.backupDir)
	if err != nil {
		_, _ = fmt.Fprintf(m.log, "core: rollback refused — %v (keeping current state)\n", err)
		return false
	}
	if gerr := m.runTestGate(bak); gerr != nil {
		_, _ = fmt.Fprintf(m.log, "core: rollback refused — newest backup %s failed the -test "+
			"gate: %v (keeping current state)\n", bak, gerr)
		return false
	}
	raw, rerr := os.ReadFile(bak)
	if rerr != nil {
		_, _ = fmt.Fprintf(m.log, "core: rollback refused — backup %s unreadable: %v "+
			"(keeping current state)\n", bak, rerr)
		return false
	}
	if werr := store.WriteFileAtomic(m.livePath, func(f *os.File) error {
		_, werr := f.Write(raw)
		return werr
	}); werr != nil {
		_, _ = fmt.Fprintf(m.log, "core: rollback refused — restore write failed: %v "+
			"(keeping current state)\n", werr)
		return false
	}
	if serr := m.stopLocked(); serr != nil {
		_, _ = fmt.Fprintf(m.log, "core: rollback restart stop failed: %v\n", serr)
		return false
	}
	if serr := m.ensureRunningLocked(context.Background()); serr != nil {
		_, _ = fmt.Fprintf(m.log, "core: rollback restart failed — the restored config %s is on "+
			"disk but the core did not come back: %v\n", bak, serr)
		return false
	}
	_, _ = fmt.Fprintf(m.log, "core: ROLLBACK after %d consecutive failed health checks — "+
		"restored %s, core restarted\n", min(m.strikes, m.strikeK), bak)
	// The rollback record is disk truth (the restore really happened): it
	// lands in the mirror immediately, before RecordHealth's post-rollback
	// strike reset rewrites the file around it. Read-modify-write — the
	// resolution provenance fields are DISK HISTORY too and must survive
	// the record (a fresh struct here would silently drop them).
	state := m.readHealthStateLocked()
	state.Strikes = min(m.strikes, m.strikeK)
	state.LastRollbackAt = time.Now()
	state.LastRollbackBackup = filepath.Base(bak)
	m.writeHealthStateLocked(state)
	return true
}

// newestBackup returns the newest <dir>/config.json.bak-<ts> file. The
// activate stage stamps backups 20060102-150405 UTC (the activate
// package's format), which sorts lexicographically — the max name IS the
// newest.
func newestBackup(dir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "config.json.bak-*"))
	if err != nil {
		return "", fmt.Errorf("backup glob %s: %w", dir, err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no config.json.bak-<ts> backup exists in %s", dir)
	}
	sort.Strings(matches)
	return matches[len(matches)-1], nil
}

// runTestGate gates a candidate config with the managed binary:
// `xray run -test -c <path>` — the same validate-and-exit shape the
// activation gate uses (L10: a bad config never reaches the live path).
// The gate runs on the BACKUP file itself (a standalone candidate, never
// the live one).
func (m *Manager) runTestGate(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), testGateTimeout)
	defer cancel()
	//nolint:gosec // the binary comes from the owner's [core].xray_bin — the config file IS the trust root
	cmd := exec.CommandContext(ctx, m.bin, "run", "-test", "-c", path)
	cmd.WaitDelay = testGateTimeout // M-3: a killed gate's pipes must never block Wait past the deadline
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("xray run -test -c %s: %w\n%s", path, err, out.String())
	}
	return nil
}
