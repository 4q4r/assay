package core

// download.go carries the core-binary lifecycle (D4/S5/G4 + the owner
// ruling 2026-11-11, revised 2026-11-12 — «запись в локал не требует судо»):
// the resolution of WHICH xray binary runs, the download, sha256
// verification and atomic user-local install of the release, plus the
// Manager's auto-update. The network and exec mechanics (release fetch,
// checksum verify, flat unpack, staged `-test` gate) are the xrayupdate
// package's proven surface, exported for this path — download.go owns the
// MANAGED decisions: the resolution order, the version floor, the
// user-local install target (~/.local/bin/xray — no elevation anywhere),
// the .previous rollback artifact, the C2 asset-dir contract
// (<data>/share/xray), the update interval state, and the restart after a
// swap.
//
// Resolution order (owner ruling, binding):
//   1. an explicit [core].xray_bin override → honored as-is (download and
//      auto-update inert, one-time INFO per S5);
//   2. an existing user-local ~/.local/bin/xray → bound (assay's OWN
//      binary — auto-update keeps it current);
//   3. an existing system xray (/usr/local/bin/xray, /usr/bin/xray — first
//      match) → bound as found (auto-update inert; a below-floor core
//      warns LOUD and non-blocking — the owner's 26.3.27 bound core is the
//      expected case, and the W19 adaptive observatory interval already
//      caps the probe rate);
//   4. none of the above → download the sha-verified release and install
//      it ATOMICALLY to ~/.local/bin/xray (user-writable — no elevation,
//      no sudo anywhere), keeping the previous binary as
//      ~/.local/bin/xray.previous for instant binary-level rollback, with
//      a one-time loud PATH note (~/.local/bin precedes /usr/bin on PATH,
//      so assay's copy shadows any later apt-installed xray).
//
// Contracts:
//   - S5: auto-update is ASSAY-OWNED-BINARY-ONLY — an override or a bound
//     pre-existing system core makes EnsureCoreBinary's download leg and
//     AutoUpdate inert with a loud INFO (one time for the per-wave
//     AutoUpdate).
//   - C2 (T2 contract): the downloader materializes the release's asset
//     files in <data>/share/xray — the spawn wires XRAY_LOCATION_ASSET
//     there for assay-owned binaries, so gate and child resolve assets
//     identically.
//   - Version floor: releases below the observatory-safe floor are refused
//     loud (the pre-#6666 observatory busy-looped ~100% CPU when
//     subjectSelector matched nothing); a bound EXISTING binary below the
//     floor warns loud but never blocks the bind.
//   - Failures NEVER break the wave: the auto-update stage swallows the
//     error into a loud WARNING (pipeline wiring); this package only ever
//     returns errors loudly.
//   - Provenance: every resolution change lands in <data>/core-state.json
//     (binary_source / binary_path / binary_version) for the status block.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"assay/internal/config"
	"assay/internal/platform"
	"assay/internal/store"
	"assay/internal/xrayupdate"
)

// coreUpdateStateName is the auto-update check-timestamp state file inside
// the data dir. One storage mode, one file: last successful check time is
// the whole state (a failed check does NOT advance the timestamp, so the
// next wave retries soon).
const coreUpdateStateName = "core-update-state.json"

// coreRestartPendingName is the auto-update RESTART marker (T6 disposition
// of the T5 M-1 residual): when a newer binary was installed but the running
// core could not be restarted on it, the marker survives so the NEXT wave —
// not the next due interval — re-attempts only the restart leg. Without it,
// the "already at latest" early-return below defeated the re-attempt
// forever in the readable-binary case (install succeeded, so the version
// pair matches on every later check).
const coreRestartPendingName = "core-update-restart-pending"

// coreVersionFloor is the observatory-safe core floor: v26.9.9 (2026-09-08)
// is the first XTLS/Xray-core release carrying the issue #6666 fix (PR
// #6669, closed 2026-08-25 — the observatory busy-looped ~100% CPU when
// subjectSelector matched nothing; the issue was reproduced on v26.7.28).
// Verified against the XTLS issue tracker and the releases page
// 2026-11-11. Fresh installs and updates refuse any release below it; a
// bound EXISTING binary below it warns loud and non-blocking. Var, not
// const: the tests pin fixtures against an injected floor.
var coreVersionFloor = "26.9.9"

// releaseAPIBase is the GitHub API base of the managed-core release fetch.
// Production = the canonical host; tests point it at an httptest server.
var releaseAPIBase = xrayupdate.DefaultAPIBase

// BinarySource is the core-binary resolution provenance recorded in
// <data>/core-state.json (binary_source) and rendered by the status block.
type BinarySource string

const (
	// SourceOverride — an explicit [core].xray_bin points at this binary;
	// download and auto-update are inert (S5).
	SourceOverride BinarySource = "override"
	// SourceUserLocal — ~/.local/bin/xray, assay's own install: bound and
	// UPDATABLE (auto-update keeps it current per [core].update_interval).
	SourceUserLocal BinarySource = "user-local"
	// SourceSystemPreexisting — a system xray (/usr/local/bin/xray or
	// /usr/bin/xray) bound as found: auto-update inert, floor warning
	// non-blocking.
	SourceSystemPreexisting BinarySource = "system-preexisting"
)

// VersionFloor is the observatory-safe core floor (the status block renders
// it next to the bound version).
func VersionFloor() string { return coreVersionFloor }

// VersionBelowFloor reports whether a parsed version sits below the floor.
// An unparseable version errors — the caller reports it loud (fail-honest).
func VersionBelowFloor(version string) (bool, error) {
	cmp, err := compareVersionTags(version, coreVersionFloor)
	if err != nil {
		return false, fmt.Errorf("version %q does not parse against the floor %s: %w",
			version, coreVersionFloor, err)
	}
	return cmp < 0, nil
}

// coreUpdateState is the persisted auto-update check state.
type coreUpdateState struct {
	LastCheck time.Time `json:"last_check"`
}

// EnsureCoreBinary guarantees a usable core binary exists (D4: `assay
// install` resolves the core before the first wave) per the owner-ruling
// resolution order: an override is honored inert (S5); an existing
// user-local or system binary is bound (no download — the user-local one
// with its floor probed, the system one with the non-blocking floor
// warning); with neither, the latest sha-verified release installs
// atomically to ~/.local/bin/xray (no elevation anywhere). A
// download/verification failure is a loud error: the daemon's waves retry
// through auto-update, so install stays a warning in the caller's hands.
func EnsureCoreBinary(ctx context.Context, cfg config.CoreConfig, dataDir string, log io.Writer) error {
	if cfg.XrayBin != "" {
		_, _ = fmt.Fprintf(log, "INFO: core: [core].xray_bin is overridden (%s) — the core download "+
			"and auto-update stay inert for this binary (S5)\n", cfg.XrayBin)
		writeCoreProvenance(dataDir, SourceOverride, cfg.XrayBin, "", log)
		return nil
	}
	if user := config.UserLocalXrayBin(); user != "" && isRegularExecutable(user) {
		version := probeBoundVersion(ctx, user, log)
		warnBelowFloor("user-local", user, version, log)
		_, _ = fmt.Fprintf(log, "core: user-local xray core present (%s) — nothing to download "+
			"(assay owns it; auto-update keeps it current per [core].update_interval)\n", user)
		writeCoreProvenance(dataDir, SourceUserLocal, user, version, log)
		return nil
	}
	for _, sys := range config.DefaultSystemXrayPaths {
		if !isRegularExecutable(sys) {
			continue
		}
		version := probeBoundVersion(ctx, sys, log)
		warnBelowFloor("system", sys, version, log)
		_, _ = fmt.Fprintf(log, "core: binding existing system xray %s — assay does not manage it: "+
			"the core download and auto-update stay inert (S5)\n", sys)
		writeCoreProvenance(dataDir, SourceSystemPreexisting, sys, version, log)
		return nil
	}

	// No binary anywhere: download the sha-verified release and install it
	// to the user-local target (the resolution's canonical fill).
	staged, tag, err := downloadStagedCore(ctx, dataDir, log)
	if err != nil {
		return err
	}
	installed, err := installUserLocalCore(staged, log)
	if err != nil {
		return err
	}
	materializeAssets(dataDir, log)
	_, _ = fmt.Fprintf(log, "core: xray core %s installed at %s (sha256 verified, "+
		"-test gate passed; assets in %s)\n", tag, installed, managedAssetDir(dataDir))
	writeCoreProvenance(dataDir, SourceUserLocal, installed, strings.TrimPrefix(tag, "v"), log)
	return nil
}

// isRegularExecutable is the download package-local twin of
// config.isRegularExecutable (same semantics — a regular file with any
// execute bit).
func isRegularExecutable(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}

// probeBoundVersion reads a bound binary's version banner; a binary that
// cannot answer is NOT a resolution failure — the version stays unknown
// (""), the warning names it, and the bind proceeds.
func probeBoundVersion(ctx context.Context, bin string, log io.Writer) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	version, err := xrayupdate.CurrentVersion(ctx, bin)
	if err != nil {
		_, _ = fmt.Fprintf(log, "WARNING: core: bound binary %s did not answer `version` (%v) — "+
			"the version stays unknown and the floor cannot be checked\n", bin, err)
		return ""
	}
	return version
}

// warnBelowFloor logs the LOUD, NON-BLOCKING floor warning for a bound
// binary below the observatory-safe floor. The bind proceeds either way —
// the owner's 26.3.27 bound core is the expected case, and the W19
// adaptive observatory interval already caps the probe rate.
func warnBelowFloor(kind, bin, version string, log io.Writer) {
	if version == "" {
		return // unknown versions are already flagged by the probe warning
	}
	below, err := VersionBelowFloor(version)
	if err != nil {
		_, _ = fmt.Fprintf(log, "WARNING: core: bound %s xray %s reported version %q that does not "+
			"parse against the floor %s — continuing (non-blocking), the auto-update floor still applies\n",
			kind, bin, version, VersionFloor())
		return
	}
	if below {
		_, _ = fmt.Fprintf(log, "WARNING: core: bound %s xray %s is version %s — below the "+
			"observatory-safe floor %s (the pre-#6666 observatory busy-loop); continuing "+
			"(non-blocking): the W19 adaptive observatory interval caps the probe rate\n",
			kind, bin, version, VersionFloor())
	}
}

// downloadStagedCore fetches + verifies + gates the latest release into the
// data dir's staging area and enforces the version floor on the tag (a
// below-floor release never downloads past the check leg). The staging dir
// is pure scratch — the binary and assets are copied OUT of it by the
// install.
func downloadStagedCore(ctx context.Context, dataDir string, log io.Writer) (string, string, error) {
	tag, err := xrayupdate.FetchLatestTag(ctx, releaseAPIBase)
	if err != nil {
		return "", "", fmt.Errorf("core: fetch latest release: %w", err)
	}
	if err := checkVersionFloor(tag); err != nil {
		return "", "", err
	}
	stagingDir := coreStagingDir(dataDir)
	// Bound the staging dir to exactly ONE release (fix M-3, staging half):
	// previous releases' leftovers (files a newer release dropped) are wiped
	// before the new one lands.
	if err := wipeStaging(stagingDir); err != nil {
		_, _ = fmt.Fprintf(log, "WARNING: core: staging wipe failed: %v (staging over the old content)\n", err)
	}
	staged, tag, err := xrayupdate.StageVerifiedRelease(ctx, releaseAPIBase, stagingDir, "core:", log, nil)
	if err != nil {
		return "", "", fmt.Errorf("core: stage release %s: %w", tag, err)
	}
	return staged, tag, nil
}

// coreStagingDir is the release-download scratch area (the same staging
// convention the manual `xray-update` uses, under the data dir).
func coreStagingDir(dataDir string) string {
	return filepath.Join(dataDir, "xray-staged")
}

// wipeStaging removes the staging dir's previous release content (fix M-3,
// staging half). A missing dir is the clean no-op.
func wipeStaging(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return fmt.Errorf("remove %s: %w", filepath.Join(dir, entry.Name()), err)
		}
	}
	return nil
}

// managedAssetDir is the C2 asset dir: <data>/share/xray — the path the
// spawn wires XRAY_LOCATION_ASSET to (managedAssetDirRel).
func managedAssetDir(dataDir string) string {
	return filepath.Join(dataDir, managedAssetDirRel)
}

// installUserLocalCore atomically installs the staged binary at the
// user-local target (~/.local/bin/xray — user-writable, NO elevation
// anywhere; the owner ruling «запись в локал не требует судо»): a
// same-directory temp + rename (xrayupdate's applyStaged shape — a crash
// never leaves a half-written binary), and the CURRENT binary is preserved
// as <target>.previous FIRST — the instant binary-level rollback artifact
// the D8 strike trigger restores (graceful-migration contract; the swap
// itself is zero-downtime at the file level, and the cutover budget is the
// stop/start restart).
func installUserLocalCore(staged string, log io.Writer) (string, error) {
	target := config.UserLocalXrayBin()
	if target == "" {
		return "", errors.New("user-local core install: no home directory could be resolved " +
			"(~/.local/bin is unavailable) — set HOME or point [core].xray_bin at a binary")
	}
	binDir := filepath.Dir(target)
	//nolint:gosec // G301: ~/.local/bin is a SHARED PATH dir owned by the user —
	// 0755 is its convention; the binary file itself is 0755 by design.
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", fmt.Errorf("create user bin dir %s: %w", binDir, err)
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	temp := filepath.Join(binDir, ".xray-install-"+stamp)
	if err := copyFile(staged, temp, 0o755); err != nil {
		_ = os.Remove(temp)
		return "", fmt.Errorf("core: stage temp copy %s: %w", temp, err)
	}
	// ONE stat decides both freshness and the .previous preservation (N-1:
	// a second stat after the copy could see a target that appeared in
	// between and hand the PATH note to an update).
	fresh := true
	if _, err := os.Stat(target); err == nil {
		fresh = false
		// Preserve the current binary as the rollback artifact (temp+rename
		// — the artifact itself is placed atomically).
		prevTemp := target + ".previous." + stamp
		if err := copyFile(target, prevTemp, 0o755); err != nil {
			_ = os.Remove(temp)
			_ = os.Remove(prevTemp)
			return "", fmt.Errorf("core: preserve the previous binary: %w", err)
		}
		if err := os.Rename(prevTemp, target+".previous"); err != nil {
			_ = os.Remove(temp)
			_ = os.Remove(prevTemp)
			return "", fmt.Errorf("core: place the previous-binary artifact: %w", err)
		}
	}
	if err := os.Rename(temp, target); err != nil {
		_ = os.Remove(temp)
		return "", fmt.Errorf("core: atomic install %s: %w", target, err)
	}
	if fresh {
		// One-time loud PATH note on a FRESH install: ~/.local/bin precedes
		// /usr/bin on PATH, so assay's copy shadows any later apt-installed
		// xray (the owner ruling's duplicate-prevention mechanism).
		_, _ = fmt.Fprintf(log, "NOTE: core: installed the xray core at %s — ensure %s is on PATH; "+
			"it shadows any later apt-installed xray (PATH precedence)\n", target, binDir)
	}
	return target, nil
}

// materializeAssets copies every non-binary release asset from the staging
// scratch into <data>/share/xray (C2): geoip.dat / geosite.dat … land where
// the spawn wires XRAY_LOCATION_ASSET for assay-owned binaries.
func materializeAssets(dataDir string, log io.Writer) {
	entries, rerr := os.ReadDir(coreStagingDir(dataDir))
	if rerr != nil {
		_, _ = fmt.Fprintf(log, "WARNING: core: read staged assets: %v (the binary is installed; "+
			"geosite-style routes will fall back to their own resolution)\n", rerr)
		return
	}
	assetDir := managedAssetDir(dataDir)
	if err := os.MkdirAll(assetDir, 0o750); err != nil {
		_, _ = fmt.Fprintf(log, "WARNING: core: create asset dir %s: %v (geosite-style routes "+
			"will fall back to their own resolution)\n", assetDir, err)
		return
	}
	assets := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || name == platform.CoreBinaryName(runtime.GOOS) || name == "test-config.json" ||
			strings.HasSuffix(name, ".zip") || strings.HasPrefix(name, ".") {
			continue
		}
		src := filepath.Join(coreStagingDir(dataDir), name)
		dst := filepath.Join(assetDir, name)
		if err := copyFile(src, dst, 0o644); err != nil {
			_, _ = fmt.Fprintf(log, "WARNING: core: asset %s copy failed: %v\n", name, err)
			continue
		}
		assets++
	}
	_, _ = fmt.Fprintf(log, "core: %d release asset(s) materialized in %s\n", assets, assetDir)
}

// AutoUpdate runs the core auto-update check (D4/G4 + the owner ruling):
// gated by [core].auto_update and update_interval (persisted check state in
// the data dir), it re-runs the binary resolution first (the per-wave
// re-detection), then — for the ASSAY-OWNED user-local binary only —
// fetches the latest release tag, refuses below-floor releases loud, and —
// when a newer release exists — stages + verifies + gates it, atomically
// swaps ~/.local/bin/xray (keeping the previous binary for the D8 binary-
// level rollback), materializes the assets (C2) and restarts the running
// core ON the new binary. An override or a bound pre-existing system core
// makes the whole path inert with a ONE-TIME loud INFO (S5). Failures are
// loud errors that never break the wave (the stage wiring swallows them
// into a WARNING); a failed check does not advance the interval state, so
// the next wave retries.
func (m *Manager) AutoUpdate(ctx context.Context, cfg config.CoreConfig) error {
	if !cfg.AutoUpdate {
		m.logDisabledInfo()
		return nil
	}
	m.reattach(ctx)
	if !m.updatable() {
		m.logInertInfo()
		return nil
	}
	interval := cfg.UpdateInterval.Duration
	if interval <= 0 {
		interval = config.DefaultCoreUpdateInterval
	}
	statePath := filepath.Join(m.dataDir, coreUpdateStateName)
	// The pending restart leg is LOCAL (no API traffic), so it runs BEFORE
	// the interval gate: a failed restart from the previous wave is retried
	// on THIS wave regardless of the check cadence.
	if m.retryPendingRestart(ctx) {
		return nil
	}
	if m.updateCheckSkipped(statePath, interval) {
		return nil
	}
	if err := m.updateToLatest(ctx, statePath); err != nil {
		_, _ = fmt.Fprintf(m.log, "WARNING: core: auto-update: %v (the wave continues)\n", err)
		return err
	}
	return nil
}

// updatable reports whether auto-update may act on the CURRENT binding:
// only the assay-owned user-local binary (and the pending-install state
// that will become one). An override and a pre-existing system core are
// inert (S5).
func (m *Manager) updatable() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.source {
	case SourceUserLocal, "":
		return true
	case SourceOverride, SourceSystemPreexisting:
		return false
	default:
		return false
	}
}

// logDisabledInfo emits the ONE-TIME INFO for [core].auto_update = false
// (per manager lifetime).
func (m *Manager) logDisabledInfo() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inertInfoLogged {
		return
	}
	m.inertInfoLogged = true
	_, _ = fmt.Fprintf(m.log, "INFO: core: [core].auto_update = false — the core update check "+
		"is disabled; the bound binary %s stays as it is\n", m.bin)
}

// logInertInfo emits the S5 ONE-TIME inert INFO (per manager lifetime) for
// the bindings auto-update may not touch.
func (m *Manager) logInertInfo() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inertInfoLogged {
		return
	}
	switch m.source {
	case SourceOverride:
		m.inertInfoLogged = true
		_, _ = fmt.Fprintf(m.log, "INFO: core: [core].xray_bin is overridden (%s) — core "+
			"auto-update stays inert for this binary (S5)\n", m.bin)
	case SourceSystemPreexisting:
		m.inertInfoLogged = true
		_, _ = fmt.Fprintf(m.log, "INFO: core: bound pre-existing system xray %s — auto-update "+
			"stays inert (assay does not manage a binary it did not install; S5)\n", m.bin)
	case SourceUserLocal, "": // updatable bindings never log inert
	}
}

// reattach is the per-wave re-detection (owner ruling): the resolution is
// re-run (pure stat — no download, no network) and the binding flips when
// the answer changed (a binary installed or removed between waves). Every
// other entry point is read-only, so this is the one place the wave
// reconciles the binding with the disk.
func (m *Manager) reattach(_ context.Context) {
	bin := config.ResolveCoreXrayBin(m.override, m.dataDir)
	src := classifyBinarySource(m.override, bin)
	// m.override is immutable after NewManager; the CURRENT binding reads
	// under mu — the single-writer invariant (only this wave path and the
	// constructor mutate bin/source) holds, and the lock keeps it honest
	// for any future second caller.
	m.mu.Lock()
	unchanged := bin == m.bin && src == m.source
	m.mu.Unlock()
	if unchanged {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyBindingLocked(src, bin) //nolint:contextcheck // the binding probe is bounded-local (10s), not wave work
}

// classifyBinarySource maps a resolved binary path back onto its
// provenance (the resolution order's inverse for bookkeeping). "" = the
// pending-install state (no binary anywhere; the bound path is the
// install target).
func classifyBinarySource(override, bin string) BinarySource {
	if override != "" {
		return SourceOverride
	}
	if user := config.UserLocalXrayBin(); user != "" && bin == user {
		return SourceUserLocal
	}
	if slices.Contains(config.DefaultSystemXrayPaths, bin) {
		return SourceSystemPreexisting
	}
	return ""
}

// applyBindingLocked adopts a new binding: it probes the bound binary's
// version (a non-answer is loud, never fatal), warns loud and
// non-blocking on a below-floor binary, writes the provenance, and logs
// the binding line. mu is held by the caller. The "" (pending) source
// binds the install target silently — there is nothing to probe or record
// yet.
func (m *Manager) applyBindingLocked(src BinarySource, bin string) {
	m.bin = bin
	m.source = src
	version := ""
	//nolint:gosec // G703: the bound path comes from the owner-ruling resolution —
	// the owner's config and the standard-path list are the trust root.
	if _, err := os.Stat(bin); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		v, err := xrayupdate.CurrentVersion(ctx, bin)
		if err != nil {
			_, _ = fmt.Fprintf(m.log, "WARNING: core: bound binary %s did not answer `version` (%v) — "+
				"the version stays unknown and the floor cannot be checked\n", bin, err)
		} else {
			version = v
			warnBelowFloor(binarySourceKind(src), bin, version, m.log)
		}
	}
	switch src {
	case SourceUserLocal:
		_, _ = fmt.Fprintf(m.log, "core: bound user-local xray core %s (assay owns it — "+
			"auto-update keeps it current)\n", bin)
	case SourceSystemPreexisting:
		_, _ = fmt.Fprintf(m.log, "core: bound existing system xray %s (S5: assay does not "+
			"update a binary it did not install)\n", bin)
	case SourceOverride, "":
		// The override messaging belongs to EnsureCoreBinary/logInertInfo;
		// the pending state has nothing to announce.
	}
	if src != "" {
		writeCoreProvenance(m.dataDir, src, bin, version, m.log)
	}
}

// binarySourceKind names the binding kind for the floor-warning lines.
func binarySourceKind(src BinarySource) string {
	if src == SourceUserLocal {
		return "user-local"
	}
	return "system"
}

// updateCheckSkipped reports whether the persisted check state makes the
// check not-due (logging the loud skip when so).
func (m *Manager) updateCheckSkipped(statePath string, interval time.Duration) bool {
	last, ok := readUpdateState(statePath)
	if !ok || time.Since(last) >= interval {
		return false
	}
	_, _ = fmt.Fprintf(m.log, "core: auto-update skipped (checked %s ago; interval %s)\n",
		time.Since(last).Round(time.Second), interval)
	return true
}

// retryPendingRestart re-attempts a PENDING restart leg (the marker from a
// previous wave's failed post-install restart): a running core restarts on
// the swapped binary; a dead core is started (EnsureRunning boots the new
// binary); nothing running and nothing to do clears the marker. Success
// clears the marker and logs loud — the wave continues normally. The return
// reports whether a pending leg existed (the caller stops there: the update
// check itself remains gated by the interval).
// The ctx parameter exists for the contextcheck call-site contract only —
// it is deliberately NOT forwarded: both legs of this function run on a
// non-canceling background context (C4 — a restarted/started core must
// outlive the wave that triggered it), so forwarding the caller's ctx
// would change the contract, not honor it.
func (m *Manager) retryPendingRestart(_ context.Context) bool {
	marker := filepath.Join(m.dataDir, coreRestartPendingName)
	tagRaw, err := os.ReadFile(marker)
	if err != nil {
		return false // no pending leg — the common path
	}
	tag := strings.TrimSpace(string(tagRaw))
	if m.running() {
		// C4: the restart's ctx is deliberately NON-canceling — the child
		// must outlive this wave (the same contract as the install-path
		// restart below; the suppressed lint IS the contract).
		if rerr := m.Restart(context.Background()); rerr != nil { //nolint:contextcheck // C4 non-canceling
			_, _ = fmt.Fprintf(m.log,
				"WARNING: core: restart-pending leg failed (binary %s on disk, retrying next wave): %v\n",
				orUnknown(tag), rerr)
			return true
		}
		m.clearRestartPending()
		_, _ = fmt.Fprintf(m.log, "core: pending restart leg completed — the running core is now on %s\n", orUnknown(tag))
		return true
	}
	// Nothing running: EnsureRunning boots the new binary directly (the
	// fresh-install path — no restart needed, the marker's purpose is served).
	if serr := m.EnsureRunning(context.Background()); serr != nil { //nolint:contextcheck // C4 non-canceling
		_, _ = fmt.Fprintf(m.log,
			"WARNING: core: restart-pending leg could not start the core on %s (retrying next wave): %v\n",
			orUnknown(tag), serr)
		return true
	}
	m.clearRestartPending()
	_, _ = fmt.Fprintf(m.log, "core: pending restart leg completed via start — the core is now on %s\n", orUnknown(tag))
	return true
}

// clearRestartPending removes the marker; a missing marker is the clean
// no-op (removal failures are loud — a stale marker would re-restart the
// core on every wave).
func (m *Manager) clearRestartPending() {
	if err := os.Remove(filepath.Join(m.dataDir, coreRestartPendingName)); err != nil && !os.IsNotExist(err) {
		_, _ = fmt.Fprintf(m.log, "WARNING: core: restart-pending marker removal failed: %v\n", err)
	}
}

func orUnknown(tag string) string {
	if tag == "" {
		return "(unknown release)"
	}
	return tag
}

// updateToLatest is the update leg: fetch the latest tag, floor-check it,
// compare with the bound version, and — when newer — stage, verify, install
// atomically at the user-local target (keeping the previous binary for the
// D8 binary-level rollback), rebind, and restart the running core onto the
// new binary. Every failure is a loud error; a failed check does not
// advance the interval state (the next wave retries).
func (m *Manager) updateToLatest(ctx context.Context, statePath string) error {
	// The CURRENT version is read BEFORE any network (fail fast): a core
	// binary that cannot answer `version` fails the leg hermetically-local.
	current, err := xrayupdate.CurrentVersion(ctx, m.bin)
	if err != nil {
		return fmt.Errorf("could not read the current version: %w", err)
	}
	tag, err := xrayupdate.FetchLatestTag(ctx, releaseAPIBase)
	if err != nil {
		return fmt.Errorf("release check failed: %w (retrying next interval)", err)
	}
	// The floor applies to the LATEST tag before anything is downloaded: a
	// below-floor release is never installed, never downloaded past the
	// check leg.
	if ferr := checkVersionFloor(tag); ferr != nil {
		_ = writeUpdateState(statePath, time.Now()) // do not hammer the API every wave
		return ferr
	}
	if current != "" && strings.TrimPrefix(tag, "v") == current {
		_ = writeUpdateState(statePath, time.Now())
		_, _ = fmt.Fprintf(m.log, "core: xray core already at %s — nothing to update\n", tag)
		return nil
	}
	staged, newTag, err := downloadStagedCore(ctx, m.dataDir, m.log)
	if err != nil {
		return fmt.Errorf("staging failed: %w", err)
	}
	installed, err := installUserLocalCore(staged, m.log)
	if err != nil {
		return fmt.Errorf("install failed (the previous binary is untouched): %w", err)
	}
	materializeAssets(m.dataDir, m.log)
	// Rebind onto the freshly installed user-local binary (probes its
	// version, refreshes the provenance, logs the binding).
	// The binding probe is bounded-local (10s), not wave work (C4-adjacent).
	m.mu.Lock()
	//nolint:contextcheck // bounded-local probe, not wave work
	m.applyBindingLocked(SourceUserLocal, installed)
	m.mu.Unlock()
	// A running core restarts ON the new binary (the old inode keeps a
	// running process alive — the swap alone changes nothing). A fresh
	// install (nothing running) needs no restart leg; the next
	// EnsureRunning boots the new binary.
	if m.running() {
		// C4: the restart's ctx is deliberately NON-canceling — the child
		// must outlive this wave/update regardless of the caller's ctx.
		if err := m.Restart(context.Background()); err != nil { //nolint:contextcheck // C4: non-canceling ctx is the contract
			// The restart-pending marker (T6 disposition of the T5 M-1
			// residual): the binary on disk is new but the RUNNING core kept
			// the old one. The "already at latest" early-return above would
			// otherwise skip the re-attempt forever (the version pair
			// matches once the install landed); the marker routes the NEXT
			// wave through retryPendingRestart instead.
			if perr := os.WriteFile(filepath.Join(m.dataDir, coreRestartPendingName), []byte(newTag), 0o600); perr != nil {
				// Degenerate double failure (restart AND marker write): with
				// no marker, the next due check takes the "already at latest"
				// early-return above — the restart is NEVER re-attempted
				// automatically. Say so, name the manual remedy.
				_, _ = fmt.Fprintf(m.log, "WARNING: core: restart-pending marker write failed: %v — "+
					"the restart will NOT be re-attempted automatically (the next check reports "+
					"'already at latest'); restart the core manually or remove %s to force a re-install\n",
					perr, m.bin)
			}
			return fmt.Errorf("core %s installed but the restart failed: %w", newTag, err)
		}
	}
	m.clearRestartPending()
	_ = writeUpdateState(statePath, time.Now())
	if current == "" {
		_, _ = fmt.Fprintf(m.log, "core: xray core %s installed at %s (sha256 verified, "+
			"-test gate passed)\n", newTag, m.bin)
	} else {
		_, _ = fmt.Fprintf(m.log, "core: xray core updated v%s → %s at %s (sha256 verified, "+
			"-test gate passed; the previous binary stays at %s for the D8 binary-level rollback)\n",
			current, newTag, m.bin, userLocalPreviousBin())
	}
	return nil
}

// running reports whether a core process is currently running (the
// auto-update restart leg's condition). childAliveLocked already covers
// both ownership shapes (session child, adopted pid — liveness-polled), so
// no extra adoptedPID clause is needed (a dead adopted pid reads dead).
func (m *Manager) running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.childAliveLocked()
}

// checkVersionFloor refuses a release tag below coreVersionFloor (fail-
// closed: an unparseable tag refuses too — the floor is the point).
func checkVersionFloor(tag string) error {
	cmp, err := compareVersionTags(strings.TrimPrefix(tag, "v"), coreVersionFloor)
	if err != nil {
		return fmt.Errorf("core release %s does not parse against the version floor %s — "+
			"refusing (fail-closed): %w", tag, coreVersionFloor, err)
	}
	if cmp < 0 {
		return fmt.Errorf("core release %s is below the observatory-safe version floor %s "+
			"(the pre-#6666 observatory busy-loop) — refusing to install", tag, coreVersionFloor)
	}
	return nil
}

// compareVersionTags numerically compares dotted version strings ("26.9.9"
// vs "26.10.31"); missing components count as 0; a non-numeric component
// is an error (the caller refuses loud).
func compareVersionTags(a, b string) (int, error) {
	pa, err := parseVersionTriple(a)
	if err != nil {
		return 0, fmt.Errorf("version %q: %w", a, err)
	}
	pb, err := parseVersionTriple(b)
	if err != nil {
		return 0, fmt.Errorf("version %q: %w", b, err)
	}
	for i := range pa {
		switch {
		case pa[i] < pb[i]:
			return -1, nil
		case pa[i] > pb[i]:
			return 1, nil
		}
	}
	return 0, nil
}

// parseVersionTriple parses "26.9.9" into its numeric components (missing
// components = 0).
func parseVersionTriple(v string) ([3]int, error) {
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, errors.New("not a dotted version triple")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, fmt.Errorf("component %q: not numeric", p)
		}
		if n < 0 {
			return out, fmt.Errorf("component %q: negative", p)
		}
		out[i] = n
	}
	return out, nil
}

// readUpdateState reads the persisted check timestamp; an absent or corrupt
// state means "due now" (ok=false) — the check is cheap, a corrupt file
// must never wedge the cadence.
func readUpdateState(path string) (time.Time, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	var state coreUpdateState
	if err := json.Unmarshal(raw, &state); err != nil || state.LastCheck.IsZero() {
		return time.Time{}, false
	}
	return state.LastCheck, true
}

// writeUpdateState persists the check timestamp atomically (0600 — the
// state carries no secrets, but the data dir's convention is
// owner-private).
func writeUpdateState(path string, now time.Time) error {
	raw, err := json.Marshal(coreUpdateState{LastCheck: now.UTC()})
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(path, func(f *os.File) error {
		_, werr := f.Write(raw)
		return werr
	})
}

// copyFile copies src → dst with the given permission (create/truncate).
// The download package-local twin of xrayupdate.copyFile (same semantics).
func copyFile(src, dst string, perm os.FileMode) error {
	//nolint:gosec // G703: src is a staged/verified artifact or a fixture the
	// resolution just wrote — the config/trust-root suppression applies.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
