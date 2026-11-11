package core

// download.go carries the managed-core lifecycle (D4/S5/G4): the download,
// sha256 verification and atomic install of the managed xray binary, plus
// the Manager's auto-update. The network and exec mechanics (release fetch,
// checksum verify, flat unpack, staged `-test` gate) are the xrayupdate
// package's proven surface, exported for this path — download.go owns the
// MANAGED decisions: the version floor, the C2 asset-dir contract
// (<data>/share/xray), the atomic swap into <data>/bin/xray, the update
// interval state, and the restart after a swap.
//
// Contracts:
//   - S5: auto-update is MANAGED-CORE-ONLY — an overridden [core].xray_bin
//     makes EnsureCoreBinary and AutoUpdate inert with a loud INFO (one
//     time for the per-wave AutoUpdate).
//   - C2 (T2 contract): the downloader materializes the release's asset
//     files in <data>/share/xray — the spawn wires XRAY_LOCATION_ASSET
//     there, so gate and child resolve assets identically.
//   - Version floor: releases below the observatory-safe floor are refused
//     loud (the pre-#6666 observatory busy-looped ~100% CPU when
//     subjectSelector matched nothing — the shapes assay renders would
//     trip it on an old core).
//   - Failures NEVER break the wave: the auto-update stage swallows the
//     error into a loud WARNING (pipeline wiring); this package only ever
//     returns errors loudly.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"assay/internal/config"
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

// coreVersionFloor is the observatory-safe managed-core floor: v26.9.9
// (2026-09-08) is the first XTLS/Xray-core release carrying the issue
// #6666 fix (PR #6669, closed 2026-08-25 — the observatory busy-looped
// ~100% CPU when subjectSelector matched nothing; the issue was reproduced
// on v26.7.28). Verified against the XTLS issue tracker and the releases
// page 2026-11-11. Auto-update and fresh installs refuse any release below
// it. Var, not const: the tests pin fixtures against an injected floor.
var coreVersionFloor = "26.9.9"

// releaseAPIBase is the GitHub API base of the managed-core release fetch.
// Production = the canonical host; tests point it at an httptest server.
var releaseAPIBase = xrayupdate.DefaultAPIBase

// coreUpdateState is the persisted auto-update check state.
type coreUpdateState struct {
	LastCheck time.Time `json:"last_check"`
}

// EnsureCoreBinary guarantees the managed core binary exists (D4: `assay
// install` downloads it before the first wave). No-op when the managed
// binary already exists, and INERT with a loud INFO when
// [core].xray_bin is overridden (S5 — the override owns that path).
// Otherwise the latest release asset for the platform is downloaded,
// sha256-verified against the release checksum file, floor-checked, and
// installed atomically to <data>/bin/xray with the assets materialized in
// <data>/share/xray (C2). A download/verification failure is a loud error:
// the daemon's waves retry through auto-update, so install stays a warning
// in the caller's hands.
func EnsureCoreBinary(ctx context.Context, cfg config.CoreConfig, dataDir string, log io.Writer) error {
	if cfg.XrayBin != "" {
		_, _ = fmt.Fprintf(log, "INFO: core: [core].xray_bin is overridden (%s) — the managed core "+
			"download and auto-update stay inert for this binary (S5)\n", cfg.XrayBin)
		return nil
	}
	bin := filepath.Join(dataDir, "bin", "xray")
	if _, err := os.Stat(bin); err == nil {
		_, _ = fmt.Fprintf(log, "core: managed core binary present (%s) — nothing to download\n", bin)
		return nil
	}
	staged, tag, err := downloadStagedCore(ctx, dataDir, log)
	if err != nil {
		return err
	}
	if err := installManagedCore(dataDir, staged, log); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(log, "core: managed xray core %s installed at %s (sha256 verified, "+
		"-test gate passed; assets in %s)\n", tag, bin, managedAssetDir(dataDir))
	return nil
}

// downloadStagedCore fetches + verifies + gates the latest release into the
// data dir's staging area and enforces the version floor on the tag (a
// below-floor release never downloads past the check leg).
func downloadStagedCore(ctx context.Context, dataDir string, log io.Writer) (string, string, error) {
	tag, err := xrayupdate.FetchLatestTag(ctx, releaseAPIBase)
	if err != nil {
		return "", "", fmt.Errorf("managed core: fetch latest release: %w", err)
	}
	if err := checkVersionFloor(tag); err != nil {
		return "", "", err
	}
	stagingDir := coreStagingDir(dataDir)
	// Bound the staging dir to exactly ONE release (fix M-3, staging half):
	// previous releases' leftovers (files a newer release dropped) are wiped
	// before the new one lands. The dir is pure scratch — the binary and
	// assets are copied out by installManagedCore, and the manual
	// xray-update flow reads its staged binary within its own invocation.
	if err := wipeStaging(stagingDir); err != nil {
		_, _ = fmt.Fprintf(log, "WARNING: core: staging wipe failed: %v (staging over the old content)\n", err)
	}
	staged, tag, err := xrayupdate.StageVerifiedRelease(ctx, releaseAPIBase, stagingDir, "core:", log, nil)
	if err != nil {
		return "", "", fmt.Errorf("managed core: stage release %s: %w", tag, err)
	}
	return staged, tag, nil
}

// coreStagingDir is the managed download's scratch area (the same staging
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

// installManagedCore atomically installs the staged binary into
// <data>/bin/xray and materializes the release's asset files into
// <data>/share/xray (C2). Same-directory temp + rename (xrayupdate's
// applyStaged shape) — a crash never leaves a half-written binary.
func installManagedCore(dataDir, staged string, log io.Writer) error {
	binDir := filepath.Join(dataDir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		return fmt.Errorf("managed core: create bin dir: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	temp := filepath.Join(binDir, ".xray-install-"+stamp)
	if err := copyFile(staged, temp, 0o755); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("managed core: stage temp copy: %w", err)
	}
	bin := filepath.Join(binDir, "xray")
	if err := os.Rename(temp, bin); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("managed core: atomic install %s: %w", bin, err)
	}

	// C2: every non-binary release asset (geoip.dat / geosite.dat …) lands
	// in the managed asset dir the spawn wires XRAY_LOCATION_ASSET to.
	assets := 0
	assetDir := managedAssetDir(dataDir)
	entries, rerr := os.ReadDir(coreStagingDir(dataDir))
	if rerr != nil {
		_, _ = fmt.Fprintf(log, "WARNING: core: read staged assets: %v (the binary is installed; "+
			"geosite-style routes will fall back to their own resolution)\n", rerr)
		return nil
	}
	if err := os.MkdirAll(assetDir, 0o750); err != nil {
		return fmt.Errorf("managed core: create asset dir: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || name == "xray" || name == "test-config.json" ||
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
	return nil
}

// AutoUpdate runs the managed-core auto-update check (D4/G4, S5): gated by
// update_interval (persisted check state in the data dir), it fetches the
// latest release tag, refuses below-floor releases loud, and — when a newer
// release exists — stages + verifies + gates it, atomically swaps
// <data>/bin/xray, materializes the assets (C2) and restarts the running
// core ON the new binary. An overridden [core].xray_bin makes the whole
// path inert with a ONE-TIME loud INFO (S5). Failures are loud errors that
// never break the wave (the stage wiring swallows them into a WARNING); a
// failed check does not advance the interval state, so the next wave
// retries.
func (m *Manager) AutoUpdate(ctx context.Context, cfg config.CoreConfig) error {
	if !m.managed {
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

// logInertInfo emits the S5 ONE-TIME inert INFO (per manager lifetime).
func (m *Manager) logInertInfo() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inertInfoLogged {
		return
	}
	m.inertInfoLogged = true
	_, _ = fmt.Fprintf(m.log, "INFO: core: [core].xray_bin is overridden (%s) — managed-core "+
		"auto-update stays inert for this binary (S5)\n", m.bin)
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
// compare with the installed version, and — when newer — stage, verify,
// install and restart. Every failure is a loud error; a failed check does
// not advance the interval state (the next wave retries).
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
		_, _ = fmt.Fprintf(m.log, "core: managed core already at %s — nothing to update\n", tag)
		return nil
	}
	staged, newTag, err := downloadStagedCore(ctx, m.dataDir, m.log)
	if err != nil {
		return fmt.Errorf("staging failed: %w", err)
	}
	if err := installManagedCore(m.dataDir, staged, m.log); err != nil {
		return fmt.Errorf("install failed (the previous binary is untouched): %w", err)
	}
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
			return fmt.Errorf("managed core %s installed but the restart failed: %w", newTag, err)
		}
	}
	m.clearRestartPending()
	_ = writeUpdateState(statePath, time.Now())
	if current == "" {
		_, _ = fmt.Fprintf(m.log, "core: managed xray core %s installed at %s (sha256 verified, "+
			"-test gate passed)\n", newTag, m.bin)
	} else {
		_, _ = fmt.Fprintf(m.log, "core: managed xray core updated v%s → %s at %s (sha256 verified, "+
			"-test gate passed)\n", current, newTag, m.bin)
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
		return fmt.Errorf("managed core release %s does not parse against the version floor %s — "+
			"refusing (fail-closed): %w", tag, coreVersionFloor, err)
	}
	if cmp < 0 {
		return fmt.Errorf("managed core release %s is below the observatory-safe version floor %s "+
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
