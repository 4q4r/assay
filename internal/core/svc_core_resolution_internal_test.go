//go:build unix

package core

// svc_core_resolution_internal_test.go pins the windows service-context core
// lifecycle end to end (the live SCM diagnostics root cause, 2026-11-19):
//
//   - the MANAGER in the service context binds the MANAGED core
//     <data>/bin/xray (never the user-local spot — the SYSTEM profile's
//     systemprofile tree is poison) and records the SourceManaged
//     provenance;
//   - the manager REFUSES construction loud, naming `assay install`, when
//     the service-context resolution lands on a missing core (fail-closed
//     — the old shape bound a nonexistent path and fork/exec failed on it
//     at every bootstrap + crash-supervision retry);
//   - the per-wave reattach KEEPS the binding and warns loud when the
//     managed core vanishes mid-run (never flips to a missing path);
//   - EnsureCoreBinary's windows placement leg copies the bound core to the
//     managed spot — the leg-completion guarantee the service resolution
//     consumes (the installing user's context fills the same -c data dir
//     the service then reads);
//   - the context-aware install target: auto-update in the service context
//     swaps the MANAGED binary in place (never the SYSTEM-profile user-local
//     spot), keeping the .previous rollback artifact next to it;
//   - the D8 binary-level rollback covers the managed source.
//
// The service context itself is pinned through config.ServiceContextDetected
// (the injectable seam) — no Windows machine is needed for any of these.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"assay/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withServiceContext pins the service-context seam for the test's duration.
func withServiceContext(t *testing.T) {
	t.Helper()
	orig := config.ServiceContextDetected
	config.ServiceContextDetected = func() bool { return true }
	t.Cleanup(func() { config.ServiceContextDetected = orig })
}

// withManagedPlacement pins the windows managed-placement seam: ON = the
// windows host posture (the placement leg fires), OFF = linux/darwin (the
// interactive goldens stay untouched).
func withManagedPlacement(t *testing.T, on bool) {
	t.Helper()
	orig := managedCorePlacementEnabled
	managedCorePlacementEnabled = func() bool { return on }
	t.Cleanup(func() { managedCorePlacementEnabled = orig })
}

// newManagedCoreFixture arms the resolution seams with a user-local binary
// that EXISTS (the poison stand-in the service context must skip) and a
// managed core at <dataDir>/bin/xray. Returns the manager's data dir, the
// user-local path, and the managed path.
func newManagedCoreFixture(t *testing.T, managedVersion string) (string, string, string) {
	t.Helper()
	userLocal, _ := withResolutionSeams(t)
	writeVersionScript(t, userLocal, "26.9.9")
	dir := t.TempDir()
	managed := writeVersionScript(t, config.ManagedCoreBin(dir), managedVersion)
	return dir, userLocal, managed
}

// TestNewManagerServiceContextBindsManagedCore pins the service-context
// binding: the manager binds the MANAGED core (SourceManaged — assay-owned,
// updatable) even though the user-local binary exists, logs the binding
// loud, and records the provenance.
func TestNewManagerServiceContextBindsManagedCore(t *testing.T) {
	dir, userLocal, managed := newManagedCoreFixture(t, "26.10.31")
	withServiceContext(t)

	log := &syncBuffer{}
	m, err := NewManager(config.CoreConfig{SocksPort: 22950, RollbackStrikes: 3}, dir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)

	assert.Equal(t, managed, m.bin, "the service-context manager binds the managed core")
	assert.NotEqual(t, userLocal, m.bin, "the user-local spot is never bound in the service context")
	assert.Equal(t, SourceManaged, m.source, "the managed binding carries the managed provenance")
	assert.Contains(t, log.String(), managed, "the bound path is logged loud")
	assert.Contains(t, log.String(), "managed", "the binding kind is named")

	state := readProvenanceFixture(t, dir)
	assert.Equal(t, SourceManaged, BinarySource(state.BinarySource), "the provenance records the managed source")
	assert.Equal(t, managed, state.BinaryPath)
	assert.Equal(t, "26.10.31", state.BinaryVersion)
}

// TestNewManagerServiceContextRefusesWithoutCore pins the fail-closed gate:
// with no managed core on disk (install never ran / was purged), the
// manager refuses to construct in the service context with a LOUD error
// naming `assay install` — the exact production incident, now named at the
// actionable boundary instead of surfacing as an opaque fork/exec "cannot
// find the path specified" at every bootstrap and crash-supervision retry.
func TestNewManagerServiceContextRefusesWithoutCore(t *testing.T) {
	userLocal, _ := withResolutionSeams(t)
	dir := t.TempDir()
	_ = userLocal // exists nowhere — the fresh-service state of the incident
	withServiceContext(t)

	log := &syncBuffer{}
	m, err := NewManager(config.CoreConfig{SocksPort: 22952, RollbackStrikes: 3}, dir, log)
	require.Error(t, err, "no core anywhere in the service context → construction refuses")
	assert.Nil(t, m, "no manager is handed out on the refusal")
	assert.Contains(t, err.Error(), "assay install", "the error names the fix")
	assert.Contains(t, err.Error(), config.ManagedCoreBin(dir), "the error names the missing managed spot")
}

// TestNewManagerServiceContextOverrideBindsWithoutGate pins the owner's
// knob: an explicit [core].xray_bin override binds verbatim in the service
// context with NO existence gate (the override path is honored as-is — the
// spawn failure names a bad override path loud, today's posture).
func TestNewManagerServiceContextOverrideBindsWithoutGate(t *testing.T) {
	dir, _, _ := newManagedCoreFixture(t, "26.10.31")
	withServiceContext(t)

	log := &syncBuffer{}
	m, err := NewManager(config.CoreConfig{XrayBin: "/custom/xray", SocksPort: 22954}, dir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)
	assert.Equal(t, "/custom/xray", m.bin, "the override binds verbatim in the service context")
	assert.Equal(t, SourceOverride, m.source)
}

// TestReattachServiceContextKeepsBindingWhenManagedVanishes pins the
// per-wave reattach posture: when the managed core disappears mid-run (the
// running child holds its own inode), reattach KEEPS the current binding
// and warns loud — it never flips the binding onto a missing path (the
// silent-flip would be the regression walking backwards).
func TestReattachServiceContextKeepsBindingWhenManagedVanishes(t *testing.T) {
	dir, _, managed := newManagedCoreFixture(t, "26.10.31")
	withServiceContext(t)

	log := &syncBuffer{}
	m, err := NewManager(config.CoreConfig{SocksPort: 22956, RollbackStrikes: 3}, dir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)
	require.Equal(t, managed, m.bin)

	require.NoError(t, os.Remove(managed), "the managed core vanishes mid-run")
	m.reattach(context.Background())

	assert.Equal(t, managed, m.bin, "the binding is kept — never flipped to a missing path")
	assert.Equal(t, SourceManaged, m.source, "the provenance stays on the kept binding")
	assert.Contains(t, log.String(), "WARNING", "the vanished core is loud")
	assert.Contains(t, log.String(), "assay install", "the warning names the fix")
}

// TestEnsureCoreBinaryWindowsPlacesManagedServiceCopy pins the leg
// completion: on a windows host (the placement seam ON) EnsureCoreBinary —
// running in the INSTALLING user's context — ALSO materializes the bound
// core at the managed spot <data>/bin/xray, so the service (LocalSystem,
// reading the SAME explicit -c data dir) finds a real core. The copy is
// byte-identical and executable; no download is triggered by the placement.
func TestEnsureCoreBinaryWindowsPlacesManagedServiceCopy(t *testing.T) {
	t.Run("user-local binding is copied to the managed spot", func(t *testing.T) {
		userLocal, _ := withResolutionSeams(t)
		writeVersionScript(t, userLocal, "26.10.31")
		dir := t.TempDir()
		withManagedPlacement(t, true)

		srv, hits := fakeCoreReleaseServer(t, "v26.10.31", "", "", nil)
		withReleaseAPIBase(t, srv.URL)
		log := &bytes.Buffer{}
		require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log))

		assert.Zero(t, releaseHits(hits), "the placement never downloads")
		raw, err := os.ReadFile(config.ManagedCoreBin(dir))
		require.NoError(t, err, "the managed copy exists at <data>/bin/xray")
		local, rerr := os.ReadFile(userLocal)
		require.NoError(t, rerr)
		assert.Equal(t, string(local), string(raw), "the managed copy is byte-identical to the bound core")
		st, serr := os.Stat(config.ManagedCoreBin(dir))
		require.NoError(t, serr)
		assert.Equal(t, os.FileMode(0o755), st.Mode().Perm(), "the managed copy is executable")
		assert.Contains(t, log.String(), "managed core copy", "the placement is loud")
	})

	t.Run("download leg also places the managed copy", func(t *testing.T) {
		userLocal, _ := withResolutionSeams(t)
		dir := t.TempDir()
		withManagedPlacement(t, true)
		script := filepath.Join(t.TempDir(), "core-script")
		require.NoError(t, os.WriteFile(script, []byte(shellCoreScript), 0o755))
		srv, hits := fakeCoreReleaseServer(t, "v26.10.31", script, "", nil)
		withReleaseAPIBase(t, srv.URL)

		require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, &bytes.Buffer{}))
		assert.Positive(t, releaseHits(hits), "the download leg ran for real")
		_, err := os.Stat(config.ManagedCoreBin(dir))
		require.NoError(t, err, "a fresh download also lands the managed service copy")
		_, lerr := os.Stat(userLocal)
		require.NoError(t, lerr, "the user-local install target is still filled (interactive behavior)")
	})

	t.Run("override places nothing", func(t *testing.T) {
		withResolutionSeams(t)
		dir := t.TempDir()
		withManagedPlacement(t, true)
		require.NoError(t, EnsureCoreBinary(context.Background(),
			config.CoreConfig{XrayBin: "/usr/bin/xray"}, dir, &bytes.Buffer{}))
		_, err := os.Stat(config.ManagedCoreBin(dir))
		assert.True(t, os.IsNotExist(err),
			"an overridden binary is the owner's knob — the service honors it directly, no managed copy")
	})

	t.Run("placement seam off places nothing (linux/darwin untouched)", func(t *testing.T) {
		userLocal, _ := withResolutionSeams(t)
		writeVersionScript(t, userLocal, "26.10.31")
		dir := t.TempDir()
		withManagedPlacement(t, false)

		require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, &bytes.Buffer{}))
		_, err := os.Stat(config.ManagedCoreBin(dir))
		assert.True(t, os.IsNotExist(err),
			"off-windows installs keep today's shape: no managed spot materialization")
	})
}

// TestInstallCoreBinaryServiceContextTargetsManaged pins the context-aware
// install target: in the service context the atomic install lands at the
// MANAGED spot (the auto-update swap and any bootstrap download leg write
// where the service resolution binds), never the SYSTEM-profile user-local
// spot, and the .previous rollback artifact lands next to it.
func TestInstallCoreBinaryServiceContextTargetsManaged(t *testing.T) {
	dir := t.TempDir()
	_, _ = withResolutionSeams(t)
	withServiceContext(t)

	staged := filepath.Join(t.TempDir(), "staged")
	require.NoError(t, os.WriteFile(staged, []byte(shellCoreScript), 0o755))

	installed, err := installCoreBinary(staged, dir, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Equal(t, config.ManagedCoreBin(dir), installed, "the service-context install targets the managed spot")
	raw, rerr := os.ReadFile(installed)
	require.NoError(t, rerr)
	assert.Equal(t, shellCoreScript, string(raw))
	_, serr := os.Stat(installed + ".previous")
	assert.True(t, os.IsNotExist(serr), "a FRESH install lays no rollback artifact (pre-update shape)")

	// A second install over it swaps atomically and keeps the .previous.
	staged2 := filepath.Join(t.TempDir(), "staged2")
	require.NoError(t, os.WriteFile(staged2, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	installed2, ierr := installCoreBinary(staged2, dir, &bytes.Buffer{})
	require.NoError(t, ierr)
	assert.Equal(t, installed, installed2)
	prev, perr := os.ReadFile(installed + ".previous")
	require.NoError(t, perr, "the previous binary survives the swap as the rollback artifact")
	assert.Equal(t, shellCoreScript, string(prev), "the .previous copy carries the PRE-swap payload")
}

// TestAutoUpdateServiceContextSwapsManagedBinary pins the full service
// auto-update flow: a manager bound to a STALE managed core updates it IN
// PLACE at the managed spot (the release payload lands at
// <data>/bin/xray), the .previous artifact survives next to it, the
// user-local spot is never created, and the provenance flips to the new
// version — all in the service context.
func TestAutoUpdateServiceContextSwapsManagedBinary(t *testing.T) {
	dir, userLocal, _ := newManagedCoreFixture(t, "26.9.9")
	withServiceContext(t)
	releaseBin := writeVersionScript(t, filepath.Join(t.TempDir(), "release"), "26.10.31")
	srv, hits := fakeCoreReleaseServer(t, "v26.10.31", releaseBin, "", nil)
	withReleaseAPIBase(t, srv.URL)

	log := &syncBuffer{}
	m, err := NewManager(config.CoreConfig{SocksPort: 22958, RollbackStrikes: 3}, dir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)
	require.Equal(t, SourceManaged, m.source)

	require.NoError(t, m.AutoUpdate(context.Background(),
		config.CoreConfig{AutoUpdate: true, UpdateInterval: config.Duration{Duration: 24 * time.Hour}}))

	updated, rerr := os.ReadFile(config.ManagedCoreBin(dir))
	require.NoError(t, rerr)
	assert.Contains(t, string(updated), "Xray 26.10.31", "the managed core carries the new release payload")
	prev, perr := os.ReadFile(config.ManagedCoreBin(dir) + ".previous")
	require.NoError(t, perr, "the .previous rollback artifact survives next to the managed core")
	assert.Contains(t, string(prev), "Xray 26.9.9", "the artifact carries the pre-update payload")
	untouched, uerr := os.ReadFile(userLocal)
	require.NoError(t, uerr)
	assert.Contains(t, string(untouched), "Xray 26.9.9",
		"the user-local spot is never written by the service-context update (stale fixture payload intact)")
	assert.Contains(t, log.String(), "updated", "the update is loud")
	state := readProvenanceFixture(t, dir)
	assert.Equal(t, "26.10.31", state.BinaryVersion, "the provenance tracks the swap")
	assert.Equal(t, config.ManagedCoreBin(dir), state.BinaryPath)
	assert.GreaterOrEqual(t, releaseHits(hits), 3, "a real release check + download happened")
}

// TestClassifyBinarySourcePins pins the provenance mapping including the
// managed spot: the managed path classifies SourceManaged (assay-owned,
// updatable), the user-local path stays SourceUserLocal, the system paths
// stay SourceSystemPreexisting, an override stays SourceOverride, and an
// unknown path stays the "" pending state.
func TestClassifyBinarySourcePins(t *testing.T) {
	userLocal, system := withResolutionSeams(t)
	dir := t.TempDir()

	assert.Equal(t, SourceUserLocal, classifyBinarySource("", userLocal, dir))
	assert.Equal(t, SourceManaged, classifyBinarySource("", config.ManagedCoreBin(dir), dir))
	assert.Equal(t, SourceOverride, classifyBinarySource("/ovr", "/ovr", dir))
	assert.Equal(t, SourceSystemPreexisting, classifyBinarySource("", system, dir))
	assert.Equal(t, BinarySource(""), classifyBinarySource("", "/nowhere/xray", dir),
		"an unknown path stays the pending state")
}

// TestRestorePreviousBinaryCoversManagedSource pins the D8 binary-level
// rollback on the managed binding: the .previous artifact next to the
// managed core restores over it (the same atomic-rename mechanism as the
// user-local contract).
func TestRestorePreviousBinaryCoversManagedSource(t *testing.T) {
	dir, _, managed := newManagedCoreFixture(t, "26.10.31")
	withServiceContext(t)

	log := &syncBuffer{}
	m, err := NewManager(config.CoreConfig{SocksPort: 22960, RollbackStrikes: 3}, dir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)
	require.Equal(t, SourceManaged, m.source)

	knownGood := "known-good-payload"
	require.NoError(t, os.WriteFile(managed+".previous", []byte(knownGood), 0o755))

	require.True(t, m.restorePreviousBinaryLocked(), "the managed source is rollback-capable")
	restored, rerr := os.ReadFile(managed)
	require.NoError(t, rerr)
	assert.Equal(t, knownGood, string(restored), "the .previous copy restored over the managed core")
	assert.NoFileExists(t, managed+".previous", "the restore consumes the artifact")
	assert.Contains(t, log.String(), "binary-level rollback", "the restore is loud")
}
