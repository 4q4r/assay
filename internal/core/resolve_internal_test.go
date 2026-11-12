//go:build unix

package core

// resolve_internal_test.go pins the OWNER-RULING resolution order (2026-11-11,
// revised 2026-11-12: «запись в локал не требует судо»): an explicit
// [core].xray_bin override wins (inert, S5); an EXISTING user-local
// ~/.local/bin/xray is assay's OWN binary — bound and UPDATABLE; an
// EXISTING system xray at the standard paths (/usr/local/bin/xray,
// /usr/bin/xray — first match) is BOUND with auto-update INERT and a
// non-blocking floor WARNING; with NONE of the above the sha-verified
// release installs ATOMICALLY to ~/.local/bin/xray (user-writable, NO
// elevation) with a one-time loud PATH note. Provenance
// (binary_source / binary_path / binary_version) lands in
// <data>/core-state.json on every resolution change.
//
// Hermeticity: the user-local bin dir and the standard-path list are
// injectable seams (config.UserLocalBinDir / config.DefaultSystemXrayPaths)
// — no test touches the real $HOME/.local tree or the real /usr tree, and
// no elevation exists anywhere on the path.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"assay/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withResolutionSeams injects BOTH resolution seams into fixture dirs: the
// user-local bin dir (~/.local/bin stand-in) and the standard-path scan
// list (the canonical system target stays absent). Returns the user-local
// binary path and the (absent) canonical system target. No test can ever
// touch the real $HOME/.local or /usr trees through the resolution.
func withResolutionSeams(t *testing.T) (string, string) {
	t.Helper()
	userBinDir := filepath.Join(t.TempDir(), "local-bin")
	systemTarget := filepath.Join(t.TempDir(), "xray")

	origDirFn := config.UserLocalBinDir
	origPaths := config.DefaultSystemXrayPaths
	config.UserLocalBinDir = func() string { return userBinDir }
	config.DefaultSystemXrayPaths = []string{systemTarget}
	t.Cleanup(func() {
		config.UserLocalBinDir = origDirFn
		config.DefaultSystemXrayPaths = origPaths
	})
	return filepath.Join(userBinDir, "xray"), systemTarget
}

// writeVersionScript plants a stand-in "xray binary" at path that answers
// `version` with the given version banner and exits 0 for everything else —
// the parsable-banner contract of xrayupdate.CurrentVersion.
func writeVersionScript(t *testing.T, path, ver string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path,
		[]byte("#!/bin/sh\necho \"Xray "+ver+" (fixture, Penetrates Nothing.) Custom Build\"\nexit 0\n"),
		0o755))
	return path
}

// readProvenanceFixture reads the resolution provenance from the data dir's
// core-state.json (the cross-process contract the status block consumes).
func readProvenanceFixture(t *testing.T, dataDir string) *HealthState {
	t.Helper()
	state, err := ReadHealthState(dataDir)
	require.NoError(t, err)
	require.NotNil(t, state, "core-state.json exists after a resolution")
	return state
}

// TestResolutionBindsExistingSystemXray (brief test 1, owner-revised
// mapping): an existing user-local ~/.local/bin/xray binds FIRST (it is
// assay's own binary); with no user-local binary, an existing system xray
// at the injected standard path binds SECOND. Neither downloads anything.
func TestResolutionBindsExistingSystemXray(t *testing.T) {
	newSeams := func(t *testing.T) (string, string) {
		t.Helper()
		userLocal, system := withResolutionSeams(t)
		srv, _ := fakeCoreReleaseServer(t, "v26.10.31", "", "", nil)
		withReleaseAPIBase(t, srv.URL)
		return userLocal, system
	}

	t.Run("user-local binary binds first and is updatable", func(t *testing.T) {
		userLocal, _ := newSeams(t)
		writeVersionScript(t, userLocal, "26.9.9")
		dir := t.TempDir()

		log := &bytes.Buffer{}
		require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log))

		logs := log.String()
		assert.Contains(t, logs, userLocal, "the bound path is reported loud")
		assert.Contains(t, logs, "user-local", "the assay-owned binding is named")

		state := readProvenanceFixture(t, dir)
		assert.Equal(t, SourceUserLocal, BinarySource(state.BinarySource))
		assert.Equal(t, userLocal, state.BinaryPath)
		assert.Equal(t, "26.9.9", state.BinaryVersion)
	})

	t.Run("system xray binds second when no user-local exists", func(t *testing.T) {
		_, system := newSeams(t)
		writeVersionScript(t, system, "26.10.31")
		dir := t.TempDir()

		srv, hits := fakeCoreReleaseServer(t, "v26.10.31", "", "", nil)
		withReleaseAPIBase(t, srv.URL)

		log := &bytes.Buffer{}
		require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log))

		assert.Zero(t, releaseHits(hits), "an existing system core downloads nothing")
		logs := log.String()
		assert.Contains(t, logs, system, "the bound system path is reported loud")
		assert.Contains(t, logs, "inert", "the system binding names the inert auto-update")

		state := readProvenanceFixture(t, dir)
		assert.Equal(t, SourceSystemPreexisting, BinarySource(state.BinarySource))
		assert.Equal(t, system, state.BinaryPath)
		assert.Equal(t, "26.10.31", state.BinaryVersion)

		// A second pass re-binds without any network work.
		require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, &bytes.Buffer{}))
		assert.Zero(t, releaseHits(hits), "re-binding stays local")
	})
}

// TestResolutionInstallsUserLocalWhenAbsent (brief test 2, owner-revised):
// with no user-local binary and no system xray anywhere, the sha-verified
// release installs ATOMICALLY to ~/.local/bin/xray — user-writable, NO
// elevation anywhere — with the one-time loud PATH note and the user-local
// provenance.
func TestResolutionInstallsUserLocalWhenAbsent(t *testing.T) {
	userLocal, _ := withResolutionSeams(t)
	dir := t.TempDir()

	script := filepath.Join(t.TempDir(), "core-script")
	require.NoError(t, os.WriteFile(script, []byte(shellCoreScript), 0o755))
	srv, hits := fakeCoreReleaseServer(t, "v26.10.31", script, "", nil)
	withReleaseAPIBase(t, srv.URL)

	log := &bytes.Buffer{}
	require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log))

	installed, err := os.ReadFile(userLocal)
	require.NoError(t, err, "the user-local binary exists after the install")
	assert.Equal(t, shellCoreScript, string(installed), "the installed binary is the verified payload")
	st, statErr := os.Stat(userLocal)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o755), st.Mode().Perm(), "the installed binary is executable")

	logs := log.String()
	assert.Contains(t, logs, "sha256", "the verification is loud")
	assert.Contains(t, logs, "PATH", "the PATH note is loud on a fresh install")
	assert.Contains(t, logs, "shadows", "the note names the shadowing rationale")
	assert.NotContains(t, logs, "sudo", "no elevation exists anywhere on the install path")
	assert.Positive(t, releaseHits(hits), "a real download happened")

	state := readProvenanceFixture(t, dir)
	assert.Equal(t, SourceUserLocal, BinarySource(state.BinarySource))
	assert.Equal(t, userLocal, state.BinaryPath)
	assert.Equal(t, "26.10.31", state.BinaryVersion)
}

// TestResolutionInstallsAtomicallyAndRebindsOnReinstall (brief test 3,
// owner-revised mapping): the install is atomic (same-directory temp +
// rename) and the resolution is idempotent — a re-run over an installed
// binary is a bind, not a second download.
func TestResolutionInstallsAtomicallyAndRebindsOnReinstall(t *testing.T) {
	userLocal, _ := withResolutionSeams(t)
	dir := t.TempDir()

	script := filepath.Join(t.TempDir(), "core-script")
	require.NoError(t, os.WriteFile(script, []byte(shellCoreScript), 0o755))
	srv, hits := fakeCoreReleaseServer(t, "v26.10.31", script, "", nil)
	withReleaseAPIBase(t, srv.URL)

	require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, &bytes.Buffer{}))
	// No install scratch left behind in the bin dir (the atomic temp is
	// renamed away, never accumulated).
	entries, err := os.ReadDir(filepath.Dir(userLocal))
	require.NoError(t, err)
	for _, entry := range entries {
		assert.False(t, strings.HasPrefix(entry.Name(), ".xray-install-"),
			"no install temp files accumulate in the user bin dir (atomic rename)")
	}

	// The re-run binds the installed binary: zero further network work.
	before := releaseHits(hits)
	log := &bytes.Buffer{}
	require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log))
	assert.Equal(t, before, releaseHits(hits), "the re-run binds without a download")
	assert.Contains(t, log.String(), userLocal, "the re-run reports the bound binary")
}

// TestUserLocalInstallDetectedNextWave (brief test 4, owner-revised
// mapping): the daemon binds the freshly installed user-local binary on the
// next wave — the manager's resolution observes it, and the provenance
// carries the binding.
func TestUserLocalInstallDetectedNextWave(t *testing.T) {
	userLocal, _ := withResolutionSeams(t)
	dir := t.TempDir()

	payload := writeVersionScript(t, filepath.Join(t.TempDir(), "release"), "26.10.31")
	srv, hits := fakeCoreReleaseServer(t, "v26.10.31", payload, "", nil)
	withReleaseAPIBase(t, srv.URL)
	require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, &bytes.Buffer{}))
	afterInstall := releaseHits(hits)

	// The next wave: a manager over the same data dir binds the installed
	// binary WITHOUT any download. The update check itself is not due
	// (fresh state) — the binding, not the update, is under test.
	writeUpdateStateFixture(t, dir, time.Now())
	log := &syncBuffer{}
	m, err := NewManager(config.CoreConfig{SocksPort: 22928, RollbackStrikes: 3}, dir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)

	assert.Equal(t, userLocal, m.bin, "the manager binds the installed user-local binary")
	assert.Equal(t, SourceUserLocal, m.source)
	require.NoError(t, m.AutoUpdate(context.Background(),
		config.CoreConfig{AutoUpdate: true, UpdateInterval: config.Duration{Duration: 24 * time.Hour}}))
	state := readProvenanceFixture(t, dir)
	assert.Equal(t, SourceUserLocal, BinarySource(state.BinarySource))
	assert.Equal(t, userLocal, state.BinaryPath)
	assert.Equal(t, afterInstall, releaseHits(hits), "the next-wave binding downloads nothing")
}

// newStaleUserLocalFixture arms the resolution seams and installs a STALE
// user-local core (26.9.9) with a newer release waiting on the fake server
// (v26.10.31) — the "update available" state for the auto-update tests.
func newStaleUserLocalFixture(t *testing.T) (string, string, *int) {
	t.Helper()
	userLocal, _ := withResolutionSeams(t)
	dir := t.TempDir()
	// The installed user-local core is STALE (26.9.9); the release carries
	// a newer one.
	writeVersionScript(t, userLocal, "26.9.9")
	releaseBin := writeVersionScript(t, filepath.Join(t.TempDir(), "release"), "26.10.31")
	srv, h := fakeCoreReleaseServer(t, "v26.10.31", releaseBin, "", nil)
	withReleaseAPIBase(t, srv.URL)
	return dir, userLocal, h
}

// TestAutoUpdateUpdatesUserLocalButInertOnPreexisting (brief test 5,
// owner-revised): auto-update is provenance-driven — the assay-owned
// user-local core is UPDATED in place (no elevation); a system-preexisting
// bound core stays INERT with the one-time INFO; the [core].auto_update
// master switch gates the whole surface off.
func TestAutoUpdateUpdatesUserLocalButInertOnPreexisting(t *testing.T) {
	t.Run("user-local core is updated in place without elevation", func(t *testing.T) {
		dir, userLocal, hits := newStaleUserLocalFixture(t)
		log := &syncBuffer{}
		m, err := NewManager(config.CoreConfig{SocksPort: 22930, RollbackStrikes: 3}, dir, log)
		require.NoError(t, err)
		t.Cleanup(m.release)

		require.NoError(t, m.AutoUpdate(context.Background(),
			config.CoreConfig{AutoUpdate: true, UpdateInterval: config.Duration{Duration: 24 * time.Hour}}))

		updated, err := os.ReadFile(userLocal)
		require.NoError(t, err)
		assert.Contains(t, string(updated), "Xray 26.10.31",
			"the user-local binary carries the new release payload")
		assert.Contains(t, log.String(), "updated", "the update is loud")
		state := readProvenanceFixture(t, dir)
		assert.Equal(t, SourceUserLocal, BinarySource(state.BinarySource))
		assert.Equal(t, "26.10.31", state.BinaryVersion)
		assert.GreaterOrEqual(t, releaseHits(hits), 3, "a real release check + download happened")
	})

	t.Run("system-preexisting core stays inert with a one-time INFO", func(t *testing.T) {
		_, system := withResolutionSeams(t)
		writeVersionScript(t, system, "26.3.27")
		dir := t.TempDir()
		srv, hits := fakeCoreReleaseServer(t, "v26.10.31", "", "", nil)
		withReleaseAPIBase(t, srv.URL)
		// Bind the pre-existing core (writes the provenance below the floor —
		// the binding itself must proceed).
		require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, &bytes.Buffer{}))

		log := &syncBuffer{}
		m, err := NewManager(config.CoreConfig{SocksPort: 22932, RollbackStrikes: 3}, dir, log)
		require.NoError(t, err)
		t.Cleanup(m.release)

		cfg := config.CoreConfig{AutoUpdate: true, UpdateInterval: config.Duration{Duration: 24 * time.Hour}}
		require.NoError(t, m.AutoUpdate(context.Background(), cfg))
		require.NoError(t, m.AutoUpdate(context.Background(), cfg))

		assert.Zero(t, releaseHits(hits), "a pre-existing core never touches the network")
		assert.Equal(t, 1, strings.Count(log.String(), "inert"),
			"the inert INFO is ONE-TIME loud, not per-wave noise")
		assert.Equal(t, system, m.bin, "the pre-existing core stays bound")
	})

	t.Run("auto_update=false gates the whole surface off", func(t *testing.T) {
		dir, _, hits := newStaleUserLocalFixture(t)
		log := &syncBuffer{}
		m, err := NewManager(config.CoreConfig{SocksPort: 22934, RollbackStrikes: 3}, dir, log)
		require.NoError(t, err)
		t.Cleanup(m.release)

		require.NoError(t, m.AutoUpdate(context.Background(),
			config.CoreConfig{AutoUpdate: false, UpdateInterval: config.Duration{Duration: 24 * time.Hour}}))

		assert.Zero(t, releaseHits(hits), "the master switch gates off every network leg")
		assert.Contains(t, log.String(), "auto_update", "the disabled state is loud")
	})
}

// TestFloorWarnsNonBlockingOnSystemPreexistingBelowFloor (brief test 6): a
// bound system core below the observatory-safe floor logs a LOUD WARNING
// and the bind PROCEEDS (non-blocking — the owner's 26.3.27 bound core is
// the expected case; the W19 adaptive observatory interval caps the probe
// rate).
func TestFloorWarnsNonBlockingOnSystemPreexistingBelowFloor(t *testing.T) {
	_, system := withResolutionSeams(t)
	writeVersionScript(t, system, "26.3.27")
	withVersionFloor(t, "26.9.9")

	srv, hits := fakeCoreReleaseServer(t, "v26.10.31", "", "", nil)
	withReleaseAPIBase(t, srv.URL)
	dir := t.TempDir()

	log := &bytes.Buffer{}
	require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log),
		"the floor warning must not fail the bind")

	logs := log.String()
	assert.Contains(t, logs, "WARNING", "the floor miss is loud")
	assert.Contains(t, logs, "below the observatory-safe floor", "the warning names the floor")
	assert.Contains(t, logs, "26.3.27", "the warning names the bound version")
	assert.Zero(t, releaseHits(hits), "no download for a bound core")

	state := readProvenanceFixture(t, dir)
	assert.Equal(t, SourceSystemPreexisting, BinarySource(state.BinarySource))
	assert.Equal(t, system, state.BinaryPath, "the bind proceeded despite the floor warning")
	assert.Equal(t, "26.3.27", state.BinaryVersion)
}

// TestBinaryRollbackKeepsPreviousThroughUpdate (graceful-migration
// contract): a user-local update swaps the binary ATOMICALLY (rename over
// ~/.local/bin/xray — zero downtime at the file level) and keeps the
// previous binary at ~/.local/bin/xray.previous through the swap — the
// instant binary-level rollback artifact.
func TestBinaryRollbackKeepsPreviousThroughUpdate(t *testing.T) {
	dir, userLocal, _ := newStaleUserLocalFixture(t)
	log := &syncBuffer{}
	m, err := NewManager(config.CoreConfig{SocksPort: 22936, RollbackStrikes: 3}, dir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)

	old, err := os.ReadFile(userLocal)
	require.NoError(t, err)

	require.NoError(t, m.AutoUpdate(context.Background(),
		config.CoreConfig{AutoUpdate: true, UpdateInterval: config.Duration{Duration: 24 * time.Hour}}))

	updated, err := os.ReadFile(userLocal)
	require.NoError(t, err)
	assert.NotEqual(t, string(old), string(updated), "the update swapped the binary in place")
	previous, err := os.ReadFile(userLocal + ".previous")
	require.NoError(t, err, "the previous binary survives the swap as the rollback artifact")
	assert.Equal(t, string(old), string(previous), "the .previous copy carries the PRE-update payload")
}

// TestStrikeRollbackRestoresPreviousBinary (graceful-migration contract):
// K consecutive failed healths trigger the D8 rollback — the BINARY-LEVEL
// mirror runs first (the .previous copy is restored over the user-local
// binary) so the `-test` gate and the respawn run the known-good binary;
// the config-level D8 rollback proceeds on top.
func TestStrikeRollbackRestoresPreviousBinary(t *testing.T) {
	dir, userLocal, _ := newStaleUserLocalFixture(t)
	const port = 22938
	writeLiveFixture(t, dir, port, "binary-rollback")
	fakeBin(t) // the known-good payload is the COREFAKE double: gate + respawn children play xray
	// M-1 pin: the RESTORED binary reports this version — the provenance
	// must track it after the binary-level rollback (the resolution change
	// contract), not keep describing the failed update.
	fakeBinVersion(t, "26.10.31")

	log := &syncBuffer{}
	m, err := NewManager(config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)

	// The known-good previous binary: the COREFAKE payload (serves socks,
	// passes the gate). The bound binary is the "bad update" (a script that
	// cannot serve) — exactly the state a failed cutover leaves behind.
	require.NoError(t, copyFile(os.Args[0], userLocal+".previous", 0o755))
	badUpdate := writeVersionScript(t, filepath.Join(t.TempDir(), "elsewhere"), "9.9.9")
	require.NoError(t, copyFile(badUpdate, userLocal, 0o755))
	writeBackupFixture(t, dir, port, "20260102-030405", "binary-rollback-backup")

	rolled := m.RecordHealth(errors.New("probe fail 1"))
	assert.False(t, rolled)
	rolled = m.RecordHealth(errors.New("probe fail 2"))
	assert.False(t, rolled)
	rolled = m.RecordHealth(errors.New("probe fail 3"))
	require.True(t, rolled, "the K-strike trigger fired the rollback")

	restored, err := os.ReadFile(userLocal)
	require.NoError(t, err)
	knownGood, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	assert.Equal(t, string(knownGood), string(restored),
		"the binary-level rollback restored the known-good payload over the bad update")
	assert.NoFileExists(t, userLocal+".previous",
		"the restore consumes the .previous copy (it lives at the binary path now)")
	assert.Contains(t, log.String(), "binary-level rollback", "the restore is loud")
	assert.Contains(t, log.String(), "ROLLBACK", "the config-level D8 rollback ran on top")

	// M-1: the resolution CHANGED (a different binary is at the bound path)
	// — the provenance must be re-probed and rewritten, never left
	// describing the failed update.
	state := readProvenanceFixture(t, dir)
	assert.Equal(t, "26.10.31", state.BinaryVersion,
		"binary_version reflects the RESTORED binary after the binary-level rollback")
	assert.Equal(t, userLocal, state.BinaryPath)
	assert.Equal(t, SourceUserLocal, BinarySource(state.BinarySource))
}

// TestProvenanceCorruptStateRewritesLoud (review M-3): a corrupt
// core-state.json never loses its disk history SILENTLY — the provenance
// rewrite warns loud naming the corruption first (the F9 corrupt-artifact
// honesty precedent), then lands the new record.
func TestProvenanceCorruptStateRewritesLoud(t *testing.T) {
	userLocal, _ := withResolutionSeams(t)
	writeVersionScript(t, userLocal, "26.10.31")
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, StateFileName), []byte("{corrupt"), 0o600))

	log := &bytes.Buffer{}
	require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log))

	state := readProvenanceFixture(t, dir)
	assert.Equal(t, SourceUserLocal, BinarySource(state.BinarySource),
		"the provenance lands despite the corrupt predecessor")
	assert.Contains(t, log.String(), "corrupt",
		"the corruption is named loud BEFORE the overwrite (the old rollback record is lost)")
}
