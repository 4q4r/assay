package install

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeExecutor records every invocation; tests never execute systemctl.
type fakeExecutor struct {
	calls [][]string
	fail  error
}

func (f *fakeExecutor) Systemctl(args ...string) error {
	if f.fail != nil {
		return f.fail
	}
	f.calls = append(f.calls, args)
	return nil
}

// stubBinary writes a tiny stand-in for the running executable.
func stubBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "running-publicvpn")
	require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	return p
}

func installOpts(t *testing.T, ex *fakeExecutor) (Options, string, string) {
	t.Helper()
	home := t.TempDir()
	binDir := filepath.Join(home, "bin")
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	// Hermetic session probe: point XDG_RUNTIME_DIR at a dir that carries the
	// systemd marker, so the tests never depend on the host's real session.
	run := filepath.Join(home, "run")
	require.NoError(t, os.MkdirAll(filepath.Join(run, "systemd"), 0o755))
	t.Setenv("XDG_RUNTIME_DIR", run)
	return Options{
		BinDir:        binDir,
		UnitDir:       unitDir,
		RunningBinary: stubBinary(t),
		ConfigPath:    filepath.Join(home, "config.toml"),
		Exec:          ex,
	}, binDir, unitDir
}

func TestInstallCopiesBinaryAtomicallyAndExecutable(t *testing.T) {
	ex := &fakeExecutor{}
	opts, binDir, _ := installOpts(t, ex)
	res, err := Install(opts)
	require.NoError(t, err)

	assert.Equal(t, filepath.Join(binDir, "publicvpn"), res.BinaryPath)
	st, err := os.Stat(res.BinaryPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), st.Mode().Perm(), "installed binary must be 0755")
	content, err := os.ReadFile(res.BinaryPath)
	require.NoError(t, err)
	running, err := os.ReadFile(opts.RunningBinary)
	require.NoError(t, err)
	assert.Equal(t, running, content, "the copy must be byte-identical to the running image")
	assert.True(t, res.ServiceActive)
	assert.Equal(t, []string{filepath.Join(opts.UnitDir, WatchService)}, res.UnitPaths,
		"the W10 install renders exactly the daemon unit")
}

// TestInstallReRunIsSelfUpgrade pins the idempotent re-install: a changed
// running binary replaces the installed one (that IS the upgrade flow).
func TestInstallReRunIsSelfUpgrade(t *testing.T) {
	ex := &fakeExecutor{}
	opts, _, _ := installOpts(t, ex)
	_, err := Install(opts)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(opts.RunningBinary, []byte("#!/bin/sh\nexit 1\n"), 0o755))
	res, err := Install(opts)
	require.NoError(t, err)
	content, err := os.ReadFile(res.BinaryPath)
	require.NoError(t, err)
	assert.Equal(t, "#!/bin/sh\nexit 1\n", string(content), "re-install replaces the binary (self-upgrade)")
}

// TestInstallRendersWatchUnit pins the rendered unit content: ExecStart
// carries the installed binary + the config path, Restart=always (the W10
// daemon contract), and NO interval rendering — the daemon reads the
// schedule from the config live.
func TestInstallRendersWatchUnit(t *testing.T) {
	ex := &fakeExecutor{}
	opts, binDir, unitDir := installOpts(t, ex)
	res, err := Install(opts)
	require.NoError(t, err)
	require.Len(t, res.UnitPaths, 1)

	service, err := os.ReadFile(filepath.Join(unitDir, WatchService))
	require.NoError(t, err)
	s := string(service)
	assert.Contains(t, s, "ExecStart="+filepath.Join(binDir, "publicvpn")+" watch -c "+opts.ConfigPath)
	assert.Contains(t, s, "Type=notify")
	assert.Contains(t, s, "WatchdogSec=300")
	assert.Contains(t, s, "TimeoutStopSec=1800",
		"the installed unit carries the W17 stop timeout (mid-wave restart waits, not SIGKILL)")
	assert.Contains(t, s, "Restart=always")
	assert.NotContains(t, s, "{{", "template placeholders must all be rendered")
	assert.NotContains(t, s, "systemctl", "units never invoke systemctl themselves")
	assert.NotContains(t, s, "OnUnitActiveSec", "the daemon era has no timers — the schedule lives in the config")
	for _, legacy := range LegacyUnitNames() {
		assert.NotContains(t, s, legacy, "no legacy unit may leak into the daemon unit")
	}

	// Executor sequence: reload, then enable --now the daemon — nothing else
	// on a fresh host (the legacy cleanup path is pinned separately below).
	require.Len(t, ex.calls, 2)
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[0])
	assert.Equal(t, []string{"--user", "enable", "--now", WatchService}, ex.calls[1])
}

// TestInstallCleansUpLegacyTimerUnits pins the W5→W10 migration: an install
// over an old timer-era deployment disables the legacy timers and REMOVES
// their unit files, then arms the daemon — waves fire from exactly one
// scheduler afterwards.
func TestInstallCleansUpLegacyTimerUnits(t *testing.T) {
	ex := &fakeExecutor{}
	opts, _, unitDir := installOpts(t, ex)
	require.NoError(t, os.MkdirAll(unitDir, 0o750))
	for _, name := range LegacyUnitNames() {
		require.NoError(t, os.WriteFile(filepath.Join(unitDir, name), []byte("[Unit]\n"), 0o644))
	}
	res, err := Install(opts)
	require.NoError(t, err)
	assert.ElementsMatch(t, LegacyUnitNames(), res.LegacyCleaned)
	for _, name := range LegacyUnitNames() {
		_, err := os.Stat(filepath.Join(unitDir, name))
		assert.True(t, os.IsNotExist(err), "legacy unit %s must be removed", name)
	}
	require.Len(t, ex.calls, 3)
	assert.Equal(t, []string{"--user", "disable", "--now", RefreshTimer, SpeedtestTimer}, ex.calls[0],
		"the legacy timers are disabled BEFORE the daemon is armed")
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[1])
	assert.Equal(t, []string{"--user", "enable", "--now", WatchService}, ex.calls[2])
}

// TestInstallIsIdempotent pins re-install: same unit rewritten, the same
// systemctl steps re-run — no duplicates, no drift, no second enable shape.
func TestInstallIsIdempotent(t *testing.T) {
	ex := &fakeExecutor{}
	opts, _, unitDir := installOpts(t, ex)
	_, err := Install(opts)
	require.NoError(t, err)

	opts.Exec = ex
	_, err = Install(opts)
	require.NoError(t, err)

	watch, err := os.ReadFile(filepath.Join(unitDir, WatchService))
	require.NoError(t, err)
	assert.NotContains(t, string(watch), "{{")
	assert.Len(t, ex.calls, 4, "exactly reload+enable per install run")
}

func TestInstallNoSystemdCopiesBinaryOnly(t *testing.T) {
	ex := &fakeExecutor{}
	opts, _, _ := installOpts(t, ex)
	opts.NoSystemd = true
	opts.ConfigPath = "" // even without a config the binary installs
	res, err := Install(opts)
	require.NoError(t, err)
	assert.True(t, res.SkippedUnits)
	assert.Empty(t, ex.calls, "no systemd interaction under --no-systemd")
	_, err = os.Stat(res.BinaryPath)
	require.NoError(t, err)
}

// TestInstallNoSystemdDefaultLocationMaterializes pins the W13-deploy
// --no-systemd contract: without -c the default config is STILL
// materialized (the deploy layout is not a systemd concern), the unit files
// are skipped, and no systemctl interaction happens.
func TestInstallNoSystemdDefaultLocationMaterializes(t *testing.T) {
	ex := &fakeExecutor{}
	opts, home, _ := installOpts(t, ex)
	opts.NoSystemd = true
	opts.ConfigPath = ""
	opts.DefaultConfigPath = filepath.Join(home, ".local", "share", "publicvpn", "config.toml")
	opts.DataDir = filepath.Join(home, ".local", "share", "publicvpn")
	res, err := Install(opts)
	require.NoError(t, err)
	assert.True(t, res.SkippedUnits)
	assert.Empty(t, ex.calls, "no systemd interaction under --no-systemd")
	assert.Equal(t, opts.DefaultConfigPath, res.ConfigWritten, "the deploy layout materializes without systemd")
	_, err = os.Stat(opts.DefaultConfigPath)
	require.NoError(t, err)
}

func TestInstallWithoutSystemdSessionFailsLoud(t *testing.T) {
	// installOpts hermetically points XDG_RUNTIME_DIR at a VALID session —
	// override it with an empty dir to force the no-session branch.
	ex := &fakeExecutor{}
	opts, _, _ := installOpts(t, ex)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	_, err := Install(opts)
	require.Error(t, err, "a non-systemd host must fail loud, not half-install")
	assert.Contains(t, err.Error(), "--no-systemd", "the failure must be actionable")
	assert.Empty(t, ex.calls, "nothing executed when the session is missing")
}

// TestInstallDefaultLocationRendersPlainWatch pins the W13-deploy unit
// contract at the package level: ConfigPath == "" is a default-location
// install — the unit renders plain `watch` (NO -c; the daemon reads the
// default config location), and an optional DefaultConfigPath materializes
// the embedded default config (created once, kept afterwards).
func TestInstallDefaultLocationRendersPlainWatch(t *testing.T) {
	ex := &fakeExecutor{}
	opts, home, unitDir := installOpts(t, ex)
	opts.ConfigPath = ""
	opts.DefaultConfigPath = filepath.Join(home, ".local", "share", "publicvpn", "config.toml")
	opts.DataDir = filepath.Join(home, ".local", "share", "publicvpn")
	res, err := Install(opts)
	require.NoError(t, err)
	assert.Empty(t, res.ConfigKept)
	assert.Equal(t, opts.DefaultConfigPath, res.ConfigWritten)

	watch, err := os.ReadFile(filepath.Join(unitDir, WatchService))
	require.NoError(t, err)
	assert.Contains(t, string(watch), " watch\n", "ExecStart must be plain watch (no -c)")
	assert.NotContains(t, string(watch), " -c ")

	// Re-install: the materialized config is KEPT, never overwritten.
	opts2, _, _ := installOpts(t, ex)
	opts2.ConfigPath = ""
	opts2.DefaultConfigPath = opts.DefaultConfigPath
	opts2.DataDir = opts.DataDir
	res2, err := Install(opts2)
	require.NoError(t, err)
	assert.Empty(t, res2.ConfigWritten)
	assert.Equal(t, opts.DefaultConfigPath, res2.ConfigKept)
}

func TestInstallWithoutExecutorIsLoud(t *testing.T) {
	opts, _, _ := installOpts(t, &fakeExecutor{})
	opts.Exec = nil
	_, err := Install(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "executor")
}

func TestUninstallDisablesAndRemoves(t *testing.T) {
	ex := &fakeExecutor{}
	opts, _, unitDir := installOpts(t, ex)
	_, err := Install(opts)
	require.NoError(t, err)

	res, err := Uninstall(UninstallOptions{UnitDir: unitDir, Exec: ex})
	require.NoError(t, err)
	assert.Equal(t, []string{WatchService}, res.DisabledUnits)
	assert.Equal(t, []string{WatchService}, res.RemovedUnits)
	assert.ElementsMatch(t, LegacyUnitNames(), res.MissingUnits,
		"the legacy names are reported absent, not errors")
	for _, name := range AllKnownUnitNames() {
		_, err := os.Stat(filepath.Join(unitDir, name))
		assert.True(t, os.IsNotExist(err), "%s must be removed", name)
	}
	require.Len(t, ex.calls, 4) // install: reload+enable, uninstall: disable + daemon-reload (I-2)
	assert.Equal(t, []string{"--user", "disable", "--now", WatchService}, ex.calls[2])
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[3],
		"I-2: the manager must reload after the unit files are gone or it keeps ghost not-found entries")
}

// TestUninstallCleansLegacyUnits pins the uninstall migration surface: an
// old timer-era deployment (no daemon) is torn down completely — the legacy
// disable command runs, all five unit files go away.
func TestUninstallCleansLegacyUnits(t *testing.T) {
	ex := &fakeExecutor{}
	_, unitDir := func() (string, string) {
		home := t.TempDir()
		run := filepath.Join(home, "run")
		require.NoError(t, os.MkdirAll(filepath.Join(run, "systemd"), 0o755))
		t.Setenv("XDG_RUNTIME_DIR", run)
		return home, filepath.Join(home, ".config", "systemd", "user")
	}()
	require.NoError(t, os.MkdirAll(unitDir, 0o750))
	for _, name := range LegacyUnitNames() {
		require.NoError(t, os.WriteFile(filepath.Join(unitDir, name), []byte("[Unit]\n"), 0o644))
	}

	res, err := Uninstall(UninstallOptions{UnitDir: unitDir, Exec: ex})
	require.NoError(t, err)
	assert.Equal(t, LegacyUnitNames(), res.DisabledUnits)
	assert.ElementsMatch(t, LegacyUnitNames(), res.RemovedUnits,
		"a legacy-only deployment removes exactly the four timer units")
	assert.Equal(t, []string{WatchService}, res.MissingUnits, "the daemon unit was never installed here")
	require.Len(t, ex.calls, 2)
	assert.Equal(t, []string{"--user", "disable", "--now", RefreshTimer, SpeedtestTimer}, ex.calls[0])
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[1])
}

func TestUninstallWithoutInstallIsClean(t *testing.T) {
	ex := &fakeExecutor{}
	unitDir := t.TempDir()
	res, err := Uninstall(UninstallOptions{UnitDir: unitDir, Exec: ex})
	require.NoError(t, err)
	assert.Empty(t, res.RemovedUnits)
	assert.Len(t, res.MissingUnits, len(AllKnownUnitNames()), "absent units are reported, not errors")
	assert.True(t, res.SkippedDisable, "nothing on disk = nothing disabled")
	assert.Empty(t, ex.calls, "no systemctl call when no unit is present")
}

func TestUninstallPurgeRemovesConfigAndDataOnly(t *testing.T) {
	ex := &fakeExecutor{}
	home := t.TempDir()
	cfgPath := filepath.Join(home, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("data_dir"), 0o600))
	dataDir := filepath.Join(home, "data")
	require.NoError(t, os.MkdirAll(dataDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "geo-base.jsonl"), []byte("{}"), 0o600))
	keep := filepath.Join(home, "unrelated")
	require.NoError(t, os.MkdirAll(keep, 0o750))

	res, err := Uninstall(UninstallOptions{
		UnitDir:         t.TempDir(),
		Exec:            ex,
		PurgeConfigPath: cfgPath,
		PurgeDataDir:    dataDir,
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{cfgPath, dataDir}, res.Purged)
	_, err = os.Stat(cfgPath)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(dataDir)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(keep)
	assert.NoError(t, err, "everything outside config+data stays untouched")
}

// TestSpanDisplayRoundTrip pins the display formatter used by status (the
// read-back parse side is gone with the timers — the daemon reads the
// config, not the unit).
func TestSpanDisplayRoundTrip(t *testing.T) {
	assert.Equal(t, "1h", Span(1*time.Hour))
	assert.Equal(t, "168h", Span(168*time.Hour))
	assert.Equal(t, "5m", Span(5*time.Minute))
	assert.Equal(t, "90m", Span(90*time.Minute))
	assert.Equal(t, "45s", Span(45*time.Second))
	assert.Equal(t, "0", Span(0))
}
