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
		BinDir:            binDir,
		UnitDir:           unitDir,
		RunningBinary:     stubBinary(t),
		ConfigPath:        filepath.Join(home, "config.toml"),
		RefreshInterval:   6 * time.Hour,
		SpeedtestInterval: 168 * time.Hour,
		Exec:              ex,
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
	assert.True(t, res.TimersActive)
	assert.Len(t, res.UnitPaths, 4, "full install renders all four units")
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

// TestInstallRendersUnitFilesFromConfigIntervals pins the rendered unit
// content: ExecStart carries the installed binary + the config path; timers
// carry OnBootSec + OnUnitActiveSec=<configured interval> (no OnCalendar —
// arbitrary durations must be expressible).
func TestInstallRendersUnitFilesFromConfigIntervals(t *testing.T) {
	ex := &fakeExecutor{}
	opts, binDir, unitDir := installOpts(t, ex)
	opts.RefreshInterval = 90 * time.Minute
	opts.SpeedtestInterval = 7 * 24 * time.Hour
	res, err := Install(opts)
	require.NoError(t, err)
	require.Len(t, res.UnitPaths, 4)

	service, err := os.ReadFile(filepath.Join(unitDir, RefreshService))
	require.NoError(t, err)
	s := string(service)
	assert.Contains(t, s, "ExecStart="+filepath.Join(binDir, "publicvpn")+" maintain -c "+opts.ConfigPath)
	assert.Contains(t, s, "Type=oneshot")
	assert.NotContains(t, s, "{{", "template placeholders must all be rendered")
	assert.NotContains(t, s, "systemctl", "units never invoke systemctl themselves")

	timer, err := os.ReadFile(filepath.Join(unitDir, RefreshTimer))
	require.NoError(t, err)
	tr := string(timer)
	assert.Contains(t, tr, "OnBootSec=2min")
	assert.Contains(t, tr, "OnUnitActiveSec=90m", "config interval renders as OnUnitActiveSec")
	assert.Contains(t, tr, "Persistent=true")
	assert.Contains(t, tr, "Unit=public_vpn-refresh.service")
	assert.NotRegexp(t, `(?m)^OnCalendar=`, tr, "arbitrary durations require OnBootSec/OnUnitActiveSec, not an OnCalendar directive")
	assert.NotContains(t, tr, "{{")

	speedService, err := os.ReadFile(filepath.Join(unitDir, SpeedtestService))
	require.NoError(t, err)
	assert.Contains(t, string(speedService),
		"ExecStart="+filepath.Join(binDir, "publicvpn")+" maintain --speedtest -c "+opts.ConfigPath)

	speedTimer, err := os.ReadFile(filepath.Join(unitDir, SpeedtestTimer))
	require.NoError(t, err)
	st := string(speedTimer)
	assert.Contains(t, st, "OnUnitActiveSec=168h")
	assert.Contains(t, st, "OnBootSec=20min")
	assert.NotContains(t, st, "{{")

	// Executor sequence: reload, then enable --now both timers — nothing else
	// (install-only test; the uninstall sequence is pinned in
	// TestUninstallDisablesAndRemoves below).
	require.Len(t, ex.calls, 2)
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[0])
	assert.Equal(t, []string{"--user", "enable", "--now", RefreshTimer, SpeedtestTimer}, ex.calls[1])
}

// TestInstallIsIdempotent pins the supported period-change flow: re-running
// install rewrites the units (new interval) and re-runs the same two systemctl
// steps — no duplicates, no drift.
func TestInstallIsIdempotent(t *testing.T) {
	ex := &fakeExecutor{}
	opts, _, unitDir := installOpts(t, ex)
	_, err := Install(opts)
	require.NoError(t, err)

	opts.RefreshInterval = 5 * time.Hour
	opts.Exec = ex
	_, err = Install(opts)
	require.NoError(t, err)

	timer, err := os.ReadFile(filepath.Join(unitDir, RefreshTimer))
	require.NoError(t, err)
	assert.Regexp(t, `(?m)^OnUnitActiveSec=5h$`, string(timer))
	assert.NotRegexp(t, `(?m)^OnUnitActiveSec=6h$`, string(timer), "the old period must not survive")
	assert.Len(t, ex.calls, 4, "exactly reload+enable per install run")
	require.NoError(t, os.RemoveAll(filepath.Join(unitDir, "timers.target.wants")))
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

func TestInstallRequiresConfigForUnits(t *testing.T) {
	ex := &fakeExecutor{}
	opts, _, _ := installOpts(t, ex)
	opts.ConfigPath = ""
	_, err := Install(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--config")
	assert.Empty(t, ex.calls)
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

	// The enable step created wants-symlinks in the real flow; uninstall does
	// not manage them (systemd removes them on disable) — model that here.
	res, err := Uninstall(UninstallOptions{UnitDir: unitDir, Exec: ex})
	require.NoError(t, err)
	assert.True(t, res.DisabledTimers)
	assert.Len(t, res.RemovedUnits, 4)
	assert.Empty(t, res.MissingUnits)
	for _, name := range UnitNames() {
		_, err := os.Stat(filepath.Join(unitDir, name))
		assert.True(t, os.IsNotExist(err), "%s must be removed", name)
	}
	require.Len(t, ex.calls, 4) // install: reload+enable, uninstall: disable + daemon-reload (I-2)
	assert.Equal(t, []string{"--user", "disable", "--now", RefreshTimer, SpeedtestTimer}, ex.calls[2])
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[3],
		"I-2: the manager must reload after the unit files are gone or it keeps ghost not-found entries")
}

func TestUninstallWithoutInstallIsClean(t *testing.T) {
	ex := &fakeExecutor{}
	_, unitDir := "", t.TempDir()
	res, err := Uninstall(UninstallOptions{UnitDir: unitDir, Exec: ex})
	require.NoError(t, err)
	assert.Empty(t, res.RemovedUnits)
	assert.Len(t, res.MissingUnits, 4, "absent units are reported, not errors")
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

func TestSpanAndParseSpanRoundTrip(t *testing.T) {
	for _, d := range []time.Duration{
		6 * time.Hour, 168 * time.Hour, 5 * time.Minute, 90 * time.Minute,
		45 * time.Second, 24 * 30 * time.Hour,
	} {
		span := Span(d)
		parsed, err := ParseSpan(span)
		require.NoError(t, err, "span %q", span)
		assert.Equal(t, d, parsed, "round-trip %s", d)
	}
	// systemd-style input the installer never writes but status must read.
	for span, want := range map[string]time.Duration{
		"5min":  5 * time.Minute,
		"1h30m": 90 * time.Minute,
		"2d":    48 * time.Hour,
		"1w":    168 * time.Hour,
		"30s":   30 * time.Second,
	} {
		got, err := ParseSpan(span)
		require.NoError(t, err, "span %q", span)
		assert.Equal(t, want, got, "span %q", span)
	}
	for _, bad := range []string{"", "6", "h", "6x", "6h5"} {
		_, err := ParseSpan(bad)
		assert.Error(t, err, "span %q must be rejected", bad)
	}
}
