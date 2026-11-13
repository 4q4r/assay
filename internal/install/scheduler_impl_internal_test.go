package install

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"assay/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// systemdUserScheduler — the §3.1.1 adapter over the EXISTING install path
// (the CLI keeps its byte-identical generic systemd flow; the adapter makes
// Detect return a Scheduler and lets the cross-scheduler scan ask systemd).
// ---------------------------------------------------------------------------

func TestSystemdSchedulerNameAndAvailability(t *testing.T) {
	home := t.TempDir()
	s := &systemdUserScheduler{unitDir: filepath.Join(home, "units"), systemdProbe: fakeProbe(nil)}
	assert.Equal(t, "systemd-user", s.Name())
	avail, _ := s.Available()
	assert.True(t, avail)
	s2 := &systemdUserScheduler{unitDir: filepath.Join(home, "units"), systemdProbe: fakeProbe(assert.AnError)}
	avail, _ = s2.Available()
	assert.False(t, avail)
}

func TestSystemdSchedulerHeldRegistrationIsTheUnitFile(t *testing.T) {
	home := t.TempDir()
	unitDir := filepath.Join(home, "units")
	s := &systemdUserScheduler{unitDir: unitDir, systemdProbe: fakeProbe(nil)}
	held, _ := s.HeldRegistration()
	assert.False(t, held)
	require.NoError(t, os.MkdirAll(unitDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(unitDir, WatchService), []byte("x"), 0o644))
	held, where := s.HeldRegistration()
	assert.True(t, held)
	assert.Equal(t, filepath.Join(unitDir, WatchService), where)
}

func TestSystemdSchedulerInstallDelegatesToInstall(t *testing.T) {
	home := t.TempDir()
	unitDir := filepath.Join(home, "units")
	// The delegated Install re-runs the session probe as a safety net —
	// hermetic fake session (the CLI tests' writeWaveConfig pattern).
	run := filepath.Join(home, "run")
	require.NoError(t, os.MkdirAll(filepath.Join(run, "systemd"), 0o755))
	t.Setenv("XDG_RUNTIME_DIR", run)
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	ex := &fakeExecutor{} // the package's recording systemctl double
	s := &systemdUserScheduler{unitDir: unitDir, exec: ex, systemdProbe: fakeProbe(nil)}
	res, err := s.Install(SchedulerInstallSpec{
		RunningBinary: filepath.Join(home, "running-assay"),
		BinDir:        filepath.Join(home, "bin"),
		ConfigPath:    filepath.Join(home, "custom.toml"),
		DataDir:       filepath.Join(home, "data"),
	})
	require.NoError(t, err)
	// The delegation lands in the SAME Install the CLI generic path uses —
	// the exact systemd sequence (daemon-reload → enable --now) is pinned
	// there; here we pin that the adapter routes through it unchanged.
	require.Len(t, ex.calls, 2)
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[0])
	assert.Equal(t, []string{"--user", "enable", "--now", WatchService}, ex.calls[1])
	assert.True(t, res.ServiceActive)
}

func TestSystemdSchedulerStatusHonestWithoutIs_active(t *testing.T) {
	home := t.TempDir()
	unitDir := filepath.Join(home, "units")
	s := &systemdUserScheduler{unitDir: unitDir, systemdProbe: fakeProbe(nil)}
	st, err := s.Status()
	require.NoError(t, err)
	assert.False(t, st.Active, "no unit file — not registered")
	require.NoError(t, os.MkdirAll(filepath.Join(unitDir, "default.target.wants"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(unitDir, WatchService), []byte("x"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(unitDir, WatchService),
		filepath.Join(unitDir, "default.target.wants", WatchService)))
	st, err = s.Status()
	require.NoError(t, err)
	assert.True(t, st.Active)
	assert.Contains(t, st.Note, "Restart=always", "the supervision parity note is honest")
}

// ---------------------------------------------------------------------------
// ForegroundScheduler — §3.1.6 last resort
// ---------------------------------------------------------------------------

func TestForegroundInstallCopiesBinaryAndMaterializes(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, "data")
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	s := &ForegroundScheduler{}
	assert.Equal(t, "foreground", s.Name())
	res, err := s.Install(SchedulerInstallSpec{
		RunningBinary:     filepath.Join(home, "running-assay"),
		BinDir:            filepath.Join(home, "bin"),
		DefaultConfigPath: filepath.Join(dataDir, "config.toml"),
		DataDir:           dataDir,
	})
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(home, "bin", platform.AssayBinaryName(runtime.GOOS)))
	require.NoError(t, err, "the binary is still copied — §3.1.6 (the installed name is the GOOS table's)")
	_, err = os.Stat(filepath.Join(dataDir, "config.toml"))
	require.NoError(t, err, "the default config is still materialized — §3.1.6")
	assert.False(t, res.ServiceActive, "nothing is activated — there is no scheduler")
	assert.Contains(t, res.ServiceNote, "foreground")
}

func TestForegroundUninstallTeardownUnchanged(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, "data")
	s := &ForegroundScheduler{}
	res, err := s.Uninstall(SchedulerUninstallSpec{DataDir: dataDir})
	require.NoError(t, err)
	assert.Empty(t, res.DisabledUnits, "nothing scheduler-owned to disable")
	held, _ := s.HeldRegistration()
	assert.False(t, held)
	st, err := s.Status()
	require.NoError(t, err)
	assert.False(t, st.Active)
}
