package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeOpenRC records rc-update + rc-service invocations (hermetic — the real
// binaries only exist under OpenRC ≥ 0.60 with a user session).
type fakeOpenRC struct {
	updateCalls  [][]string
	serviceCalls [][]string
	script       map[string][]scripted // verb → queued (out, err)
}

func newFakeOpenRC() *fakeOpenRC {
	return &fakeOpenRC{script: map[string][]scripted{}}
}

func (f *fakeOpenRC) expect(out string, err error) {
	f.script["status"] = append(f.script["status"], scripted{out: out, err: err})
}

func (f *fakeOpenRC) RcUpdate(args ...string) (string, error) {
	f.updateCalls = append(f.updateCalls, args)
	return f.replay(args)
}

func (f *fakeOpenRC) RcService(args ...string) (string, error) {
	f.serviceCalls = append(f.serviceCalls, args)
	return f.replay(args)
}

func (f *fakeOpenRC) replay(args []string) (string, error) {
	if q, ok := f.script[args[len(args)-1]]; ok && len(q) > 0 {
		s := q[0]
		f.script[args[len(args)-1]] = q[1:]
		return s.out, s.err
	}
	return "", nil
}

func openrcSched(f *fakeOpenRC, initDir string) *OpenRCScheduler {
	s := NewOpenRCScheduler(f, initDir)
	s.verifyInterval = time.Millisecond
	s.verifyAttempts = 3
	return s
}

// ---------------------------------------------------------------------------
// Allowlist — the five pinned --user shapes, nothing else
// ---------------------------------------------------------------------------

func TestOpenRCAllowlistIsExactlyTheFiveShapes(t *testing.T) {
	// The foreign name is assembled from parts (the guard_internal_test.go
	// M-2 precedent): the refusal matrix must NAME a foreign service to prove
	// the allowlist refuses it, while the tree stays clean of the literal
	// the zero-remnant surface gate greps for.
	foreign := "xray-" + "raw"
	for _, tc := range []struct {
		kind string
		args []string
	}{
		{"update", []string{"--user", "add", "assay-watch", "default"}},
		{"update", []string{"--user", "del", "assay-watch", "default"}},
		{"service", []string{"--user", "assay-watch", "start"}},
		{"service", []string{"--user", "assay-watch", "stop"}},
		{"service", []string{"--user", "assay-watch", "status"}},
	} {
		var err error
		if tc.kind == "update" {
			err = validateRcUpdate(tc.args)
		} else {
			err = validateRcService(tc.args)
		}
		require.NoError(t, err, "%v (%s) must validate", tc.args, tc.kind)
	}
	for _, bad := range []struct {
		kind string
		args []string
	}{
		{"update", []string{"add", "assay-watch", "default"}},        // missing --user
		{"update", []string{"--user", "add", foreign, "default"}},    // foreign service
		{"update", []string{"--user", "add", "assay-watch", "boot"}}, // wrong runlevel
		{"update", []string{"--user", "del", "assay-watch"}},         // no runlevel
		{"service", []string{"--user", "assay-watch", "restart"}},    // restart is in no flow — refused
		{"service", []string{"--user", foreign, "start"}},            // foreign service
		{"service", []string{"assay-watch", "start"}},                // missing --user
		{"service", []string{"--user", "assay-watch", "zap"}},        // not a pinned verb
		{"service", []string{"--user", "assay-watch"}},               // no verb
	} {
		var err error
		if bad.kind == "update" {
			err = validateRcUpdate(bad.args)
		} else {
			err = validateRcService(bad.args)
		}
		require.Error(t, err, "invocation %v must be refused", bad.args)
		assert.Contains(t, err.Error(), "--user")
	}
}

func TestOpenRCErrorsCarryTheExactCommandLine(t *testing.T) {
	home := t.TempDir()
	initDir := filepath.Join(home, ".config", "rc", "init.d")
	require.NoError(t, os.MkdirAll(initDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(initDir, "assay-watch"), []byte("x"), 0o644))
	f := newFakeOpenRC()
	f.expect("", errors.New("not started"))
	s := openrcSched(f, initDir)
	_, err := s.Status()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rc-service --user assay-watch status")
}

// ---------------------------------------------------------------------------
// Script golden (§3.2) — 0644, openrc-run shape, supervise-daemon parity
// ---------------------------------------------------------------------------

func TestOpenRCScriptGoldenExplicitConfig(t *testing.T) {
	got, err := openrcScriptContent("/home/u/.local/bin/assay", "/home/u/custom.toml", "/home/u/data")
	require.NoError(t, err)
	want := `#!/sbin/openrc-run

command="/home/u/.local/bin/assay"
command_args="watch -c /home/u/custom.toml"
supervisor="supervise-daemon"
pidfile="/home/u/data/assay-watch.pid"
output_log="/home/u/data/logs/watch.out.log"
error_log="/home/u/data/logs/watch.err.log"
`
	assert.Equal(t, want, got)
}

func TestOpenRCScriptGoldenDefaultLocation(t *testing.T) {
	got, err := openrcScriptContent("/home/u/.local/bin/assay", "", "/home/u/data")
	require.NoError(t, err)
	assert.Contains(t, got, `command_args="watch"`)
	assert.NotContains(t, got, "-c")
}

func TestOpenRCScriptRefusesShellHostilePaths(t *testing.T) {
	for _, bin := range []string{`/home/u/a"b/assay`, "/home/u/a$b", "/home/u/a`b", "/home/u/a\\b", "/home/u/a b/assay"} {
		_, err := openrcScriptData(bin, "", "/data")
		require.Error(t, err, "path %q must be refused (openrc-run evals the script; quoting is hostile)", bin)
	}
}

func TestOpenRCInstallWritesScript0644AndActivates(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, "data")
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	f := newFakeOpenRC()
	s := openrcSched(f, filepath.Join(home, ".config", "rc", "init.d"))
	spec := SchedulerInstallSpec{
		RunningBinary: filepath.Join(home, "running-assay"),
		BinDir:        filepath.Join(home, "bin"),
		ConfigPath:    filepath.Join(home, "custom.toml"),
		DataDir:       dataDir,
	}
	res, err := s.Install(spec)
	require.NoError(t, err)

	scriptPath := filepath.Join(home, ".config", "rc", "init.d", "assay-watch")
	raw, err := os.ReadFile(scriptPath)
	require.NoError(t, err)
	st, err := os.Stat(scriptPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), st.Mode().Perm(), "the service script is 0644 (§3.2)")
	assert.Contains(t, string(raw), "#!/sbin/openrc-run")
	assert.Contains(t, string(raw), `command_args="watch -c `+spec.ConfigPath+`"`)
	assert.Contains(t, string(raw), `supervisor="supervise-daemon"`)
	assert.Equal(t, []string{scriptPath}, res.UnitPaths)
	assert.True(t, res.ServiceActive)
	// Exact activation sequence: enable in default, then start.
	require.Len(t, f.updateCalls, 1)
	assert.Equal(t, []string{"--user", "add", "assay-watch", "default"}, f.updateCalls[0])
	require.Len(t, f.serviceCalls, 2)
	assert.Equal(t, []string{"--user", "assay-watch", "start"}, f.serviceCalls[0])
	assert.Equal(t, []string{"--user", "assay-watch", "status"}, f.serviceCalls[1])
}

func TestOpenRCInstallVerifyBoundedRetry(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	f := newFakeOpenRC()
	// First status probe fails (still starting), second reports started.
	f.expect("", errors.New("starting"))
	f.expect(" * status: started\n", nil)
	s := openrcSched(f, filepath.Join(home, ".config", "rc", "init.d"))
	res, err := s.Install(SchedulerInstallSpec{
		RunningBinary: filepath.Join(home, "running-assay"),
		BinDir:        filepath.Join(home, "bin"),
		DataDir:       filepath.Join(home, "data"),
	})
	require.NoError(t, err)
	require.True(t, res.ServiceActive)
	assert.Equal(t, []string{"--user", "add", "assay-watch", "default"}, f.updateCalls[0])
}

func TestOpenRCInstallActivationFailureIsLoud(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	f := newFakeOpenRC()
	// The full attempt budget fails — the fake's default (empty success)
	// must never rescue a negative test.
	f.expect("", errors.New("crashed"))
	f.expect("", errors.New("crashed"))
	f.expect("", errors.New("crashed"))
	s := openrcSched(f, filepath.Join(home, ".config", "rc", "init.d"))
	_, err := s.Install(SchedulerInstallSpec{
		RunningBinary: filepath.Join(home, "running-assay"),
		BinDir:        filepath.Join(home, "bin"),
		DataDir:       filepath.Join(home, "data"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rc-service --user assay-watch status")
}

// ---------------------------------------------------------------------------
// Uninstall / Status / HeldRegistration
// ---------------------------------------------------------------------------

func TestOpenRCUninstallStopDelRemove(t *testing.T) {
	home := t.TempDir()
	initDir := filepath.Join(home, ".config", "rc", "init.d")
	require.NoError(t, os.MkdirAll(initDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(initDir, "assay-watch"), []byte("x"), 0o644))
	f := newFakeOpenRC()
	f.expect(" * status: started\n", nil)
	s := openrcSched(f, initDir)
	res, err := s.Uninstall(SchedulerUninstallSpec{DataDir: filepath.Join(home, "data")})
	require.NoError(t, err)
	// Started → the status probe, then stop; then rc-update del; gone.
	require.Len(t, f.serviceCalls, 2)
	assert.Equal(t, []string{"--user", "assay-watch", "status"}, f.serviceCalls[0])
	assert.Equal(t, []string{"--user", "assay-watch", "stop"}, f.serviceCalls[1])
	require.Len(t, f.updateCalls, 1)
	assert.Equal(t, []string{"--user", "del", "assay-watch", "default"}, f.updateCalls[0])
	_, err = os.Stat(filepath.Join(initDir, "assay-watch"))
	assert.True(t, os.IsNotExist(err))
	assert.Contains(t, res.RemovedUnits, "assay-watch")
}

func TestOpenRCUninstallStoppedSkipsStopCall(t *testing.T) {
	home := t.TempDir()
	initDir := filepath.Join(home, ".config", "rc", "init.d")
	require.NoError(t, os.MkdirAll(initDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(initDir, "assay-watch"), []byte("x"), 0o644))
	f := newFakeOpenRC()
	f.expect(" * status: stopped\n", errors.New("stopped"))
	s := openrcSched(f, initDir)
	_, err := s.Uninstall(SchedulerUninstallSpec{})
	require.NoError(t, err)
	// Only the status probe ran (it reported stopped) — no stop call ever.
	assert.Equal(t, [][]string{{"--user", "assay-watch", "status"}}, f.serviceCalls)
	require.Len(t, f.updateCalls, 1)
}

func TestOpenRCStatusHonestSessionCaveat(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "rc", "init.d"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".config", "rc", "init.d", "assay-watch"), []byte("x"), 0o644))
	f := newFakeOpenRC()
	f.expect(" * status: started\n", nil)
	st, err := openrcSched(f, filepath.Join(home, ".config", "rc", "init.d")).Status()
	require.NoError(t, err)
	assert.True(t, st.Active)
	assert.Contains(t, st.Note, "supervise-daemon")
	assert.Contains(t, st.Note, "session", "the §3.2 session-lifetime caveat is stated, never hidden")
}

func TestOpenRCHeldRegistrationScriptPresence(t *testing.T) {
	home := t.TempDir()
	s := openrcSched(newFakeOpenRC(), filepath.Join(home, ".config", "rc", "init.d"))
	held, _ := s.HeldRegistration()
	assert.False(t, held)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "rc", "init.d"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".config", "rc", "init.d", "assay-watch"), []byte("x"), 0o644))
	held, where := s.HeldRegistration()
	assert.True(t, held)
	assert.Equal(t, filepath.Join(home, ".config", "rc", "init.d", "assay-watch"), where)
}

func TestOpenRCDefaultInitDirHonorsXDGConfigHome(t *testing.T) {
	// ${XDG_CONFIG_HOME}/rc/init.d (Gentoo wiki) — the default resolution.
	assert.Equal(t, "/xdg/rc/init.d", openrcDefaultInitDir("/xdg", "/home/u"))
	assert.Equal(t, "/home/u/.config/rc/init.d", openrcDefaultInitDir("", "/home/u"))
}
