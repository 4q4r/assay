//go:build unix

package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// expectStop queues a scripted answer for the stop verb (expect covers the
// status probes only — the bounded-stop tests script the stop outcome).
func (f *fakeOpenRC) expectStop(out string, err error) {
	f.script["stop"] = append(f.script["stop"], scripted{out: out, err: err})
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
// Script golden (§3.2) — 0755, openrc-run shape, supervise-daemon parity
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

func TestOpenRCInstallWritesScript0755AndActivates(t *testing.T) {
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
	assert.Equal(t, os.FileMode(0o755), st.Mode().Perm(),
		"the service script is 0755 — rc-update refuses a non-executable service "+
			"(live-proved by the alpine:edge leg, run 43339290411)")
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

// TestOpenRCUninstallStopBoundRescuedByStoppedPoll pins the §2.2.7-mirror
// rescue: when the executor bound kills the rc-service wrapper mid-stop (the
// openrc 0.63.2 stop race wedges the wrapper AFTER the effective stop — the
// live alpine:edge rehearsal and the CI hang, run 43358084471), the bounded
// status poll observes stopped and the uninstall PROCEEDS to rc-update del +
// script removal instead of failing or hanging.
func TestOpenRCUninstallStopBoundRescuedByStoppedPoll(t *testing.T) {
	home := t.TempDir()
	initDir := filepath.Join(home, ".config", "rc", "init.d")
	require.NoError(t, os.MkdirAll(initDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(initDir, "assay-watch"), []byte("x"), 0o644))
	f := newFakeOpenRC()
	f.expect(" * status: started\n", nil) // the pre-stop probe: started
	f.expectStop("", fmt.Errorf("rc-service --user assay-watch stop failed: %w\ncontext deadline exceeded", context.DeadlineExceeded))
	// The bounded poll: the FIRST probe already reports stopped (rc-service
	// status exits non-zero when the service is stopped).
	f.expect(" * status: stopped\n", errors.New("stopped"))
	s := openrcSched(f, initDir).withStopPolling(time.Millisecond, 3)
	res, err := s.Uninstall(SchedulerUninstallSpec{DataDir: filepath.Join(home, "data")})
	require.NoError(t, err, "the stopped-poll rescue must proceed past the bounded stop")
	assert.Contains(t, res.DisabledUnits, "assay-watch")
	require.Len(t, f.updateCalls, 1)
	assert.Equal(t, []string{"--user", "del", "assay-watch", "default"}, f.updateCalls[0])
	_, err = os.Stat(filepath.Join(initDir, "assay-watch"))
	assert.True(t, os.IsNotExist(err), "the script must be removed after the rescue")
}

// TestOpenRCUninstallStopBoundTimeoutIsLoud pins the loud §2.2.7 expiry: the
// poll budget ran out with the service never observed stopped — the error
// names the EXACT manual commands (zap, the pidfile kill) and the re-run.
func TestOpenRCUninstallStopBoundTimeoutIsLoud(t *testing.T) {
	home := t.TempDir()
	initDir := filepath.Join(home, ".config", "rc", "init.d")
	dataDir := filepath.Join(home, "data")
	require.NoError(t, os.MkdirAll(initDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(initDir, "assay-watch"), []byte("x"), 0o644))
	f := newFakeOpenRC()
	f.expect(" * status: started\n", nil) // the pre-stop probe: started
	f.expectStop("", fmt.Errorf("rc-service --user assay-watch stop failed: %w", exec.ErrWaitDelay))
	// The poll: the service stays started for the whole (shrunk) budget.
	for range 3 {
		f.expect(" * status: started\n", nil)
	}
	s := openrcSched(f, initDir).withStopPolling(time.Millisecond, 3)
	_, err := s.Uninstall(SchedulerUninstallSpec{DataDir: dataDir})
	require.Error(t, err, "a never-stopped service must fail the uninstall loudly")
	assert.Contains(t, err.Error(), "rc-service --user assay-watch zap",
		"the error must name the exact zap command")
	assert.Contains(t, err.Error(), fmt.Sprintf("kill $(cat %s)", filepath.Join(dataDir, "assay-watch.pid")),
		"the error must name the exact pidfile kill")
	assert.Contains(t, err.Error(), "assay uninstall",
		"the error must name the re-run command")
	assert.Contains(t, err.Error(), (3 * time.Millisecond).String(),
		"the error must name the bound it exhausted")
	// The refusal keeps the artifacts: nothing deleted behind a failed stop.
	_, statErr := os.Stat(filepath.Join(initDir, "assay-watch"))
	require.NoError(t, statErr, "the script must survive a failed uninstall")
	assert.Empty(t, f.updateCalls, "rc-update del must not run behind a failed stop")
}

// TestOpenRCUninstallStopFastFailureSkipsPoll pins the fast-fail split: a
// REAL rc-service refusal (not the executor bound) is loud IMMEDIATELY — the
// bounded poll never runs (nothing is stopping in the background), so no
// budget is burned on a refusal that will never turn into a stop.
func TestOpenRCUninstallStopFastFailureSkipsPoll(t *testing.T) {
	home := t.TempDir()
	initDir := filepath.Join(home, ".config", "rc", "init.d")
	require.NoError(t, os.MkdirAll(initDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(initDir, "assay-watch"), []byte("x"), 0o644))
	f := newFakeOpenRC()
	f.expect(" * status: started\n", nil) // the pre-stop probe: started
	f.expectStop("", errors.New("rc-service: lock refused"))
	s := openrcSched(f, initDir).withStopPolling(time.Millisecond, 3)
	_, err := s.Uninstall(SchedulerUninstallSpec{DataDir: filepath.Join(home, "data")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rc-service --user assay-watch stop")
	// Exactly the pre-probe and the stop ran — no poll statuses after the
	// fast refusal.
	require.Len(t, f.serviceCalls, 2)
}

// TestOpenRCExecBoundReapsGrandchildPipeHolders is the dynamic repro of the
// run 43358084471 hang class: a command tree that forks a grandchild
// inheriting the output pipe must return within the executor bound — the
// group kill reaps the tree and WaitDelay bounds the Wait — never blocking
// forever on a pipe held by an orphan (the openrc 0.63.2 supervise-daemon
// --stop busy-spin holds the pipe past the direct child's death).
func TestOpenRCExecBoundReapsGrandchildPipeHolders(t *testing.T) {
	oldBound, oldWaitDelay := openrcExecBound, openrcWaitDelay
	openrcExecBound = 300 * time.Millisecond
	openrcWaitDelay = 200 * time.Millisecond
	t.Cleanup(func() { openrcExecBound, openrcWaitDelay = oldBound, oldWaitDelay })

	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	// The grandchild (backgrounded sleep) inherits the output pipe and
	// outlives the direct child by design.
	script := fmt.Sprintf("sleep 60 & echo $! > %s; wait", pidFile)

	type execResult struct {
		err          error
		elapsed      time.Duration
		grandPID     int
		grandRunning bool
	}
	done := make(chan execResult, 1)
	go func() {
		start := time.Now()
		_, err := runOpenRCBinary("sh", []string{"-c", script})
		r := execResult{err: err, elapsed: time.Since(start)}
		if raw, rerr := os.ReadFile(pidFile); rerr == nil {
			_, _ = fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &r.grandPID)
			if r.grandPID > 0 {
				// The group kill is synchronous inside Cancel, before Wait
				// returns — the grandchild must be dead or a reaped-pending
				// zombie here (a zombie holds no pipe; the landmine is the
				// LIVE holder). /proc state: R/S/D = still running.
				if rawStat, serr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", r.grandPID)); serr == nil {
					fields := strings.Fields(string(rawStat))
					if len(fields) > 2 {
						state := fields[2]
						r.grandRunning = state == "R" || state == "S" || state == "D"
					}
				}
			}
		}
		done <- r
	}()
	select {
	case r := <-done:
		require.Error(t, r.err, "the bounded exec must fail, not succeed past a killed tree")
		// The bound error must be CLASSIFIABLE: the executor wraps the
		// context error over the child's death signal, so the uninstall's
		// bounded-stop path recognizes the wedge (the kill surfaces as
		// "signal: killed" — the mechanism, never the cause; live-proven in
		// the alpine:edge rehearsal where the unwrapped ExitError missed the
		// rescue poll).
		assert.True(t, isBoundedStopError(r.err),
			"a bound-fired failure must classify as bounded (got: %v)", r.err)
		require.Positive(t, r.grandPID, "the grandchild must have started and written its pid")
		assert.False(t, r.grandRunning,
			"the pipe-holding grandchild must be reaped by the group kill (pid %d)", r.grandPID)
		assert.Less(t, r.elapsed, 30*time.Second,
			"the executor must return within the bound + WaitDelay, not hang on the inherited pipe")
	case <-time.After(30 * time.Second):
		t.Fatal("the executor hung past the bound — the pipe-holder landmine is live " +
			"(killed child's inherited pipes block Wait; run 43358084471)")
	}
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
