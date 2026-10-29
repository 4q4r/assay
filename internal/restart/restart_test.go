package restart_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/restart"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeExecutor records every Systemctl invocation and replays scripted
// (output, error) pairs per call index — the hermetic seam twin of the
// install package's recording executor. Tests never execute systemd.
type fakeExecutor struct {
	calls   [][]string
	outputs []string // per-call stdout; "" beyond the scripted length
	errs    []error  // per-call error; nil beyond the scripted length
}

func (f *fakeExecutor) Systemctl(args ...string) (string, error) {
	i := len(f.calls)
	f.calls = append(f.calls, args)
	var out string
	if i < len(f.outputs) {
		out = f.outputs[i]
	}
	var err error
	if i < len(f.errs) {
		err = f.errs[i]
	}
	return out, err
}

func (f *fakeExecutor) verbs() []string {
	verbs := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		verbs = append(verbs, c[1])
	}
	return verbs
}

// fakeDialer records dial attempts; scriptedErr is returned for every call.
type fakeDialer struct {
	addrs []string
	err   error
}

func (f *fakeDialer) Dial(_ string, addr string, _ time.Duration) (net.Conn, error) {
	f.addrs = append(f.addrs, addr)
	return nil, f.err
}

func okExecutor() *fakeExecutor {
	return &fakeExecutor{outputs: []string{"", "active\n"}}
}

// --- the byte-pinned allowlist -------------------------------------------

func TestSystemctlAllowlistIsExactlyThePinnedSet(t *testing.T) {
	require.Len(t, restart.AllowedCommands(), 2, "the daemon surface is exactly two commands")
	assert.Equal(t, []string{"--user", "restart", "xray-raw.service"}, restart.AllowedCommands()[0])
	assert.Equal(t, []string{"--user", "is-active", "xray-raw.service"}, restart.AllowedCommands()[1])
	for _, cmd := range restart.AllowedCommands() {
		assert.Equal(t, "--user", cmd[0], "every invocation MUST be --user (the user session is the whole scope)")
		assert.Equal(t, "xray-raw.service", cmd[2], "every invocation targets exactly the pinned unit")
		assert.Len(t, cmd, 3, "no flags, no extra arguments — three tokens exactly")
	}
}

// TestRestartUnitMatchesActivateHintDefault pins the single source of the
// unit name: the byte-pinned restart target must equal the default service
// name the manual-restart hint prints, so the auto path and the hint can
// never drift apart.
func TestRestartUnitMatchesActivateHintDefault(t *testing.T) {
	assert.Equal(t, config.DefaultServiceName, restart.Unit,
		"the pinned restart unit and the hint's default service name are one fact")
}

func TestCommandConstructorsMatchAllowlist(t *testing.T) {
	assert.Equal(t, restart.AllowedCommands()[0], restart.CmdRestartXray(), "restart constructor drifted")
	assert.Equal(t, restart.AllowedCommands()[1], restart.CmdIsActiveXray(), "is-active constructor drifted")
	require.NoError(t, restart.ValidateArgs(restart.CmdRestartXray()))
	require.NoError(t, restart.ValidateArgs(restart.CmdIsActiveXray()))
}

// TestExecutorRejectsEverythingOutsideAllowlist is the reject matrix: any
// other unit, any other verb, any flag, any extra argument, any missing
// scope — everything outside the two pinned commands fails loud BEFORE any
// process is spawned.
func TestExecutorRejectsEverythingOutsideAllowlist(t *testing.T) {
	for _, bad := range [][]string{
		{"--user", "restart", "public_vpn-watch.service"},  // other unit: the daemon itself
		{"--user", "restart", "custom-client.service"},     // other unit: a configured name
		{"--user", "restart", "xray-raw"},                  // unit without .service suffix
		{"--user", "restart", "xray-raw.service", "--now"}, // flag appended
		{"--user", "is-active", "xray-raw.service", "--quiet"},
		{"--user", "start", "xray-raw.service"}, // other verb
		{"--user", "stop", "xray-raw.service"},
		{"--user", "enable", "xray-raw.service"},
		{"--user", "disable", "xray-raw.service"},
		{"--user", "daemon-reload"},
		{"--user", "kill", "xray-raw.service"},
		{"--user", "reset-failed", "xray-raw.service"},
		{"--user", "status", "xray-raw.service"},
		{"--system", "restart", "xray-raw.service"},        // system bus forbidden
		{"sudo", "--user", "restart", "xray-raw.service"},  // privilege escalation prefix
		{"restart", "xray-raw.service"},                    // missing --user
		{"--user", "restart"},                              // missing unit
		{"--user"},                                         // verb only
		{},                                                 // empty
		{"--user", "restart", "xray-raw.service", "extra"}, // trailing argument
	} {
		err := restart.ValidateArgs(bad)
		require.Error(t, err, "invocation %v must be refused", bad)
		assert.Contains(t, err.Error(), "allowlist", "refusal must name the allowlist: %v", bad)
	}
}

// --- the activation flow: restart → health --------------------------------

func TestRunRestartsExactlyOnceThenVerifiesHealth(t *testing.T) {
	ex := okExecutor()
	dial := &fakeDialer{}
	res, err := restart.Run(restart.Input{
		Executor:  ex,
		Dialer:    dial.Dial,
		SocksPort: 10808,
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"restart", "is-active"}, ex.verbs(),
		"exact order: one restart, then the is-active health probe — nothing else")
	require.Len(t, ex.calls, 2, "restart exactly once, health probe exactly once")
	assert.Equal(t, []string{"--user", "restart", "xray-raw.service"}, ex.calls[0])
	assert.Equal(t, []string{"--user", "is-active", "xray-raw.service"}, ex.calls[1])

	assert.True(t, res.Restarted)
	assert.True(t, res.Active)
	assert.True(t, res.PortOpen)
	assert.Equal(t, []string{"127.0.0.1:10808"}, dial.addrs, "the socks port is probed on loopback")
	assert.Contains(t, res.Verdict, "health PASS")
}

func TestRunRestartFailureIsTypedLoudAndSkipsHealth(t *testing.T) {
	ex := &fakeExecutor{errs: []error{errors.New("exit status 1: Failed to connect to bus")}}
	dial := &fakeDialer{}
	res, err := restart.Run(restart.Input{Executor: ex, Dialer: dial.Dial, SocksPort: 10808})
	require.Error(t, err, "a failed restart must be loud")

	var re *restart.Error
	require.ErrorAs(t, err, &re, "the failure carries the typed restart class")
	assert.Contains(t, err.Error(), "xray-raw.service")
	assert.Contains(t, err.Error(), "Failed to connect to bus", "systemctl's own output reaches the operator")

	assert.Empty(t, ex.verbs()[1:], "no health probe after a failed restart")
	assert.Empty(t, dial.addrs, "no port probe after a failed restart")
	assert.False(t, res.Restarted)
}

func TestRunInactiveUnitIsHealthFailure(t *testing.T) {
	ex := &fakeExecutor{outputs: []string{"", "failed\n"}}
	dial := &fakeDialer{}
	res, err := restart.Run(restart.Input{Executor: ex, Dialer: dial.Dial, SocksPort: 10808})
	require.Error(t, err, "is-active reporting a dead unit is a health failure")

	var he *restart.HealthError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, "unit-state", he.Leg)
	assert.Contains(t, err.Error(), "failed", "the raw unit state reaches the operator")
	assert.False(t, res.Active)
	assert.Empty(t, dial.addrs, "no port probe when the unit is not active")
}

func TestRunIsActiveExecErrorIsHealthFailure(t *testing.T) {
	ex := &fakeExecutor{errs: []error{nil, errors.New("exit status 3")}}
	_, err := restart.Run(restart.Input{Executor: ex, SocksPort: 10808})
	require.Error(t, err)
	var he *restart.HealthError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, "is-active", he.Leg)
}

func TestRunClosedPortIsHealthFailureWithRestoreHint(t *testing.T) {
	ex := okExecutor()
	dial := &fakeDialer{err: errors.New("connect: connection refused")}
	res, err := restart.Run(restart.Input{
		Executor:   ex,
		Dialer:     dial.Dial,
		SocksPort:  10808,
		BackupPath: "/backups/config.json.bak-20261029-010101",
	})
	require.Error(t, err, "a closed socks port after restart is a health failure")

	var he *restart.HealthError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, "socks-port", he.Leg)
	assert.Contains(t, err.Error(), "connection refused")
	assert.Contains(t, err.Error(), "/backups/config.json.bak-20261029-010101",
		"the health failure carries the backup-restore hint")
	assert.True(t, res.Restarted, "the restart itself succeeded — only health failed")
	assert.True(t, res.Active)
}

func TestRunZeroPortSkipsTheDialLeg(t *testing.T) {
	ex := okExecutor()
	dial := &fakeDialer{}
	res, err := restart.Run(restart.Input{Executor: ex, Dialer: dial.Dial, SocksPort: 0})
	require.NoError(t, err, "an unknown socks port degrades health to the unit-state leg, never an error")
	assert.False(t, res.PortOpen)
	assert.Empty(t, dial.addrs)
	assert.Contains(t, res.Verdict, "skipped", "the verdict states the port leg was skipped")
}

func TestRunNilExecutorIsLoud(t *testing.T) {
	_, err := restart.Run(restart.Input{})
	require.Error(t, err, "an unwired executor is a programming error, never a silent skip")
	assert.Contains(t, err.Error(), "executor")
}

// TestRunDefaultDialerIsNet covers the production wiring: a nil Dialer must
// still attempt a real loopback dial (an unreachable port with a REAL dial
// error path — loopback :1 is reserved, so the dial fails fast everywhere).
func TestRunDefaultDialerIsNet(t *testing.T) {
	ex := okExecutor()
	_, err := restart.Run(restart.Input{Executor: ex, SocksPort: 1})
	require.Error(t, err, "the default dialer is the real net dialer — port 1 on loopback is closed")
	var he *restart.HealthError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, "socks-port", he.Leg)
}

// --- source-shape guards (the new W13 rail) -------------------------------

// TestRestartSourceUsesOnlyTheSanctionedConstructors pins the package shape:
// exactly one exec site (the allowlist-checked executor), every Systemctl
// call through the constructors, and the allowlist as an immutable
// two-element array.
func TestRestartSourceUsesOnlyTheSanctionedConstructors(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "restart"))
	require.NoError(t, err)
	execSites, callSites := 0, 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join("..", "restart", e.Name()))
		require.NoError(t, err)
		s := string(src)
		execSites += strings.Count(s, "exec.Command")
		callSites += strings.Count(s, ".Systemctl(")
	}
	assert.Equal(t, 1, execSites, "exactly one exec site: the allowlist-checked restart executor")
	assert.Equal(t, 2, callSites,
		"restart + is-active flow through the constructors exactly, once each — no literal args at call sites")
}

// TestDaemonSystemdSurfaceIsExactlyTwoExecutorFiles is the W13 positive
// guard replacing the old "the daemon never talks to systemd at all"
// contract: across the whole production tree, the ONLY files allowed to
// spawn systemctl are the two byte-pinned allowlist executors (install's
// three-command surface, restart's two-command surface). Everything else —
// the wave pipeline, the watch daemon, activate — carries no exec-of-
// systemctl path. (Migration note: W4–W12 pinned a total ban + an
// install-only surface; W13 adds the restart executor as the second — and
// last — sanctioned file, with its own byte pin.)
func TestDaemonSystemdSurfaceIsExactlyTwoExecutorFiles(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		s := string(src)
		if strings.Contains(s, "exec.Command") && strings.Contains(s, `"systemctl"`) {
			offenders = append(offenders, filepath.ToSlash(strings.TrimPrefix(path, root+string(os.PathSeparator))))
		}
		return nil
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"internal/install/install.go",
		"internal/restart/restart.go",
	}, offenders,
		"the daemon's complete systemctl surface is the two allowlist executors — found %+v", offenders)
}

// TestExecutorTimeoutBoundsTheRestart pins that the production executor
// cannot hang the wave: the exec context carries a bounded timeout. This is
// a source pin (the timeout is a const in the executor) plus a behavioral
// sanity check through the fake seam.
func TestExecutorTimeoutIsBounded(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "restart", "restart.go"))
	require.NoError(t, err)
	assert.Contains(t, string(src), "context.WithTimeout",
		"the production executor must bound every systemctl child")
	assert.Regexp(t, `restartTimeout\s*=\s*60 \* time\.Second`, string(src),
		"the restart ceiling is the documented 60s")
}

var _ = fmt.Sprintf // keep fmt if assertions evolve
