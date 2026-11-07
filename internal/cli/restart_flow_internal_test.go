package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/restart"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingExecutor is the hermetic systemctl seam for the activation-flow
// tests. On every call it appends a trace line (and — for the restart leg —
// records what is ACTUALLY on disk at that instant: the live config bytes
// and the backup count), so the ordering evidence gate→backup→replace→
// restart→health is proven from recorded disk state, not from code reading.
type recordingExecutor struct {
	calls       [][]string
	tracePath   string
	livePath    string
	backupDir   string
	isActiveOut string   // replayed for every is-active call; default "active\n"
	isActiveSeq []string // per-call replay when set; falls back to isActiveOut
	isActiveN   int      // is-active calls seen so far (the seq replay cursor)
	restartErr  error
	isActiveErr error
	dialErr     error
	// dialFailFirst makes the first N dials fail (the late-bind production
	// race) and every later dial succeed.
	dialFailFirst int
	dialN         int
	// onRestart, when set, runs inside the restart leg — the seam for the
	// SIGTERM-mid-activate pin (the daemon's shutdown flag flips while the
	// activate stage is in flight).
	onRestart func()
}

func (r *recordingExecutor) Systemctl(args ...string) (string, error) {
	if len(args) < 2 {
		r.calls = append(r.calls, args)
		r.trace("MALFORMED")
		return "", fmt.Errorf("recordingExecutor: malformed invocation %v", args)
	}
	verb := args[1]
	r.calls = append(r.calls, args)
	switch verb {
	case "restart":
		detail := ""
		if r.livePath != "" {
			if b, err := os.ReadFile(r.livePath); err == nil {
				detail += " live=" + strings.TrimSpace(string(b))
			}
		}
		if r.backupDir != "" {
			if m, _ := filepath.Glob(filepath.Join(r.backupDir, "*.bak-*")); len(m) > 0 {
				detail += fmt.Sprintf(" backups=%d", len(m))
			}
		}
		r.trace("restart:" + detail)
		if r.onRestart != nil {
			r.onRestart()
		}
		if r.restartErr != nil {
			return "", r.restartErr
		}
		return "", nil
	case "is-active":
		r.trace("is-active")
		r.isActiveN++
		if r.isActiveErr != nil {
			return "", r.isActiveErr
		}
		if len(r.isActiveSeq) > 0 {
			if r.isActiveN <= len(r.isActiveSeq) {
				return r.isActiveSeq[r.isActiveN-1], nil
			}
			return r.isActiveSeq[len(r.isActiveSeq)-1], nil
		}
		if r.isActiveOut == "" {
			return "active\n", nil
		}
		return r.isActiveOut, nil
	default:
		r.trace("UNEXPECTED:" + verb)
		return "", fmt.Errorf("recordingExecutor: unexpected verb %q", verb)
	}
}

func (r *recordingExecutor) trace(line string) {
	f, err := os.OpenFile(r.tracePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "%s\n", line)
}

func (r *recordingExecutor) dial(_ string, addr string, _ time.Duration) (net.Conn, error) {
	r.trace("dial " + addr)
	r.dialN++
	if r.dialN <= r.dialFailFirst {
		return nil, errors.New("connect: connection refused")
	}
	return nil, r.dialErr
}

func (r *recordingExecutor) verbs() []string {
	verbs := make([]string, 0, len(r.calls))
	for _, c := range r.calls {
		verbs = append(verbs, c[1])
	}
	return verbs
}

func traceLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var lines []string
	for l := range strings.SplitSeq(string(b), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// restartFixture wires a full activation scenario: differing render + live
// target, a fake xray that traces the gate, and a recording executor. The
// rendered config carries a socks inbound on 10808 (the template-defined
// port the health check must probe).
func restartFixture(t *testing.T, xrayVerdict string) (*config.Config, *recordingExecutor) {
	t.Helper()
	cfg := maintainCfg(t)
	fake := fakeXrayForMaintain(t, t.TempDir(), xrayVerdict)
	cfg.Activate.XrayBin = fake
	// The fake xray appends its gate verdict to the shared trace file.
	trace := filepath.Join(t.TempDir(), "trace.log")
	body, err := os.ReadFile(fake)
	require.NoError(t, err)
	gateLine := "echo 'Configuration OK'; echo gate >> " + trace
	patched := strings.Replace(string(body), "echo 'Configuration OK'", gateLine, 1)
	require.NoError(t, os.WriteFile(fake, []byte(patched), 0o755))
	cfg.Activate.BackupDir = "backups"
	p := newPaths(cfg)
	require.NoError(t, os.MkdirAll(p.renderedDir, 0o750))
	rec := &recordingExecutor{tracePath: trace}
	rec.livePath = cfg.Activate.Target
	rec.backupDir = p.backupDir
	return cfg, rec
}

// fixtureRendered is the rendered-config body the flow tests activate: a
// config with the template-shaped socks inbound on 10808.
const fixtureRendered = `{"inbounds":[{"protocol":"http","port":"10809","listen":"127.0.0.1"},` +
	`{"protocol":"socks","port":10808,"listen":"127.0.0.1"}],"log":{"loglevel":"warning"},"pool":"new"}`

// TestW13ActivationRestartsExactlyOnceInOrder is the flow-ordering evidence
// gate: a differing render goes gate → backup → replace → restart (exactly
// once) → health check, proven by the trace the fake xray and the recording
// executor write AS each step observes the world:
//   - "gate"             — the -test child ran;
//   - "restart: live=NEW backups=N" — at restart time the live target ALREADY
//     holds the new config and a backup exists (replace and backup preceded
//     the restart);
//   - "is-active", "dial" — the health legs, after the restart.
func TestW13ActivationRestartsExactlyOnceInOrder(t *testing.T) {
	cfg, rec := restartFixture(t, "ok")
	writeMaintainFiles(t, cfg, fixtureRendered, `{"v":1}`)
	wiring := &restartWiring{Executor: rec, Dialer: rec.dial}

	require.NoError(t, runActivateStage(newTestCmd(), cfg, wiring))
	require.Len(t, rec.calls, 2, "restart exactly once + health exactly once — nothing else")
	assert.Equal(t, []string{"restart", "is-active"}, rec.verbs())

	lines := traceLines(t, rec.tracePath)
	require.Len(t, lines, 4, "gate, restart, is-active, dial — in this order")
	assert.Equal(t, "gate", lines[0], "the -test gate runs first")
	assert.Contains(t, lines[1], "restart:")
	assert.Contains(t, lines[1], `"pool":"new"`,
		"at restart time the live target already holds the gated NEW config (replace → restart order)")
	assert.Contains(t, lines[1], "backups=1",
		"at restart time the date-stamped backup exists (backup → restart order)")
	assert.Equal(t, "is-active", lines[2], "health follows the restart")
	assert.Equal(t, "dial 127.0.0.1:10808", lines[3], "the socks port leg probes the template's port")

	live, err := os.ReadFile(cfg.Activate.Target)
	require.NoError(t, err)
	assert.JSONEq(t, fixtureRendered, string(live))
}

// TestW13SocksPortComesFromTheRenderedConfig pins the health port source:
// the socks inbound of the just-activated config (the template's own
// definition — no duplicate knob). A STRING-form port in the config must
// resolve too (xray accepts both shapes).
func TestW13SocksPortComesFromTheRenderedConfig(t *testing.T) {
	cfg, rec := restartFixture(t, "ok")
	rendered := `{"inbounds":[{"protocol":"socks","port":"11508","listen":"127.0.0.1"}],"log":{"loglevel":"warning"}}`
	writeMaintainFiles(t, cfg, rendered, `{"v":1}`)
	wiring := &restartWiring{Executor: rec, Dialer: rec.dial}

	out := runStageCapturing(t, cfg, wiring)
	assert.Contains(t, out, "127.0.0.1:11508 reachable",
		"the health verdict names the socks port read from the activated config (string-form port)")
}

// TestW13NoOpActivationRestartsNothing pins the no-op boundary: a
// byte-identical render activates nothing and restarts nothing.
func TestW13NoOpActivationRestartsNothing(t *testing.T) {
	cfg, rec := restartFixture(t, "ok")
	writeMaintainFiles(t, cfg, `{"v":1}`, `{"v":1}`)

	out := runStageCapturing(t, cfg, &restartWiring{Executor: rec, Dialer: rec.dial})
	assert.Contains(t, out, "no changes")
	assert.Empty(t, rec.calls, "no-op activation must not touch systemd at all")
}

// TestW13AutoRestartFalsePrintsHintInstead pins the manual semantics: an
// explicit [maintain].auto_restart = false prints the restart hint and
// never restarts.
func TestW13AutoRestartFalsePrintsHintInstead(t *testing.T) {
	cfg, rec := restartFixture(t, "ok")
	v := false
	cfg.Maintain.AutoRestart = &v
	writeMaintainFiles(t, cfg, `{"v":2}`, `{"old":true}`)

	out := runStageCapturing(t, cfg, &restartWiring{Executor: rec, Dialer: rec.dial})
	assert.Contains(t, out, "restart manually", "manual mode prints the operator hint")
	assert.Contains(t, out, "systemctl --user restart xray-raw.service")
	assert.Empty(t, rec.calls, "auto_restart=false never executes the restart")
}

// TestW13NilWiringWithAutoRestartIsLoud pins the wiring contract: auto
// restart enabled but no executor wired is a programming error, never a
// silent skip.
func TestW13NilWiringWithAutoRestartIsLoud(t *testing.T) {
	cfg, _ := restartFixture(t, "ok")
	writeMaintainFiles(t, cfg, `{"v":2}`, `{"old":true}`)
	err := runActivateStage(newTestCmd(), cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auto_restart")
}

// TestW13RestartFailureIsDONE_WITH pins the restart-failure class: loud
// ERROR line, the wave COMPLETES (the config on disk is the gated new one,
// so the wave is DONE_WITH restart-failure), health legs never run.
func TestW13RestartFailureIsDONE_WITH(t *testing.T) {
	cfg, rec := restartFixture(t, "ok")
	rec.restartErr = errors.New("exit status 1: Failed to connect to bus")
	writeMaintainFiles(t, cfg, `{"v":2}`, `{"old":true}`)
	wiring := &restartWiring{Executor: rec, Dialer: rec.dial}

	out, err := captureStageErr(t, cfg, wiring)
	require.NoError(t, err, "the wave completes — the config IS on disk (DONE_WITH, not FAILED)")
	assert.Contains(t, out, "ERROR:")
	assert.Contains(t, out, "restart FAILED")
	assert.Contains(t, out, "Failed to connect to bus", "systemctl's own output reaches the operator")
	assert.Contains(t, out, "DONE_WITH restart-failure")
	assert.Contains(t, out, "still runs the previous config")
	assert.Equal(t, []string{"restart"}, rec.verbs(), "no health probe after a failed restart")
}

// TestW13HealthFailureWarnsWithRestoreHint pins the health-failure class:
// loud WARNING naming the backup restore hint, wave completes, report-only
// (no auto-restore in this generation).
func TestW13HealthFailureWarnsWithRestoreHint(t *testing.T) {
	cfg, rec := restartFixture(t, "ok")
	rec.isActiveOut = "failed\n"
	rec.dialErr = errors.New("connect: connection refused")
	writeMaintainFiles(t, cfg, `{"v":2}`, `{"old":true}`)
	wiring := &restartWiring{Executor: rec, Dialer: rec.dial, Sleep: noSleep}

	out, err := captureStageErr(t, cfg, wiring)
	require.NoError(t, err, "a health failure is DONE_WITH, not a wave failure")
	assert.Contains(t, out, "WARNING:")
	assert.Contains(t, out, "health")
	assert.Contains(t, out, "no auto-restore")
	live, readErr := os.ReadFile(cfg.Activate.Target)
	require.NoError(t, readErr)
	assert.Equal(t, `{"v":2}`, string(live), "the gated new config stays on disk — report only")
}

// TestW13FailedGateNeverRestarts pins L10: the -test gate failing aborts
// the activation BEFORE any systemd interaction.
func TestW13FailedGateNeverRestarts(t *testing.T) {
	cfg, rec := restartFixture(t, "fail")
	writeMaintainFiles(t, cfg, `{"bad":true}`, `{"v":1}`)
	wiring := &restartWiring{Executor: rec, Dialer: rec.dial}

	_, err := captureStageErr(t, cfg, wiring)
	require.Error(t, err, "a config failing -test must fail the wave loud (L10)")
	assert.Empty(t, rec.calls, "a failed gate never reaches systemd")
	live, readErr := os.ReadFile(cfg.Activate.Target)
	require.NoError(t, readErr)
	assert.Equal(t, `{"v":1}`, string(live), "live config untouched after failed gate")
}

// --- the W17 health ladder at the flow level -------------------------------

// TestW17HealthLadderPassesOnLaterAttemptInFlow drives the production race
// through the whole activate stage: xray has not bound the socks port when
// the restart returns; the dial is refused twice, binds on attempt 3. The
// stage must PASS (attempt counted in the verdict) instead of the old
// false-positive health WARNING — with the injected clock, never a real
// wait.
func TestW17HealthLadderPassesOnLaterAttemptInFlow(t *testing.T) {
	cfg, rec := restartFixture(t, "ok")
	rec.dialFailFirst = 2 // the listener binds on attempt 3
	writeMaintainFiles(t, cfg, fixtureRendered, `{"v":1}`)
	wiring := &restartWiring{Executor: rec, Dialer: rec.dial, Sleep: noSleep}

	out := runStageCapturing(t, cfg, wiring)
	assert.Contains(t, out, "health PASS on attempt 3/5",
		"the late-bind client PASSES the health check — the boot race is absorbed")
	assert.NotContains(t, out, "WARNING:", "no false-positive health warning")
	assert.Equal(t, []string{"restart", "is-active", "is-active", "is-active"}, rec.verbs(),
		"one restart, three health attempts (stop at the first PASS)")
	lines := traceLines(t, rec.tracePath)
	require.Len(t, lines, 8, "gate, restart, is-active×3, dial×3 — in this order")
	assert.Equal(t, "dial 127.0.0.1:10808", lines[5], "the first refused dial probes the template's port")
	assert.Equal(t, "dial 127.0.0.1:10808", lines[7], "the third dial is the PASS")
}

// TestW17HealthLadderExhaustedIsLoudWarningInFlow pins the bounded loud
// class at the flow level: a client that never binds exhausts the ladder
// (five attempts, injected clock) and the wave completes as the existing
// DONE_WITH health-failure WARNING naming the backup.
func TestW17HealthLadderExhaustedIsLoudWarningInFlow(t *testing.T) {
	cfg, rec := restartFixture(t, "ok")
	rec.dialErr = errors.New("connect: connection refused")
	writeMaintainFiles(t, cfg, fixtureRendered, `{"old":true}`)
	wiring := &restartWiring{Executor: rec, Dialer: rec.dial, Sleep: noSleep}

	out, err := captureStageErr(t, cfg, wiring)
	require.NoError(t, err, "a health failure is DONE_WITH, not a wave failure")
	assert.Contains(t, out, "WARNING:")
	assert.Contains(t, out, "health")
	assert.Contains(t, out, "after 5 attempt(s)", "the loud line names the exhausted ladder")
	assert.Contains(t, out, "no auto-restore")
	assert.Len(t, rec.calls, 1+5, "one restart + all five ladder attempts")
}

// TestW17MidActivateShutdownCannotInterruptRestart is the non-interruptible
// pin (W17, part b): a restart of xray-raw issued by the wave must not be
// interrupted by the daemon's own shutdown between replace and xray-restart
// — a checkpoint landing there orphans the live client (new config on disk,
// old config running, no restart issued). The test flips the daemon's
// shutdown flag INSIDE the executor's restart leg (SIGTERM arrives exactly
// mid-activate) and asserts the whole step still completes: is-active AND
// the dial both happen — activate+auto-restart is ONE step, the shutdown
// checkpoint fires only between stages.
func TestW17MidActivateShutdownCannotInterruptRestart(t *testing.T) {
	cfg, rec := restartFixture(t, "ok")
	var shutdown atomic.Bool
	rec.onRestart = func() { shutdown.Store(true) } // SIGTERM mid-activate
	writeMaintainFiles(t, cfg, fixtureRendered, `{"v":1}`)

	// The wave seam: every pre-activate stage a no-op, activate = the real
	// runner, and between() = the shutdown flag (true from the restart leg
	// onward).
	cmd := &cobra.Command{}
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	stages := defaultMaintainStages(maintainOptions{})
	noop := func(*cobra.Command, *config.Config) error { return nil }
	stages.fetch, stages.parse, stages.filter = noop, noop, noop
	stages.probe = noop
	stages.stats, stages.prune, stages.selectS, stages.render = noop, noop, noop, noop
	stages.activate = func(c *cobra.Command, cc *config.Config) error {
		return runActivateStage(c, cc, &restartWiring{Executor: rec, Dialer: rec.dial, Sleep: noSleep})
	}
	require.NoError(t, runMaintainGraceful(buf, cfg, maintainOptions{}, stages, shutdown.Load),
		"an in-flight activate completes even with shutdown already requested")

	assert.Equal(t, []string{"restart", "is-active"}, rec.verbs(),
		"the restart + health verification ran to completion — no checkpoint between replace and restart")
	assert.Contains(t, buf.String(), "health PASS", "the health leg completed")
	assert.NotContains(t, buf.String(), "wave paused",
		"no stage boundary fired mid-activate: the pause can only precede the stage")
}

// noSleep is the cli-level injected clock: the ladder's waits are recorded
// policy in the restart package pins, never real time in the flow suite.
func noSleep(time.Duration) {}

// --- helpers ---------------------------------------------------------------

func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	return cmd
}

// runStageCapturing runs the activate stage and returns its output.
func runStageCapturing(t *testing.T, cfg *config.Config, wiring *restartWiring) string {
	t.Helper()
	buf := &strings.Builder{}
	cmd := newTestCmd()
	cmd.SetOut(buf)
	require.NoError(t, runActivateStage(cmd, cfg, wiring))
	return buf.String()
}

// captureStageErr runs the activate stage and returns (output, error).
func captureStageErr(t *testing.T, cfg *config.Config, wiring *restartWiring) (string, error) {
	t.Helper()
	buf := &strings.Builder{}
	cmd := newTestCmd()
	cmd.SetOut(buf)
	err := runActivateStage(cmd, cfg, wiring)
	return buf.String(), err
}

var _ = restart.Unit // keep the import pinned to the seam under test
