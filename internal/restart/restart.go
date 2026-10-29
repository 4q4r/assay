// Package restart is the daemon's ENTIRE systemd surface for the live xray
// client (W13, owner ruling «само будет обновлять xray»): a byte-pinned
// allowlist executor in the same style as install's, plus the post-restart
// health check. The allowlist is EXACTLY two commands —
//
//	systemctl --user restart   xray-raw.service
//	systemctl --user is-active xray-raw.service
//
// — no other unit, no other verb, no flags. `restart` is the only
// state-changing systemctl command the daemon may ever run (exactly once per
// real activation); `is-active` is its read-only verification leg. Anything
// else fails loud at validateArgs before any process is spawned. The whole
// production tree is guard-tested to carry no other exec-of-systemctl path
// (TestDaemonSystemdSurfaceIsExactlyTwoExecutorFiles).
//
// The flow is restart → is-active → socks-port dial. Every failure is typed
// and loud: Error (systemctl refused/failed — the config on disk is
// already the gated new one) and HealthError (the client did not come back
// — report-only, the caller surfaces the backup-restore hint; there is NO
// auto-restore in this generation). A missing user session surfaces as a
// loud Error carrying systemctl's own "Failed to connect to bus"
// output — no separate probe, no silent skip.
package restart

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Unit is the byte-pinned target of both allowlisted commands. It MUST equal
// config.DefaultServiceName (the manual-restart hint's default unit) — the
// equality is guard-pinned, so the auto path and the hint cannot drift.
const Unit = "xray-raw.service"

// userFlag is the mandatory scope of every invocation: the USER service
// manager only. The system bus is outside the allowlist by design.
const userFlag = "--user"

// restartTimeout bounds every systemctl child of this executor. A hung
// systemctl fails the wave loud instead of stalling the schedule.
const restartTimeout = 60 * time.Second

// portProbeTimeout is the health check's socks-port dial budget per attempt:
// the unit reported active, so the listener is expected up; a dial that
// outlives this fails the attempt (and the attempt is retried only within
// the bounded ladder below — the W17 boot-race fix).
const portProbeTimeout = 3 * time.Second

// The W17 health ladder (production boot race): `systemctl restart` returns
// the instant systemd forked the client — xray has not bound the socks port
// yet (geosite/geoip hash-compare + config parse + bind happen after fork),
// and the old single-shot dial false-positived a health failure on a live
// client. The health phase (is-active + socks dial) is retried on a
// BOUNDED exponential ladder: 5 attempts with 1s/2s/4s/8s backoff between
// them. Success on ANY attempt; all five fail → the same loud HealthError
// class as before, now provably post-ladder.
//
// These are code-owned constants, NOT knobs (owner no-floor ruling: retry
// politeness is not operator-facing configuration — the ladder exists to
// absorb a boot race, and an operator who needs to tune it has a different
// problem). Deadline safety is arithmetic, pinned by test: 15s of backoff +
// 5 × 3s port-probe budget ≈ 30s worst case, well under the daemon's
// run budget — a genuinely dead client cannot wedge the wave.
const healthAttempts = 5

// healthBackoff is the between-attempt sleep schedule (no trailing sleep
// after the final attempt): attempts land at ≈0s/4s/9s/16s/27s wall time.
var healthBackoff = [healthAttempts - 1]time.Duration{
	1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
}

// HealthAttempts exposes the ladder length for the guard pins.
func HealthAttempts() int { return healthAttempts }

// Executor is the injected seam for systemctl: tests never execute systemd —
// they record invocations. The production executor validates every call
// against the allowlist before spawning anything.
type Executor interface {
	Systemctl(args ...string) (string, error)
}

// Dialer is the health check's port-probe seam (net.DialTimeout shape).
// Tests inject a recorder; production uses the default.
type Dialer func(network, addr string, timeout time.Duration) (net.Conn, error)

// allowedCommands is the EXACT set of systemctl invocations the daemon may
// execute for the live client. It is an immutable two-element array (not a
// slice) — the same compile-time immutability pin as the install surface.
var allowedCommands = [2][]string{
	{userFlag, "restart", Unit},
	{userFlag, "is-active", Unit},
}

// AllowedCommands returns the pinned allowlist for the guard tests.
func AllowedCommands() [][]string {
	return [][]string{allowedCommands[0], allowedCommands[1]}
}

// Command constructors — the only sanctioned call shapes. The guard tests
// pin these to the allowlist byte-for-byte and pin the source to these
// constructors as the sole Systemctl call sites.
func cmdRestartXray() []string  { return []string{userFlag, "restart", Unit} }
func cmdIsActiveXray() []string { return []string{userFlag, "is-active", Unit} }

// CmdRestartXray returns the pinned restart command (guard-test wrapper for
// the unexported constructor, which is the real call site).
func CmdRestartXray() []string { return cmdRestartXray() }

// CmdIsActiveXray returns the pinned health-probe command (guard-test
// wrapper for the unexported constructor, which is the real call site).
func CmdIsActiveXray() []string { return cmdIsActiveXray() }

// ValidateArgs reports whether args is exactly one of the pinned commands.
func ValidateArgs(args []string) error { return validateArgs(args) }

func validateArgs(args []string) error {
	for _, allowed := range allowedCommands {
		if equalArgs(args, allowed) {
			return nil
		}
	}
	return fmt.Errorf("restart: systemctl invocation %v is outside the allowlist "+
		"(permitted: exactly %v) — refusing", args, allowedCommands)
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SystemctlExecutor is the production Executor: allowlist-checked
// `systemctl ...` invocations. A refused command is a loud error — the
// executor never falls back, never widens its scope.
type SystemctlExecutor struct{}

// Systemctl validates args against the allowlist and executes systemctl,
// returning its combined output. args are allowlist-checked below (exact
// pinned command set); the binary name is the constant "systemctl" — G204's
// variable-args warning is the seam's entire purpose.
func (SystemctlExecutor) Systemctl(args ...string) (string, error) {
	if err := validateArgs(args); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), restartTimeout)
	defer cancel()
	//nolint:gosec // allowlist-validated, see validateArgs
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("systemctl %v failed: %w\n%s", args, err, out)
	}
	return string(out), nil
}

// Input bundles the restart flow's dependencies and facts.
type Input struct {
	// Executor is required: a nil executor is a wiring error and fails loud
	// (never a silent skip).
	Executor Executor
	// Dialer probes the socks port; nil = the real net dialer.
	Dialer Dialer
	// Sleep is the ladder's clock seam; nil = the real time.Sleep. Tests
	// inject a recorder so the bounded-time pins never wait.
	Sleep func(time.Duration)
	// SocksPort is the socks inbound port of the just-activated config
	// (0 = unknown — the port leg is skipped and the verdict says so).
	SocksPort int
	// BackupPath is the pre-activation backup; it is quoted verbatim in
	// health-failure messages as the restore hint (report-only).
	BackupPath string
}

// Result reports the flow's outcome legs.
type Result struct {
	Restarted bool
	Active    bool
	PortOpen  bool
	// Attempts counts health-phase attempts made (1 = first-try PASS with
	// zero retries; HealthAttempts() = the ladder was exhausted).
	Attempts int
	Verdict  string
}

// Error marks a failed restart: the live client still runs the
// PREVIOUS config while the gated new one is already on disk. The wave
// completes (DONE_WITH restart-failure) — this type is how the caller
// distinguishes the class for the loud line.
type Error struct {
	Cmd []string
	Err error
}

func (e *Error) Error() string {
	return fmt.Sprintf("restart failed (%v): %v", e.Cmd, e.Err)
}

// HealthError marks a post-restart health failure: the restart command
// succeeded but the client did not come back cleanly. Attempts records how
// many ladder attempts were made before the failure surfaced (the W17
// bounded retry — see healthAttempts). RestoreHint quotes the pre-activation
// backup (empty when none was taken).
type HealthError struct {
	Leg         string // "is-active" | "unit-state" | "socks-port"
	Attempts    int
	RestoreHint string
	Err         error
}

func (e *HealthError) Error() string {
	msg := fmt.Sprintf("post-restart health check failed at the %s leg after %d attempt(s): %v",
		e.Leg, e.Attempts, e.Err)
	if e.Attempts > 1 {
		msg += fmt.Sprintf(" — the bounded health ladder (%d attempts, 1s/2s/4s/8s backoff) "+
			"gave the client ~30s to come up", healthAttempts)
	}
	if e.RestoreHint != "" {
		msg += " — restore hint: the pre-activation backup " + e.RestoreHint +
			" holds the previous working config (report-only; no auto-restore)"
	}
	return msg
}

// Run executes the mandatory post-activation flow: restart → health phase.
// Exactly one restart per call — the caller (the wave's activate stage)
// invokes Run only after a real config replacement. The health phase
// (is-active → socks-port dial) runs on the W17 bounded retry ladder: PASS
// on any attempt, all attempts fail → the final attempt's loud HealthError.
func Run(in Input) (Result, error) {
	res := Result{}
	if in.Executor == nil {
		return res, errors.New("restart: no executor wired — the restart seam must be injected (programming error)")
	}

	// 1. The restart — exactly one allowlisted invocation, never retried:
	//    systemctl restart is idempotent-per-call but the retry ladder is a
	//    HEALTH contract, not a restart contract.
	if _, err := in.Executor.Systemctl(cmdRestartXray()...); err != nil {
		return res, &Error{Cmd: cmdRestartXray(), Err: err}
	}
	res.Restarted = true

	// 2. The health phase on the bounded ladder: success on ANY attempt;
	//    between attempts, the injected (or real) sleep waits out the
	//    backoff. No sleep after the final failed attempt — the loud class
	//    surfaces immediately.
	sleep := in.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	var lastErr error
	for attempt := 1; attempt <= healthAttempts; attempt++ {
		res.Attempts = attempt
		err := healthPhase(in, &res, attempt)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if attempt < healthAttempts {
			sleep(healthBackoff[attempt-1])
		}
	}
	return res, lastErr
}

// healthPhase is one ladder attempt: the unit must report active, then the
// socks port (when known) must answer on loopback. A nil error sets the
// Result verdict (with the attempt count) and marks the legs it proved.
func healthPhase(in Input, res *Result, attempt int) error {
	out, err := in.Executor.Systemctl(cmdIsActiveXray()...)
	if err != nil {
		return &HealthError{
			Leg: "is-active", Attempts: attempt, RestoreHint: in.BackupPath,
			Err: fmt.Errorf("systemctl is-active failed: %w", err),
		}
	}
	if state := strings.TrimSpace(out); state != "active" {
		return &HealthError{
			Leg: "unit-state", Attempts: attempt, RestoreHint: in.BackupPath,
			Err: fmt.Errorf("unit reports %q, not active — the client may be crash-looping on the new config", state),
		}
	}
	res.Active = true

	// An unknown port degrades to the unit-state verdict — stated, never
	// silent.
	if in.SocksPort <= 0 {
		res.Verdict = fmt.Sprintf("restart ok — unit active (health PASS on attempt %d/%d; "+
			"socks port not found in the activated config — port probe skipped)",
			attempt, healthAttempts)
		return nil
	}
	dial := in.Dialer
	if dial == nil {
		dial = net.DialTimeout
	}
	conn, err := dial("tcp", fmt.Sprintf("127.0.0.1:%d", in.SocksPort), portProbeTimeout)
	if err != nil {
		return &HealthError{
			Leg: "socks-port", Attempts: attempt, RestoreHint: in.BackupPath,
			Err: fmt.Errorf("socks 127.0.0.1:%d unreachable after restart: %w "+
				"(check `journalctl --user -u %s`)", in.SocksPort, err, Unit),
		}
	}
	if conn != nil {
		_ = conn.Close()
	}
	res.PortOpen = true
	res.Verdict = fmt.Sprintf("restart ok — unit active, socks 127.0.0.1:%d reachable "+
		"(health PASS on attempt %d/%d)", in.SocksPort, attempt, healthAttempts)
	return nil
}
