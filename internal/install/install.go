// install.go carries the systemctl executor seam of package install (see
// units.go for the package doc and the install/uninstall flows): the EXACT
// allowlist of sanctioned invocations (--user, assay-* units only),
// the command constructors, and the production executor.

package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Unit file base names installed into the user unit directory / cleaned up
// from older installs live in units.go (WatchService + the legacy timer
// names).

// userFlag is the mandatory scope of every systemctl invocation: the USER
// service manager only — the system bus is outside the allowlist by design.
const (
	userFlag = "--user"
	nowFlag  = "--now"
)

// Executor is the injected seam for systemctl: tests never execute systemd —
// they record invocations. The production executor validates every call
// against allowedCommands before spawning anything.
type Executor interface {
	Systemctl(args ...string) error
}

// allowedCommands is the EXACT set of systemctl invocations the installer
// may execute. Hard scope (W5 mandate, W10 surface): every invocation
// carries --user and references ONLY assay-* units; there is no
// restart of anything else, no --system, nothing else. The legacy-timer
// disable exists solely for the one-time W5→W10 migration (stale timers
// must not fire waves concurrently with the daemon). Both the code
// (validateArgs, below) and the guard tests pin this set.
var allowedCommands = [][]string{
	{userFlag, "daemon-reload"},
	{userFlag, "enable", "--now", WatchService},
	{userFlag, "disable", "--now", WatchService},
	{userFlag, "disable", "--now", RefreshTimer, SpeedtestTimer},
}

// Command constructors — the only sanctioned call shapes. The guard tests pin
// these to the allowlist byte-for-byte and pin the source to these
// constructors as the sole Systemctl call sites.
func cmdDaemonReload() []string {
	return []string{userFlag, "daemon-reload"}
}

func cmdEnableWatch() []string {
	return []string{userFlag, "enable", nowFlag, WatchService}
}

func cmdDisableWatch() []string {
	return []string{userFlag, "disable", nowFlag, WatchService}
}

func cmdDisableLegacyTimers() []string {
	return []string{userFlag, "disable", nowFlag, RefreshTimer, SpeedtestTimer}
}

func validateArgs(args []string) error {
	for _, allowed := range allowedCommands {
		if equalArgs(args, allowed) {
			return nil
		}
	}
	return fmt.Errorf("install: systemctl invocation %v is outside the allowlist "+
		"(permitted: exactly %v) — refusing", args, allowedCommands)
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		//nolint:gosec // G602 false positive: the lengths are proven equal above
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

// Systemctl validates args against the allowlist and executes systemctl.
// The 10-minute ceiling matches the repo's golangci run timeout; a hung
// systemctl fails the install loud instead of hanging the wave.
func (SystemctlExecutor) Systemctl(args ...string) error {
	if err := validateArgs(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// args are allowlist-checked above (exact pinned command set); the binary
	// name is the constant "systemctl" — G204's variable-args warning is the
	// seam's entire purpose.
	cmd := exec.CommandContext(ctx, "systemctl", args...) //nolint:gosec // allowlist-validated, see validateArgs
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %v failed: %w\n%s", args, err, out)
	}
	return nil
}

// UserSystemdAvailable reports whether a systemd USER session exists on this
// host (XDG_RUNTIME_DIR or /run/user/<uid> carrying a systemd dir) and
// systemctl is on PATH — a pure read-only probe, no process execution.
func UserSystemdAvailable() error {
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	if runtime == "" {
		runtime = filepath.Join("/run/user", strconv.Itoa(os.Getuid()))
	}
	// The runtime dir comes from the environment by definition; this is a
	// read-only stat (G703 taint), no path below it is ever written.
	sessionDir := filepath.Join(runtime, "systemd")
	if _, err := os.Stat(sessionDir); err != nil { //nolint:gosec // read-only probe of the session dir
		return fmt.Errorf("no systemd user session found (looked for %s): "+
			"this host does not run a user systemd — install fails loud unless --no-systemd "+
			"is given (binary copy only, timers skipped)", sessionDir)
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl not found on PATH: systemd is required for unit installation, " +
			"or pass --no-systemd to install the binary only")
	}
	return nil
}
