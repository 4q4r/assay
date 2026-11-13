// openrc.go carries the OpenRC user-service installer (plan §3.2, Stage S3).
// OpenRC facts the design relies on (primary sources, verified 2026-11-12):
//
//   - User services exist since OpenRC 0.60, "modeled after similar
//     functionality in systemd" (Gentoo wiki OpenRC); scripts live in
//     ${XDG_CONFIG_HOME}/rc/init.d (default ~/.config/rc/init.d); state in
//     ${XDG_RUNTIME_DIR}/openrc (XDG_RUNTIME_DIR must be set);
//   - all OpenRC commands accept --user (short -U): rc-update --user add
//     <svc> <runlevel>, rc-service --user <svc> {start,stop,status},
//     rc-status --user;
//   - openrc-run(8) service-script variables (verified against the upstream
//     man page): command=, command_args=, pidfile=, output_log= ("for the
//     standard output"), error_log= ("for the standard error output"),
//     supervisor= ("defaults to start-stop-daemon for historical reasons";
//     supervise-daemon supported); supervise-daemon(8) "starts a daemon and
//     restarts it if it crashes" — the Restart=always parity. command_background
//     is deliberately NOT emitted: it is a start-stop-daemon mechanism
//     (forcing the daemon into the background) and would defeat supervision;
//     supervise-daemon runs the daemon in the FOREGROUND and supervises it;
//   - session-lifetime caveat (Gentoo wiki): user services run while the
//     user session lives; lingering needs the user.<name> symlink trick
//     which requires root — NOT supported (no-sudo). Status says so.
//
// The allowlist pins exactly five --user shapes: rc-update add/del and
// rc-service start/stop/status (restart is in no flow — refused).

package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"assay/internal/platform"
)

// OpenRCServiceName is the service name inside the user init.d dir.
const OpenRCServiceName = "assay-watch"

// openrcPIDFileName is the pidfile the service script declares (the script
// template and the loud manual-command errors share the one definition —
// supervise-daemon's --pidfile and `kill $(cat ...)` must never drift).
const openrcPIDFileName = "assay-watch.pid"

// ---------------------------------------------------------------------------
// OpenRCExecutor — the injected rc-update/rc-service seam with its
// byte-pinned allowlist
// ---------------------------------------------------------------------------

// OpenRCExecutor is the injected OpenRC command seam: tests record
// invocations, never execute rc-*.
type OpenRCExecutor interface {
	RcUpdate(args ...string) (string, error)
	RcService(args ...string) (string, error)
}

// openrcRunlevel is the enable runlevel (§3.2): default.
const openrcRunlevel = "default"

// validateRcUpdate refuses everything outside the two pinned shapes:
// rc-update --user {add,del} assay-watch default.
func validateRcUpdate(args []string) error {
	for _, shape := range [][]string{
		{"--user", "add", OpenRCServiceName, openrcRunlevel},
		{"--user", "del", OpenRCServiceName, openrcRunlevel},
	} {
		if equalArgs(args, shape) {
			return nil
		}
	}
	return fmt.Errorf("install: rc-update invocation %v is outside the allowlist "+
		"(permitted: exactly `rc-update --user add assay-watch default` and "+
		"`rc-update --user del assay-watch default`) — refusing", args)
}

// validateRcService refuses everything outside the three pinned shapes:
// rc-service --user assay-watch {start,stop,status}.
func validateRcService(args []string) error {
	for _, verb := range []string{"start", "stop", "status"} {
		if equalArgs(args, []string{"--user", OpenRCServiceName, verb}) {
			return nil
		}
	}
	return fmt.Errorf("install: rc-service invocation %v is outside the allowlist "+
		"(permitted: exactly `rc-service --user assay-watch {start,stop,status}` — "+
		"the --user flag is mandatory, only assay-watch is ever touched) — refusing", args)
}

// OpenRCExecutorImpl is the production OpenRCExecutor: allowlist-checked
// rc-update / rc-service invocations.
type OpenRCExecutorImpl struct{}

// RcUpdate validates and executes rc-update.
func (OpenRCExecutorImpl) RcUpdate(args ...string) (string, error) {
	if err := validateRcUpdate(args); err != nil {
		return "", err
	}
	return runOpenRCBinary("rc-update", args)
}

// RcService validates and executes rc-service.
func (OpenRCExecutorImpl) RcService(args ...string) (string, error) {
	if err := validateRcService(args); err != nil {
		return "", err
	}
	return runOpenRCBinary("rc-service", args)
}

// Executor exec bounds (vars: test-shrunk — the dynamic repro test drives
// the real kill path at sub-second scale).
var (
	// openrcExecBound is the ceiling for ONE rc-update/rc-service invocation
	// (the pre-existing 2-minute ceiling).
	openrcExecBound = 2 * time.Minute
	// openrcWaitDelay bounds exec.Wait AFTER the bound's kill: lingering
	// pipe-holding grandchildren can never hang the caller (the same
	// contract as the core manager's killWaitDelay).
	openrcWaitDelay = 5 * time.Second
)

// runOpenRCBinary executes one allowlist-checked OpenRC binary (2-minute
// ceiling; a failure carries the exact command line).
func runOpenRCBinary(name string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), openrcExecBound)
	defer cancel()
	// args are allowlist-checked above; the binary name is a constant —
	// G204's variable-args warning is the seam's entire purpose.
	//nolint:gosec // allowlist-validated, see validateRcUpdate/validateRcService
	cmd := exec.CommandContext(ctx, name, args...)
	// The executor owns its whole process tree: rc-service forks openrc-run
	// helpers (and a supervise-daemon --stop leg) that inherit this pipe —
	// killing the direct child alone cannot unblock CombinedOutput's Wait
	// while one of them lives. Live-proven on alpine:edge/openrc 0.63.2
	// (run 43358084471): the --stop leg busy-spins forever when the
	// supervisor already exited, holding the pipe; the uninstall then never
	// returned (3h to the run cancel). The group kill reaps the tree at the
	// bound; WaitDelay bounds the Wait afterwards even if a straggler still
	// holds the pipe. Daemons that setsid away (supervise-daemon's child)
	// are deliberately outside the group and unaffected.
	platform.SetExecProcessGroup(cmd)
	cmd.Cancel = func() error { return platform.KillExecProcessGroup(cmd) }
	cmd.WaitDelay = openrcWaitDelay
	out, err := cmd.CombinedOutput()
	if err != nil {
		// The bound's kill surfaces as the child's own death signal
		// ("signal: killed" *ExitError) — the mechanism, not the cause.
		// Wrap the bound error HERE, where the bound fired, so callers
		// classify the stop as bounded (isBoundedStopError) regardless of
		// which error Go's Wait chose to surface.
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = fmt.Errorf("%w (the %s executor bound fired)", ctxErr, openrcExecBound)
		}
		return string(out), fmt.Errorf("%s %v failed: %w\n%s\n(run by hand: %s %v)",
			name, args, err, out, name, args)
	}
	return string(out), nil
}

// probeRCStatusUser is the §3.1.3 detection fallback: `rc-status --user`
// exits 0 on a live user session. Read-only, exit-code semantics only.
func probeRCStatusUser() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "rc-status", "--user")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rc-status --user failed: %w "+
			"(OpenRC user services need OpenRC >= 0.60, an openrc-user session, and XDG_RUNTIME_DIR)", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// OpenRCScheduler
// ---------------------------------------------------------------------------

// OpenRCScheduler installs/uninstalls/inspects the assay-watch OpenRC user
// service through the injected OpenRCExecutor. InitDir is the user init.d
// dir (${XDG_CONFIG_HOME}/rc/init.d; "" = the default resolution at use).
type OpenRCScheduler struct {
	exec    OpenRCExecutor
	InitDir string

	verifyInterval time.Duration
	verifyAttempts int

	// stopPollInterval/stopPollAttempts bound the uninstall's post-stop
	// wait (§2.2.7-mirror): production 500ms × 3600 = 30 minutes — the
	// exact TimeoutStopSec=1800 parity, the same numbers the windows
	// awaitStopped bound uses. Test-shrunk through withStopPolling.
	stopPollInterval time.Duration
	stopPollAttempts int
}

// NewOpenRCScheduler wires the scheduler over exec for initDir ("" = the
// XDG/home default resolution).
func NewOpenRCScheduler(exec OpenRCExecutor, initDir string) *OpenRCScheduler {
	return &OpenRCScheduler{
		exec:             exec,
		InitDir:          initDir,
		verifyInterval:   schedulerVerifyInterval,
		verifyAttempts:   schedulerVerifyAttempts,
		stopPollInterval: 500 * time.Millisecond,
		// 30 minutes — the §2.2.7 bound (TimeoutStopSec=1800 parity), the
		// WinSvcScheduler awaitStopped mirror.
		stopPollAttempts: 30 * 60 * 2,
	}
}

// withStopPolling shrinks the uninstall stop-poll bound (tests).
func (s *OpenRCScheduler) withStopPolling(interval time.Duration, attempts int) *OpenRCScheduler {
	s.stopPollInterval, s.stopPollAttempts = interval, attempts
	return s
}

// openrcDefaultInitDir resolves the user init.d dir: ${XDG_CONFIG_HOME}/rc/
// init.d, else <home>/.config/rc/init.d (Gentoo wiki layout).
func openrcDefaultInitDir(xdgConfigHome, homeDir string) string {
	base := xdgConfigHome
	if base == "" {
		base = filepath.Join(homeDir, ".config")
	}
	return filepath.Join(base, "rc", "init.d")
}

// resolveInitDir pins the effective init dir.
func (s *OpenRCScheduler) resolveInitDir() (string, error) {
	if s.InitDir != "" {
		return s.InitDir, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install: resolve home dir: %w", err)
	}
	return openrcDefaultInitDir(os.Getenv("XDG_CONFIG_HOME"), h), nil
}

// resolveRunlevelDir resolves the USER runlevel dir for the default
// runlevel (${XDG_CONFIG_HOME:-~/.config}/rc/runlevels/default — the same
// config base the init.d dir lives under). rc-update REQUIRES the runlevel
// to exist: it refuses "`default' is not a valid runlevel" on a fresh user
// account where no runlevel dir has been created yet (the alpine:edge CI
// leg reproduced exactly that refusal — run 43330792666). System-mode
// installs never hit this because /etc/runlevels/* ship pre-created.
func (s *OpenRCScheduler) resolveRunlevelDir() (string, error) {
	if s.InitDir != "" {
		// A pinned init dir shares its config base: <initDir>/../../runlevels/default.
		return filepath.Join(filepath.Dir(filepath.Dir(s.InitDir)), "runlevels", openrcRunlevel), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install: resolve home dir: %w", err)
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(h, ".config")
	}
	return filepath.Join(base, "rc", "runlevels", openrcRunlevel), nil
}

// Name implements the Scheduler seam.
func (s *OpenRCScheduler) Name() string { return SchedulerOpenRC }

// Available reports the detection inputs.
func (s *OpenRCScheduler) Available() (bool, string) {
	if s.exec == nil {
		return false, "no OpenRC executor wired"
	}
	return true, ""
}

// openrcScriptData builds the script body with the shell-hostile path
// refusal (openrc-run evals the script — quoting matters, per the man page).
func openrcScriptData(binaryPath, configPath, dataDir string) (string, error) {
	for field, p := range map[string]string{
		"BinaryPath": binaryPath,
		"DataDir":    dataDir,
	} {
		if strings.ContainsAny(p, "\"$`\\\n \t") {
			return "", fmt.Errorf("install: %s %q contains a shell-hostile character "+
				"(quote, $, backtick, backslash, whitespace, newline) — openrc-run evals the "+
				"service script and such a path breaks at start time; choose a plain path", field, p)
		}
	}
	args := "watch"
	if configPath != "" {
		if strings.ContainsAny(configPath, "\"$`\\\n \t") {
			return "", fmt.Errorf("install: ConfigPath %q contains a shell-hostile character "+
				"(quote, $, backtick, backslash, whitespace, newline) — openrc-run evals the "+
				"service script and such a path breaks at start time; choose a plain path", configPath)
		}
		args = "watch -c " + configPath
	}
	return "#!/sbin/openrc-run\n\n" +
		`command="` + binaryPath + `"` + "\n" +
		`command_args="` + args + `"` + "\n" +
		`supervisor="supervise-daemon"` + "\n" +
		`pidfile="` + filepath.Join(dataDir, openrcPIDFileName) + `"` + "\n" +
		`output_log="` + filepath.Join(dataDir, "logs", "watch.out.log") + `"` + "\n" +
		`error_log="` + filepath.Join(dataDir, "logs", "watch.err.log") + `"` + "\n", nil
}

// openrcScriptContent renders the §3.2 script (the golden-test spelling of
// openrcScriptData; Install uses openrcScriptData to refuse loudly).
func openrcScriptContent(binaryPath, configPath, dataDir string) (string, error) {
	return openrcScriptData(binaryPath, configPath, dataDir)
}

// Install runs the §3.2 flow: copyBinary → config materialize → write the
// service script (0755 — rc-update refuses a non-executable service: the
// alpine:edge leg live-proved "rc-update: service `assay-watch' is not
// executable" against the old 0644) into the user init.d dir → rc-update --user add
// assay-watch default → rc-service --user assay-watch start → bounded
// rc-service --user assay-watch status verify.
func (s *OpenRCScheduler) Install(spec SchedulerInstallSpec) (Result, error) {
	res := Result{}
	if s.exec == nil {
		return res, errors.New("install: no OpenRC executor wired (openrc-user)")
	}
	initDir, err := s.resolveInitDir()
	if err != nil {
		return res, err
	}
	binPath, err := copyBinary(spec.RunningBinary, spec.BinDir)
	if err != nil {
		return res, err
	}
	res.BinaryPath = binPath
	if err := materializeForSpec(spec, &res); err != nil {
		return res, err
	}
	if err := ensureLogsDir(spec.DataDir); err != nil {
		return res, err
	}
	body, err := openrcScriptData(binPath, spec.ConfigPath, spec.DataDir)
	if err != nil {
		return res, err
	}
	if err := os.MkdirAll(initDir, 0o750); err != nil {
		return res, fmt.Errorf("install: create OpenRC init dir %s: %w", initDir, err)
	}
	// The user runlevel must exist before rc-update --user add (see
	// resolveRunlevelDir) — create it idempotently, exactly like init.d.
	runlevelDir, rerr := s.resolveRunlevelDir()
	if rerr != nil {
		return res, rerr
	}
	if err := os.MkdirAll(runlevelDir, 0o750); err != nil {
		return res, fmt.Errorf("install: create OpenRC runlevel dir %s: %w", runlevelDir, err)
	}
	scriptPath := filepath.Join(initDir, OpenRCServiceName)
	if err := writeFileAtomic(scriptPath, []byte(body), 0o755); err != nil {
		return res, err
	}
	res.UnitPaths = []string{scriptPath}
	// Enable in the default runlevel, then start (§3.2 exact sequence).
	if _, err := s.exec.RcUpdate("--user", "add", OpenRCServiceName, openrcRunlevel); err != nil {
		return res, fmt.Errorf("install: rc-update --user add %s %s failed: %w\n"+
			"(run by hand: rc-update --user add %s %s)", OpenRCServiceName, openrcRunlevel,
			err, OpenRCServiceName, openrcRunlevel)
	}
	if _, err := s.exec.RcService("--user", OpenRCServiceName, "start"); err != nil {
		return res, fmt.Errorf("install: rc-service --user %s start failed: %w\n"+
			"(run by hand: rc-service --user %s start)", OpenRCServiceName, err, OpenRCServiceName)
	}
	// §3.3 bounded verify: the status probe exits 0 once the service reports
	// started (`* status: started` — the rc-service status shape).
	probe := "rc-service --user " + OpenRCServiceName + " status"
	for range s.verifyAttempts {
		if _, verr := s.exec.RcService("--user", OpenRCServiceName, "status"); verr == nil {
			res.ServiceActive = true
			return res, nil
		}
		time.Sleep(s.verifyInterval)
	}
	return res, loudProbeFailure(SchedulerOpenRC, probe, probe, s.verifyAttempts,
		errors.New("the service never reported started"))
}

// Uninstall stops the service when the status probe reports it started,
// removes it from the default runlevel, and deletes the script. A stop that
// outlives the executor bound is rescued by the §2.2.7-mirror bounded
// status poll (the stop machinery keeps draining in background sessions, or
// the service already stopped under us — the openrc 0.63.2 stop race);
// a stop that never lands within the poll bound is a LOUD error naming the
// exact manual commands.
func (s *OpenRCScheduler) Uninstall(spec SchedulerUninstallSpec) (UninstallResult, error) {
	res := UninstallResult{}
	initDir, err := s.resolveInitDir()
	if err != nil {
		return res, err
	}
	scriptPath := filepath.Join(initDir, OpenRCServiceName)
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return s.finishUninstall(spec, res)
	}
	// Stop only when started (the status probe failing = stopped/unreachable).
	started := false
	if _, serr := s.exec.RcService("--user", OpenRCServiceName, "status"); serr == nil {
		started = true
	}
	if started {
		pidfilePath := filepath.Join(spec.DataDir, openrcPIDFileName)
		if _, kerr := s.exec.RcService("--user", OpenRCServiceName, "stop"); kerr != nil {
			if !isBoundedStopError(kerr) {
				// A real rc-service refusal (failed fast — nothing is
				// stopping in the background). Loud, exact manual chain,
				// nothing deleted behind a failed stop.
				return res, fmt.Errorf("uninstall: rc-service --user %s stop failed: %w\n"+
					"(finish it by hand, then re-run `assay uninstall`:\n"+
					"  rc-service --user %s zap\n"+
					"  kill $(cat %s)   # when the pidfile still exists)",
					OpenRCServiceName, kerr, OpenRCServiceName, pidfilePath)
			}
			// The executor bound killed the rc-service wrapper mid-stop: the
			// openrc stop machinery (openrc-run, supervise-daemon) may still
			// be draining in background sessions, or the service already
			// stopped under us (the openrc 0.63.2 stop race — its
			// supervise-daemon --stop leg busy-spins AFTER the effective
			// stop; live-proven on alpine:edge, run 43358084471). The
			// §2.2.7-mirror bounded poll decides: proceed on observed
			// stopped, loud error on exhaustion.
			if werr := s.awaitStopped(pidfilePath); werr != nil {
				return res, werr
			}
		}
		res.DisabledUnits = []string{OpenRCServiceName}
	}
	if _, uerr := s.exec.RcUpdate("--user", "del", OpenRCServiceName, openrcRunlevel); uerr != nil {
		return res, fmt.Errorf("uninstall: rc-update --user del %s %s failed: %w\n"+
			"(run by hand: rc-update --user del %s %s)", OpenRCServiceName, openrcRunlevel,
			uerr, OpenRCServiceName, openrcRunlevel)
	}
	if err := os.Remove(scriptPath); err != nil {
		return res, fmt.Errorf("uninstall: remove %s: %w", scriptPath, err)
	}
	res.RemovedUnits = []string{OpenRCServiceName}
	return s.finishUninstall(spec, res)
}

// isBoundedStopError reports whether the stop failure came from the
// executor's bound (context deadline, the WaitDelay pipe-bound expiry, or an
// explicit cancellation) rather than a fast real rc-service refusal. Only
// bound failures leave background stop machinery worth polling; a fast
// refusal gets the immediate loud error instead of a pointless poll budget.
func isBoundedStopError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, exec.ErrWaitDelay)
}

// awaitStopped is the §2.2.7-mirror bounded stop-wait (the WinSvcScheduler
// awaitStopped shape on the rc-service seam): poll `rc-service --user
// assay-watch status` until it reports stopped — the probe exiting non-zero
// IS the stopped verdict (rc-service status exits 3 on `* status: stopped`,
// live-proven on alpine:edge 0.63.2). On exhaustion the error names the
// exact manual commands (zap + the pidfile kill) and the re-run.
func (s *OpenRCScheduler) awaitStopped(pidfilePath string) error {
	for range s.stopPollAttempts {
		if _, serr := s.exec.RcService("--user", OpenRCServiceName, "status"); serr != nil {
			//nolint:nilerr // the probe's non-zero exit IS the stopped verdict — the answer, not an error
			return nil // (rc-service status exits 3 on `* status: stopped`, live-proven on alpine:edge 0.63.2)
		}
		time.Sleep(s.stopPollInterval)
	}
	return fmt.Errorf("uninstall: the assay service did not reach stopped within %s — "+
		"finish it by hand, then re-run `assay uninstall`:\n"+
		"  rc-service --user %s zap\n"+
		"  kill $(cat %s)   # when the pidfile still exists",
		time.Duration(s.stopPollAttempts)*s.stopPollInterval, OpenRCServiceName, pidfilePath)
}

// finishUninstall is the shared tail: managed-core teardown + purge.
func (s *OpenRCScheduler) finishUninstall(spec SchedulerUninstallSpec, res UninstallResult) (UninstallResult, error) {
	coreRemoved, err := removeManagedCore(spec.DataDir)
	if err != nil {
		return res, err
	}
	res.CoreRemoved = coreRemoved
	for _, purge := range []string{spec.PurgeConfigPath, spec.PurgeDataDir} {
		if purge == "" {
			continue
		}
		if err := os.RemoveAll(purge); err != nil {
			return res, fmt.Errorf("uninstall: purge %s: %w", purge, err)
		}
		res.Purged = append(res.Purged, purge)
	}
	return res, nil
}

// Status reports the service state with the HONEST session-lifetime caveat
// (§3.2: user services live while the session lives; lingering needs root —
// not supported).
func (s *OpenRCScheduler) Status() (SchedulerStatus, error) {
	initDir, err := s.resolveInitDir()
	if err != nil {
		return SchedulerStatus{}, err
	}
	scriptPath := filepath.Join(initDir, OpenRCServiceName)
	if _, err := os.Stat(scriptPath); err != nil {
		//nolint:nilerr // the stat failure IS the answer: not registered — an honest status, not an error
		return SchedulerStatus{
			Active: false,
			Note:   "service script absent (" + scriptPath + " — run `assay install`)",
		}, nil
	}
	if _, serr := s.exec.RcService("--user", OpenRCServiceName, "status"); serr != nil {
		return SchedulerStatus{}, fmt.Errorf("rc-service --user %s status failed: %w\n"+
			"(run by hand: rc-service --user %s status)", OpenRCServiceName, serr, OpenRCServiceName)
	}
	return SchedulerStatus{
		Active: true,
		Note: "started — supervision: supervise-daemon restart-on-crash; " +
			"user services run while the session lives (no lingering without root)",
	}, nil
}

// HeldRegistration reports the service script presence (the symlink into the
// runlevel may be gone while the script remains — a stale registration still
// re-enables at the next openrc-user start, so the script counts).
func (s *OpenRCScheduler) HeldRegistration() (bool, string) {
	initDir, err := s.resolveInitDir()
	if err != nil {
		return false, ""
	}
	p := filepath.Join(initDir, OpenRCServiceName)
	if _, err := os.Stat(p); err != nil {
		return false, ""
	}
	return true, p
}
