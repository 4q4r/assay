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
)

// OpenRCServiceName is the service name inside the user init.d dir.
const OpenRCServiceName = "assay-watch"

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

// runOpenRCBinary executes one allowlist-checked OpenRC binary (2-minute
// ceiling; a failure carries the exact command line).
func runOpenRCBinary(name string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// args are allowlist-checked above; the binary name is a constant —
	// G204's variable-args warning is the seam's entire purpose.
	//nolint:gosec // allowlist-validated, see validateRcUpdate/validateRcService
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
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
}

// NewOpenRCScheduler wires the scheduler over exec for initDir ("" = the
// XDG/home default resolution).
func NewOpenRCScheduler(exec OpenRCExecutor, initDir string) *OpenRCScheduler {
	return &OpenRCScheduler{
		exec:           exec,
		InitDir:        initDir,
		verifyInterval: schedulerVerifyInterval,
		verifyAttempts: schedulerVerifyAttempts,
	}
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
		`pidfile="` + filepath.Join(dataDir, "assay-watch.pid") + `"` + "\n" +
		`output_log="` + filepath.Join(dataDir, "logs", "watch.out.log") + `"` + "\n" +
		`error_log="` + filepath.Join(dataDir, "logs", "watch.err.log") + `"` + "\n", nil
}

// openrcScriptContent renders the §3.2 script (the golden-test spelling of
// openrcScriptData; Install uses openrcScriptData to refuse loudly).
func openrcScriptContent(binaryPath, configPath, dataDir string) (string, error) {
	return openrcScriptData(binaryPath, configPath, dataDir)
}

// Install runs the §3.2 flow: copyBinary → config materialize → write the
// service script (0644) into the user init.d dir → rc-update --user add
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
	scriptPath := filepath.Join(initDir, OpenRCServiceName)
	if err := writeFileAtomic(scriptPath, []byte(body), 0o644); err != nil {
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
// removes it from the default runlevel, and deletes the script.
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
		if _, kerr := s.exec.RcService("--user", OpenRCServiceName, "stop"); kerr != nil {
			return res, fmt.Errorf("uninstall: rc-service --user %s stop failed: %w\n"+
				"(run by hand: rc-service --user %s stop)", OpenRCServiceName, kerr, OpenRCServiceName)
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
