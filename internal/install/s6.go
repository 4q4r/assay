// s6.go carries the s6 user-supervision installer (plan §3.2, Stage S3).
// s6 facts the design relies on (primary sources, verified 2026-11-12):
//
//   - s6-svscan(1) scans "the current directory for subdirectories … which
//     must be service directories" — so the scandir IS the detected
//     s6-svscan's /proc cwd; "it exits 100 if another s6-svscan process is
//     already monitoring this scan directory"; names starting with dots are
//     skipped;
//   - with rescan off (the default) the scanner "will only detect new
//     services when told to via a s6-svscanctl -a command" — the activation;
//   - s6-svscanctl has NO single-service stop: -n only kills supervisors
//     "that did not match a service directory last time scandir was scanned"
//     (a janitor, not a live-stop); the verified live-stop is s6-svc -d —
//     "if the supervised process is up, send it a SIGTERM … and do not
//     restart it";
//   - removing a live service's directory flags it inactive WITHOUT stopping
//     it ("no command is sent to stop inactive s6-supervise processes") —
//     uninstall therefore stops FIRST (s6-svc -d), waits for down, and only
//     then removes the dir and rescans;
//   - s6-svstat(1) reports whether the service is up or down first; exit 1
//     = s6-supervise not running.
//
// skarnet publishes no official user-overlay convention (the s6-user-resources
// page 404s) — the scandir is taken from the DETECTED user s6-svscan's cwd,
// never invented.

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

// S6ServiceDirName is the service directory name inside the scandir.
const S6ServiceDirName = "assay-watch"

// ---------------------------------------------------------------------------
// S6Executor — the injected seam with its byte-pinned allowlist
// ---------------------------------------------------------------------------

// S6Executor is the injected s6 command seam (three binaries, one interface):
// tests record invocations, never execute s6.
type S6Executor interface {
	Svc(args ...string) (string, error)       // s6-svc — the verified live-stop
	Svscanctl(args ...string) (string, error) // s6-svscanctl — the activation rescan
	Svstat(args ...string) (string, error)    // s6-svstat — the status probe
}

// validateS6Svc refuses everything outside the one pinned shape:
// s6-svc -d <abs scandir>/assay-watch. `-u` is never sent (activation is the
// dir + rescan); `-d` on anything but assay's own service dir is refused.
func validateS6Svc(args []string) error {
	if len(args) == 2 && args[0] == "-d" && isS6WatchDir(args[1]) {
		return nil
	}
	return fmt.Errorf("install: s6-svc invocation %v is outside the allowlist "+
		"(permitted: exactly `s6-svc -d <abs scandir>/assay-watch` — the verified live-stop; "+
		"assay's own service only) — refusing", args)
}

// validateS6Svscanctl refuses everything outside the one pinned shape:
// s6-svscanctl -a <abs scandir>. -n/-t/-q/-b touch the whole tree or
// unmatched supervisors — never ours to send.
func validateS6Svscanctl(args []string) error {
	if len(args) == 2 && args[0] == "-a" && isAbsDir(args[1]) {
		return nil
	}
	return fmt.Errorf("install: s6-svscanctl invocation %v is outside the allowlist "+
		"(permitted: exactly `s6-svscanctl -a <abs scandir>` — the activation rescan) — refusing", args)
}

// validateS6Svstat refuses everything outside the one pinned shape:
// s6-svstat <abs scandir>/assay-watch.
func validateS6Svstat(args []string) error {
	if len(args) == 1 && isS6WatchDir(args[0]) {
		return nil
	}
	return fmt.Errorf("install: s6-svstat invocation %v is outside the allowlist "+
		"(permitted: exactly `s6-svstat <abs scandir>/assay-watch`) — refusing", args)
}

// isS6WatchDir reports whether p is an absolute path whose base is the
// assay-watch service dir.
func isS6WatchDir(p string) bool {
	return filepath.IsAbs(p) && filepath.Base(p) == S6ServiceDirName
}

// isAbsDir reports whether p is an absolute path.
func isAbsDir(p string) bool { return filepath.IsAbs(p) }

// The bound validators (defense in depth): the shape allowlist above is
// stateless; these additionally pin the target to THIS scheduler's own
// scandir — the scheduler only ever builds args from its ScanDir, and the
// bound checks make that invariant refuse-shaped rather than conventional.

// validateS6SvcForScanDir refuses a -d target outside <scanDir>/assay-watch.
func validateS6SvcForScanDir(args []string, scanDir string) error {
	if err := validateS6Svc(args); err != nil {
		return err
	}
	if want := filepath.Join(scanDir, S6ServiceDirName); args[1] != want {
		return fmt.Errorf("install: s6-svc invocation %v is outside the allowlist "+
			"(bound to this scheduler's own %s) — refusing", args, want)
	}
	return nil
}

// validateS6SvscanctlForScanDir refuses a rescan of any dir but our scandir.
func validateS6SvscanctlForScanDir(args []string, scanDir string) error {
	if err := validateS6Svscanctl(args); err != nil {
		return err
	}
	if args[1] != scanDir {
		return fmt.Errorf("install: s6-svscanctl invocation %v is outside the allowlist "+
			"(bound to this scheduler's own scandir %s) — refusing", args, scanDir)
	}
	return nil
}

// validateS6SvstatForScanDir refuses a status probe outside our service dir.
func validateS6SvstatForScanDir(args []string, scanDir string) error {
	if err := validateS6Svstat(args); err != nil {
		return err
	}
	if want := filepath.Join(scanDir, S6ServiceDirName); args[0] != want {
		return fmt.Errorf("install: s6-svstat invocation %v is outside the allowlist "+
			"(bound to this scheduler's own %s) — refusing", args, want)
	}
	return nil
}

// runS6Binary executes one allowlist-checked s6 binary (2-minute ceiling; a
// failure carries the exact command line).
func runS6Binary(name string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// args are allowlist-checked above; the binary name is a constant —
	// G204's variable-args warning is the seam's entire purpose.
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // allowlist-validated, see validateS6*
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %v failed: %w\n%s\n(run by hand: %s %v)",
			name, args, err, out, name, args)
	}
	return string(out), nil
}

// S6ExecutorImpl is the production S6Executor: allowlist-checked s6-svc /
// s6-svscanctl / s6-svstat invocations.
type S6ExecutorImpl struct{}

// Svc validates and executes s6-svc.
func (S6ExecutorImpl) Svc(args ...string) (string, error) {
	if err := validateS6Svc(args); err != nil {
		return "", err
	}
	return runS6Binary("s6-svc", args)
}

// Svscanctl validates and executes s6-svscanctl.
func (S6ExecutorImpl) Svscanctl(args ...string) (string, error) {
	if err := validateS6Svscanctl(args); err != nil {
		return "", err
	}
	return runS6Binary("s6-svscanctl", args)
}

// Svstat validates and executes s6-svstat.
func (S6ExecutorImpl) Svstat(args ...string) (string, error) {
	if err := validateS6Svstat(args); err != nil {
		return "", err
	}
	return runS6Binary("s6-svstat", args)
}

// ---------------------------------------------------------------------------
// S6Scheduler
// ---------------------------------------------------------------------------

// S6Scheduler installs/uninstalls/inspects the assay-watch s6 service
// through the injected S6Executor. ScanDir is the DETECTED user s6-svscan's
// cwd (never invented).
type S6Scheduler struct {
	exec    S6Executor
	ScanDir string

	verifyInterval time.Duration
	verifyAttempts int
	stopInterval   time.Duration
	stopAttempts   int
}

// NewS6Scheduler wires the scheduler over exec for the given scandir.
func NewS6Scheduler(exec S6Executor, scanDir string) *S6Scheduler {
	return &S6Scheduler{
		exec:           exec,
		ScanDir:        scanDir,
		verifyInterval: schedulerVerifyInterval,
		verifyAttempts: schedulerVerifyAttempts,
		stopInterval:   schedulerVerifyInterval,
		stopAttempts:   schedulerVerifyAttempts,
	}
}

// Name implements the Scheduler seam.
func (s *S6Scheduler) Name() string { return SchedulerS6 }

// Available reports the detection inputs.
func (s *S6Scheduler) Available() (bool, string) {
	if s.exec == nil {
		return false, "no s6 executor wired"
	}
	if s.ScanDir == "" {
		return false, "no user s6-svscan detected (start one with `s6-svscan ~/scandir` — " +
			"the scandir is taken from the scanner's cwd, never invented)"
	}
	return true, ""
}

// watchDir is the service directory path.
func (s *S6Scheduler) watchDir() string {
	return filepath.Join(s.ScanDir, S6ServiceDirName)
}

// Install runs the §3.2 flow: copyBinary → config materialize →
// <scandir>/assay-watch with `run` (0755, the shared runit content contract)
// → `s6-svscanctl -a <scandir>` (the activation rescan) → bounded
// `s6-svstat` verify until the service reports up.
func (s *S6Scheduler) Install(spec SchedulerInstallSpec) (Result, error) {
	res := Result{}
	if s.exec == nil {
		return res, errors.New("install: no s6 executor wired (s6)")
	}
	if s.ScanDir == "" {
		return res, errors.New("install: no user s6-svscan detected — start one with " +
			"`s6-svscan <scandir>` and re-run `assay install`")
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
	watchDir := s.watchDir()
	if err := os.MkdirAll(watchDir, 0o750); err != nil {
		return res, fmt.Errorf("install: create s6 service dir %s: %w", watchDir, err)
	}
	script, err := runScriptContent(binPath, spec.ConfigPath, spec.DataDir)
	if err != nil {
		return res, err
	}
	runPath := filepath.Join(watchDir, "run")
	if err := writeFileAtomic(runPath, script, 0o755); err != nil {
		return res, err
	}
	res.UnitPaths = []string{runPath}
	// Activation: the rescan alarm (s6-svscanctl -a) — without it a
	// default-configured scanner would never notice the new directory.
	if err := validateS6SvscanctlForScanDir([]string{"-a", s.ScanDir}, s.ScanDir); err != nil {
		return res, err
	}
	if _, err := s.exec.Svscanctl("-a", s.ScanDir); err != nil {
		return res, fmt.Errorf("install: s6-svscanctl -a %s failed: %w\n"+
			"(run by hand: s6-svscanctl -a %s)", s.ScanDir, err, s.ScanDir)
	}
	// §3.3 bounded verify: s6-svstat until the service reports up (the
	// s6-svstat summary leads with up/down).
	probe := "s6-svstat " + watchDir
	for range s.verifyAttempts {
		if up, _ := s.svstatUp(); up {
			res.ServiceActive = true
			return res, nil
		}
		time.Sleep(s.verifyInterval)
	}
	return res, loudProbeFailure(SchedulerS6, probe, probe, s.verifyAttempts,
		errors.New("the service never reported up"))
}

// svstatUp runs one s6-svstat probe and reports whether the output leads
// with "up" (exit 0). A failing probe = not up (supervise not attached yet).
func (s *S6Scheduler) svstatUp() (bool, error) {
	dir := s.watchDir()
	if err := validateS6SvstatForScanDir([]string{dir}, s.ScanDir); err != nil {
		return false, err
	}
	out, err := s.exec.Svstat(dir)
	if err != nil {
		return false, err
	}
	fields := strings.Fields(out)
	return len(fields) > 0 && fields[0] == "up", nil
}

// Uninstall runs the VERIFIED live-stop contract: s6-svc -d (SIGTERM + no
// restart) → bounded wait until s6-svstat reports down → remove the service
// dir → s6-svscanctl -a rescan. Removing the dir FIRST would only flag the
// service inactive — nothing would ever stop it (s6-svscan kills nothing on
// scan).
func (s *S6Scheduler) Uninstall(spec SchedulerUninstallSpec) (UninstallResult, error) {
	res := UninstallResult{}
	watchDir := s.watchDir()
	if _, err := os.Stat(watchDir); os.IsNotExist(err) {
		return s.finishUninstall(spec, res)
	}
	// Live stop — the one verified shape (s6-svc -d).
	if err := validateS6SvcForScanDir([]string{"-d", watchDir}, s.ScanDir); err != nil {
		return res, err
	}
	if _, err := s.exec.Svc("-d", watchDir); err != nil {
		return res, fmt.Errorf("uninstall: s6-svc -d %s failed: %w\n"+
			"(run by hand: s6-svc -d %s)", watchDir, err, watchDir)
	}
	res.DisabledUnits = []string{S6ServiceDirName}
	// Bounded wait for down — never remove a live service dir.
	down := false
	for range s.stopAttempts {
		if up, _ := s.svstatUp(); !up {
			down = true
			break
		}
		time.Sleep(s.stopInterval)
	}
	if !down {
		return res, fmt.Errorf("uninstall: the s6 service did not report down after "+
			"s6-svc -d within %d probes — refusing to remove a live service dir\n"+
			"(inspect by hand: s6-svstat %s)", s.stopAttempts, watchDir)
	}
	if err := os.RemoveAll(watchDir); err != nil {
		return res, fmt.Errorf("uninstall: remove %s: %w", watchDir, err)
	}
	res.RemovedUnits = []string{S6ServiceDirName + " (service dir)"}
	// Rescan so the scanner drops the removed entry.
	if err := validateS6SvscanctlForScanDir([]string{"-a", s.ScanDir}, s.ScanDir); err != nil {
		return res, err
	}
	if _, err := s.exec.Svscanctl("-a", s.ScanDir); err != nil {
		return res, fmt.Errorf("uninstall: s6-svscanctl -a %s failed: %w\n"+
			"(run by hand: s6-svscanctl -a %s)", s.ScanDir, err, s.ScanDir)
	}
	return s.finishUninstall(spec, res)
}

// finishUninstall is the shared tail: managed-core teardown + purge.
func (s *S6Scheduler) finishUninstall(spec SchedulerUninstallSpec, res UninstallResult) (UninstallResult, error) {
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

// Status probes s6-svstat and reports the raw line (verbatim) plus the
// supervision mechanism.
func (s *S6Scheduler) Status() (SchedulerStatus, error) {
	watchDir := s.watchDir()
	if _, err := os.Stat(watchDir); err != nil {
		//nolint:nilerr // the stat failure IS the answer: not registered — an honest status, not an error
		return SchedulerStatus{
			Active: false,
			Note:   "service dir absent (" + watchDir + " — run `assay install`)",
		}, nil
	}
	out, err := s.exec.Svstat(watchDir)
	if err != nil {
		//nolint:nilerr // the svstat failure is REPORTED in the honest note, not swallowed
		return SchedulerStatus{
			Active: true,
			Note: "registered (" + watchDir + "); s6-svstat: " + firstLine(out) +
				" — supervision: s6-supervise restart-on-exit; logs unrotated",
		}, nil
	}
	return SchedulerStatus{
		Active: true,
		Note:   "s6-svstat: " + firstLine(out) + " — supervision: s6-supervise restart-on-exit; logs unrotated",
	}, nil
}

// HeldRegistration reports the service dir presence inside the DETECTED
// scandir (no scanner detected = no s6 registration can be live).
func (s *S6Scheduler) HeldRegistration() (bool, string) {
	if s.ScanDir == "" {
		return false, ""
	}
	watchDir := s.watchDir()
	if st, err := os.Stat(watchDir); err != nil || !st.IsDir() {
		return false, ""
	}
	return true, watchDir
}
