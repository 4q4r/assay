// runit.go carries the runit user-supervision installer (plan §3.2, Stage
// S3). runit facts the design relies on (primary sources, verified
// 2026-11-12):
//
//   - runsvdir(8) "starts and monitors a collection of runsv(8) processes",
//     re-checks the directory every five seconds (mtime/inode/device), skips
//     names starting with dots, caps at 1000 services — enabling a service
//     is CREATING its directory inside the scanned dir; disabling is the
//     dot-prefixed rename;
//   - runsv(8) "switches to the directory service and starts ./run"; "if
//     ./run or ./finish exit immediately, runsv waits a second before ...
//     restarting ./run" (Restart=always parity with a 1s backoff); a `down`
//     file defers the first start;
//   - sv(8) `stop` sends TERM+CONT and waits up to 7 seconds; the allowlist
//     pins exactly sv {status,stop,restart,up,down} <abs assay-watch dir>.
//
// No sudo anywhere: the service dir is the USER's own runsvdir dir (detected
// from the runsvdir cmdline, never invented).

package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// WatchDirName is the service directory name inside the user service dir —
// the runit analog of WatchService.
const WatchDirName = "assay-watch"

// RunitDisabledPrefix is the dot-prefix runsvdir skips (§3.2 disable).
const RunitDisabledPrefix = ".assay-watch.disabled"

// ---------------------------------------------------------------------------
// SvExecutor — the injected sv seam with its byte-pinned allowlist
// ---------------------------------------------------------------------------

// SvExecutor is the injected `sv` seam: tests record invocations, never
// execute runit.
type SvExecutor interface {
	Sv(args ...string) (string, error)
}

// svVerbs is the EXACT verb set (§3.2): status (read-only probe + the
// activation verify), stop (uninstall), restart/up/down (ops surface). `term`
// and `once` are deliberately absent — no flow uses them.
var svVerbs = []string{"status", "stop", "restart", "up", "down"}

// validateSv refuses every invocation outside the allowlist: exactly
// `sv <verb> <abs dir>` with verb in the pinned set and dir == an absolute
// path whose base is assay-watch — this scheduler's own artifact, never
// anything else.
func validateSv(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("install: sv invocation %v is outside the allowlist "+
			"(permitted: exactly `sv {status,stop,restart,up,down} <abs service dir>/assay-watch`) — refusing", args)
	}
	verb, dir := args[0], args[1]
	if !slices.Contains(svVerbs, verb) {
		return fmt.Errorf("install: sv invocation %v is outside the allowlist "+
			"(permitted verbs: exactly %v) — refusing", args, svVerbs)
	}
	if !filepath.IsAbs(dir) || filepath.Base(dir) != WatchDirName {
		return fmt.Errorf("install: sv invocation %v is outside the allowlist "+
			"(the directory must be absolute and name assay-watch — assay's own service only) — refusing", args)
	}
	return nil
}

// RunitExecutor is the production SvExecutor: allowlist-checked
// `sv ...` invocations. A refused command is a loud error.
type RunitExecutor struct{}

// Sv validates args against the allowlist and executes sv, returning the
// combined output (the status probe's raw line is surfaced, never parsed).
func (RunitExecutor) Sv(args ...string) (string, error) {
	if err := validateSv(args); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// args are allowlist-checked above; the binary name is the constant "sv"
	// — G204's variable-args warning is the seam's entire purpose.
	cmd := exec.CommandContext(ctx, "sv", args...) //nolint:gosec // allowlist-validated, see validateSv
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("sv %v failed: %w\n%s\n(run by hand: sv %v)", args, err, out, args)
	}
	return string(out), nil
}

// ---------------------------------------------------------------------------
// RunitScheduler
// ---------------------------------------------------------------------------

// RunitScheduler installs/uninstalls/inspects the assay-watch runit service
// through the injected SvExecutor. ServiceDir is the scanned user service
// dir (from the runsvdir cmdline at detection; the CLI never invents one).
type RunitScheduler struct {
	exec       SvExecutor
	ServiceDir string

	verifyInterval time.Duration
	verifyAttempts int
}

// NewRunitScheduler wires the scheduler over exec for the given service dir.
func NewRunitScheduler(exec SvExecutor, serviceDir string) *RunitScheduler {
	return &RunitScheduler{
		exec:           exec,
		ServiceDir:     serviceDir,
		verifyInterval: schedulerVerifyInterval,
		verifyAttempts: schedulerVerifyAttempts,
	}
}

// Name implements the Scheduler seam.
func (s *RunitScheduler) Name() string { return SchedulerRunit }

// Available reports the detection inputs (a scheduler from Detect is
// available by construction; a hand-built one names what's missing).
func (s *RunitScheduler) Available() (bool, string) {
	if s.exec == nil {
		return false, "no sv executor wired"
	}
	if s.ServiceDir == "" {
		return false, "no runsvdir service dir detected (run `runsvdir ~/service` to start user supervision)"
	}
	return true, ""
}

// Install runs the §3.2 flow: copyBinary → config materialize →
// <ServiceDir>/assay-watch with `run` (0755) → bounded `sv status` verify
// (the dir's existence IS the enablement — runsvdir picks it up within its
// five-second rescan; no sv command starts it).
func (s *RunitScheduler) Install(spec SchedulerInstallSpec) (Result, error) {
	res := Result{}
	if s.exec == nil {
		return res, errRunitExecutorMissing
	}
	if s.ServiceDir == "" {
		return res, errors.New("install: runit service dir not detected — " +
			"start user supervision with `runsvdir ~/service` and re-run `assay install`")
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
	watchDir := filepath.Join(s.ServiceDir, WatchDirName)
	if err := os.MkdirAll(watchDir, 0o750); err != nil {
		return res, fmt.Errorf("install: create runit service dir %s: %w", watchDir, err)
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
	// §3.3 bounded verify: poll `sv status` until it succeeds — sv talks to
	// the supervise pipe of a LIVE runsv, so success proves runsvdir picked
	// the dir up. The raw output line is surfaced in the note (the sv status
	// line format is intentionally not parsed — no format guessing).
	probe := "sv status " + watchDir
	for range s.verifyAttempts {
		if _, verr := s.exec.Sv("status", watchDir); verr == nil {
			res.ServiceActive = true
			return res, nil
		}
		time.Sleep(s.verifyInterval)
	}
	return res, loudProbeFailure(SchedulerRunit, probe, "sv status "+watchDir, s.verifyAttempts,
		errors.New("runsvdir has not picked up the service dir"))
}

// Uninstall stops the service (`sv stop` — verified: TERM+CONT and a
// bounded wait up to 7 seconds) and removes the service dir. An absent dir
// is the clean no-op.
func (s *RunitScheduler) Uninstall(spec SchedulerUninstallSpec) (UninstallResult, error) {
	res := UninstallResult{}
	watchDir := filepath.Join(s.ServiceDir, WatchDirName)
	if _, err := os.Stat(watchDir); err != nil {
		if !os.IsNotExist(err) {
			return res, fmt.Errorf("uninstall: stat runit service dir %s: %w", watchDir, err)
		}
		return s.finishUninstall(spec, res)
	}
	// Stop only when the supervisor is reachable and running; a down or
	// unreachable service needs no stop (sv status fails → skip).
	if _, serr := s.exec.Sv("status", watchDir); serr == nil {
		if _, kerr := s.exec.Sv("stop", watchDir); kerr != nil {
			return res, fmt.Errorf("uninstall: sv stop %s failed: %w\n"+
				"(run by hand: sv stop %s)", watchDir, kerr, watchDir)
		}
		res.DisabledUnits = []string{WatchDirName}
	}
	if err := os.RemoveAll(watchDir); err != nil {
		return res, fmt.Errorf("uninstall: remove %s: %w", watchDir, err)
	}
	res.RemovedUnits = []string{WatchDirName + " (service dir)"}
	return s.finishUninstall(spec, res)
}

// finishUninstall is the shared tail: managed-core teardown + purge.
func (s *RunitScheduler) finishUninstall(spec SchedulerUninstallSpec, res UninstallResult) (UninstallResult, error) {
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

// Status probes `sv status` and reports the RAW output line verbatim (the
// sv status line format is not parsed — honesty over guessing) plus the
// supervision mechanism.
func (s *RunitScheduler) Status() (SchedulerStatus, error) {
	watchDir := filepath.Join(s.ServiceDir, WatchDirName)
	if _, err := os.Stat(watchDir); err != nil {
		//nolint:nilerr // the stat failure IS the answer: not registered — an honest status, not an error
		return SchedulerStatus{
			Active: false,
			Note:   "service dir absent (" + watchDir + " — run `assay install`)",
		}, nil
	}
	out, err := s.exec.Sv("status", watchDir)
	if err != nil {
		//nolint:nilerr // the sv failure is REPORTED in the honest note, not swallowed
		return SchedulerStatus{
			Active: true,
			Note: "registered (" + watchDir + "); sv status: " + firstLine(out) +
				" — supervision: runsv restart-on-exit (1s backoff); logs unrotated",
		}, nil
	}
	return SchedulerStatus{
		Active: true,
		Note:   "sv status: " + firstLine(out) + " — supervision: runsv restart-on-exit (1s backoff); logs unrotated",
	}, nil
}

// HeldRegistration reports the service dir presence — a dot-disabled dir is
// skipped by runsvdir and is NOT a live registration.
func (s *RunitScheduler) HeldRegistration() (bool, string) {
	if s.ServiceDir == "" {
		return false, ""
	}
	watchDir := filepath.Join(s.ServiceDir, WatchDirName)
	if st, err := os.Stat(watchDir); err != nil || !st.IsDir() {
		return false, ""
	}
	return true, watchDir
}

// firstLine returns the first non-empty line of out ("" when none).
func firstLine(out string) string {
	for line := range strings.SplitSeq(out, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// errRunitExecutorMissing is the loud programmer-error shape.
var errRunitExecutorMissing = errors.New("install: no sv executor wired (runit)")
