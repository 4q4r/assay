// launchd.go carries the darwin LaunchAgent installer (plan §1, Stage S1):
// the LaunchctlExecutor with its byte-pinned allowlist (§1.2.5), the plist
// renderer (§1.2.2/§1.2.3, Apple's 600/400 file-mode requirement), and the
// LaunchdScheduler — the macOS answer to the Scheduler seam (§4.1). The
// lifecycle surface is exactly the modern launchctl contract: bootstrap /
// bootout / print / kickstart on the gui/<uid> domain — no load/unload
// (legacy), no sudo, no system/ domain, ever.
//
// macOS facts the design relies on (plan §1.1 citations): per-user agents
// live in ~/Library/LaunchAgents, must be owned by the user, and must carry
// file mode 600 or 400 (Apple, Daemons and Services Programming Guide).
// launchd agents get a minimal environment (no XDG), so every path here is
// absolute and nothing may depend on shell env (§1.2.2).

package install

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// LaunchdLabel is the agent label (§1.2.1): the same base name as the
// systemd unit (WatchService = "assay-watch.service") — cross-platform
// symmetry beats reverse-DNS guesswork. launchd labels are arbitrary unique
// strings.
const (
	LaunchdLabel     = "assay-watch"
	LaunchdPlistName = LaunchdLabel + ".plist"
)

// SchedulerInstallSpec is the §4.1 scheduler-neutral name of the
// per-scheduler install input — a type ALIAS of LaunchdInstallSpec (its
// fields are platform-generic: running binary, bin dir, config paths, data
// dir). The windows scheduler (winsvc.go) and the CLI consumer seam use the
// neutral names; the launchd implementation and its tests keep theirs.
type SchedulerInstallSpec = LaunchdInstallSpec

// SchedulerUninstallSpec is the §4.1 scheduler-neutral name of the
// uninstall input — a type ALIAS of LaunchdUninstallSpec. One type, two
// spellings, zero conversion.
type SchedulerUninstallSpec = LaunchdUninstallSpec

// launchdTemplates carries the embedded agent plist template (single source
// of truth, go:embed — the sibling of the unit-template pattern).
//
//go:embed templates/assay-watch.plist.tmpl
var launchdTemplates embed.FS

// verify pacing of the activation flow (§1.2.6: bounded print-verify loop
// 10×500ms; the bootout wait uses the same bounded probe shape). Tests
// shrink these; production never changes them.
const (
	defaultVerifyInterval  = 500 * time.Millisecond
	defaultVerifyAttempts  = 10
	defaultBootoutInterval = 250 * time.Millisecond
	defaultBootoutAttempts = 10
)

// Launchctl is the injected launchctl seam: tests never execute launchctl,
// they record invocations (the Executor pattern of install.go, adapted for
// the verbs whose OUTPUT the flow reads — print drives the probes).
type Launchctl interface {
	Launchctl(args ...string) (string, error)
}

// The four sanctioned launchctl constructors (§1.2.5). The guard tests pin
// their output byte-for-byte and pin validateLaunchctl to exactly these
// shapes — the launchd analog of install.go's allowedCommands.

// cmdLaunchdBootstrap registers the agent: `bootstrap gui/<uid> <abs plist>`.
func cmdLaunchdBootstrap(uid int, plist string) []string {
	return []string{"bootstrap", "gui/" + strconv.Itoa(uid), plist}
}

// cmdLaunchdBootout removes the registration: `bootout gui/<uid>/assay-watch`.
func cmdLaunchdBootout(uid int) []string {
	return []string{"bootout", launchdTarget(uid)}
}

// cmdLaunchdPrint is the read-only status probe: `print gui/<uid>/assay-watch`.
func cmdLaunchdPrint(uid int) []string {
	return []string{"print", launchdTarget(uid)}
}

// cmdLaunchdKickstart restarts the agent: `kickstart -k gui/<uid>/assay-watch`.
func cmdLaunchdKickstart(uid int) []string {
	return []string{"kickstart", "-k", launchdTarget(uid)}
}

func launchdTarget(uid int) string {
	return "gui/" + strconv.Itoa(uid) + "/" + LaunchdLabel
}

// validateLaunchctl refuses every invocation outside the §1.2.5 allowlist:
// exactly the four shapes above, on exactly assay's own artifact. No
// load/unload (legacy), no sudo, no system/ domain, no foreign labels — a
// refusal is a loud error naming the allowlist.
func validateLaunchctl(args []string) error {
	if launchctlShapeAllowed(args) {
		return nil
	}
	return fmt.Errorf("install: launchctl invocation %v is outside the allowlist "+
		"(permitted: exactly `bootstrap gui/<uid> <abs assay-watch.plist>`, "+
		"`bootout gui/<uid>/assay-watch`, `print gui/<uid>/assay-watch`, "+
		"`kickstart -k gui/<uid>/assay-watch`) — refusing", args)
}

// launchctlShapeAllowed matches the four pinned shapes (§1.2.5); every
// variable position is checked, nothing is prefix- or substring-matched.
func launchctlShapeAllowed(args []string) bool {
	switch {
	case isBootstrapShape(args), isBootoutShape(args),
		isPrintShape(args), isKickstartShape(args):
		return true
	default:
		return false
	}
}

func isBootstrapShape(args []string) bool {
	if len(args) != 3 || args[0] != "bootstrap" || !isGUIToken(args[1]) {
		return false
	}
	return filepath.IsAbs(args[2]) && filepath.Base(args[2]) == LaunchdPlistName
}

func isBootoutShape(args []string) bool {
	return len(args) == 2 && args[0] == "bootout" && isAssayTarget(args[1])
}

func isPrintShape(args []string) bool {
	return len(args) == 2 && args[0] == "print" && isAssayTarget(args[1])
}

func isKickstartShape(args []string) bool {
	return len(args) == 3 && args[0] == "kickstart" && args[1] == "-k" && isAssayTarget(args[2])
}

// isGUIToken reports whether s is the `gui/<uid>` scope token (bare digit
// run after the gui/ prefix).
func isGUIToken(s string) bool {
	uid, ok := strings.CutPrefix(s, "gui/")
	return ok && isUIDToken(uid)
}

// isAssayTarget reports whether s is `gui/<uid>/assay-watch` — this
// scheduler's own target and nothing else.
func isAssayTarget(s string) bool {
	rest, ok := strings.CutPrefix(s, "gui/")
	if !ok {
		return false
	}
	uid, label, ok := strings.Cut(rest, "/")
	return ok && isUIDToken(uid) && label == LaunchdLabel
}

// isUIDToken reports whether s is a bare digit run (a uid).
func isUIDToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// LaunchctlExecutor is the production Launchctl: allowlist-checked
// `launchctl ...` invocations, output returned for the print-driven probes.
// A refused command is a loud error — the executor never falls back, never
// widens its scope.
type LaunchctlExecutor struct{}

// Launchctl validates args against the allowlist and executes launchctl,
// returning the combined output (print output drives the probes).
func (LaunchctlExecutor) Launchctl(args ...string) (string, error) {
	if err := validateLaunchctl(args); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// args are allowlist-checked above (exact pinned command set); the binary
	// name is the constant "launchctl" — G204's variable-args warning is the
	// seam's entire purpose.
	cmd := exec.CommandContext(ctx, "launchctl", args...) //nolint:gosec // allowlist-validated, see validateLaunchctl
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("launchctl %v failed: %w\n%s\n"+
			"(run by hand: launchctl %v)", args, err, out, args)
	}
	return string(out), nil
}

// ---------------------------------------------------------------------------
// Plist rendering (§1.2.2/§1.2.3)
// ---------------------------------------------------------------------------

// renderPlist renders the embedded agent plist template at outPath, mode
// 0600 (Apple's LaunchAgent 600/400 requirement, §1.1/§1.2.3), atomically.
// XML-hostile characters in any rendered path are refused BEFORE the write:
// the plist is XML and launchd/plutil would reject a raw `&` long after
// install printed success — the I-1 class, refused loudly up front instead.
func renderPlist(data TemplateData, outPath string) error {
	for field, p := range map[string]string{
		"BinaryPath": data.BinaryPath,
		"ConfigPath": data.ConfigPath,
		"LogOutPath": data.LogOutPath,
		"LogErrPath": data.LogErrPath,
	} {
		if strings.ContainsAny(p, "&<>\"") {
			return fmt.Errorf("install: %s %q contains an XML-hostile character (& < > \") — "+
				"the agent plist is XML and launchd would refuse it at load time; "+
				"choose a path without these characters", field, p)
		}
	}
	tmpl, err := template.ParseFS(launchdTemplates, "templates/assay-watch.plist.tmpl")
	if err != nil {
		return fmt.Errorf("install: parse embedded plist template: %w", err)
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("install: render plist: %w", err)
	}
	return writeFileAtomic(outPath, []byte(buf.String()), 0o600)
}

// ---------------------------------------------------------------------------
// LaunchdScheduler — the §4.1 Scheduler implementation for macOS
// ---------------------------------------------------------------------------

// LaunchdInstallSpec is the launchd install input (§4.1): everything the flow
// needs, all paths absolute (the CLI layer expands ~).
type LaunchdInstallSpec struct {
	// RunningBinary is the running image to copy (os.Executable of the
	// caller); BinDir the atomic-copy target (~/.local/bin).
	RunningBinary string
	BinDir        string
	// ConfigPath is the explicit -c (absolute) embedded into
	// ProgramArguments. EMPTY = default-location install: DefaultConfigPath
	// drives materialization and the agent runs plain `watch` — the same
	// TemplateData semantics as the systemd unit (§1.2.2).
	ConfigPath        string
	DefaultConfigPath string
	// DataDir is rendered into the materialized config and parents the log
	// files the plist points at (<data>/logs/watch.{out,err}.log).
	DataDir string
	// AgentDir is the LaunchAgents directory (~/Library/LaunchAgents).
	AgentDir string
}

// LaunchdUninstallSpec is the launchd uninstall input (§1.2.7).
type LaunchdUninstallSpec struct {
	AgentDir string
	// DataDir drives the managed-core teardown (unchanged from systemd).
	DataDir string
	// Purge paths passthrough (destructive --purge semantics unchanged).
	PurgeConfigPath string
	PurgeDataDir    string
}

// SchedulerStatus is the launchd status answer (§1.2.8 + ADDENDUM §1): the
// print-derived state and pid plus the HONEST supervision note.
type SchedulerStatus struct {
	Active bool
	PID    int
	Note   string
}

// LaunchdScheduler installs/uninstalls/inspects the assay-watch LaunchAgent
// through the injected Launchctl seam.
type LaunchdScheduler struct {
	exec Launchctl

	verifyInterval  time.Duration
	verifyAttempts  int
	bootoutInterval time.Duration
	bootoutAttempts int
}

// NewLaunchdScheduler wires the production scheduler over exec.
func NewLaunchdScheduler(exec Launchctl) *LaunchdScheduler {
	return &LaunchdScheduler{
		exec:            exec,
		verifyInterval:  defaultVerifyInterval,
		verifyAttempts:  defaultVerifyAttempts,
		bootoutInterval: defaultBootoutInterval,
		bootoutAttempts: defaultBootoutAttempts,
	}
}

// Name implements the Scheduler seam (§4.1).
func (s *LaunchdScheduler) Name() string { return "launchd" }

// Available implements the Scheduler seam: macOS is always launchd (single-
// init platform, §1.1) — the only real checks are the GOOS and launchctl on
// PATH.
func (s *LaunchdScheduler) Available() (bool, string) {
	if runtime.GOOS != "darwin" {
		return false, "launchd agents are macOS-only; this host is " + runtime.GOOS
	}
	if _, err := exec.LookPath("launchctl"); err != nil {
		return false, "launchctl not found on PATH — a macOS system always ships it; " +
			"the environment looks broken"
	}
	return true, ""
}

// Install runs the §1.2.6 flow: copyBinary → config materialize →
// MkdirAll AgentDir → render plist 0600 → print-probe → bootout-if-loaded →
// bootstrap → bounded print-verify loop confirming a PID. Failure anywhere
// is a loud error carrying the exact launchctl line to run by hand (owner
// UX rule).
func (s *LaunchdScheduler) Install(spec LaunchdInstallSpec) (Result, error) {
	res := Result{}
	if spec.RunningBinary == "" || spec.BinDir == "" || spec.AgentDir == "" {
		return res, errors.New("install: RunningBinary, BinDir and AgentDir are required")
	}
	// 1. copyBinary — the SAME atomic primitive the systemd install uses.
	binPath, err := copyBinary(spec.RunningBinary, spec.BinDir)
	if err != nil {
		return res, err
	}
	res.BinaryPath = binPath
	// 2. materialize the default config (explicit -c installs skip).
	if err := s.materializeForLaunchd(spec, &res); err != nil {
		return res, err
	}
	// 3+4. agent dir + log dir, then render the plist (atomic, 0600).
	plist, err := renderAgentPlist(binPath, spec)
	if err != nil {
		return res, err
	}
	res.UnitPaths = []string{plist}

	// 5-7. idempotent activation: print-probe → bootout-if-loaded →
	// bootstrap → bounded print-verify (§1.2.6).
	if err := s.activate(plist); err != nil {
		return res, err
	}
	res.ServiceActive = true
	return res, nil
}

// materializeForLaunchd is the default-location materialization (explicit
// -c installs skip — the config stays where it is; never overwritten,
// kept = reported).
func (s *LaunchdScheduler) materializeForLaunchd(spec LaunchdInstallSpec, res *Result) error {
	if spec.ConfigPath != "" || spec.DefaultConfigPath == "" {
		return nil
	}
	created, err := MaterializeDefaultConfig(spec.DefaultConfigPath, spec.DataDir)
	if err != nil {
		return err
	}
	if created {
		res.ConfigWritten = spec.DefaultConfigPath
	} else {
		res.ConfigKept = spec.DefaultConfigPath
	}
	return nil
}

// renderAgentPlist creates the agent and log dirs (launchd opens the log
// files itself, but their PARENT dir must exist) and renders the plist
// (atomic, 0600, §1.2.3).
func renderAgentPlist(binPath string, spec LaunchdInstallSpec) (string, error) {
	if err := os.MkdirAll(spec.AgentDir, 0o750); err != nil {
		return "", fmt.Errorf("install: create agent dir %s: %w", spec.AgentDir, err)
	}
	logDir := filepath.Join(spec.DataDir, "logs")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return "", fmt.Errorf("install: create log dir %s: %w", logDir, err)
	}
	plist := filepath.Join(spec.AgentDir, LaunchdPlistName)
	data := TemplateData{
		BinaryPath: binPath,
		ConfigPath: spec.ConfigPath,
		LogOutPath: filepath.Join(logDir, "watch.out.log"),
		LogErrPath: filepath.Join(logDir, "watch.err.log"),
	}
	return plist, renderPlist(data, plist)
}

// activate is the idempotent activation sequence (§1.2.6): probe with
// print; bootout ONLY what the probe proved loaded; a bootout failure is
// LOUD (the probe just proved the job exists — ignoring that failure would
// leave the old registration racing the new one); bootstrap; bounded
// print-verify loop confirming a PID.
func (s *LaunchdScheduler) activate(plist string) error {
	uid := os.Getuid()
	loaded, _, err := s.printProbe(uid)
	if err != nil {
		// print failing = the job is not loaded — the expected fresh-host
		// state, not an error.
		loaded = false
	}
	if loaded {
		if _, berr := s.exec.Launchctl(cmdLaunchdBootout(uid)...); berr != nil {
			return fmt.Errorf("install: the previous agent registration is loaded and "+
				"bootout failed: %w\n(run by hand: launchctl bootout gui/%d/%s)",
				berr, uid, LaunchdLabel)
		}
		if err := s.waitBootout(uid); err != nil {
			return err
		}
	}
	if _, err := s.exec.Launchctl(cmdLaunchdBootstrap(uid, plist)...); err != nil {
		return fmt.Errorf("install: bootstrap failed: %w\n"+
			"(run by hand: launchctl bootstrap gui/%d %s)", err, uid, plist)
	}
	// bounded print-verify loop confirming a PID (§1.2.6: 10×500ms).
	_, verr := s.waitRunning(uid)
	return verr
}

// printProbe runs one print and reports whether the job is loaded, plus the
// parsed pid when the output carries one.
func (s *LaunchdScheduler) printProbe(uid int) (bool, int, error) {
	out, err := s.exec.Launchctl(cmdLaunchdPrint(uid)...)
	if err != nil {
		return false, 0, err
	}
	return true, parseLaunchdPID(out), nil
}

// waitBootout polls print until the job stops responding (bounded) after a
// successful bootout — the §1.2.6 "bootout → wait for exit" step.
func (s *LaunchdScheduler) waitBootout(uid int) error {
	for range s.bootoutAttempts {
		if _, err := s.exec.Launchctl(cmdLaunchdPrint(uid)...); err != nil {
			return nil //nolint:nilerr // print failing = the job is gone — bootout complete, exactly the §1.2.6 design
		}
		time.Sleep(s.bootoutInterval)
	}
	return fmt.Errorf("install: the old agent registration survived bootout "+
		"(%d probes) — refusing to bootstrap over a live registration\n"+
		"(inspect by hand: launchctl print gui/%d/%s)", s.bootoutAttempts, uid, LaunchdLabel)
}

// waitRunning polls print until the job reports a real PID (bounded,
// §1.2.6). A timeout is a LOUD failure: install never claims ServiceActive
// without a confirmed PID.
func (s *LaunchdScheduler) waitRunning(uid int) (int, error) {
	for range s.verifyAttempts {
		out, err := s.exec.Launchctl(cmdLaunchdPrint(uid)...)
		if err == nil {
			if pid := parseLaunchdPID(out); pid > 0 {
				return pid, nil
			}
		}
		time.Sleep(s.verifyInterval)
	}
	return 0, fmt.Errorf("install: the agent did not report a running PID within "+
		"%d×%s — bootstrap may have failed silently\n"+
		"(inspect by hand: launchctl print gui/%d/%s; logs: <data>/logs/watch.err.log)",
		s.verifyAttempts, s.verifyInterval, uid, LaunchdLabel)
}

// parseLaunchdPID extracts the pid from launchctl print output (`pid = N`
// line; launchd.info's documented print shape — exact formatting
// re-verified against `man launchctl` on the macOS CI runner). 0 = no pid
// line or unparsable value (the caller treats that as not-yet-running).
func parseLaunchdPID(out string) int {
	for line := range strings.SplitSeq(out, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) != "pid" {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(val), ";")))
		if err != nil {
			return 0
		}
		return pid
	}
	return 0
}

// Uninstall runs the §1.2.7 teardown: bootout (only when the probe proves
// the job loaded — an absent registration is reported, never faked), remove
// the plist file, managed-core teardown unchanged, purge passthrough. No
// legacy cleanup exists on darwin (no prior darwin installs).
func (s *LaunchdScheduler) Uninstall(spec LaunchdUninstallSpec) (UninstallResult, error) {
	res := UninstallResult{}
	uid := os.Getuid()
	if _, err := s.exec.Launchctl(cmdLaunchdPrint(uid)...); err == nil {
		if _, berr := s.exec.Launchctl(cmdLaunchdBootout(uid)...); berr != nil {
			return res, fmt.Errorf("uninstall: bootout failed: %w\n"+
				"(run by hand: launchctl bootout gui/%d/%s)", berr, uid, LaunchdLabel)
		}
		res.DisabledUnits = []string{LaunchdLabel}
	}
	plist := filepath.Join(spec.AgentDir, LaunchdPlistName)
	if rmErr := os.Remove(plist); rmErr != nil && !os.IsNotExist(rmErr) {
		return res, fmt.Errorf("uninstall: remove %s: %w", plist, rmErr)
	}
	res.RemovedUnits = []string{LaunchdPlistName}
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

// Status implements the Scheduler seam (§1.2.8 + ADDENDUM §1): the minimal
// print parse (state + pid) plus the honest supervision note — on darwin
// the hang contract is the SELF-watchdog (a wedged daemon exits cleanly and
// KeepAlive restarts it), not sd_notify.
func (s *LaunchdScheduler) Status() (SchedulerStatus, error) {
	uid := os.Getuid()
	out, err := s.exec.Launchctl(cmdLaunchdPrint(uid)...)
	if err != nil {
		// Not registered — a normal status on an uninstalled host.
		//nolint:nilerr // print failing = not registered: an honest status, not an error (§1.2.8)
		return SchedulerStatus{
			Active: false,
			PID:    0,
			Note:   "agent not registered (" + LaunchdLabel + " — run `assay install`)",
		}, nil
	}
	pid := parseLaunchdPID(out)
	if pid == 0 {
		// §5.22 honesty: registered-but-not-running (the KeepAlive
		// throttle/restart window) is a distinct state — name it, never
		// dress it up as the running-agent note.
		return SchedulerStatus{
			Active: true,
			PID:    0,
			Note: "registered; no running pid right now (KeepAlive/ThrottleInterval governs; " +
				"mechanism: self-watchdog → KeepAlive restart)",
		}, nil
	}
	return SchedulerStatus{
		Active: true,
		PID:    pid,
		Note:   "KeepAlive restart on exit; hang detection: self-watchdog → KeepAlive restart",
	}, nil
}

// HeldRegistration implements the Scheduler seam (§4.1): whether THIS
// scheduler currently holds an assay-watch (the double-install refusal
// seam).
func (s *LaunchdScheduler) HeldRegistration() (bool, string) {
	uid := os.Getuid()
	if _, err := s.exec.Launchctl(cmdLaunchdPrint(uid)...); err != nil {
		return false, ""
	}
	return true, launchdTarget(uid)
}
