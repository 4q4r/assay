// The windows-service CLI branch (plan §2.2.4/§2.2.5/§2.2.7-§2.2.10): the
// install/uninstall/status flows route to the windows-service scheduler
// through the consumer-side `scheduler` seam — mirroring the launchd branch
// shape (S1). GOOS-neutral: the production factory is GOOS-split
// (install_winsvc_windows.go / install_winsvc_other.go); every SCM call
// lives behind the scheduler, whose pinned surface is the windows-tagged
// suite. All paths absolute; the config is ALWAYS explicit (§2.2.5).

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"assay/internal/config"
	"assay/internal/install"
	"assay/internal/platform"
	"assay/internal/ui"
)

// windowsHost is the GOOS probe seam (the darwinHost sibling): tests pin
// the windows branch without a Windows machine; production reads
// runtime.GOOS exactly.
var windowsHost = func() bool { return runtime.GOOS == "windows" }

// winsvcSchedulerFactory is the windows scheduler seam: production wires
// the mgr-backed WinSvcScheduler (GOOS-split factories); tests inject a
// recorder so the cobra-level flow never touches the SCM.
var winsvcSchedulerFactory = newWinsvcScheduler

// refusingWinSvcScheduler is the loud dead-path scheduler the non-windows
// factory hands out: never routed to (windowsHost gates the branch), and
// refusing Available() with a windows-naming reason if it ever were — a
// nil scheduler would be a silent landmine.
type refusingWinSvcScheduler struct{}

// newRefusingWinSvcScheduler is the dead-path constructor (the non-windows
// GOOS-split factory and the dead-path pin test use it).
func newRefusingWinSvcScheduler() *refusingWinSvcScheduler { return &refusingWinSvcScheduler{} }

func (*refusingWinSvcScheduler) Name() string { return "windows-service" }

func (*refusingWinSvcScheduler) Available() (bool, string) {
	return false, "the windows service scheduler is windows-only; this host is " + runtime.GOOS
}

func (s *refusingWinSvcScheduler) Install(install.SchedulerInstallSpec) (install.Result, error) {
	return install.Result{}, errors.New("install: the windows service scheduler is windows-only; " +
		"this host is " + runtime.GOOS)
}

func (s *refusingWinSvcScheduler) Uninstall(install.SchedulerUninstallSpec) (install.UninstallResult, error) {
	return install.UninstallResult{}, errors.New("uninstall: the windows service scheduler is windows-only; " +
		"this host is " + runtime.GOOS)
}

func (s *refusingWinSvcScheduler) Status() (install.SchedulerStatus, error) {
	return install.SchedulerStatus{}, errors.New("install: the windows service scheduler is windows-only; " +
		"this host is " + runtime.GOOS)
}

func (s *refusingWinSvcScheduler) HeldRegistration() (bool, string) { return false, "" }

// installBinDirDefault returns the §4.2 "Installed binary" dir for goos:
// ~/.local/bin on unix (unchanged), %LOCALAPPDATA%\assay\bin on windows
// (§2.2.10 — never PATH-modified; the summary carries the exact PowerShell
// line instead). goos is a parameter so the suite pins the windows value
// from linux.
func installBinDirDefault(goos string) string {
	if goos != "windows" {
		return "~/.local/bin"
	}
	// Plain filepath.Join: on a windows host it produces '\\' natively —
	// this default only ever RUNS on windows (the linux test suite pins the
	// values with whatever separator the test host's Join produces).
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "assay", "bin")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "AppData", "Local", "assay", "bin")
	}
	return "~/.local/bin"
}

// runInstallWinSvc is the windows install flow (§2.2.4 + §2.2.9): resolve
// the ALWAYS-explicit config path (§2.2.5 — the service runs as LocalSystem),
// hand the spec to the scheduler (stop→copy→register→recovery→start pinned
// in internal/install), run the D4 core bootstrap, print the loud summary.
func runInstallWinSvc(
	w io.Writer, cfg *config.Config, running, binDir, dataDir, cfgPath string, opts installOptions,
) error {
	spec := install.SchedulerInstallSpec{
		RunningBinary: running,
		BinDir:        binDir,
		DataDir:       dataDir,
	}
	switch {
	case cfgPath != "":
		// Explicit -c, or a config found in the install-style chain (the
		// daemon reads it at its default location) — embed its absolute
		// path verbatim.
		abs, err := explicitConfigAbs(cfgPath)
		if err != nil {
			return err
		}
		spec.ConfigPath = abs
	case opts.materializePath != "":
		// Configless install: materialize the default config and embed it.
		spec.DefaultConfigPath = opts.materializePath
	default:
		return errors.New("install: the windows service runs as LocalSystem and MUST carry an explicit " +
			"-c <abs config> — re-run `assay install` (it embeds your absolute config path) or " +
			"`assay install -c <path>`")
	}
	sched := winsvcSchedulerFactory()
	if avail, reason := sched.Available(); !avail {
		return fmt.Errorf("install: the windows-service scheduler is unavailable: %s", reason)
	}
	res, err := sched.Install(spec)
	if err != nil {
		return err
	}
	// D4 core bootstrap: identical contract to the systemd/launchd branches
	// (loud non-fatal warning; the waves retry through auto-update).
	if cfg != nil {
		if berr := ensureCoreBinary(context.Background(), cfg.Core, config.ExpandHome(cfg.DataDir), w); berr != nil {
			outf(w, "%s\n", ui.Warn("WARNING: core bootstrap: "+berr.Error()+
				" (install completes; the daemon's waves retry through auto-update)", ui.Amber, opts.color))
		}
	}
	printWinSvcInstallSummary(w, res, dataDir, opts)
	return nil
}

// printWinSvcInstallSummary is the loud post-install report: binary, config,
// the SCM identity, the recovery + child-stop mechanisms (named, never
// hidden — ADDENDUM §1/§2), the unrotated-log caveat, and the PATH guidance
// (§2.2.10 — never auto-modified).
func printWinSvcInstallSummary(w io.Writer, res install.Result, dataDir string, opts installOptions) {
	outf(w, "%s\n", ui.ChipKV("installed binary: ", res.BinaryPath+" (copy of the running image, mode 0755)", opts.color))
	if res.ConfigWritten != "" {
		outf(w, "%s\n", ui.ChipKV("config created:   ", res.ConfigWritten+
			" (materialized defaults — edit to configure; a re-install never overwrites it)", opts.color))
	}
	if res.ConfigKept != "" {
		outf(w, "%s\n", ui.ChipKV("config kept:      ",
			res.ConfigKept+" (already present — never overwritten)", opts.color))
	}
	for _, p := range res.UnitPaths {
		outf(w, "%s\n", ui.ChipKV("service:          ",
			p+" — StartAutomatic, LocalSystem, `watch -c <abs config>` embedded", opts.color))
	}
	note := res.ServiceNote
	if note != "" {
		outf(w, "%s\n", ui.Warn("note:             "+note, ui.Amber, opts.color))
	}
	outf(w, "%s\n", ui.ChipKV("daemon active:    ",
		"assay watch (SCM recovery: ServiceRestart after 5s; hang detection: "+
			"self-watchdog → clean self-exit → SCM recovery-actions restart)", opts.color))
	outf(w, "%s\n", ui.ChipKV("child supervision:",
		"xray stop = CTRL_BREAK (own process group) → bounded wait → TerminateProcess last resort; "+
			"Job Object (KILL_ON_JOB_CLOSE) means daemon death never orphans the child", opts.color))
	outf(w, "%s\n", ui.ChipKV("logs:             ",
		filepath.Join(dataDir, "logs", "watch.log")+" (file sink — service stdout goes nowhere; unrotated)", opts.color))
	outf(w, "%s\n", ui.ChipKV("PATH (optional):  ",
		`[Environment]::SetEnvironmentVariable("Path", $env:Path + ";%LOCALAPPDATA%\assay\bin", "User") — `+
			"never modified automatically; the service uses absolute paths only", opts.color))
}

// runUninstallWinSvc is the windows teardown (§2.2.7): stop → poll →
// delete (the scheduler owns the bounded SCM dance), managed-core teardown
// on the resolved data dir, purge passthrough.
func runUninstallWinSvc(w io.Writer, cfg *config.Config, cfgPath string, opts uninstallOptions) error {
	sched := winsvcSchedulerFactory()
	spec := install.SchedulerUninstallSpec{}
	if cfg != nil {
		spec.DataDir = config.ExpandHome(cfg.DataDir)
	}
	if opts.purge {
		if cfg == nil {
			return errors.New("--purge needs the config (-c) to resolve the data dir")
		}
		spec.PurgeConfigPath = cfgPath
		spec.PurgeDataDir = config.ExpandHome(cfg.DataDir)
	}
	res, err := sched.Uninstall(spec)
	if err != nil {
		return err
	}
	printWinSvcUninstall(w, res, opts.purge)
	return nil
}

// printWinSvcUninstall renders the windows uninstall report: the SCM
// outcome, the managed-core teardown, purge passthrough.
func printWinSvcUninstall(w io.Writer, res install.UninstallResult, purge bool) {
	if len(res.DisabledUnits) > 0 {
		outf(w, "stopped:          %s (SCM Control(Stop) → Stopped)\n", strings.Join(res.DisabledUnits, ", "))
	} else {
		outf(w, "service:          not installed (nothing to stop or delete)\n")
	}
	for _, name := range res.RemovedUnits {
		outf(w, "service deleted:  %s (SCM Delete)\n", name)
	}
	for _, name := range res.CoreRemoved {
		outf(w, "core removed:     %s\n", name)
	}
	for _, p := range res.Purged {
		outf(w, "purged:           %s\n", p)
	}
	if !purge {
		outln(w, "user data kept (config, data dir, installed binary) — pass --purge to remove config + data")
	}
}

// printWinSvcStatus is the windows install-status section (§2.2.8 + the
// §5.22 honesty rule): the scheduler's state+pid with the supervision
// mechanisms named, the log path, and the binary staleness contract.
func printWinSvcStatus(out io.Writer, binDir string, color bool) {
	printInstalledBinary(out, binDir, color)
	st, err := winsvcSchedulerFactory().Status()
	if err != nil {
		outf(out, "%s\n", ui.Warn("  service:   "+err.Error(), ui.Amber, color))
		return
	}
	if st.Active {
		outf(out, "%s\n", ui.ChipKV("  service:   ",
			fmt.Sprintf("assay registered in the SCM (pid %d)", st.PID), color))
		// The supervision mechanisms carry real content only for a
		// registered agent — on the inactive branch the note already said
		// everything on the "service:" line (P3-4: never print it twice).
		outf(out, "%s\n", ui.ChipKV("  supervision:", st.Note, color))
	} else {
		outf(out, "%s\n", ui.ChipKV("  service:   ", st.Note, color))
	}
	outf(out, "%s\n", ui.ChipKV("  logs:      ",
		"%LOCALAPPDATA%\\assay\\logs\\watch.log (file sink — unrotated)", color))
	// The core-binary row mirrors the §4.2 table (managed core <data>\bin\xray.exe).
	outf(out, "%s\n", ui.ChipKV("  core:      ",
		"managed core <data>\\bin\\"+platform.CoreBinaryName("windows")+
			" (system-bind scan list is empty on windows — override or managed only)", color))
}
