package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"assay/internal/config"
	"assay/internal/core"
	"assay/internal/install"
	"assay/internal/platform"
	"assay/internal/ui"

	"github.com/spf13/cobra"
)

// W5 self-install surface. The systemctl scope is pinned inside
// internal/install (allowlist: --user, the two assay-* timers only,
// daemon-reload + enable/disable --now — never restart, never other units).

// resolveExecutable returns the running binary's absolute path.
func resolveExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve running binary: %w", err)
	}
	return filepath.EvalSymlinks(exe)
}

// installExecutor is the systemctl seam at the command level: production
// wires the allowlisted SystemctlExecutor; tests inject a recorder so the
// cobra-level install flow never executes systemd (same pattern as
// signalChannel in watch_cmd.go).
var installExecutor = func() install.Executor { return install.SystemctlExecutor{} }

// scheduler is the CLI's consumer-side lifecycle seam over the per-OS
// schedulers (plan §4.1; the interface is defined at the CONSUMER per the
// go-design ruling — the CLI drives lifecycle control, the install package
// owns the per-OS implementations with their pinned executors).
type scheduler interface {
	Name() string
	Available() (bool, string)
	Install(spec install.LaunchdInstallSpec) (install.Result, error)
	Uninstall(spec install.LaunchdUninstallSpec) (install.UninstallResult, error)
	Status() (install.SchedulerStatus, error)
	HeldRegistration() (bool, string)
}

// darwinHost is the GOOS probe seam: tests pin the darwin branch without a
// Mac (production reads runtime.GOOS exactly).
var darwinHost = func() bool { return runtime.GOOS == "darwin" }

// linuxHost is the GOOS probe seam for the linux scheduler branch (the S3
// sibling of darwinHost/windowsHost): tests pin the branch without /proc
// fixtures; production reads runtime.GOOS exactly.
var linuxHost = func() bool { return runtime.GOOS == "linux" }

// linuxSchedulerProbe is the CLI's linux detection seam (plan §3.3 step 2):
// production = install.Detect over the real /proc plus the production
// executors, followed by the §3.1 cross-scheduler held scan. Returns the
// detected scheduler and — when a DIFFERENT scheduler already holds an
// assay-watch registration — the holder's name and artifact location ("" =
// nothing held). Tests inject fakes so the cobra layer never touches /proc
// or any scheduler binary.
var linuxSchedulerProbe = func(unitDir string) (install.Scheduler, string, string) {
	exec := install.ProductionExecutors(unitDir)
	proc := install.NewOSProcFS()
	sched := install.Detect(proc, exec)
	holder, loc, ok := install.HeldByAny(proc, exec)
	if !ok {
		return sched, "", ""
	}
	return sched, holder, loc
}

// launchdSchedulerFactory is the darwin scheduler seam: production wires
// the allowlist-checked LaunchctlExecutor inside the LaunchdScheduler;
// tests inject a recorder so the cobra-level flow never executes launchctl.
var launchdSchedulerFactory = func() scheduler {
	return install.NewLaunchdScheduler(install.LaunchctlExecutor{})
}

// ensureCoreBinary is the D4 install-bootstrap seam: production wires
// core.EnsureCoreBinary (download the managed core, sha-verified, atomic —
// inert for an overridden [core].xray_bin per S5); tests stub it so the
// wiring pins never touch the network.
var ensureCoreBinary = core.EnsureCoreBinary

func newInstallCommand(cfgPath *string) *cobra.Command {
	var (
		binDir      string
		unitDir     string
		noSystemd   bool
		noScheduler bool
	)
	cmd := &cobra.Command{
		Use: "install",
		Short: "Self-install: copy the running binary, materialize the default config (no -c)," +
			" render + enable the watch daemon unit",
		Long: `The canonical user deploy (W13-deploy): ONE command puts everything in
the XDG local-share layout.

WITHOUT -c (the canonical flow):
  1. copies the RUNNING binary (os.Executable) to --bin-dir as
     ` + "`assay`" + ` (atomic write, mode 0755; re-running after a rebuild =
     self-upgrade);
  2. materializes the default config at
     ~/.local/share/assay/config.toml — the same values a configless
     run uses, written as TOML with full comments. An EXISTING file is
     never overwritten (reported as "kept");
  3. renders the watch-daemon unit with a plain ` + "`watch`" + ` ExecStart — NO -c:
     the daemon reads the default config location;
  4. enables it:
       systemctl --user daemon-reload
       systemctl --user enable --now assay-watch.service
  5. resolves the xray core per the owner-ruling order: an existing
     ~/.local/bin/xray binds (assay-owned, auto-updated), an existing
     system xray binds as found (auto-update inert, S5), otherwise the
     release downloads sha256-verified and installs ATOMICALLY to
     ~/.local/bin/xray — user-writable, no elevation anywhere (D4 + the
     2026-11-11 ruling); the previous binary stays at
     ~/.local/bin/xray.previous for instant rollback;
  6. prints a loud summary. Every data stage (fetch → parse → filter →
     probe → select) runs meanwhile; the daemon spawns the own core on a
     fail-closed bootstrap config at start (empty pool → block, D7) and
     each wave re-renders <data>/rendered/live.json — no further setup
     required.

WITH -c <path>: the previous semantics verbatim — the unit embeds the
resolved absolute path (a relative -c resolves against the current
directory), the config is untouched where it is, and the daemon reads THAT
file.

The daemon (assay watch) runs the plugin watchdog and the maintain-wave
scheduler; [maintain].refresh_interval / [maintain].speedtest_interval and
[plugins].dir are read from the config LIVE — changing them needs only a
restart of the unit, never a re-install. Legacy W5 timer units
(assay-refresh/speedtest.*) still on disk are disabled and removed by
this install: waves fire from exactly ONE scheduler. The deprecated legacy
config location (~/.config/assay/config.toml) still wins when present —
with a loud deprecation warning naming the move.

--no-systemd installs the binary (and, without -c, materializes the default
config) but skips all unit files — for hosts without a systemd user
session.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveInstallPath(*cfgPath)
			if err != nil {
				return err
			}
			color, err := commandColor(cmd, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			reportConfigSourceStyled(cmd.OutOrStdout(), res.res, color)
			return runInstall(cmd.OutOrStdout(), res.res.Config, res.res.Path, installOptions{
				binDir:          binDir,
				unitDir:         unitDir,
				noSystemd:       noSystemd,
				noScheduler:     noScheduler,
				embedsConfig:    res.embedsConfig,
				materializePath: res.materializePath,
				color:           color,
			})
		},
	}
	attachColorFlags(cmd)
	// The bin-dir default is the §4.2 per-OS table (§2.2.10 on windows:
	// %LOCALAPPDATA%\assay\bin — never PATH-modified).
	cmd.Flags().StringVar(&binDir, "bin-dir", installBinDirDefault(runtime.GOOS),
		"directory for the installed assay binary")
	cmd.Flags().StringVar(&unitDir, "unit-dir", "~/.config/systemd/user", "systemd user unit directory")
	cmd.Flags().BoolVar(&noSystemd, "no-systemd", false,
		"renamed to --no-scheduler; kept as a loud alias (install the binary only)")
	cmd.Flags().BoolVar(&noScheduler, "no-scheduler", false,
		"install the binary only (no scheduler registration on any platform)")
	return cmd
}

// prepareInstallPaths resolves the two paths that feed install.Options:
// the absolute config path embedded into the unit (only for explicit-path
// installs), and the unit dir. I-1: ExecStart= splits argv on whitespace and
// never de-quotes, so a whitespace-bearing --bin-dir/--config renders a unit
// that installs "successfully" but dies at timer-fire ("Command ... is not
// executable") — both are refused here, before anything is copied or
// written. A whitespace unit dir is harmless (never inside ExecStart=).
func prepareInstallPaths(cfgPath, binDir string, opts installOptions) (string, string, error) {
	var cfgAbs string
	if opts.embedsConfig && cfgPath != "" {
		if filepath.IsAbs(cfgPath) {
			cfgAbs = cfgPath
		} else if abs, absErr := filepath.Abs(cfgPath); absErr != nil {
			return "", "", fmt.Errorf("resolve config path: %w", absErr)
		} else {
			cfgAbs = abs
		}
	}
	if opts.noSystemd {
		return "", cfgAbs, nil
	}
	if err := checkExecStartPath("--bin-dir", binDir); err != nil {
		return "", "", err
	}
	if cfgAbs != "" {
		if err := checkExecStartPath("--config", cfgAbs); err != nil {
			return "", "", err
		}
	}
	unitDir, err := absDir(config.ExpandHome(opts.unitDir))
	if err != nil {
		return "", "", err
	}
	return unitDir, cfgAbs, nil
}

// materializeDataDir resolves the data dir rendered into the materialized
// config (the configless default = the local-share layout). A nil config
// with a materialize target is API misuse — the data dir would render empty
// and the file would fail validation at first load.
func materializeDataDir(cfg *config.Config, opts installOptions) (string, error) {
	if opts.materializePath == "" {
		return "", nil
	}
	if cfg == nil || cfg.DataDir == "" {
		return "", errors.New("install: materializing the default config needs a resolved data dir (configless resolution)")
	}
	return cfg.DataDir, nil
}

// installOptions carries the install flags (seam for tests).
type installOptions struct {
	binDir    string
	unitDir   string
	noSystemd bool
	// noScheduler spans EVERY scheduler (§3.1.6): skip detection and any
	// registration — binary + config only. --no-systemd is its loud alias.
	noScheduler bool
	exec        install.Executor // nil = production SystemctlExecutor
	// embedsConfig renders `watch -c <cfgPath>` (explicit -c / legacy-path
	// installs); false renders plain `watch` (default-location installs).
	embedsConfig bool
	// materializePath is non-empty for the default-location install (no -c,
	// no config anywhere in the install-style chain): install materializes
	// the embedded default config there and the unit runs plain `watch`.
	materializePath string
	// color chips the summary block (W18); resolved by the command wrapper.
	color bool
}

func runInstall(w io.Writer, cfg *config.Config, cfgPath string, opts installOptions) error {
	opts = applyNoSchedulerAlias(w, opts)
	binDir, err := absDir(config.ExpandHome(opts.binDir))
	if err != nil {
		return err
	}
	running, err := resolveExecutable()
	if err != nil {
		return err
	}
	dataDir, err := materializeDataDir(cfg, opts)
	if err != nil {
		return err
	}
	// The per-OS scheduler branches (darwin/launchd, windows/SCM, and the
	// S3 linux scheduler detection) own the whole flow when they match;
	// --no-systemd / --no-scheduler keep their binary-only meaning on every
	// platform and fall through to the generic path below.
	if handled, serr := runInstallPerOSScheduler(w, cfg, running, binDir, dataDir, cfgPath, opts); handled {
		return serr
	}
	unitDir, cfgAbs, err := prepareInstallPaths(cfgPath, binDir, opts)
	if err != nil {
		return err
	}
	executor := opts.exec
	if executor == nil {
		executor = installExecutor()
	}
	res, err := install.Install(install.Options{
		BinDir:            binDir,
		UnitDir:           unitDir,
		RunningBinary:     running,
		ConfigPath:        cfgAbs,
		DefaultConfigPath: opts.materializePath,
		DataDir:           dataDir,
		NoSystemd:         opts.noSystemd || opts.noScheduler,
		Exec:              executor,
	})
	if err != nil {
		return err
	}
	// D4 core bootstrap: guarantee the managed core binary before the first
	// wave (the spec's "install is a complete user bootstrap"). Inert with a
	// loud INFO when [core].xray_bin is overridden (S5). A download failure
	// is loud but NON-fatal here: install already enabled the daemon, and
	// the waves retry through the auto-update stage.
	if cfg != nil {
		if berr := ensureCoreBinary(context.Background(), cfg.Core, config.ExpandHome(cfg.DataDir), w); berr != nil {
			outf(w, "%s\n", ui.Warn("WARNING: core bootstrap: "+berr.Error()+
				" (install completes; the daemon's waves retry through auto-update)", ui.Amber, opts.color))
		}
	}
	outf(w, "%s\n", ui.ChipKV("installed binary: ", res.BinaryPath+" (copy of the running image, mode 0755)", opts.color))
	if res.ConfigWritten != "" {
		outf(w, "%s\n", ui.ChipKV("config created:   ", res.ConfigWritten+
			" (materialized defaults — edit to configure; a re-install never overwrites it)", opts.color))
	}
	if res.ConfigKept != "" {
		outf(w, "%s\n", ui.ChipKV("config kept:      ",
			res.ConfigKept+" (already present — never overwritten)", opts.color))
	}
	if res.SkippedUnits {
		label := "--no-systemd"
		if opts.noScheduler {
			label = "--no-scheduler"
		}
		outf(w, "%s\n", ui.ChipKV("scheduler skipped ("+label+"): ",
			"no registration on any scheduler; run the maintain wave manually or from your own scheduler", opts.color))
		return nil
	}
	printInstallSummary(w, cfgAbs, daemonCfg(opts, cfgPath), res, opts.color)
	outf(w, "%s\n", ui.ChipKV("journal: ", "journalctl --user -u assay-watch.service -f", opts.color))
	return nil
}

// applyNoSchedulerAlias carries the --no-systemd → --no-scheduler rename
// (the alias warning lives HERE — one source, exercised on the direct-call
// path the tests drive too; the alias behaves identically to --no-scheduler,
// which S3 widened to span every scheduler).
func applyNoSchedulerAlias(w io.Writer, opts installOptions) installOptions {
	if opts.noSystemd && !opts.noScheduler {
		outf(w, "%s\n", ui.Warn(
			"NOTE: --no-systemd was renamed to --no-scheduler (it now spans every scheduler, "+
				"not only systemd); the old flag is kept as an alias and behaves identically",
			ui.Amber, opts.color))
		opts.noScheduler = true
	}
	return opts
}

// runInstallPerOSScheduler routes the darwin and windows installs to their
// schedulers (plan §1/§S1 launchd; §2/§S2 windows SCM). Branched BEFORE
// prepareInstallPaths: the systemd-only constraints (the --unit-dir
// default, the ExecStart whitespace check) do not apply to the LaunchAgent
// plist (XML array, whitespace-safe) or the SCM registration (args are
// typed strings, not a split line). handled=false (linux, or --no-systemd
// on any platform) falls through to the generic systemd path — which never
// touches systemctl when NoSystemd is set.
func runInstallPerOSScheduler(
	w io.Writer, cfg *config.Config, running, binDir, dataDir, cfgPath string, opts installOptions,
) (bool, error) {
	if darwinHost() && !opts.noSystemd && !opts.noScheduler {
		return true, runInstallLaunchd(w, cfg, running, binDir, dataDir, cfgPath, opts)
	}
	if windowsHost() && !opts.noSystemd && !opts.noScheduler {
		return true, runInstallWinSvc(w, cfg, running, binDir, dataDir, cfgPath, opts)
	}
	// §3.3 linux branching: detect → refuse-on-held → render+activate via
	// the matched scheduler. handled=false ONLY for the systemd fall-through
	// (the generic path below owns systemd byte-identically).
	if linuxHost() && !opts.noSystemd && !opts.noScheduler {
		return runInstallLinuxScheduler(w, cfg, running, binDir, dataDir, cfgPath, opts)
	}
	return false, nil
}

// runInstallLinuxScheduler is the §3.3 linux flow: detection through the
// linuxSchedulerProbe seam (§3.1 order), the cross-scheduler double-install
// refusal (the W5 stampede class — a holder from a DIFFERENT scheduler
// refuses loudly naming both locations), the byte-identical systemd
// fall-through, and the matched scheduler's render+activate flow followed by
// the D4 core bootstrap and the loud summary.
func runInstallLinuxScheduler(
	w io.Writer, cfg *config.Config, running, binDir, dataDir, cfgPath string, opts installOptions,
) (bool, error) {
	unitDir, uerr := absDir(config.ExpandHome(opts.unitDir))
	if uerr != nil {
		return true, uerr
	}
	sched, holder, holderLoc := linuxSchedulerProbe(unitDir)
	if holder != "" && holder != sched.Name() {
		return true, fmt.Errorf("install: refusing double registration: assay-watch is already "+
			"installed under %s (%s) and this install would register it under %s — "+
			"two schedulers running waves concurrently is the stampede class this install "+
			"refuses by design; uninstall from %s first (`assay uninstall`)",
			holder, holderLoc, sched.Name(), holder)
	}
	if sched.Name() == install.SchedulerSystemd {
		// §3.1.1: today's path, unchanged — the generic flow below renders
		// and enables the unit through the same allowlisted executor.
		return false, nil
	}
	if avail, reason := sched.Available(); !avail {
		return true, fmt.Errorf("install: the %s scheduler is unavailable: %s", sched.Name(), reason)
	}
	cfgAbs := ""
	if opts.embedsConfig && cfgPath != "" {
		abs, err := explicitConfigAbs(cfgPath)
		if err != nil {
			return true, err
		}
		cfgAbs = abs
	}
	res, err := sched.Install(install.SchedulerInstallSpec{
		RunningBinary:     running,
		BinDir:            binDir,
		ConfigPath:        cfgAbs,
		DefaultConfigPath: opts.materializePath,
		DataDir:           dataDir,
	})
	if err != nil {
		return true, err
	}
	// D4 core bootstrap: identical contract to the systemd/launchd/windows
	// branches (loud non-fatal warning; the waves retry through auto-update).
	if cfg != nil {
		if berr := ensureCoreBinary(context.Background(), cfg.Core, config.ExpandHome(cfg.DataDir), w); berr != nil {
			outf(w, "%s\n", ui.Warn("WARNING: core bootstrap: "+berr.Error()+
				" (install completes; the daemon's waves retry through auto-update)", ui.Amber, opts.color))
		}
	}
	printLinuxSchedulerSummary(w, sched.Name(), res, dataDir, cfgAbs, opts.color)
	return true, nil
}

// printLinuxSchedulerSummary is the loud post-install report per scheduler:
// artifacts written, the supervision mechanism (honest parity — plan §5.22),
// the unrotated-log caveat where logs land in files, and for the foreground
// fall-through the EXACT run instructions (§3.1.6).
func printLinuxSchedulerSummary(w io.Writer, name string, res install.Result, dataDir, cfgAbs string, color bool) {
	outf(w, "%s\n", ui.ChipKV("scheduler:        ", name+" detected — waves are supervised by this scheduler", color))
	outf(w, "%s\n", ui.ChipKV("installed binary: ", res.BinaryPath+" (copy of the running image, mode 0755)", color))
	if res.ConfigWritten != "" {
		outf(w, "%s\n", ui.ChipKV("config created:   ", res.ConfigWritten+
			" (materialized defaults — edit to configure; a re-install never overwrites it)", color))
	}
	if res.ConfigKept != "" {
		outf(w, "%s\n", ui.ChipKV("config kept:      ",
			res.ConfigKept+" (already present — never overwritten)", color))
	}
	for _, p := range res.UnitPaths {
		outf(w, "%s\n", ui.ChipKV("registered:       ", p, color))
	}
	switch name {
	case install.SchedulerRunit:
		outf(w, "%s\n", ui.ChipKV("daemon active:    ",
			"assay watch under runsvdir (picked up within its 5s rescan; runsv restart-on-exit, "+
				"1s backoff); logs "+filepath.Join(dataDir, "logs", "watch.out.log")+
				" + watch.err.log (unrotated)", color))
		outf(w, "%s\n", ui.ChipKV("manage:           ",
			"sv status|stop|restart <service-dir>/assay-watch", color))
	case install.SchedulerOpenRC:
		outf(w, "%s\n", ui.ChipKV("daemon active:    ",
			"assay watch under supervise-daemon (restart-on-crash; rc-service --user assay-watch {status,stop})", color))
		outf(w, "%s\n", ui.ChipKV("session note:     ",
			"user services run while the session lives — no lingering without root (OpenRC >= 0.60)", color))
	case install.SchedulerS6:
		outf(w, "%s\n", ui.ChipKV("daemon active:    ",
			"assay watch under s6-supervise (restart-on-exit; activated via s6-svscanctl -a); logs "+
				filepath.Join(dataDir, "logs", "watch.out.log")+" + watch.err.log (unrotated)", color))
		outf(w, "%s\n", ui.ChipKV("manage:           ",
			"s6-svstat <scandir>/assay-watch (stop: s6-svc -d)", color))
	case install.SchedulerCron:
		outf(w, "%s\n", ui.ChipKV("daemon active:    ",
			"assay watch via the @reboot crontab entry (fires when cron starts, i.e. at boot — not at login)", color))
		outf(w, "%s\n", ui.Warn("NOTE: cron carries NO supervision — no crash restart; "+
			"`assay watch` runs until it exits", ui.Amber, color))
	case install.SchedulerForeground:
		outf(w, "%s\n", ui.Warn("NOTE: no scheduler detected — nothing will start the daemon automatically", ui.Amber, color))
		if cfgAbs != "" {
			outf(w, "%s\n", ui.ChipKV("run in foreground:", res.BinaryPath+" watch -c "+cfgAbs, color))
		} else {
			outf(w, "%s\n", ui.ChipKV("run in foreground:", res.BinaryPath+" watch", color))
		}
		outf(w, "%s\n", ui.ChipKV("                  ",
			"no supervision: no crash restart — the daemon runs until it exits; "+
				"install again once systemd (user session), runit, OpenRC >= 0.60, s6, or cron is available", color))
	}
	if cfgAbs != "" && name != install.SchedulerForeground {
		outf(w, "%s\n", ui.ChipKV("config reference: ",
			cfgAbs+" (install never creates or moves it — keep it in place)", color))
	}
}

// daemonCfg resolves the default-location config display path: the
// materialization target when one was passed, else the resolved canonical
// file already present at the default location.
func daemonCfg(opts installOptions, cfgPath string) string {
	if opts.materializePath != "" {
		return opts.materializePath
	}
	return cfgPath
}

// printInstallSummary is the loud post-install report: units, daemon,
// legacy cleanup, and the config guidance — explicit-path installs name the
// referenced file, default-location installs name where the daemon reads
// its config and what the owner must fill to activate.
func printInstallSummary(w io.Writer, cfgAbs string,
	daemonCfgPath string, res install.Result, color bool,
) {
	for _, p := range res.UnitPaths {
		outf(w, "%s\n", ui.ChipKV("unit written:     ", p, color))
	}
	outf(w, "%s\n", ui.ChipKV("daemon active:    ",
		"assay watch (Restart=always) — wave intervals and the plugins dir", color))
	outf(w, "%s\n", ui.ChipKV("                  ",
		"are read from the config live (a change needs a restart, not a re-install)", color))
	for _, name := range res.LegacyCleaned {
		outf(w, "%s\n", ui.ChipKV("legacy removed:   ",
			name+" (W5 timer unit — the daemon replaced the timers)", color))
	}
	if cfgAbs != "" {
		outf(w, "%s\n", ui.ChipKV("config reference: ",
			cfgAbs+" (install never creates or moves it — keep it in place)", color))
		return
	}
	outf(w, "%s\n", ui.ChipKV("daemon config:    ",
		daemonCfgPath+" (the daemon reads the default location — no -c in the unit)", color))
}

// explicitConfigAbs resolves the explicit -c for the launchd branch:
// absolute as given, relative resolved against the cwd. No ExecStart
// whitespace check — ProgramArguments is an XML array (whitespace-safe);
// the plist's own XML-hostile-character check lives in renderPlist.
func explicitConfigAbs(cfgPath string) (string, error) {
	if filepath.IsAbs(cfgPath) {
		return cfgPath, nil
	}
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		return "", fmt.Errorf("resolve config path: %w", err)
	}
	return abs, nil
}

// runInstallLaunchd is the darwin install flow (plan §1/§S1): the
// LaunchdScheduler owns the whole §1.2.6 sequence (copyBinary → config
// materialize → agent dir → plist 0600 → print-probe → bootout-if-loaded →
// bootstrap → bounded print-verify), and the D4 core bootstrap runs
// unchanged afterwards. Every scheduler failure already carries the exact
// launchctl line (owner UX rule) — this layer adds nothing but the summary.
func runInstallLaunchd(
	w io.Writer, cfg *config.Config, running, binDir, dataDir, cfgPath string, opts installOptions,
) error {
	cfgAbs := ""
	if opts.embedsConfig && cfgPath != "" {
		abs, err := explicitConfigAbs(cfgPath)
		if err != nil {
			return err
		}
		cfgAbs = abs
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("install: resolve home dir: %w", err)
	}
	sched := launchdSchedulerFactory()
	if avail, reason := sched.Available(); !avail {
		return fmt.Errorf("install: the launchd scheduler is unavailable: %s", reason)
	}
	res, err := sched.Install(install.LaunchdInstallSpec{
		RunningBinary:     running,
		BinDir:            binDir,
		ConfigPath:        cfgAbs,
		DefaultConfigPath: opts.materializePath,
		DataDir:           dataDir,
		AgentDir:          filepath.Join(home, "Library", "LaunchAgents"),
	})
	if err != nil {
		return err
	}
	// D4 core bootstrap: identical contract to the systemd branch (loud
	// non-fatal warning; the waves retry through auto-update).
	if cfg != nil {
		if berr := ensureCoreBinary(context.Background(), cfg.Core, config.ExpandHome(cfg.DataDir), w); berr != nil {
			outf(w, "%s\n", ui.Warn("WARNING: core bootstrap: "+berr.Error()+
				" (install completes; the daemon's waves retry through auto-update)", ui.Amber, opts.color))
		}
	}
	printLaunchdInstallSummary(w, res, dataDir, cfgAbs, opts)
	return nil
}

// printLaunchdInstallSummary is the loud post-install report for the
// LaunchAgent: the plist path, the supervision + hang mechanism (ADDENDUM
// §1 — named, never hidden), the unrotated-log caveat, and the config
// guidance.
func printLaunchdInstallSummary(w io.Writer, res install.Result, dataDir, cfgAbs string, opts installOptions) {
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
		outf(w, "%s\n", ui.ChipKV("agent written:    ",
			p+" (mode 0600 — RunAtLoad=true, KeepAlive=true, ThrottleInterval=5, ProcessType=Background)", opts.color))
	}
	outf(w, "%s\n", ui.ChipKV("daemon active:    ",
		"assay watch (KeepAlive restart on exit; hang detection: "+
			"self-watchdog → clean self-exit → KeepAlive restart)", opts.color))
	outf(w, "%s\n", ui.ChipKV("logs:             ",
		filepath.Join(dataDir, "logs", "watch.out.log")+" + watch.err.log "+
			"(launchd redirect — unrotated; loglevel warning default)", opts.color))
	if cfgAbs != "" {
		outf(w, "%s\n", ui.ChipKV("config reference: ",
			cfgAbs+" (install never creates or moves it — keep it in place)", opts.color))
	}
}

func newUninstallCommand(cfgPath *string) *cobra.Command {
	var (
		unitDir string
		purge   bool
	)
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Disable the watch daemon and remove the rendered unit files (default: user data kept)",
		Long: `Symmetric teardown: disables the watch daemon and any legacy timer units
still present, removes every known unit file (assay-watch.service plus
the W5-era assay-refresh/speedtest units), daemon-reloads the user
manager (so it drops its not-found entries for the removed units), and
reports. The installed binary and all user data are KEPT by default.

--purge is DESTRUCTIVE and must be passed explicitly: it also removes the
config file and the pipeline data dir ([data_dir]). It never touches
anything outside those two paths — in particular nothing outside assay's
own deployment (the owner's hand-managed proxy client is never touched). The
config resolves the same way install does: explicit -c wins; the
default-location layout (no -c) purges the canonical
~/.local/share/assay/config.toml plus the data dir under it; the
deprecated legacy location still wins when present. The cwd default
(./config.toml) is never consulted — a purge must never depend on the
caller's working directory.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The config resolves on BOTH paths now: the managed-core
			// teardown (D4) needs the data dir on the plain path too. A
			// configless machine resolves to the built-in defaults; a
			// resolution FAILURE leaves cfg nil (nothing is guessed — the
			// core teardown is skipped; --purge still refuses: it cannot
			// resolve what to purge).
			ir, err := resolveInstallPath(*cfgPath)
			if err != nil {
				if purge {
					return fmt.Errorf("--purge needs the config: %w", err)
				}
				ir = installResolution{}
			}
			if purge {
				reportConfigSource(cmd.OutOrStdout(), ir.res)
			}
			var cfg *config.Config
			if ir.res != nil {
				cfg = ir.res.Config
			}
			// cfgPath is the purge's consumer (the resolved config path, or
			// the materialized default for the W13 default-location purge).
			var cfgPath string
			if ir.res != nil {
				cfgPath = ir.res.Path
			}
			if purge && cfgPath == "" {
				cfgPath = ir.materializePath
			}
			return runUninstall(cmd.OutOrStdout(), cfg, cfgPath, uninstallOptions{
				unitDir: unitDir,
				purge:   purge,
			})
		},
	}
	cmd.Flags().StringVar(&unitDir, "unit-dir", "~/.config/systemd/user", "systemd user unit directory")
	cmd.Flags().BoolVar(&purge, "purge", false,
		"DESTRUCTIVE: also remove the config file and the data dir (default: keep all user data)")
	return cmd
}

// uninstallOptions carries the uninstall flags (seam for tests).
type uninstallOptions struct {
	unitDir string
	purge   bool
	exec    install.Executor // nil = production SystemctlExecutor
}

func runUninstall(w io.Writer, cfg *config.Config, cfgPath string, opts uninstallOptions) error {
	if opts.purge && cfg == nil {
		return errors.New("--purge needs the config (-c) to resolve the data dir")
	}
	// darwin branch (plan §1.2.7): bootout via the scheduler, plist removal,
	// managed-core teardown unchanged, purge passthrough.
	if darwinHost() {
		return runUninstallLaunchd(w, cfg, cfgPath, opts)
	}
	// windows branch (plan §2.2.7): Control(Stop) → poll → Delete via the
	// scheduler, managed-core teardown unchanged, purge passthrough.
	if windowsHost() {
		return runUninstallWinSvc(w, cfg, cfgPath, opts)
	}
	unitDir, err := absDir(config.ExpandHome(opts.unitDir))
	if err != nil {
		return err
	}
	executor := opts.exec
	if executor == nil {
		executor = installExecutor()
	}
	uo := install.UninstallOptions{UnitDir: unitDir, Exec: executor}
	if cfg != nil {
		// The managed-core teardown (D4) rides the resolved data dir; with
		// no resolvable config there is nothing known to remove.
		uo.ManagedCoreDataDir = config.ExpandHome(cfg.DataDir)
	}
	if opts.purge {
		uo.PurgeConfigPath = cfgPath
		uo.PurgeDataDir = config.ExpandHome(cfg.DataDir)
	}
	res, err := install.Uninstall(uo)
	if err != nil {
		return err
	}
	printSystemdUninstall(w, res, opts.purge)
	return nil
}

// printSystemdUninstall renders the systemd uninstall report: what was
// disabled, removed, already-absent, the managed-core teardown, purge.
func printSystemdUninstall(w io.Writer, res install.UninstallResult, purge bool) {
	switch {
	case len(res.DisabledUnits) > 0:
		outf(w, "disabled:         %s\n", strings.Join(res.DisabledUnits, ", "))
	case res.SkippedDisable:
		outln(w, "units:            no systemd user session — nothing to disable")
	}
	for _, name := range res.RemovedUnits {
		outf(w, "unit removed:     %s\n", name)
	}
	for _, name := range res.MissingUnits {
		outf(w, "unit absent:      %s (already clean)\n", name)
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

// runUninstallLaunchd is the darwin teardown (§1.2.7): bootout (reported
// honestly when nothing is registered), plist removal, the D4 managed-core
// teardown on the resolved data dir, purge passthrough. No legacy cleanup
// exists on darwin (no prior darwin installs).
func runUninstallLaunchd(w io.Writer, cfg *config.Config, cfgPath string, opts uninstallOptions) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("uninstall: resolve home dir: %w", err)
	}
	sched := launchdSchedulerFactory()
	spec := install.LaunchdUninstallSpec{
		AgentDir: filepath.Join(home, "Library", "LaunchAgents"),
	}
	if cfg != nil {
		spec.DataDir = config.ExpandHome(cfg.DataDir)
	}
	if opts.purge {
		spec.PurgeConfigPath = cfgPath
		if cfg != nil {
			spec.PurgeDataDir = config.ExpandHome(cfg.DataDir)
		}
	}
	res, err := sched.Uninstall(spec)
	if err != nil {
		return err
	}
	printLaunchdUninstall(w, res, opts.purge)
	return nil
}

// printLaunchdUninstall renders the darwin uninstall report: the bootout
// outcome (nothing registered is REPORTED, never faked), the plist removal,
// the managed-core teardown, and the purge passthrough.
func printLaunchdUninstall(w io.Writer, res install.UninstallResult, purge bool) {
	if len(res.DisabledUnits) > 0 {
		outf(w, "booted out:       %s\n", strings.Join(res.DisabledUnits, ", "))
	} else {
		outf(w, "agent:            not registered (nothing to boot out)\n")
	}
	for _, name := range res.RemovedUnits {
		outf(w, "agent removed:    %s\n", name)
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

// absDir rejects empty expansions and makes the path absolute.
func absDir(p string) (string, error) {
	if p == "" {
		return "", errors.New("directory must not be empty")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", p, err)
	}
	return abs, nil
}

// checkExecStartPath refuses paths that would land in a unit's ExecStart=
// carrying whitespace (space/tab/newline): systemd splits the ExecStart value
// into argv on whitespace and does not de-quote, so such a unit installs
// cleanly but fails at timer-fire time with "Command ... is not executable" —
// long after install printed success (I-1). The rejection is loud and
// actionable instead.
func checkExecStartPath(flag, p string) error {
	if strings.ContainsAny(p, " \t\n\r") {
		return fmt.Errorf("install: %s %q contains whitespace — "+
			"systemd ExecStart cannot carry unquoted whitespace; "+
			"choose a whitespace-free path (the timer unit would fail at fire time)", flag, p)
	}
	return nil
}

// binariesDiffer reports whether two files carry different CONTENT (sha256
// — the drift is content-level, not path-level). A read failure on either
// side returns an error: the caller skips the notice rather than guessing.
func binariesDiffer(a, b string) (bool, error) {
	sha := func(p string) ([]byte, error) {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil, err
		}
		return h.Sum(nil), nil
	}
	aSha, err := sha(a)
	if err != nil {
		return false, err
	}
	bSha, err := sha(b)
	if err != nil {
		return false, err
	}
	return string(aSha) != string(bSha), nil
}

// printInstallStatus extends `status` with the install state: binary path,
// the watch-daemon unit, its enablement, and any legacy W5 timer units still
// awaiting migration. Read-only: pure filesystem inspection of the given
// unit dir, no systemctl. binDir/unitDir arrive from the status --bin-dir /
// --unit-dir flags (defaults = the install defaults) — no hardcoded paths
// here, so a custom-dir install is tracked by passing the same values
// (round-7 item 11). The daemon reads intervals from the config live, so —
// unlike the W5 timers — there is no configured-vs-installed mismatch class.
func printInstallStatus(out io.Writer, cfg *config.Config, cfgPath, binDir, unitDir string, color bool) {
	outln(out, ui.Header("install:", color))
	// darwin branch (§1.2.8 + ADDENDUM §1): the LaunchAgent state via the
	// scheduler seam, with the supervision mechanism named honestly.
	if darwinHost() {
		printLaunchdStatus(out, binDir, color)
		return
	}
	// windows branch (§2.2.8 + ADDENDUM §1): the SCM Query state + pid via
	// the scheduler seam, with the recovery/child-stop mechanisms named.
	if windowsHost() {
		printWinSvcStatus(out, binDir, color)
		return
	}
	printInstalledBinary(out, binDir, color)
	// unitDir arrives already expanded (status flags → ExpandHome at the
	// caller); the rest of this function only joins names onto it.
	_, watchErr := os.Stat(filepath.Join(unitDir, install.WatchService))
	if watchErr != nil {
		outf(out, "%s\n", ui.ChipKV("  units:     ",
			"watch daemon not rendered ("+unitDir+")", color))
	} else {
		outf(out, "%s\n", ui.ChipKV("  units:     ",
			fmt.Sprintf("%s present in %s", install.WatchService, unitDir), color))
		enabled := false
		for _, wants := range []string{"default.target.wants", "multi-user.target.wants"} {
			if _, err := os.Stat(filepath.Join(unitDir, wants, install.WatchService)); err == nil {
				enabled = true
			}
		}
		if enabled {
			speedtest := "disabled (speedtest_interval = 0s — no speedtest waves)"
			if cfg.Maintain.SpeedtestWaveEnabled() {
				speedtest = install.Span(cfg.Maintain.SpeedtestWavePeriod())
			}
			outf(out, "%s\n", ui.ChipKV("  service:   ",
				fmt.Sprintf("enabled (wants symlink) — waves: refresh %s, speedtest %s (read live from the config)",
					install.Span(cfg.Maintain.RefreshInterval.Duration), speedtest), color))
		} else {
			outf(out, "%s\n", ui.ChipKV("  service:   ",
				"not enabled — run `assay install`", color))
		}
	}
	legacy := install.LegacyUnitNames()
	present := 0
	for _, name := range legacy {
		if _, err := os.Stat(filepath.Join(unitDir, name)); err == nil {
			present++
		}
	}
	if present > 0 {
		if cfgPath != "" {
			outf(out, "%s\n", ui.Warn(fmt.Sprintf(
				"  LEGACY:    %d W5 timer units still on disk — re-run `assay install -c %s` to migrate",
				present, cfgPath), ui.Amber, color))
		} else {
			outf(out, "%s\n", ui.Warn(fmt.Sprintf("  LEGACY:    %d W5 timer units still on disk — re-run `assay install` "+
				"with a config (-c or %s) to migrate", present, config.ShareConfigDisplay), ui.Amber, color))
		}
	}
}

// printInstalledBinary renders the installed-binary line plus the W13
// stale-binary notice — shared by the systemd, launchd, and windows
// install-status sections. The name joins through the platform table
// (assay.exe on windows, assay elsewhere — §4.2).
func printInstalledBinary(out io.Writer, binDir string, color bool) {
	binPath := filepath.Join(binDir, platform.AssayBinaryName(runtime.GOOS))
	if st, err := os.Stat(binPath); err == nil {
		outf(out, "%s\n", ui.ChipKV("  binary:    ",
			fmt.Sprintf("%s (mode %s)", binPath, st.Mode()), color))
		// W13 stale-binary notice (the owner's incident): the installed
		// binary does NOT self-update on `git pull` — a rebuilt-but-not-
		// reinstalled binary keeps running OLD code under the daemon unit.
		// A cheap sha256 pair names the drift and the recovery. Honest in
		// every divergence case, including dev builds (`go run` differs
		// from the install by definition).
		if running, e := os.Executable(); e == nil && running != binPath {
			if differ, shaErr := binariesDiffer(running, binPath); shaErr == nil && differ {
				outf(out, "%s\n", ui.Warn("  STALE:     running binary differs from the installed one — "+
					"the installed binary does not self-update; re-run `assay install` "+
					"(self-copy) and restart assay-watch.service to load the new code", ui.Red, color))
			}
		}
	} else {
		outf(out, "%s\n", ui.ChipKV("  binary:    ",
			"not installed ("+binPath+" missing) — run `assay install`", color))
	}
}

// printLaunchdStatus is the darwin install-status section (§1.2.8): the
// print-derived agent state and PID plus the HONEST supervision note —
// "self-watchdog → KeepAlive restart" (ADDENDUM §1) — and the unrotated-log
// caveat.
func printLaunchdStatus(out io.Writer, binDir string, color bool) {
	printInstalledBinary(out, binDir, color)
	st, err := launchdSchedulerFactory().Status()
	if err != nil {
		outf(out, "%s\n", ui.Warn("  agent:     launchctl print failed: "+err.Error(), ui.Amber, color))
		return
	}
	if st.Active {
		outf(out, "%s\n", ui.ChipKV("  agent:     ",
			fmt.Sprintf("assay-watch registered (pid %d)", st.PID), color))
	} else {
		outf(out, "%s\n", ui.ChipKV("  agent:     ", st.Note, color))
	}
	outf(out, "%s\n", ui.ChipKV("  supervision:", st.Note, color))
	outf(out, "%s\n", ui.ChipKV("  logs:      ",
		"~/Library/Application Support/assay/logs/watch.{out,err}.log (launchd redirect — unrotated)", color))
}
