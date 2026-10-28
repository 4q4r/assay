package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/install"

	"github.com/spf13/cobra"
)

// W5 self-install surface. The systemctl scope is pinned inside
// internal/install (allowlist: --user, the two public_vpn-* timers only,
// daemon-reload + enable/disable --now — never restart, never other units).

// resolveExecutable returns the running binary's absolute path.
func resolveExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve running binary: %w", err)
	}
	return filepath.EvalSymlinks(exe)
}

func newInstallCommand(cfgPath *string) *cobra.Command {
	var (
		binDir    string
		unitDir   string
		noSystemd bool
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Self-install: copy the running binary and render + enable the systemd user timers",
		Long: `Copies the RUNNING binary (os.Executable) to --bin-dir as ` + "`publicvpn`" + `
(atomic write, mode 0755; re-running after a rebuild = self-upgrade), then
renders the four systemd user units from the repo templates and enables both
timers:

  systemctl --user daemon-reload
  systemctl --user enable --now public_vpn-refresh.timer public_vpn-speedtest.timer

The timers' recheck periods come from [maintain].refresh_interval /
[maintain].speedtest_interval (rendered as OnBootSec + OnUnitActiveSec, so
any duration works). Changing a period = edit the config and re-run install
(idempotent). Config files are NEVER created or moved: the units reference
the --config path you pass, so it must be absolute or ~-expanded and must
stay in place.

--no-systemd installs the binary only (hosts without a systemd user session;
timers skipped).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runInstall(cmd.OutOrStdout(), cfg, *cfgPath, installOptions{
				binDir:    binDir,
				unitDir:   unitDir,
				noSystemd: noSystemd,
			})
		},
	}
	cmd.Flags().StringVar(&binDir, "bin-dir", "~/.local/bin", "directory for the installed publicvpn binary")
	cmd.Flags().StringVar(&unitDir, "unit-dir", "~/.config/systemd/user", "systemd user unit directory")
	cmd.Flags().BoolVar(&noSystemd, "no-systemd", false,
		"install the binary only (no unit files, no timers) — for hosts without a user systemd session")
	return cmd
}

// installOptions carries the install flags (seam for tests).
type installOptions struct {
	binDir    string
	unitDir   string
	noSystemd bool
	exec      install.Executor // nil = production SystemctlExecutor
}

func runInstall(w io.Writer, cfg *config.Config, cfgPath string, opts installOptions) error {
	binDir, err := absDir(config.ExpandHome(opts.binDir))
	if err != nil {
		return err
	}
	unitDir := ""
	cfgAbs := ""
	if !opts.noSystemd {
		// I-1: ExecStart= splits argv on whitespace and never de-quotes, so a
		// whitespace-bearing path renders a unit that installs "successfully"
		// but dies at timer-fire ("Command ... is not executable"). Refuse the
		// path here, before the binary is copied or any unit is written.
		if err := checkExecStartPath("--bin-dir", binDir); err != nil {
			return err
		}
		if !filepath.IsAbs(cfgPath) {
			cfgAbs, err = filepath.Abs(cfgPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
		} else {
			cfgAbs = cfgPath
		}
		if err := checkExecStartPath("--config", cfgAbs); err != nil {
			return err
		}
		unitDir, err = absDir(config.ExpandHome(opts.unitDir))
		if err != nil {
			return err
		}
	}
	running, err := resolveExecutable()
	if err != nil {
		return err
	}
	executor := opts.exec
	if executor == nil {
		executor = install.SystemctlExecutor{}
	}
	res, err := install.Install(install.Options{
		BinDir:            binDir,
		UnitDir:           unitDir,
		RunningBinary:     running,
		ConfigPath:        cfgAbs,
		NoSystemd:         opts.noSystemd,
		RefreshInterval:   cfg.Maintain.RefreshInterval.Duration,
		SpeedtestInterval: cfg.Maintain.SpeedtestInterval.Duration,
		Exec:              executor,
	})
	if err != nil {
		return err
	}
	outf(w, "installed binary: %s (copy of the running image, mode 0755)\n", res.BinaryPath)
	if res.SkippedUnits {
		outln(w, "systemd units skipped (--no-systemd): no timers installed; "+
			"run the maintain wave manually or from your own scheduler")
		return nil
	}
	for _, p := range res.UnitPaths {
		outf(w, "unit written:     %s\n", p)
	}
	outf(w, "timers active:    refresh every %s, speedtest every %s (OnUnitActiveSec)\n",
		install.Span(cfg.Maintain.RefreshInterval.Duration), install.Span(cfg.Maintain.SpeedtestInterval.Duration))
	outf(w, "config reference: %s (install never creates or moves it — keep it in place)\n", cfgAbs)
	outln(w, "journal: journalctl --user -u public_vpn-refresh.service -f")
	return nil
}

func newUninstallCommand(cfgPath *string) *cobra.Command {
	var (
		unitDir string
		purge   bool
	)
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Disable the timers and remove the rendered unit files (default: user data kept)",
		Long: `Symmetric teardown: disables both timers
(systemctl --user disable --now public_vpn-refresh.timer public_vpn-speedtest.timer),
removes the four rendered unit files, daemon-reloads the user manager (so it
drops its not-found entries for the removed units), and reports. The installed
binary and all user data are KEPT by default.

--purge is DESTRUCTIVE and must be passed explicitly: it also removes the
config file (-c) and the pipeline data dir ([data_dir]). It never touches
anything outside those two paths — in particular nothing xray-raw.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var cfg *config.Config
			if purge {
				var err error
				cfg, err = load(*cfgPath)
				if err != nil {
					return fmt.Errorf("--purge needs the config (-c) to resolve the data dir: %w", err)
				}
			}
			return runUninstall(cmd.OutOrStdout(), cfg, *cfgPath, uninstallOptions{
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
	unitDir, err := absDir(config.ExpandHome(opts.unitDir))
	if err != nil {
		return err
	}
	executor := opts.exec
	if executor == nil {
		executor = install.SystemctlExecutor{}
	}
	uo := install.UninstallOptions{UnitDir: unitDir, Exec: executor}
	if opts.purge {
		uo.PurgeConfigPath = cfgPath
		uo.PurgeDataDir = config.ExpandHome(cfg.DataDir)
	}
	res, err := install.Uninstall(uo)
	if err != nil {
		return err
	}
	switch {
	case res.DisabledTimers:
		outln(w, "timers disabled:  public_vpn-refresh.timer, public_vpn-speedtest.timer")
	case res.SkippedDisable:
		outln(w, "timers:           no systemd user session — nothing to disable")
	}
	for _, name := range res.RemovedUnits {
		outf(w, "unit removed:     %s\n", name)
	}
	for _, name := range res.MissingUnits {
		outf(w, "unit absent:      %s (already clean)\n", name)
	}
	for _, p := range res.Purged {
		outf(w, "purged:           %s\n", p)
	}
	if !opts.purge {
		outln(w, "user data kept (config, data dir, installed binary) — pass --purge to remove config + data")
	}
	return nil
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

// printInstallStatus extends `status` with the install state: binary path,
// unit files present, timers enabled, and configured-vs-installed periods
// (mismatch = the config changed after the last install — re-run install).
// Read-only: pure filesystem inspection of the user unit dir, no systemctl.
func printInstallStatus(out io.Writer, cfg *config.Config, cfgPath string) {
	outln(out, "install:")
	binPath := filepath.Join(config.ExpandHome("~/.local/bin"), "publicvpn")
	if st, err := os.Stat(binPath); err == nil {
		outf(out, "  binary:    %s (mode %s)\n", binPath, st.Mode())
	} else {
		outln(out, "  binary:    not installed ("+binPath+" missing) — run `publicvpn install`")
	}
	unitDir := config.ExpandHome("~/.config/systemd/user")
	missing := 0
	for _, name := range install.UnitNames() {
		if _, err := os.Stat(filepath.Join(unitDir, name)); err != nil {
			missing++
		}
	}
	if missing == len(install.UnitNames()) {
		outln(out, "  units:     none rendered ("+unitDir+")")
		return
	}
	outf(out, "  units:     %d/4 present in %s\n", len(install.UnitNames())-missing, unitDir)

	enabled := 0
	for _, name := range []string{install.RefreshTimer, install.SpeedtestTimer} {
		if _, err := os.Stat(filepath.Join(unitDir, "timers.target.wants", name)); err == nil {
			enabled++
		}
	}
	outf(out, "  timers:    %d/2 enabled (timers.target.wants symlinks)\n", enabled)

	installedRefresh, errRefresh := installedPeriod(unitDir, install.RefreshTimer)
	installedSpeed, errSpeed := installedPeriod(unitDir, install.SpeedtestTimer)
	cfgRefresh := cfg.Maintain.RefreshInterval.Duration
	cfgSpeed := cfg.Maintain.SpeedtestInterval.Duration
	outf(out, "  refresh:   configured %s, installed %s\n", cfgRefresh, orUnreadable(installedRefresh, errRefresh))
	outf(out, "  speedtest: configured %s, installed %s\n", cfgSpeed, orUnreadable(installedSpeed, errSpeed))
	installHint := fmt.Sprintf(" — re-run `publicvpn install -c %s` to apply\n", cfgPath)
	if errRefresh == nil && installedRefresh != cfgRefresh {
		outf(out, "  MISMATCH:  refresh period changed in the config%s", installHint)
	}
	if errSpeed == nil && installedSpeed != cfgSpeed {
		outf(out, "  MISMATCH:  speedtest period changed in the config%s", installHint)
	}
}

func orUnreadable(d time.Duration, err error) string {
	if err != nil {
		return "unreadable (" + err.Error() + ")"
	}
	return d.String()
}

// installedPeriod reads OnUnitActiveSec from an installed timer unit.
func installedPeriod(unitDir, unit string) (time.Duration, error) {
	b, err := os.ReadFile(filepath.Join(unitDir, unit))
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, "OnUnitActiveSec="); ok {
			return install.ParseSpan(value)
		}
	}
	return 0, fmt.Errorf("no OnUnitActiveSec in %s", unit)
}
