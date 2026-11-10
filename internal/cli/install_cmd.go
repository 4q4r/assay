package cli

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"assay/internal/config"
	"assay/internal/install"
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

func newInstallCommand(cfgPath *string) *cobra.Command {
	var (
		binDir    string
		unitDir   string
		noSystemd bool
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
  5. prints a loud summary — including what YOU still must fill:
     [render].template and [activate].target in the materialized config.
     Until those exist the render/activate stages fail loud at their
     boundary; every data stage (fetch → parse → filter → probe → geo →
     select) runs meanwhile.

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
				embedsConfig:    res.embedsConfig,
				materializePath: res.materializePath,
				color:           color,
			})
		},
	}
	attachColorFlags(cmd)
	cmd.Flags().StringVar(&binDir, "bin-dir", "~/.local/bin", "directory for the installed assay binary")
	cmd.Flags().StringVar(&unitDir, "unit-dir", "~/.config/systemd/user", "systemd user unit directory")
	cmd.Flags().BoolVar(&noSystemd, "no-systemd", false,
		"install the binary only (no unit files, no timers) — for hosts without a user systemd session")
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
	exec      install.Executor // nil = production SystemctlExecutor
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
	binDir, err := absDir(config.ExpandHome(opts.binDir))
	if err != nil {
		return err
	}
	unitDir, cfgAbs, err := prepareInstallPaths(cfgPath, binDir, opts)
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
		NoSystemd:         opts.noSystemd,
		Exec:              executor,
	})
	if err != nil {
		return err
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
		outf(w, "%s\n", ui.ChipKV("systemd units skipped (--no-systemd): ",
			"no timers installed; run the maintain wave manually or from your own scheduler", opts.color))
		return nil
	}
	printInstallSummary(w, cfg, cfgAbs, daemonCfg(opts, cfgPath), res, opts.color)
	outf(w, "%s\n", ui.ChipKV("journal: ", "journalctl --user -u assay-watch.service -f", opts.color))
	return nil
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
func printInstallSummary(w io.Writer, cfg *config.Config, cfgAbs string,
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
	if cfg != nil && cfg.Render.Template == "" && cfg.Activate.Target == "" {
		outf(w, "%s\n", ui.ChipKV("to activate:      ",
			"fill [render].template and [activate].target in the config above;", color))
		outf(w, "%s\n", ui.ChipKV("                  ",
			"until then render/activate fail loud at their stage boundary (data stages run)", color))
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
anything outside those two paths — in particular nothing xray-raw. The
config resolves the same way install does: explicit -c wins; the
default-location layout (no -c) purges the canonical
~/.local/share/assay/config.toml plus the data dir under it; the
deprecated legacy location still wins when present. The cwd default
(./config.toml) is never consulted — a purge must never depend on the
caller's working directory.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var ir installResolution
			if purge {
				var err error
				ir, err = resolveInstallPath(*cfgPath)
				if err != nil {
					return fmt.Errorf("--purge needs the config: %w", err)
				}
				reportConfigSource(cmd.OutOrStdout(), ir.res)
			}
			var cfg *config.Config
			if ir.res != nil {
				cfg = ir.res.Config
			}
			// C-1: ir.res is nil on the non-purge path — only --purge resolves a
			// config. cfgPath must stay "" there (runUninstall's purge branch
			// is the only consumer), never a nil dereference.
			var cfgPath string
			if ir.res != nil {
				cfgPath = ir.res.Path
			}
			// W13-deploy: the default-location install (--purge without -c)
			// purges the canonical local-share config — the materialized
			// default — plus the data dir (never the caller's cwd file).
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
	unitDir, err := absDir(config.ExpandHome(opts.unitDir))
	if err != nil {
		return err
	}
	executor := opts.exec
	if executor == nil {
		executor = installExecutor()
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
	binPath := filepath.Join(binDir, "assay")
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
