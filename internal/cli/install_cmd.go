package cli

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
		Use:   "install",
		Short: "Self-install: copy the running binary and render + enable the watch daemon unit",
		Long: `Copies the RUNNING binary (os.Executable) to --bin-dir as ` + "`publicvpn`" + `
(atomic write, mode 0755; re-running after a rebuild = self-upgrade), then
renders the watch-daemon unit from the repo template and enables it:

  systemctl --user daemon-reload
  systemctl --user enable --now public_vpn-watch.service

The daemon (publicvpn watch) runs the plugin watchdog and the maintain-wave
scheduler; [maintain].refresh_interval / [maintain].speedtest_interval and
[plugins].dir are read from the config LIVE — changing them needs only a
restart of the unit, never a re-install. Legacy W5 timer units
(public_vpn-refresh/speedtest.*) still on disk are disabled and removed by
this install: waves fire from exactly ONE scheduler. Config files are NEVER
created or moved: the unit references the resolved --config path, so it must
be absolute or ~-expanded and must stay in place.

Install REQUIRES a resolvable config (the unit embeds its path): an explicit
-c wins and must exist; otherwise the home default
(~/.config/publicvpn/config.toml) is used when present; otherwise install
fails loud with guidance. The CWD default (./config.toml) is deliberately
NOT consulted — a daemon unit must reference a stable location, never the
directory the operator happened to stand in.

--no-systemd installs the binary only (hosts without a systemd user session;
the unit is skipped).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveInstallPath(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			return runInstall(cmd.OutOrStdout(), res.Config, res.Path, installOptions{
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

func runInstall(w io.Writer, _ *config.Config, cfgPath string, opts installOptions) error {
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
		executor = installExecutor()
	}
	res, err := install.Install(install.Options{
		BinDir:        binDir,
		UnitDir:       unitDir,
		RunningBinary: running,
		ConfigPath:    cfgAbs,
		NoSystemd:     opts.noSystemd,
		Exec:          executor,
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
	outln(w, "daemon active:    publicvpn watch (Restart=always) — wave intervals and the plugins dir")
	outln(w, "                  are read from the config live (a change needs a restart, not a re-install)")
	for _, name := range res.LegacyCleaned {
		outf(w, "legacy removed:   %s (W5 timer unit — the daemon replaced the timers)\n", name)
	}
	outf(w, "config reference: %s (install never creates or moves it — keep it in place)\n", cfgAbs)
	outln(w, "journal: journalctl --user -u public_vpn-watch.service -f")
	return nil
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
still present, removes every known unit file (public_vpn-watch.service plus
the W5-era public_vpn-refresh/speedtest units), daemon-reloads the user
manager (so it drops its not-found entries for the removed units), and
reports. The installed binary and all user data are KEPT by default.

--purge is DESTRUCTIVE and must be passed explicitly: it also removes the
config file and the pipeline data dir ([data_dir]). It never touches
anything outside those two paths — in particular nothing xray-raw. The
config resolves the same way install does (explicit -c, else the home
default; never the cwd default): a purge must never depend on the caller's
working directory.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var res *config.Resolved
			if purge {
				var err error
				res, err = resolveInstallPath(*cfgPath)
				if err != nil {
					return fmt.Errorf("--purge needs the config: %w", err)
				}
				reportConfigSource(cmd.OutOrStdout(), res)
			}
			var cfg *config.Config
			if res != nil {
				cfg = res.Config
			}
			// C-1: res is nil on the non-purge path — only --purge resolves a
			// config. cfgPath must stay "" there (runUninstall's purge branch
			// is the only consumer), never a nil dereference.
			var cfgPath string
			if res != nil {
				cfgPath = res.Path
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
// awaiting migration. Read-only: pure filesystem inspection of the user unit
// dir, no systemctl. The daemon reads intervals from the config live, so —
// unlike the W5 timers — there is no configured-vs-installed mismatch class.
func printInstallStatus(out io.Writer, cfg *config.Config, cfgPath string) {
	outln(out, "install:")
	binPath := filepath.Join(config.ExpandHome("~/.local/bin"), "publicvpn")
	if st, err := os.Stat(binPath); err == nil {
		outf(out, "  binary:    %s (mode %s)\n", binPath, st.Mode())
		// W13 stale-binary notice (the owner's incident): the installed
		// binary does NOT self-update on `git pull` — a rebuilt-but-not-
		// reinstalled binary keeps running OLD code under the daemon unit.
		// A cheap sha256 pair names the drift and the recovery. Honest in
		// every divergence case, including dev builds (`go run` differs
		// from the install by definition).
		if running, e := os.Executable(); e == nil && running != binPath {
			if differ, shaErr := binariesDiffer(running, binPath); shaErr == nil && differ {
				outln(out, "  STALE:     running binary differs from the installed one — "+
					"the installed binary does not self-update; re-run `publicvpn install` "+
					"(self-copy) and restart public_vpn-watch.service to load the new code")
			}
		}
	} else {
		outln(out, "  binary:    not installed ("+binPath+" missing) — run `publicvpn install`")
	}
	unitDir := config.ExpandHome("~/.config/systemd/user")
	_, watchErr := os.Stat(filepath.Join(unitDir, install.WatchService))
	if watchErr != nil {
		outln(out, "  units:     watch daemon not rendered ("+unitDir+")")
	} else {
		outf(out, "  units:     %s present in %s\n", install.WatchService, unitDir)
		enabled := false
		for _, wants := range []string{"default.target.wants", "multi-user.target.wants"} {
			if _, err := os.Stat(filepath.Join(unitDir, wants, install.WatchService)); err == nil {
				enabled = true
			}
		}
		if enabled {
			outln(out, "  service:   enabled (wants symlink) — waves: refresh "+
				install.Span(cfg.Maintain.RefreshInterval.Duration)+", speedtest "+
				install.Span(cfg.Maintain.SpeedtestInterval.Duration)+" (read live from the config)")
		} else {
			outln(out, "  service:   not enabled — run `publicvpn install`")
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
			outf(out, "  LEGACY:    %d W5 timer units still on disk — re-run `publicvpn install -c %s` to migrate\n",
				present, cfgPath)
		} else {
			outf(out, "  LEGACY:    %d W5 timer units still on disk — re-run `publicvpn install` "+
				"with a config (-c or %s) to migrate\n", present, config.HomeConfigDisplay)
		}
	}
}
