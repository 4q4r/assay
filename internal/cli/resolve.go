// CLI-side config resolution (W12): the shared funnel every command uses to
// turn the optional -c flag into one effective config plus its visible
// provenance. The precedence itself lives in config.Resolve (single source);
// this layer owns the process seams (HOME, cwd) and the printed source line.

package cli

import (
	"fmt"
	"io"
	"os"

	"public_vpn/internal/config"
)

// resolveCommand resolves the effective config for a regular command:
// explicit -c > home default > cwd default > configless. HOME and the
// working directory are the process seams — tests inject both via
// t.Setenv/t.Chdir, so the suite never touches the real machine.
func resolveCommand(explicit string) (*config.Resolved, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	return config.Resolve(explicit, home, cwd)
}

// installResolution is the install-style resolution: the effective config,
// whether the unit must embed `-c <path>` (explicit -c and the legacy
// courtesy — the daemon must be pointed at those files), and — when NO
// config file exists anywhere in the install-style chain — the canonical
// local-share path the default config must be materialized at (the daemon
// then reads the default location; no -c in the unit).
type installResolution struct {
	res *config.Resolved
	// embedsConfig: explicit -c and legacy-path installs render
	// `watch -c <path>`; share-default and configless (default-location)
	// installs render plain `watch` — the daemon reads the default location.
	embedsConfig bool
	// materializePath is non-empty only for the configless case.
	materializePath string
}

// resolveInstallPath resolves the config for `install` (and `uninstall
// --purge`): explicit -c wins and must exist; else the canonical
// local-share default when present; else the DEPRECATED legacy home
// location (one-release-cycle courtesy — loud move warning, the unit embeds
// its exact path so the owner's tuned config keeps working); else — and
// this is the W13-deploy canonical user flow — a CONFIGLESS resolution and
// a non-empty materializePath: install materializes the default config at
// ~/.local/share/publicvpn/config.toml and the daemon unit runs plain
// `watch`. A no--c install is default-location FOREVER: even after the
// first install materialized the share config, a re-install renders plain
// `watch` (the daemon reads the default location — the unit never flips to
// -c). The CWD default is deliberately NOT consulted — a daemon unit must
// reference a stable location, never whatever directory the operator
// happened to stand in. A RELATIVE explicit -c resolves through the SAME
// single scheme as every other command: config.Resolve joins it onto the
// injected cwd (round-7 item 10).
func resolveInstallPath(explicit string) (installResolution, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return installResolution{}, fmt.Errorf("resolve home dir: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return installResolution{}, fmt.Errorf("resolve working directory: %w", err)
	}
	if explicit != "" {
		res, err := config.Resolve(explicit, home, cwd)
		return installResolution{res: res, embedsConfig: true}, err
	}
	if p := config.DefaultShareConfigPath(home); pathExists(p) {
		cfg, err := config.Load(p)
		if err != nil {
			return installResolution{}, err
		}
		return installResolution{
			res: &config.Resolved{Config: cfg, Source: config.SourceShare, Path: p},
		}, nil
	}
	if p := config.LegacyHomeConfigPath(home); pathExists(p) {
		cfg, err := config.Load(p)
		if err != nil {
			return installResolution{}, err
		}
		return installResolution{res: &config.Resolved{
			Config: cfg, Source: config.SourceLegacyHome, Path: p,
			Warnings: []string{config.LegacyLocationWarning(p, config.ShareConfigDisplay)},
		}, embedsConfig: true}, nil
	}
	res, err := config.Resolve("", home, "")
	if err != nil {
		return installResolution{}, err
	}
	return installResolution{
		res:             res,
		materializePath: config.DefaultShareConfigPath(home),
	}, nil
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// reportConfigSource prints the resolved provenance — the visibility
// contract: every command prints the line, `status` carries it too.
// Resolution warnings (e.g. a spec-invalid relative XDG_DATA_HOME treated
// as unset) print loud right after the config line — visible, attributed,
// never fatal.
func reportConfigSource(w io.Writer, res *config.Resolved) {
	if res.Path != "" {
		outf(w, "config: %s %s\n", res.Source, res.Path)
	} else {
		outf(w, "config: %s\n", res.Source)
	}
	for _, warning := range res.Warnings {
		outf(w, "warning: %s\n", warning)
	}
}
