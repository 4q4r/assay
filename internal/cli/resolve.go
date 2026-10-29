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

// resolveInstallPath resolves the config for `install` (and `uninstall
// --purge`): explicit -c wins; else the HOME default if it exists; else a
// loud, actionable error. The CWD default is deliberately NOT consulted —
// the rendered unit embeds the config path and must reference a stable
// location, never whatever directory the operator happened to stand in.
// A RELATIVE explicit -c resolves through the SAME single scheme as every
// other command: config.Resolve joins it onto the injected cwd (round-7
// item 10 — the pre-fix code passed cwd="" and silently switched to the
// process-cwd scheme; the cwd default consult above is unaffected).
func resolveInstallPath(explicit string) (*config.Resolved, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	if explicit != "" {
		return config.Resolve(explicit, home, cwd)
	}
	p := config.DefaultHomeConfigPath(home)
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf(
			"install requires a config file: pass -c /path/to/config.toml or create one at %s "+
				"(configless mode cannot install — the daemon unit must reference a real config path)",
			config.HomeConfigDisplay)
	}
	cfg, err := config.Load(p)
	if err != nil {
		return nil, err
	}
	return &config.Resolved{Config: cfg, Source: config.SourceHome, Path: p}, nil
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
