// Config resolution (W12): the CLI never REQUIRES a config path. Exactly one
// source wins whole — explicit -c, else the home default, else the cwd
// default, else the built-in defaults (fully configless). There is no
// merging, ever: multiple merged config sources are rejected by the owner's
// house rule, so the first existing file in the documented order IS the
// configuration.

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SourceKind identifies where the effective configuration came from. The
// provenance is part of the contract: every command prints it, and `status`
// carries a dedicated config-source line.
type SourceKind int

const (
	// SourceExplicit means the user passed -c <path>; the file must exist.
	SourceExplicit SourceKind = iota
	// SourceHome means ~/.config/publicvpn/config.toml existed and was loaded.
	SourceHome
	// SourceCwd means ./config.toml existed and was loaded (repo/owner
	// operational workflow keeps working).
	SourceCwd
	// SourceConfigless means no file anywhere — the built-in defaults run
	// the show (data_dir under the XDG data dir).
	SourceConfigless
)

// String renders the provenance exactly as commands print it.
func (s SourceKind) String() string {
	switch s {
	case SourceExplicit:
		return "explicit -c"
	case SourceHome:
		return "home default"
	case SourceCwd:
		return "cwd default"
	case SourceConfigless:
		return "configless (built-in defaults)"
	default:
		return fmt.Sprintf("unknown config source (%d)", int(s))
	}
}

// HomeConfigDisplay is the canonical home-config spelling used in every
// user-facing message (docs, help texts, loud errors).
const HomeConfigDisplay = "~/.config/publicvpn/config.toml"

// ConfiglessBoundaryError is the loud stage boundary: render/activate need a
// configured template/target, and a configless run has neither — the stage
// refuses with the actionable message instead of silently defaulting to the
// live client's config.
func ConfiglessBoundaryError(stage string) error {
	return fmt.Errorf("configless mode cannot %s — provide -c or a config at %s", stage, HomeConfigDisplay)
}

// DefaultHomeConfigPath returns the home-default config path under the given
// home directory.
func DefaultHomeConfigPath(home string) string {
	return filepath.Join(home, ".config", "publicvpn", "config.toml")
}

// DefaultDataDir returns the configless data dir: $XDG_DATA_HOME/publicvpn
// when XDG_DATA_HOME is set (non-empty), else the XDG user-data fallback
// ~/.local/share/publicvpn under the given home (M-1: the env var is part of
// the resolution contract, honored wherever the configless default applies).
func DefaultDataDir(home string) string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "publicvpn")
	}
	return filepath.Join(home, ".local", "share", "publicvpn")
}

// Resolved is the effective configuration plus its provenance.
type Resolved struct {
	Config *Config
	Source SourceKind
	// Path is the absolute path of the loaded file; empty when configless.
	Path string
}

// Resolve applies the documented precedence to one effective config:
//
//  1. explicit != "" — the -c path wins ALWAYS; the file must exist (loud
//     error naming the path when missing — never a silent fall-through);
//  2. <home>/.config/publicvpn/config.toml, if it exists;
//  3. <cwd>/config.toml, if it exists;
//  4. no file at all — the fully configless built-in defaults.
//
// The first existing file wins WHOLE: strict decode, defaults, and validation
// behave exactly as before for every loaded file. home and cwd are injected
// so the resolution is hermetic under test (no real $HOME pollution).
func Resolve(explicit, home, cwd string) (*Resolved, error) {
	if explicit != "" {
		// M-2: a RELATIVE explicit path resolves against the INJECTED cwd
		// (never the process cwd) — hermetic resolution stays injectable end
		// to end. An empty injected cwd (install-style resolution passes "")
		// keeps the process-cwd behavior.
		abs := explicit
		if !filepath.IsAbs(abs) {
			if cwd != "" {
				abs = filepath.Join(cwd, abs)
			} else {
				var err error
				if abs, err = filepath.Abs(abs); err != nil {
					return nil, fmt.Errorf("resolve config path: %w", err)
				}
			}
		}
		if _, err := os.Stat(abs); err != nil {
			return nil, fmt.Errorf("config not found at %s (explicit -c must exist — there is no fall-through)", abs)
		}
		cfg, err := Load(abs)
		if err != nil {
			return nil, err
		}
		return &Resolved{Config: cfg, Source: SourceExplicit, Path: abs}, nil
	}
	if home != "" {
		p := DefaultHomeConfigPath(home)
		if fileExists(p) {
			cfg, err := Load(p)
			if err != nil {
				return nil, err
			}
			return &Resolved{Config: cfg, Source: SourceHome, Path: p}, nil
		}
	}
	if cwd != "" {
		p := filepath.Join(cwd, "config.toml")
		if fileExists(p) {
			cfg, err := Load(p)
			if err != nil {
				return nil, err
			}
			return &Resolved{Config: cfg, Source: SourceCwd, Path: p}, nil
		}
	}
	return configless(home)
}

// configless builds the no-file configuration: data_dir at the XDG default,
// every knob at its documented default — EXCEPT render.template and
// activate.target, which stay EMPTY on purpose: they are the loud stage
// boundaries (configless mode cannot render/activate). An empty home is API
// misuse (M-3): callers must inject a real home — returning the config
// would build a RELATIVE data dir, so it fails loud instead.
func configless(home string) (*Resolved, error) {
	if home == "" {
		return nil, errors.New("configless: empty home is API misuse — inject a real home directory")
	}
	cfg := &Config{DataDir: DefaultDataDir(home)}
	applyDefaults(cfg, true)
	return &Resolved{Config: cfg, Source: SourceConfigless}, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
