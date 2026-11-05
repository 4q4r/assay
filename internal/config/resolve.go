// Config resolution (W12; tier 2 reworked in W13-deploy): the CLI never
// REQUIRES a config path. Exactly one source wins whole — explicit -c, else
// the local-share default (~/.local/share/publicvpn/config.toml, the XDG
// data root), else the DEPRECATED legacy home location
// (~/.config/publicvpn/config.toml — found-if-exists courtesy with a loud
// move warning, one release cycle), else the cwd default, else the built-in
// defaults (fully configless). There is no merging, ever: multiple merged
// config sources are rejected by the owner's house rule, so the first
// existing file in the documented order IS the configuration.

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// SourceKind identifies where the effective configuration came from. The
// provenance is part of the contract: every command prints it, and `status`
// carries a dedicated config-source line.
type SourceKind int

const (
	// SourceExplicit means the user passed -c <path>; the file must exist.
	SourceExplicit SourceKind = iota
	// SourceShare means <local-share>/publicvpn/config.toml existed and was
	// loaded — the W13-deploy canonical default location (the XDG data root:
	// $XDG_DATA_HOME/publicvpn when the env var is absolute, else
	// ~/.local/share/publicvpn).
	SourceShare
	// SourceLegacyHome means the DEPRECATED pre-W13 home default
	// (~/.config/publicvpn/config.toml) existed and was loaded — the one
	// release-cycle courtesy: the file keeps working, the loud deprecation
	// warning (in Resolved.Warnings) names the move.
	SourceLegacyHome
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
	case SourceShare:
		return "local-share default"
	case SourceLegacyHome:
		return "legacy home default"
	case SourceCwd:
		return "cwd default"
	case SourceConfigless:
		return "configless (built-in defaults)"
	default:
		return fmt.Sprintf("unknown config source (%d)", int(s))
	}
}

// ShareConfigDisplay is the canonical local-share config spelling used in
// every user-facing message (docs, help texts, loud errors) — the W13-deploy
// default location.
const ShareConfigDisplay = "~/.local/share/publicvpn/config.toml"

// LegacyHomeConfigDisplay is the deprecated pre-W13 home config spelling —
// it survives ONLY in the deprecation warning and the migration notes.
const LegacyHomeConfigDisplay = "~/.config/publicvpn/config.toml"

// LegacyLocationWarning is the loud one-release-cycle deprecation courtesy:
// the legacy ~/.config location still loads (found-if-exists), but every
// resolution that finds it carries this warning verbatim.
func LegacyLocationWarning(path, canonical string) string {
	return "legacy config location detected: " + path +
		" — move it to " + canonical +
		" (the ~/.config/publicvpn location is deprecated and will stop being honored in a future release)"
}

// ConfiglessBoundaryError is the loud stage boundary: render/activate need a
// configured template/target, and a configless run has neither — the stage
// refuses with the actionable message instead of silently defaulting to the
// live client's config.
func ConfiglessBoundaryError(stage string) error {
	return fmt.Errorf("configless mode cannot %s — provide -c or a config at %s", stage, ShareConfigDisplay)
}

// DefaultShareConfigPath returns the canonical local-share config path under
// the given home directory (the XDG data root: DefaultDataDir's parent
// scheme — $XDG_DATA_HOME/publicvpn when the env var is absolute, else
// ~/.local/share/publicvpn). One scheme for the whole local-share layout.
func DefaultShareConfigPath(home string) string {
	return filepath.Join(DefaultDataDir(home), "config.toml")
}

// LegacyHomeConfigPath returns the DEPRECATED pre-W13 home-default config
// path under the given home directory (found-if-exists courtesy only).
func LegacyHomeConfigPath(home string) string {
	return filepath.Join(home, ".config", "publicvpn", "config.toml")
}

// DefaultDataDir returns the configless data dir: $XDG_DATA_HOME/publicvpn
// when XDG_DATA_HOME is set to an ABSOLUTE path, else the XDG user-data
// fallback ~/.local/share/publicvpn under the given home (M-1: the env var
// is part of the resolution contract, honored wherever the configless
// default applies — the data dir AND the local-share config tier alike).
//
// A set-but-RELATIVE XDG_DATA_HOME is spec-invalid (the XDG Base Directory
// spec requires absolute paths): it is treated as UNSET — never a crash,
// never a relative data dir — and reported by XDGDataDirViolation so callers
// can warn loud.
func DefaultDataDir(home string) string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" && filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "publicvpn")
	}
	return filepath.Join(home, ".local", "share", "publicvpn")
}

// XDGDataDirViolation reports a spec-invalid XDG_DATA_HOME (set but
// relative — the XDG Base Directory spec requires absolute values) as a
// loud, specific warning message; "" means the value is valid or unset.
// Spec-invalid values are IGNORED per XDG semantics (DefaultDataDir falls
// back to the home default) — the violation is surfaced, never fatal.
func XDGDataDirViolation() string {
	xdg := os.Getenv("XDG_DATA_HOME")
	if xdg == "" || filepath.IsAbs(xdg) {
		return ""
	}
	return "XDG_DATA_HOME=" + strconv.Quote(xdg) +
		" is relative — the XDG Base Directory spec requires an absolute path; " +
		"treating it as unset (data dir falls back to ~/.local/share/publicvpn)"
}

// Resolved is the effective configuration plus its provenance.
type Resolved struct {
	Config *Config
	Source SourceKind
	// Path is the absolute path of the loaded file; empty when configless.
	Path string
	// Warnings are loud resolution warnings (a spec-invalid relative
	// XDG_DATA_HOME treated as unset; the deprecated legacy home location
	// found on disk). Every command prints them next to the config-source
	// line; they never change the resolution outcome.
	Warnings []string
}

// Resolve applies the documented precedence to one effective config:
//
//  1. explicit != "" — the -c path wins ALWAYS; the file must exist (loud
//     error naming the path when missing — never a silent fall-through);
//  2. <local-share>/publicvpn/config.toml, if it exists (the W13-deploy
//     canonical default; $XDG_DATA_HOME honored, absolute-only);
//  3. <home>/.config/publicvpn/config.toml, if it exists — the DEPRECATED
//     legacy location, still honored as a one-release-cycle courtesy; the
//     resolution carries the loud move warning;
//  4. <cwd>/config.toml, if it exists;
//  5. no file at all — the fully configless built-in defaults.
//
// The first existing file wins WHOLE: strict decode, defaults, and validation
// behave exactly as before for every loaded file. home and cwd are injected
// so the resolution is hermetic under test (no real $HOME pollution). The
// deprecation warning fires whenever the legacy file exists — even when a
// higher tier won and the file is being ignored.
func Resolve(explicit, home, cwd string) (*Resolved, error) {
	if explicit != "" {
		return resolveExplicit(explicit, cwd)
	}
	return resolveImplicit(home, cwd)
}

// resolveExplicit pins the M-2 contract: a RELATIVE explicit path resolves
// against the INJECTED cwd (never a second scheme) — every command passes
// its cwd in, so the resolution is hermetic and single-scheme end to end
// (round-7 item 10: install-style callers pass the process cwd through
// instead of the old "" process-cwd fall-back). A missing explicit file is
// a loud error naming the path — never a silent fall-through.
func resolveExplicit(explicit, cwd string) (*Resolved, error) {
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

// resolveImplicit walks the documented default tiers (local-share → legacy
// courtesy → cwd → configless). The legacy deprecation warning fires
// whenever the legacy file exists, including when a higher tier won and the
// file is being ignored.
func resolveImplicit(home, cwd string) (*Resolved, error) {
	if home != "" {
		if p := DefaultShareConfigPath(home); fileExists(p) {
			cfg, err := Load(p)
			if err != nil {
				return nil, err
			}
			res := &Resolved{Config: cfg, Source: SourceShare, Path: p}
			if lp := LegacyHomeConfigPath(home); fileExists(lp) {
				res.Warnings = append(res.Warnings, LegacyLocationWarning(lp, ShareConfigDisplay))
			}
			return res, nil
		}
		if p := LegacyHomeConfigPath(home); fileExists(p) {
			cfg, err := Load(p)
			if err != nil {
				return nil, err
			}
			return &Resolved{
				Config: cfg, Source: SourceLegacyHome, Path: p,
				Warnings: []string{LegacyLocationWarning(p, ShareConfigDisplay)},
			}, nil
		}
	}
	if cwd != "" {
		if p := filepath.Join(cwd, "config.toml"); fileExists(p) {
			cfg, err := Load(p)
			if err != nil {
				return nil, err
			}
			res := &Resolved{Config: cfg, Source: SourceCwd, Path: p}
			// The legacy courtesy spans the whole chain: the file warns even
			// when the cwd tier wins over it.
			if home != "" {
				if lp := LegacyHomeConfigPath(home); fileExists(lp) {
					res.Warnings = append(res.Warnings, LegacyLocationWarning(lp, ShareConfigDisplay))
				}
			}
			return res, nil
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
	cfg := &Config{
		DataDir: DefaultDataDir(home),
		SelfUpdate: SelfUpdateConfig{
			Enabled:       true,
			CheckInterval: Duration{Duration: 30 * time.Second},
		},
		Probe: ProbeConfig{CalibrationEnabled: true},
	}
	applyDefaults(cfg, true)
	syncResourceConfig(cfg)
	res := &Resolved{Config: cfg, Source: SourceConfigless}
	if violation := XDGDataDirViolation(); violation != "" {
		res.Warnings = append(res.Warnings, violation)
	}
	return res, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
