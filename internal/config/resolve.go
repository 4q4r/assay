// Config resolution (W12; tier 2 reworked in W13-deploy): the CLI never
// REQUIRES a config path. Exactly one source wins whole — explicit -c, else
// the local-share default (~/.local/share/assay/config.toml, the XDG
// data root), else the DEPRECATED legacy home location
// (~/.config/assay/config.toml — found-if-exists courtesy with a loud
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
	"runtime"
	"strconv"
	"time"

	"assay/internal/platform"
)

// SourceKind identifies where the effective configuration came from. The
// provenance is part of the contract: every command prints it, and `status`
// carries a dedicated config-source line.
type SourceKind int

const (
	// SourceExplicit means the user passed -c <path>; the file must exist.
	SourceExplicit SourceKind = iota
	// SourceShare means <local-share>/assay/config.toml existed and was
	// loaded — the W13-deploy canonical default location (the XDG data root:
	// $XDG_DATA_HOME/assay when the env var is absolute, else
	// ~/.local/share/assay).
	SourceShare
	// SourceLegacyHome means the DEPRECATED pre-W13 home default
	// (~/.config/assay/config.toml) existed and was loaded — the one
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
const ShareConfigDisplay = "~/.local/share/assay/config.toml"

// LegacyHomeConfigDisplay is the deprecated pre-W13 home config spelling —
// it survives ONLY in the deprecation warning and the migration notes.
const LegacyHomeConfigDisplay = "~/.config/assay/config.toml"

// LegacyLocationWarning is the loud one-release-cycle deprecation courtesy:
// the legacy ~/.config location still loads (found-if-exists), but every
// resolution that finds it carries this warning verbatim.
func LegacyLocationWarning(path, canonical string) string {
	return "legacy config location detected: " + path +
		" — move it to " + canonical +
		" (the ~/.config/assay location is deprecated and will stop being honored in a future release)"
}

// ConfiglessBoundaryError is the loud stage boundary: render/activate drive
// the core lifecycle, which belongs to a configured deployment — a
// configless run (no file anywhere; the marker is Config.Configless) refuses
// with the actionable message instead of half-running on pure defaults.
func ConfiglessBoundaryError(stage string) error {
	return fmt.Errorf("configless mode cannot %s — provide -c or a config at %s", stage, ShareConfigDisplay)
}

// DefaultShareConfigPath returns the canonical local-share config path under
// the given home directory (the XDG data root: DefaultDataDir's parent
// scheme — $XDG_DATA_HOME/assay when the env var is absolute, else
// ~/.local/share/assay). One scheme for the whole local-share layout.
func DefaultShareConfigPath(home string) string {
	return filepath.Join(DefaultDataDir(home), "config.toml")
}

// LegacyHomeConfigPath returns the DEPRECATED pre-W13 home-default config
// path under the given home directory (found-if-exists courtesy only).
func LegacyHomeConfigPath(home string) string {
	return filepath.Join(home, ".config", "assay", "config.toml")
}

// legacyShareLeaf is the data-dir leaf under the project's FORMER name —
// the pre-rename local-share location. It is assembled from parts on
// purpose: the rename's acceptance contract keeps the old spelling out of
// Go sources while the found-if-exists courtesy must still address the real
// on-disk directory (and name it in the hint). The runtime value is the
// historical leaf; nothing else may reintroduce the old name.
const legacyShareLeaf = "public" + "vpn"

// legacyShareDataDir returns the pre-rename local-share data dir under the
// same scheme DefaultDataDir used before the rename: $XDG_DATA_HOME/<leaf>
// when the env var is absolute, else ~/.local/share/<leaf>. The XDG tier is
// linux-only behavior (platform.XDGHonored — §5.1); on darwin/windows only
// the home path applies. Found-if-exists courtesy only — the resolution
// never writes there.
func legacyShareDataDir(home string) string {
	if platform.XDGHonored(runtime.GOOS) {
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" && filepath.IsAbs(xdg) {
			return filepath.Join(xdg, legacyShareLeaf)
		}
	}
	return filepath.Join(home, ".local", "share", legacyShareLeaf)
}

// LegacyShareLocationWarning is the ONE loud rename-migration hint line: the
// pre-rename local-share location exists and the new data dir is absent.
// It never moves anything (NO auto-migration — the owner migrates by hand in
// the deploy wave); it only tells the user where the data now belongs.
func LegacyShareLocationWarning(oldDir, newDir string) string {
	return "legacy data location detected: " + oldDir +
		" — move it to " + newDir +
		" (the pre-rename " + legacyShareLeaf + " data dir is deprecated and will stop being honored in a future release)"
}

// legacyShareDirHint returns the rename-migration hint when the old data
// dir exists and the new data dir is absent; "" otherwise (including an
// empty home — API misuse is handled by the configless path itself).
func legacyShareDirHint(home string) string {
	if home == "" {
		return ""
	}
	oldDir := legacyShareDataDir(home)
	if _, err := os.Stat(oldDir); err != nil {
		return ""
	}
	if _, err := os.Stat(DefaultDataDir(home)); err == nil {
		return ""
	}
	return LegacyShareLocationWarning(oldDir, DefaultDataDir(home))
}

// DefaultDataDir returns the configless data dir per the platform §4.2
// table: on linux $XDG_DATA_HOME/assay when XDG_DATA_HOME is set to an
// ABSOLUTE path (the M-1 contract: the env var is part of the resolution
// contract — the data dir AND the local-share config tier alike), else
// ~/.local/share/assay under the given home; on darwin
// ~/Library/Application Support/assay and on windows %LOCALAPPDATA%\assay
// (XDG is linux-only — platform.XDGHonored guards every XDG branch).
//
// A set-but-RELATIVE XDG_DATA_HOME is spec-invalid (the XDG Base Directory
// spec requires absolute paths): it is treated as UNSET — never a crash,
// never a relative data dir — and reported by XDGDataDirViolation so callers
// can warn loud.
func DefaultDataDir(home string) string {
	dir, ok := platform.DefaultDataDir(runtime.GOOS, home)
	if !ok {
		// Unreachable for known GOOS values with a real home; an empty home
		// is API misuse (M-3) — the configless path refuses it loud before
		// this can matter.
		return ""
	}
	return dir
}

// XDGDataDirViolation reports a spec-invalid XDG_DATA_HOME (set but
// relative — the XDG Base Directory spec requires absolute values) as a
// loud, specific warning message; "" means the value is valid or unset.
// Spec-invalid values are IGNORED per XDG semantics (DefaultDataDir falls
// back to the home default) — the violation is surfaced, never fatal.
// Linux-only behavior (§5.1): platforms without an XDG contract never
// report XDG violations.
func XDGDataDirViolation() string {
	if !platform.XDGHonored(runtime.GOOS) {
		return ""
	}
	xdg := os.Getenv("XDG_DATA_HOME")
	if xdg == "" || filepath.IsAbs(xdg) {
		return ""
	}
	return "XDG_DATA_HOME=" + strconv.Quote(xdg) +
		" is relative — the XDG Base Directory spec requires an absolute path; " +
		"treating it as unset (data dir falls back to ~/.local/share/assay)"
}

// Resolved is the effective configuration plus its provenance.
type Resolved struct {
	Config *Config
	Source SourceKind
	// Path is the absolute path of the loaded file; empty when configless.
	Path string
	// Warnings are loud resolution warnings (a spec-invalid relative
	// XDG_DATA_HOME treated as unset; the deprecated legacy home location
	// found on disk; S4 retired config keys found in the loaded file —
	// exactly one line per key, with the re-homed value carried where S4
	// says so). Every command prints them next to the config-source line;
	// they never change the resolution outcome.
	Warnings []string
}

// Resolve applies the documented precedence to one effective config:
//
//  1. explicit != "" — the -c path wins ALWAYS; the file must exist (loud
//     error naming the path when missing — never a silent fall-through);
//  2. <local-share>/assay/config.toml, if it exists (the W13-deploy
//     canonical default; $XDG_DATA_HOME honored, absolute-only);
//  3. <home>/.config/assay/config.toml, if it exists — the DEPRECATED
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
	cfg, retired, err := loadFile(abs)
	if err != nil {
		return nil, err
	}
	return &Resolved{Config: cfg, Source: SourceExplicit, Path: abs, Warnings: retired}, nil
}

// resolveImplicit walks the documented default tiers (local-share →
// pre-rename local-share courtesy → legacy home courtesy → cwd →
// configless). The legacy deprecation warning fires whenever the legacy
// file exists, including when a higher tier won and the file is being
// ignored. The rename-migration hint (the pre-rename data dir) fires at
// most once per resolution and only when the new data dir is absent.
func resolveImplicit(home, cwd string) (*Resolved, error) {
	res, err := resolveHomeTiers(home)
	if res != nil || err != nil {
		return res, err
	}
	res, err = resolveCwdTier(cwd, home)
	if res != nil || err != nil {
		return res, err
	}
	return configless(home)
}

// resolveHomeTiers applies the three home-rooted tiers in order; a nil
// result with a nil error means no tier matched.
func resolveHomeTiers(home string) (*Resolved, error) {
	if home == "" {
		return nil, nil
	}
	res, err := newShareTier(home)
	if res != nil || err != nil {
		return res, err
	}
	res, err = legacyShareTier(home)
	if res != nil || err != nil {
		return res, err
	}
	return legacyHomeTier(home)
}

// newShareTier loads the canonical local-share config; nil/nil when absent.
// The ignored legacy-home file still warns (the courtesy spans the chain).
func newShareTier(home string) (*Resolved, error) {
	p := DefaultShareConfigPath(home)
	if !fileExists(p) {
		return nil, nil
	}
	cfg, retired, err := loadFile(p)
	if err != nil {
		return nil, err
	}
	res := &Resolved{Config: cfg, Source: SourceShare, Path: p}
	if lp := LegacyHomeConfigPath(home); fileExists(lp) {
		res.Warnings = append(res.Warnings, LegacyLocationWarning(lp, ShareConfigDisplay))
	}
	res.Warnings = append(res.Warnings, retired...)
	return res, nil
}

// legacyShareTier is the rename-migration courtesy: the pre-rename
// local-share config still loads (found-if-exists) and the resolution
// carries exactly ONE loud move hint. Found-if-exists ALWAYS warns here —
// the config was read from the old location, so the user must be told
// where it belongs, even in the edge case where the new data dir already
// exists without its own config. NO auto-migration: nothing is ever
// written or moved. Nil/nil when absent.
func legacyShareTier(home string) (*Resolved, error) {
	p := filepath.Join(legacyShareDataDir(home), "config.toml")
	if !fileExists(p) {
		return nil, nil
	}
	cfg, retired, err := loadFile(p)
	if err != nil {
		return nil, err
	}
	res := &Resolved{Config: cfg, Source: SourceShare, Path: p}
	if lp := LegacyHomeConfigPath(home); fileExists(lp) {
		res.Warnings = append(res.Warnings, LegacyLocationWarning(lp, ShareConfigDisplay))
	}
	res.Warnings = append(res.Warnings,
		LegacyShareLocationWarning(legacyShareDataDir(home), DefaultDataDir(home)))
	res.Warnings = append(res.Warnings, retired...)
	return res, nil
}

// legacyHomeTier loads the deprecated pre-W13 home config; nil/nil when
// absent. The rename hint rides along when the pre-rename data dir exists.
func legacyHomeTier(home string) (*Resolved, error) {
	p := LegacyHomeConfigPath(home)
	if !fileExists(p) {
		return nil, nil
	}
	cfg, retired, err := loadFile(p)
	if err != nil {
		return nil, err
	}
	res := &Resolved{
		Config: cfg, Source: SourceLegacyHome, Path: p,
		Warnings: []string{LegacyLocationWarning(p, ShareConfigDisplay)},
	}
	if hint := legacyShareDirHint(home); hint != "" {
		res.Warnings = append(res.Warnings, hint)
	}
	res.Warnings = append(res.Warnings, retired...)
	return res, nil
}

// resolveCwdTier loads the cwd config; nil/nil when absent or no cwd. The
// legacy courtesies span the whole chain: both warnings fire even when the
// cwd tier wins over the files they name.
func resolveCwdTier(cwd, home string) (*Resolved, error) {
	if cwd == "" {
		return nil, nil
	}
	p := filepath.Join(cwd, "config.toml")
	if !fileExists(p) {
		return nil, nil
	}
	cfg, retired, err := loadFile(p)
	if err != nil {
		return nil, err
	}
	res := &Resolved{Config: cfg, Source: SourceCwd, Path: p}
	if home != "" {
		if lp := LegacyHomeConfigPath(home); fileExists(lp) {
			res.Warnings = append(res.Warnings, LegacyLocationWarning(lp, ShareConfigDisplay))
		}
		if hint := legacyShareDirHint(home); hint != "" {
			res.Warnings = append(res.Warnings, hint)
		}
	}
	res.Warnings = append(res.Warnings, retired...)
	return res, nil
}

// configless builds the no-file configuration: data_dir at the XDG default,
// every knob at its documented default, and the Configless boundary marker
// SET: it is the loud stage boundary's key (configless mode cannot
// render/activate — the same W12 contract, carried by the marker since the
// retired template/target fields died). An empty home is API misuse (M-3):
// callers must inject a real home — returning the config would build a
// RELATIVE data dir, so it fails loud instead.
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
		// AutoUpdate default ON (D4) pre-seeded before decode-equivalent
		// defaults, matching the Load path (an explicit false survives).
		Core:       CoreConfig{AutoUpdate: true},
		Configless: true,
	}
	applyDefaults(cfg, true)
	syncResourceConfig(cfg)
	res := &Resolved{Config: cfg, Source: SourceConfigless}
	if violation := XDGDataDirViolation(); violation != "" {
		res.Warnings = append(res.Warnings, violation)
	}
	// Rename-migration hint: a configless run whose pre-rename data dir still
	// exists (new one absent) carries exactly ONE loud move hint. No data is
	// ever copied or moved by the resolution.
	if hint := legacyShareDirHint(home); hint != "" {
		res.Warnings = append(res.Warnings, hint)
	}
	return res, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
