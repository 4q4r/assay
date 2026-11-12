package platform

import (
	"os"
	"path/filepath"
)

// DefaultDataDir returns the per-OS default data dir (§4.2 "Default data
// dir") under the given home directory, and whether one resolved.
//
//   - linux: $XDG_DATA_HOME/assay when XDG_DATA_HOME is set to an ABSOLUTE
//     path (a set-but-relative value is spec-invalid and treated as unset —
//     the XDG Base Directory spec), else <home>/.local/share/assay — the
//     pre-S0 XDG resolution, byte-identical (the resolve goldens pin it).
//   - darwin: <home>/Library/Application Support/assay (os.UserConfigDir's
//     darwin answer). XDG_DATA_HOME is NOT honored — no XDG contract on
//     macOS (§1.3).
//   - windows: %LOCALAPPDATA%\assay, falling back to the home-profile path
//     <home>\AppData\Local\assay when the env var is empty (§2.2.6).
//
// ok=false means the platform's inputs were insufficient (an empty home
// with no env fallback) — callers treat it as a resolution refusal, never
// a relative-path guess.
func DefaultDataDir(goos, home string) (string, bool) {
	switch goos {
	case "darwin":
		if home == "" {
			return "", false
		}
		return filepath.Join(home, "Library", "Application Support", "assay"), true
	case "windows":
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			return filepath.Join(local, "assay"), true
		}
		if home == "" {
			return "", false
		}
		return filepath.Join(home, "AppData", "Local", "assay"), true
	default:
		// linux (and any other unix target): the XDG contract.
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" && filepath.IsAbs(xdg) {
			return filepath.Join(xdg, "assay"), true
		}
		if home == "" {
			return "", false
		}
		return filepath.Join(home, ".local", "share", "assay"), true
	}
}

// SystemXrayPaths returns the system-bind scan list of the core-binary
// resolution for goos (§4.2 "System-bind scan list"): linux keeps the FHS
// pair byte-identical (config.DefaultSystemXrayPaths's pre-S0 literal);
// darwin adds the Apple-silicon homebrew prefix (/opt/homebrew/bin);
// windows is EMPTY — upstream xray ships zips with no standard install
// location there, so resolution is override/managed-only (§2.2.11). Every
// call returns a fresh slice: the values back the injectable
// config.DefaultSystemXrayPaths var, and callers may mutate what they got
// without corrupting the table.
func SystemXrayPaths(goos string) []string {
	switch goos {
	case "windows":
		return []string{}
	case "darwin":
		return []string{"/usr/local/bin/xray", "/opt/homebrew/bin/xray"}
	default:
		return []string{"/usr/local/bin/xray", "/usr/bin/xray"}
	}
}

// XDGHonored reports whether the XDG_DATA_HOME environment contract
// applies to goos (§5.1): linux-only. resolve.go consults this oracle
// before honoring or warning about XDG_DATA_HOME — launchd agents and
// windows services never see XDG semantics.
func XDGHonored(goos string) bool {
	return goos == "linux"
}
