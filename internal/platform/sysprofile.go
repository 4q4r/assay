package platform

import (
	"path/filepath"
	"strings"
)

// windowsGOOS is the per-OS table key for windows (§4.2): one definition
// beats seven repeated literals across the GOOS tables.
const windowsGOOS = "windows"

// windowsRootFallback is the documented Windows installation root, used when
// neither SystemRoot nor WINDIR is set (the env vars are always present on a
// real Windows system; the fallback keeps the SYSTEM-profile check total
// rather than silently disabled).
const windowsRootFallback = `C:\Windows`

// SystemProfilePrefix returns the Windows SYSTEM profile root for goos —
// <windir>\System32\config\systemprofile, the profile the LocalSystem
// service account owns (plan §2.2.5): under the service,
// os.UserHomeDir() and %LOCALAPPDATA% resolve inside it, so a
// default-location data dir would silently land in the SYSTEM's profile.
// An empty windir falls back to the documented root. Every other GOOS has
// no SYSTEM profile — "" (the caller treats it as "the check cannot
// apply").
func SystemProfilePrefix(goos, windir string) string {
	if goos != windowsGOOS {
		return ""
	}
	if windir == "" {
		windir = windowsRootFallback
	}
	// Joined by hand (never filepath.Join): this table must produce the
	// windows-shaped path on EVERY host — the GOOS-neutral suite pins it
	// from linux, where filepath.Join would splice '/' separators.
	return strings.ReplaceAll(filepath.Join(windir, "System32", "config", "systemprofile"), "/", `\`)
}

// UnderSystemProfile reports whether path is the SYSTEM profile root itself
// or lives under it (the §2.2.5 refusal trigger). Windows paths are
// case-insensitive and may carry either separator — the check normalizes
// both, and a prefix that only EXTENDS the profile root (systemprofile-extra)
// does not match. An empty prefix (the check cannot apply) never matches.
func UnderSystemProfile(path, prefix string) bool {
	if path == "" || prefix == "" {
		return false
	}
	p := normalizeWindowsPath(path)
	q := normalizeWindowsPath(prefix)
	if !strings.HasPrefix(p, q) {
		return false
	}
	return len(p) == len(q) || p[len(q)] == '\\' || p[len(q)] == '/'
}

// normalizeWindowsPath folds a windows path into the canonical comparison
// shape: both separators become '\', case-folded (Windows path semantics).
func normalizeWindowsPath(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	return strings.ToLower(p)
}
