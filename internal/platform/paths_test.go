package platform

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultDataDirTable pins the §4.2 path-table row "Default data dir"
// for all three release GOOSes. The linux XDG branches are byte-pinned
// against the existing resolve goldens (config.TestDefaultDataDirHonorsXDGDataHome,
// config.TestDefaultDataDirUnsetFallsBack,
// config.TestDefaultDataDirTreatsRelativeXDGAsUnset) — linux behavior must
// stay byte-identical through the S0 delegation.
func TestDefaultDataDirTable(t *testing.T) {
	t.Run("linux absolute XDG_DATA_HOME wins", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "/custom/xdg-data")
		dir, ok := DefaultDataDir("linux", "/home/tester")
		require.True(t, ok)
		assert.Equal(t, filepath.Join("/custom/xdg-data", "assay"), dir,
			"the resolve golden: an absolute XDG_DATA_HOME wins verbatim")
	})
	t.Run("linux unset XDG falls back to home", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "")
		dir, ok := DefaultDataDir("linux", "/home/tester")
		require.True(t, ok)
		assert.Equal(t, filepath.Join("/home/tester", ".local", "share", "assay"), dir,
			"the resolve golden: ~/.local/share/assay fallback")
	})
	t.Run("linux relative XDG treated as unset", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "relative/path")
		dir, ok := DefaultDataDir("linux", "/home/tester")
		require.True(t, ok)
		assert.Equal(t, filepath.Join("/home/tester", ".local", "share", "assay"), dir,
			"spec-invalid relative XDG_DATA_HOME is ignored (XDG Base Directory spec)")
	})
	t.Run("linux empty home without XDG does not resolve", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "")
		dir, ok := DefaultDataDir("linux", "")
		assert.False(t, ok, "an empty home is API misuse (config M-3): no dir resolves")
		assert.Empty(t, dir)
	})
	t.Run("darwin home-based Application Support", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "/custom/xdg-data") // must be IGNORED on darwin (§1.3)
		dir, ok := DefaultDataDir("darwin", "/Users/mac")
		require.True(t, ok)
		assert.Equal(t, filepath.Join("/Users/mac", "Library", "Application Support", "assay"), dir,
			"darwin default = ~/Library/Application Support/assay; XDG is not honored there")
	})
	t.Run("darwin empty home does not resolve", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "")
		dir, ok := DefaultDataDir("darwin", "")
		assert.False(t, ok)
		assert.Empty(t, dir)
	})
	t.Run("windows LOCALAPPDATA wins", func(t *testing.T) {
		t.Setenv("LOCALAPPDATA", `C:\Users\u\AppData\Local`)
		dir, ok := DefaultDataDir("windows", `C:\Users\u`)
		require.True(t, ok)
		assert.Equal(t, filepath.Join(`C:\Users\u\AppData\Local`, "assay"), dir,
			"windows default = %LOCALAPPDATA%\\assay (§2.2.6)")
	})
	t.Run("windows empty LOCALAPPDATA falls back to home profile", func(t *testing.T) {
		t.Setenv("LOCALAPPDATA", "")
		dir, ok := DefaultDataDir("windows", `C:\Users\u`)
		require.True(t, ok)
		assert.Equal(t, filepath.Join(`C:\Users\u`, "AppData", "Local", "assay"), dir,
			"the home-profile fallback of %LOCALAPPDATA%")
	})
	t.Run("windows no LOCALAPPDATA and no home does not resolve", func(t *testing.T) {
		t.Setenv("LOCALAPPDATA", "")
		dir, ok := DefaultDataDir("windows", "")
		assert.False(t, ok)
		assert.Empty(t, dir)
	})
	t.Run("XDG_DATA_HOME is ignored on windows", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "/custom/xdg-data") // no XDG contract on windows
		t.Setenv("LOCALAPPDATA", `C:\Users\u\AppData\Local`)
		dir, ok := DefaultDataDir("windows", `C:\Users\u`)
		require.True(t, ok)
		assert.Equal(t, filepath.Join(`C:\Users\u\AppData\Local`, "assay"), dir)
	})
}

// TestSystemXrayPathsTable pins the §4.2 row "System-bind scan list": linux
// keeps the existing FHS pair byte-identical (config.DefaultSystemXrayPaths's
// current literal), darwin adds the homebrew prefix, windows is EMPTY (no
// standard location — override or managed core only, §2.2.11).
func TestSystemXrayPathsTable(t *testing.T) {
	tests := []struct {
		goos string
		want []string
	}{
		{"linux", []string{"/usr/local/bin/xray", "/usr/bin/xray"}},
		{"darwin", []string{"/usr/local/bin/xray", "/opt/homebrew/bin/xray"}},
		{"windows", []string{}},
	}
	for _, tt := range tests {
		got := SystemXrayPaths(tt.goos)
		require.Len(t, got, len(tt.want), "SystemXrayPaths(%q) length", tt.goos)
		for i := range tt.want {
			assert.Equal(t, tt.want[i], got[i], "SystemXrayPaths(%q)[%d]", tt.goos, i)
		}
	}
}

// TestSystemXrayPathsFreshSlice pins that each call returns a fresh slice:
// config.DefaultSystemXrayPaths is an injectable var whose value comes from
// this table — a caller mutating the returned slice must never corrupt the
// table for the next caller.
func TestSystemXrayPathsFreshSlice(t *testing.T) {
	first := SystemXrayPaths("linux")
	first[0] = "mutated"
	second := SystemXrayPaths("linux")
	assert.Equal(t, "/usr/local/bin/xray", second[0],
		"the table must not leak a shared mutable slice")
}

// TestXDGHonored pins the §5.1 guard: the XDG_DATA_HOME env contract is
// linux-only behavior — resolve.go consults this oracle before honoring or
// warning about XDG_DATA_HOME (launchd/service contexts must never see XDG
// semantics on darwin/windows).
func TestXDGHonored(t *testing.T) {
	assert.True(t, XDGHonored("linux"))
	assert.False(t, XDGHonored("darwin"))
	assert.False(t, XDGHonored("windows"))
}
