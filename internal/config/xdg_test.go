package config_test

import (
	"path/filepath"
	"strings"
	"testing"

	"assay/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Round-7 item 9: XDG_DATA_HOME must be ABSOLUTE (XDG Base Directory
// spec). A set-but-relative value is spec-invalid and is treated as unset
// — never a crash, never a relative data dir — with a LOUD warning naming
// the violation.
func TestDefaultDataDirTreatsRelativeXDGAsUnset(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "relative/path")
	got := config.DefaultDataDir("/home/tester")
	assert.Equal(t, filepath.Join("/home/tester", ".local", "share", "assay"), got,
		"a relative XDG_DATA_HOME must fall back to the home default, never produce a relative data dir")
}

func TestConfiglessWarnsOnRelativeXDGDataHome(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "relative/path")
	res, err := config.Resolve("", "/home/tester", "")
	require.NoError(t, err)
	require.NotEmpty(t, res.Warnings, "a spec-invalid XDG_DATA_HOME must produce a loud warning")
	assert.Contains(t, res.Warnings[0], "XDG_DATA_HOME",
		"the warning must name the violating variable")
	assert.Contains(t, res.Warnings[0], "relative",
		"the warning must name the violation class")
	assert.True(t, filepath.IsAbs(res.Config.DataDir),
		"the resolved data dir must stay absolute despite the invalid XDG value")
}

func TestValidXDGProducesNoWarnings(t *testing.T) {
	xdg := filepath.Join(t.TempDir(), "data")
	t.Setenv("XDG_DATA_HOME", xdg) // absolute: spec-valid
	res, err := config.Resolve("", "/home/tester", "")
	require.NoError(t, err)
	assert.Empty(t, res.Warnings, "a spec-valid absolute XDG_DATA_HOME must not warn")
	assert.True(t, strings.HasPrefix(res.Config.DataDir, xdg),
		"a valid XDG_DATA_HOME is still honored")
}

func TestXDGDataDirViolationClassifies(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	assert.Empty(t, config.XDGDataDirViolation(), "unset: no violation")
	t.Setenv("XDG_DATA_HOME", "/abs/path")
	assert.Empty(t, config.XDGDataDirViolation(), "absolute: no violation")
	t.Setenv("XDG_DATA_HOME", "rel/path")
	assert.NotEmpty(t, config.XDGDataDirViolation(), "relative: violation reported")
}

// The unset-fallback branch still behaves (hermetic pin, pre-existing
// contract kept green alongside the new validation).
func TestDefaultDataDirUnsetFallsBack(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	assert.Equal(t, filepath.Join("/home/tester", ".local", "share", "assay"), config.DefaultDataDir("/home/tester"))
}
