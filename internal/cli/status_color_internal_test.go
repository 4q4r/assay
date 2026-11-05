// W18 status-screen chips: labels dim 241, values info 45, section title
// accent 99; STALE keeps its warning semantics in red 196, LEGACY migrates
// in amber 214. The whole screen rides the W12 color contract via
// --color/--no-color; with no flags (or color off) the output is the exact
// legacy plain text.

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/install"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statusFixture installs a drifted binary + a legacy timer (the STALE and
// LEGACY classes in one screen) and returns a ready status command.
func statusFixture(t *testing.T) (*cobra.Command, *bytes.Buffer, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "run", "systemd"), 0o755))

	binDir := filepath.Join(home, ".local", "bin")
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)
	require.NoError(t, runInstall(&bytes.Buffer{}, mustLoad(t, cfgPath), cfgPath,
		installOptions{binDir: binDir, unitDir: unitDir, exec: &fakeCtl{}, embedsConfig: true}))

	// wants symlink → the service line renders the enabled branch.
	wants := filepath.Join(unitDir, "default.target.wants")
	require.NoError(t, os.MkdirAll(wants, 0o755))
	require.NoError(t, os.Symlink(filepath.Join(unitDir, install.WatchService),
		filepath.Join(wants, install.WatchService)))
	// legacy W5 timer → LEGACY hint.
	require.NoError(t, os.WriteFile(filepath.Join(unitDir, install.RefreshTimer), []byte("[Unit]\n"), 0o644))
	// binary drift → STALE line.
	installed := filepath.Join(binDir, "publicvpn")
	current, err := os.ReadFile(installed)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(installed,
		append([]byte("#!/bin/sh\necho newer-build\n"), current...), 0o755))

	out := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	attachColorFlags(cmd)
	return cmd, out, cfgPath
}

// TestStatusCommandCarriesColorFlags pins the real command surface: status
// exposes the shared --color/--no-color pair.
func TestStatusCommandCarriesColorFlags(t *testing.T) {
	cfgPath := ""
	cmd := newStatusCommand(&cfgPath)
	require.NotNil(t, cmd.Flags().Lookup("color"), "the real status command carries --color")
	require.NotNil(t, cmd.Flags().Lookup("no-color"), "the real status command carries --no-color")
}

func TestStatusChipsColored(t *testing.T) {
	cmd, out, cfgPath := statusFixture(t)
	require.NoError(t, cmd.Flags().Set("color", "always"))
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
	s := out.String()

	require.Contains(t, s, "38;5;99", "the pipeline title carries the header accent")
	require.Contains(t, s, "38;5;241", "labels are dim 241 (install:/binary:/units:/service: blocks)")
	require.Contains(t, s, "38;5;45", "values are info 45 (paths, states)")
	require.Contains(t, s, "38;5;196m", "the STALE line is red (owner WARNING semantics)")
	require.Contains(t, s, "38;5;214m", "the LEGACY hint is amber")
	require.Contains(t, s, "STALE", "the STALE text survives styling")
	require.Contains(t, s, "LEGACY", "the LEGACY text survives styling")
}

func TestStatusPlainWithoutFlags(t *testing.T) {
	cmd, out, cfgPath := statusFixture(t)
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
	s := out.String()
	require.NotContains(t, s, "\x1b[", "no flags = auto = a buffer is color-off")
	require.Contains(t, s, "binary:    ", "the legacy aligned text is untouched")
	require.Contains(t, s, "install:")
}

func TestStatusColorFlagsContract(t *testing.T) {
	t.Run("--color=never strips even under forced-on defaults", func(t *testing.T) {
		cmd, out, cfgPath := statusFixture(t)
		require.NoError(t, cmd.Flags().Set("color", "never"))
		require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
		require.NotContains(t, out.String(), "\x1b[")
	})
	t.Run("NO_COLOR yields to an explicit always", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		cmd, out, cfgPath := statusFixture(t)
		require.NoError(t, cmd.Flags().Set("color", "always"))
		require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
		require.Contains(t, out.String(), "\x1b[",
			"NO_COLOR is an auto default, not an override of the explicit flag")
	})
	t.Run("invalid mode is loud", func(t *testing.T) {
		cmd, _, cfgPath := statusFixture(t)
		require.NoError(t, cmd.Flags().Set("color", "sometimes"))
		err := runStatus(cmd, explicitResolved(t, cfgPath))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auto|always|never")
	})
}

// TestInstallSummaryChipsColored pins the install summary block: labels
// dim 241, values info 45 under --color=always; byte-plain without flags
// (the existing install tests pin those bytes).
func TestInstallSummaryChipsColored(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "run", "systemd"), 0o755))

	binDir := filepath.Join(home, ".local", "bin")
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)

	out := &bytes.Buffer{}
	require.NoError(t, runInstall(out, mustLoad(t, cfgPath), cfgPath, installOptions{
		binDir: binDir, unitDir: unitDir, exec: &fakeCtl{}, embedsConfig: true,
		color: true,
	}))
	s := out.String()
	require.Contains(t, s, "38;5;241", "summary labels are dim 241")
	require.Contains(t, s, "38;5;45", "summary values are info 45")
	require.Contains(t, s, "installed binary:", "the label text survives")
	require.Contains(t, s, "daemon active:", "the daemon line survives")
}

// configSourceChipColored pins the shared provenance chip: the config line
// renders as a chip (dim label + info value), resolution warnings amber.
func TestConfigSourceChipColored(t *testing.T) {
	out := &bytes.Buffer{}
	res := &config.Resolved{Config: &config.Config{}, Source: config.SourceShare, Path: "/tmp/cfg.toml"}
	reportConfigSourceStyled(out, res, true)
	s := out.String()
	require.Contains(t, s, "38;5;241", "the config: label is dim 241")
	require.Contains(t, s, "38;5;45", "the provenance value is info 45")
	require.Contains(t, s, "local-share default /tmp/cfg.toml", "the provenance text survives")

	out.Reset()
	res.Warnings = []string{"relative XDG_DATA_HOME treated as unset"}
	reportConfigSourceStyled(out, res, true)
	require.Contains(t, out.String(), "38;5;214m", "resolution warnings are amber")

	out.Reset()
	reportConfigSourceStyled(out, res, false)
	require.Equal(t, "config: local-share default /tmp/cfg.toml\nwarning: relative XDG_DATA_HOME treated as unset\n",
		out.String(), "color-off is the exact legacy provenance block")
}

// TestStatusPluginLiveness tests the plugin liveness section of the status command.
// It verifies that the section appears with correct format showing plugin name,
// total nodes, live nodes, live %, duplicate count, duplicate %, hosting %,
// proxy %, clean %, and status (OK/WARNING/DISABLED) with threshold violations highlighted.
func TestStatusPluginLiveness(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "run", "systemd"), 0o755))

	// Create a minimal config with plugin thresholds
	cfgPath := filepath.Join(home, "config.toml")
	body := fmt.Sprintf(`
data_dir = %q

[maintain]
refresh_interval = "6h"
speedtest_interval = "168h"

[plugins]
max_duplicate_percent = 20.0
min_live_percent = 50.0
`, filepath.Join(home, "data"))
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))

	// Create fetch manifest with plugin stats in the correct location (cache/manifest.json)
	dataDir := filepath.Join(home, "data")
	cacheDir := filepath.Join(dataDir, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o750))
	manifestPath := filepath.Join(cacheDir, "manifest.json")
	manifest := map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"sources":    map[string]any{},
		"plugin_stats": []map[string]any{
			{
				"PluginID":       "plugin_a",
				"TotalNodes":     100,
				"LiveNodes":      80,
				"DuplicateCount": 10,
				"HostingCount":   30,
				"ProxyCount":     20,
				"CleanCount":     50,
			},
			{
				"PluginID":       "plugin_b",
				"TotalNodes":     50,
				"LiveNodes":      20,
				"DuplicateCount": 25,
				"HostingCount":   10,
				"ProxyCount":     5,
				"CleanCount":     35,
			},
			{
				"PluginID":       "plugin_c",
				"TotalNodes":     200,
				"LiveNodes":      180,
				"DuplicateCount": 5,
				"HostingCount":   50,
				"ProxyCount":     30,
				"CleanCount":     120,
			},
		},
	}
	require.NoError(t, os.WriteFile(manifestPath, mustMarshalJSON(t, manifest), 0o600))

	// Create minimal nodes files (jsonl format)
	nodesPath := filepath.Join(dataDir, "nodes.jsonl")
	filteredPath := filepath.Join(dataDir, "filtered.jsonl")
	selectionPath := filepath.Join(dataDir, "selection.json")
	require.NoError(t, os.WriteFile(nodesPath, []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filteredPath, []byte(""), 0o600))
	require.NoError(t, os.WriteFile(selectionPath, []byte("{}"), 0o600))

	// Create minimal probe results (jsonl format)
	probePath := filepath.Join(dataDir, "probe-results.jsonl")
	require.NoError(t, os.WriteFile(probePath, []byte(""), 0o600))

	// Create minimal geo base (jsonl format)
	geoPath := filepath.Join(dataDir, "geo-base.jsonl")
	require.NoError(t, os.WriteFile(geoPath, []byte(""), 0o600))

	// Run status command
	res := explicitResolved(t, cfgPath)
	out := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	attachColorFlags(cmd)
	require.NoError(t, cmd.Flags().Set("color", "always"))
	require.NoError(t, runStatus(cmd, res))

	s := out.String()

	// The intelligence table renders, and the empty `plugins:` header line
	// is gone — the legacy chip lines follow the table directly (owner
	// cosmetic ruling 2026-11-05).
	require.NotContains(t, s, "plugins:  \n", "the empty plugins header line is removed")

	// Verify plugin_a (OK - live% 80% > 50%, dup% 10% < 20%)
	require.Contains(t, s, "plugin_a", "plugin_a should appear")
	require.Contains(t, s, "OK", "plugin_a should show OK status")

	// Verify plugin_b (WARNING - live% 40% < 50%, dup% 50% > 20%)
	require.Contains(t, s, "plugin_b", "plugin_b should appear")
	require.Contains(t, s, "WARNING", "plugin_b should show WARNING status")

	// Verify plugin_c (OK - live% 90% > 50%, dup% 2.5% < 20%)
	require.Contains(t, s, "plugin_c", "plugin_c should appear")
	require.Contains(t, s, "OK", "plugin_c should show OK status")

	// Verify key metrics appear
	require.Contains(t, s, "total=100", "total nodes should appear")
	require.Contains(t, s, "live=80", "live nodes should appear")
	require.Contains(t, s, "dup-links=10", "duplicate count should appear (dup-links= per the owner-ordered rename, 2026-11-05)")
	require.Contains(t, s, "hosting=30", "hosting count should appear")
	require.Contains(t, s, "proxy=20", "proxy count should appear")
	require.Contains(t, s, "clean=50", "clean count should appear")

	// Verify percentages appear (format: X.Y%)
	require.Contains(t, s, "80.0%", "live percent should appear")
	require.Contains(t, s, "10.0%", "duplicate percent should appear")
	require.Contains(t, s, "30.0%", "hosting percent should appear")
	require.Contains(t, s, "20.0%", "proxy percent should appear")
	require.Contains(t, s, "50.0%", "clean percent should appear")

	// Verify colored output (dim labels, info values, status colors)
	require.Contains(t, s, "38;5;241", "labels should be dim 241")
	require.Contains(t, s, "38;5;45", "values should be info 45")
	require.Contains(t, s, "38;5;46", "OK status should be green")
	require.Contains(t, s, "38;5;214", "WARNING status should be amber")
}

// mustMarshalJSON marshals v to JSON for test fixtures.
func mustMarshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	return b
}
