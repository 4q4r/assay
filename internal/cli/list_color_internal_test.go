// W18 list-screen color flags: the list command joins the shared
// --color/--no-color surface every other screen carries, resolved through
// the same W12 contract (auto|always|never + NO_COLOR). On a pipe
// --color=always emits ANSI, --color=never strips, no flags stays plain
// (a pipe is never a terminal), and the help text lists both flags.

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/require"
)

// listWaveFixture writes a tiny active core (selection + probe results +
// geo-base) under a temp data dir and returns the config path pointing at
// it — enough for the real list command to render a full screen.
func listWaveFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	require.NoError(t, os.MkdirAll(data, 0o755))

	gen := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	sel := &model.Selection{
		GeneratedAt: gen,
		CapApplied:  2,
		Nodes: []model.SelectedNode{
			{Tag: "pool-de-01", Key: "k-de-1", Country: "de", City: "Frankfurt", RTTMs: 40},
			{Tag: "pool-fr-01", Key: "k-fr-1", Country: "fr", City: "Paris", RTTMs: 60},
		},
	}
	require.NoError(t, store.WriteSelection(filepath.Join(data, "selection.json"), sel))
	results := []store.ProbeResult{
		{Key: "k-de-1", Host: "de1.example.com", Alive: true, RTTMs: 40, CheckedAt: gen},
		{Key: "k-fr-1", Host: "fr1.example.com", Alive: true, RTTMs: 60, CheckedAt: gen},
	}
	require.NoError(t, store.AppendProbeResults(filepath.Join(data, "probe-results.jsonl"), results))
	cold := []*model.GeoRecord{
		{Tag: "pool-de-01", Country: "de", City: "Frankfurt", Alive: true, RTTMs: 40},
		{Tag: "pool-fr-01", Country: "fr", City: "Paris", Alive: true, RTTMs: 60},
	}
	require.NoError(t, store.WriteGeo(filepath.Join(data, "geo-base.jsonl"), cold))

	cfgPath := filepath.Join(dir, "config.toml")
	body := fmt.Sprintf("data_dir = %q\n", data)
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	return cfgPath
}

// runListTree executes the REAL root tree with the given args and returns
// stdout — the cobra-level seam (flags, resolution, RunE) exercised whole.
func runListTree(t *testing.T, args ...string) string {
	t.Helper()
	root := New()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(args)
	require.NoError(t, root.Execute())
	return buf.String()
}

// TestListCommandCarriesColorFlags pins the real command surface: list
// exposes the shared --color/--no-color pair (the status screen's twin).
func TestListCommandCarriesColorFlags(t *testing.T) {
	cfgPath := ""
	cmd := newListCommand(&cfgPath)
	require.NotNil(t, cmd.Flags().Lookup("color"), "the real list command carries --color")
	require.NotNil(t, cmd.Flags().Lookup("no-color"), "the real list command carries --no-color")
}

func TestListColorFlagsOnPipe(t *testing.T) {
	cfgPath := listWaveFixture(t)

	always := runListTree(t, "-c", cfgPath, "list", "--color", "always")
	require.Contains(t, always, "\x1b[", "--color=always colors the screen even onto a pipe")
	require.Contains(t, always, "38;5;99", "the header carries the title accent")

	never := runListTree(t, "-c", cfgPath, "list", "--color", "never")
	require.NotContains(t, never, "\x1b[", "--color=never strips every ANSI sequence")

	plain := runListTree(t, "-c", cfgPath, "list")
	require.NotContains(t, plain, "\x1b[", "no flags = auto = a pipe is color-off")
}

func TestListColorFlagHelpAndLoudness(t *testing.T) {
	help := runListTree(t, "list", "--help")
	require.Contains(t, help, "--color string", "the help lists the color mode flag")
	require.Contains(t, help, "colorize output: auto (terminal-detected), always, never")
	require.Contains(t, help, "--no-color", "the help lists the no-color alias")

	cfgPath := listWaveFixture(t)
	root := New()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"-c", cfgPath, "list", "--color", "sometimes"})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "auto|always|never", "an invalid --color value fails loud")
}
