package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"public_vpn/internal/cli"
	"public_vpn/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaintainWithoutConfigFailsLoud(t *testing.T) {
	// W4: maintain is the real refresh wave now; it still fails loud when the
	// single source of truth (config.toml) is missing — no fake success paths.
	root := cli.New()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"-c", filepath.Join(t.TempDir(), "nope.toml"), "maintain"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config not found")
}

// TestStatusShowsFoldedTraffic pins the W4 status addition: the geo line
// carries the total BytesUp/BytesDown the stats stage has folded into the
// cold base.
func TestStatusShowsFoldedTraffic(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf(`
data_dir = %q
`, dir)), 0o600))
	geoBase := filepath.Join(dir, "geo-base.jsonl")
	require.NoError(t, os.WriteFile(geoBase, []byte(
		`{"tag":"pool-de-01","scheme":"vless","host":"de.example.com","port":443,"alive":true,"country":"de","bytes_up":1000,"bytes_down":2000}`+"\n"+
			`{"tag":"pool-nl-01","scheme":"vless","host":"nl.example.com","port":443,"alive":false,"country":"nl","bytes_up":10,"bytes_down":20}`+"\n",
	), 0o600))

	root := cli.New()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"-c", cfgPath, "status"})
	require.NoError(t, root.Execute())
	assert.Contains(t, buf.String(), "traffic folded: 1010 up / 2020 down bytes")
}

func TestMissingConfigFailsLoud(t *testing.T) {
	root := cli.New()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"-c", filepath.Join(t.TempDir(), "nope.toml"), "status"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config not found")
}

func TestCommandTreeCompletes(t *testing.T) {
	root := cli.New()
	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"fetch", "parse", "filter", "probe", "geo", "select", "render", "activate", "status", "maintain"} {
		assert.True(t, names[want], "command %q must exist", want)
	}
	assert.False(t, names["completion"], "completion helper hidden")
}

func TestUsageMentionsConfigFlag(t *testing.T) {
	buf := &bytes.Buffer{}
	root := cli.New()
	root.SetOut(buf)
	root.SetArgs([]string{"--help"})
	require.NoError(t, root.Execute())
	assert.Contains(t, buf.String(), "-c, --config", "config flag documented")
}

// TestFilterUsesConfigSourceCapAndFlagOverride pins the cap precedence:
// [filter].source_cap is the default, the --source-cap flag is an explicit
// override (review finding 6). RED pre-fix: [filter] failed strict TOML
// decode as an unknown key.
func TestFilterUsesConfigSourceCapAndFlagOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf(`
data_dir = %q
[filter]
source_cap = 2
`, dir)), 0o600))

	// 4 nodes from source "a", 1 from source "b".
	lines := make([]string, 0, 5)
	for i := range 4 {
		n := model.NewNode("a", "vless", fmt.Sprintf("uuid-%d", i), fmt.Sprintf("a%d.example.com", i), 443,
			map[string]string{"security": "tls", "type": "tcp"})
		b, err := json.Marshal(n)
		require.NoError(t, err)
		lines = append(lines, string(b))
	}
	nb := model.NewNode("b", "vless", "uuid-b", "b.example.com", 443, map[string]string{"security": "tls", "type": "tcp"})
	b, err := json.Marshal(nb)
	require.NoError(t, err)
	lines = append(lines, string(b))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nodes.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600))

	run := func(args ...string) {
		t.Helper()
		root := cli.New()
		buf := &bytes.Buffer{}
		root.SetOut(buf)
		root.SetErr(buf)
		root.SetArgs(append([]string{"-c", cfgPath}, args...))
		require.NoError(t, root.Execute())
		_ = buf
	}

	run("filter")
	kept := readFiltered(t, dir)
	require.Len(t, kept, 3, "config source_cap=2: source a contributes 2, source b 1")
	fromA := 0
	for _, k := range kept {
		if k.Source == "a" {
			fromA++
		}
	}
	assert.Equal(t, 2, fromA, "per-source cap from config applied")

	run("filter", "--source-cap", "1")
	kept = readFiltered(t, dir)
	require.Len(t, kept, 2, "flag override: each source contributes 1")
}

func readFiltered(t *testing.T, dir string) []*model.Node {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "filtered.jsonl"))
	require.NoError(t, err)
	var out []*model.Node
	for line := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var n model.Node
		require.NoError(t, json.Unmarshal([]byte(line), &n))
		out = append(out, &n)
	}
	return out
}

// TestStateArtifactsAre0600 pins the on-disk hardening: fetch manifest and
// rendered config carry node-adjacent pipeline state and are written 0600 —
// not 0644 (review finding 11). The owner's live config is NOT this repo's
// concern and keeps its own mode.
func TestStateArtifactsAre0600(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	tmplPath := filepath.Join(dir, "template.json")
	require.NoError(t, os.WriteFile(tmplPath, []byte(`{}`), 0o600))
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf(`
data_dir = %q
[render]
template = %q
`, dir, tmplPath)), 0o600))

	run := func(args ...string) {
		t.Helper()
		root := cli.New()
		buf := &bytes.Buffer{}
		root.SetOut(buf)
		root.SetErr(buf)
		root.SetArgs(append([]string{"-c", cfgPath}, args...))
		require.NoError(t, root.Execute())
	}

	// fetch needs no network here: the manifest write itself is pinned at the
	// store level (TestJSONLArtifactsAreExplicitly0600); this integration pins
	// the rendered config.

	// render with an empty selection passes the template through and writes
	// the rendered config.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "filtered.jsonl"), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "selection.json"), []byte(`{"generated_at":"2026-10-28T00:00:00Z","cap_applied":0,"cities_alive":0,"nodes":[]}`), 0o600))
	run("render")
	rendered, err := os.Stat(filepath.Join(dir, "rendered", "config.json"))
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), rendered.Mode().Perm(), "rendered config.json must be 0600")
}
