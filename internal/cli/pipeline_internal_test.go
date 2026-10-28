package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"public_vpn/internal/config"
	"public_vpn/internal/fetch"
	"public_vpn/internal/store"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProbeOptionsWiresConfig pins the config→Options translation: max_passed
// and the check-preset/speedtest precedence must reach the probe wave
// (review finding 7 — max_passed was a lying knob pre-fix, declared in TOML
// but never copied into probe.Options).
func TestProbeOptionsWiresConfig(t *testing.T) {
	cfg := &config.Config{
		Probe: config.ProbeConfig{
			MaxPassed:           7,
			Threads:             11,
			CheckPreset:         "global",
			Speedtest:           true,
			URLSuccessThreshold: 0.9,
		},
	}

	opts := probeOptions(cfg, false, "")
	assert.Equal(t, 7, opts.MaxPassed, "probe.max_passed must reach the wave")
	assert.Equal(t, 11, opts.Threads)
	assert.Equal(t, "global", opts.CheckPreset, "config preset used when no flag")
	assert.True(t, opts.Speedtest, "config speedtest=true holds without a flag")
	assert.InDelta(t, 0.9, opts.URLSuccessThreshold, 0.0001)

	cfg.Probe.CheckPreset = ""
	opts = probeOptions(cfg, false, "cloudflare")
	assert.Equal(t, "cloudflare", opts.CheckPreset, "flag preset overrides config")
}

// TestRunParseSourceOrderIsDeterministic pins the M-b determinism contract:
// runParse iterates the fetch manifest's Sources map, whose Go iteration
// order is randomized — without a stable sort the parsed node file (and the
// dedup/cap/tag decisions downstream that consume its order) differs between
// runs on identical inputs. Twelve waves over four sources must produce the
// identical, source-id-ascending node sequence every time
// (final-review finding M-b).
func TestRunParseSourceOrderIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir}
	p := newPaths(cfg)
	require.NoError(t, os.MkdirAll(p.cacheDir, 0o750))

	ids := []string{"zulu", "alpha", "mike", "bravo"}
	manifest := fetchManifest{Sources: map[string][]fetch.FetchedFile{}}
	for _, id := range ids {
		body := "vless://uuid-" + id + "@" + id + ".example.com:443?security=tls&type=tcp#" + id + "\n"
		require.NoError(t, os.MkdirAll(filepath.Join(p.cacheDir, id), 0o750))
		require.NoError(t, os.WriteFile(
			filepath.Join(p.cacheDir, id, fetch.SafePath("nodes.txt")), []byte(body), 0o600))
		manifest.Sources[id] = []fetch.FetchedFile{{Source: id, Path: "nodes.txt"}}
	}
	mb, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, store.WriteManifest(p.manifest, mb))

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	var firstOrder []string
	for i := range 12 {
		require.NoError(t, runParse(cmd, cfg), "wave %d", i)
		nodes, err := store.ReadNodes(p.nodes)
		require.NoError(t, err)
		require.Len(t, nodes, len(ids), "wave %d: every source contributed its node", i)
		order := make([]string, 0, len(nodes))
		for _, n := range nodes {
			order = append(order, n.Source)
		}
		if i == 0 {
			firstOrder = order
			continue
		}
		require.Equal(t, firstOrder, order,
			"wave %d: parse output order must be identical across runs on identical inputs", i)
	}
	assert.Equal(t, []string{"alpha", "bravo", "mike", "zulu"}, firstOrder,
		"the stable order is source-id ascending")
}
