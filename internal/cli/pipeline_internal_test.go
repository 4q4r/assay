package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"public_vpn/internal/config"
	"public_vpn/internal/fetch"
	"public_vpn/internal/model"
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

// TestRenderKnobsReachRenderedOutputEndToEnd pins the C-1 seam: every render
// knob must cross config.Load → runRender → the rendered file. This crosses
// the FULL seam (TOML on disk → real loader → production runRender → written
// config.json) because the render-package unit tests exercise render.Render
// directly and cannot see wiring dropped in the runRender call site — that
// exact gap is why the C-1 bug shipped: all five knobs rendered defaults.
func TestRenderKnobsReachRenderedOutputEndToEnd(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "template.json")
	require.NoError(t, os.WriteFile(tmpl, []byte(`{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks"},
    {"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http"},
    {"tag": "tun-in", "listen": "127.0.0.1", "port": 10910, "protocol": "socks"}
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {
    "rules": [
      {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
      {"type": "field", "network": "tcp,udp", "balancerTag": "best_rtt"}
    ]
  }
}`), 0o644))

	tomlPath := filepath.Join(dir, "config.toml")
	content := `
data_dir = "` + dir + `"

[sources.s]
repo = "o/r"
discovery = "github-contents"

[render]
template = "` + tmpl + `"
output_dir = "rendered"
pool_inbound_tags = ["socks-in", "http-in", "tun-in"]
observatory_interval = "45s"
tcp_max_seg = 1380
tls_fingerprint = "chrome"
balancer_tolerance = 0.7

[[render.pool_routes]]
balancer = "pool_de"
domains = ["geosite:netflix"]
`
	require.NoError(t, os.WriteFile(tomlPath, []byte(content), 0o644))
	cfg, err := config.Load(tomlPath)
	require.NoError(t, err)

	// One reality node in the filtered set + a matching selection, so the
	// render emits the full pool artifact set (outbound, rule, balancer,
	// observatory) the knobs surface in.
	n := model.NewNode("src", "vless", "00000000-0000-0000-0000-000000000001", "Se.Example.com", 443,
		map[string]string{
			"security": "reality", "type": "tcp",
			"pbk": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "sid": "AA",
		})
	b, err := json.Marshal(n)
	require.NoError(t, err)
	p := newPaths(cfg)
	require.NoError(t, os.WriteFile(p.filtered, []byte(string(b)+"\n"), 0o600))
	sel := &model.Selection{Nodes: []model.SelectedNode{{Tag: "pool-de-01", Key: n.Key, Country: "de"}}}
	require.NoError(t, store.WriteSelection(p.selection, sel))

	buf := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	require.NoError(t, runRender(cmd, cfg))

	raw, err := os.ReadFile(p.rendered)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))

	outbounds := m["outbounds"].([]any)
	var pool map[string]any
	for _, o := range outbounds {
		if om, ok := o.(map[string]any); ok && om["tag"] == "pool-de-01" {
			pool = om
			break
		}
	}
	require.NotNil(t, pool, "the pool outbound must render")
	stream := pool["streamSettings"].(map[string]any)
	assert.InDelta(t, 1380, stream["sockopt"].(map[string]any)["tcpMaxSeg"], 1e-9,
		"tcp_max_seg=1380 must surface in the rendered sockopt (not the 1440 default)")
	reality := stream["realitySettings"].(map[string]any)
	assert.Equal(t, "chrome", reality["fingerprint"],
		"tls_fingerprint=chrome must surface in the rendered realitySettings (not firefox)")

	obs, hasObs := m["observatory"]
	require.True(t, hasObs, "the pool observatory must render")
	assert.Equal(t, "45s", obs.(map[string]any)["probeInterval"],
		"observatory_interval=45s must surface verbatim (not the 60s default)")

	balancers := m["routing"].(map[string]any)["balancers"].([]any)
	var countryBal map[string]any
	for _, b := range balancers {
		if bm, ok := b.(map[string]any); ok && bm["tag"] == "pool_de" {
			countryBal = bm
			break
		}
	}
	require.NotNil(t, countryBal, "the country balancer must render")
	tol := countryBal["strategy"].(map[string]any)["settings"].(map[string]any)["tolerance"]
	assert.InDelta(t, 0.7, tol, 1e-9,
		"balancer_tolerance=0.7 must surface in the balancer strategy (not the 0.2 default)")

	rules := m["routing"].(map[string]any)["rules"].([]any)
	var poolRule map[string]any
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if ok && rm["domain"] != nil {
			poolRule = rm
			break
		}
	}
	require.NotNil(t, poolRule, "the pool routing rule must render")
	assert.Equal(t, []any{"socks-in", "http-in", "tun-in"}, poolRule["inboundTag"],
		"pool_inbound_tags incl. the extra tun-in must surface in inboundTag (not the 2-tag default)")
}
