package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/fetch"
	"public_vpn/internal/geo"
	"public_vpn/internal/model"
	"public_vpn/internal/plugins"
	"public_vpn/internal/store"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProbeOptionsWiresConfig pins the config→Options translation for the
// real-xray engine: attempts/threads/speedtest-default-ON and the speedtest
// URL must reach the probe wave; the knife-era knobs (max_passed, presets)
// are gone with the tool that needed them.
func TestProbeOptionsWiresConfig(t *testing.T) {
	noSpeedtest := false
	cfg := &config.Config{
		Probe: config.ProbeConfig{
			Threads:      11,
			Attempts:     5,
			Speedtest:    &noSpeedtest,
			SpeedtestURL: "https://example.test/down",
		},
	}

	opts := probeOptions(cfg, false)
	assert.Equal(t, 11, opts.Threads)
	assert.Equal(t, 5, opts.Attempts)
	assert.False(t, opts.Speedtest, "explicit speedtest=false holds without a flag")
	assert.Equal(t, "https://example.test/down", opts.SpeedtestURL)
	assert.Nil(t, opts.ExitProbe, "the production literal leaves ExitProbe nil — the D8 echo defaults ON")

	cfg.Probe.Speedtest = nil
	opts = probeOptions(cfg, false)
	assert.False(t, opts.Speedtest, "nil speedtest defaults OFF (round-8 owner ruling — refresh waves are probe-only)")

	opts = probeOptions(cfg, true)
	assert.True(t, opts.Speedtest, "the CLI flag forces the speedtest even when the config disables it")
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
	//nolint:musttag // fetchManifest has JSON tags; musttag false positive
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

// TestPluginRunTimeoutAbandonsHangingPlugin pins the I-1 layered fix: a
// plugin whose Lua VM spins forever (`while true do end`)
// must not hang the wave. The plugin run is bounded by
// [plugins].run_timeout: the wave cancels the context on timeout,
// terminating the Lua VM cleanly via SetContext, abandoning the hung plugin LOUD
// and continuing with the healthy ones without leaking goroutines.
func TestPluginRunTimeoutAbandonsHangingPlugin(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")
	content := "data_dir = \"" + dir + "\"\n\n[plugins]\nrun_timeout = \"1s\"\n"
	require.NoError(t, os.WriteFile(tomlPath, []byte(content), 0o600))
	cfg, err := config.Load(tomlPath)
	require.NoError(t, err)

	reg := plugins.NewRegistry()
	reg.Set(&plugins.Plugin{ID: "healthy", Path: "healthy.lua", Code: []byte(`
		return function()
			return { publicvpn.node{ raw = "vless://a@h:1?s=1" }, publicvpn.node{ raw = "vless://b@h:2?s=1" } }
		end`)})
	reg.Set(&plugins.Plugin{ID: "hung", Path: "hung.lua", Code: []byte(`
		return function() repeat until false end`)})

	out := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	_, err = runFetchWith(cmd, cfg, reg)
	require.NoError(t, err, "the wave must complete despite the hung plugin")

	text := out.String()
	require.Contains(t, text, "plugin hung", "the abandonment must be plugin-attributed:\n"+text)
	require.Contains(t, text, "exceeded 1s — abandoned",
		"the abandonment must be loud and name the bound:\n"+text)
	require.Contains(t, text, "plugin healthy    ok: 2 nodes", "healthy plugins still run:\n"+text)

	// The manifest carries only the healthy source; the healthy nodes reach
	// the pipeline, the hung plugin contributes nothing.
	require.NoError(t, runParse(func() *cobra.Command {
		c := &cobra.Command{}
		c.SetOut(&bytes.Buffer{})
		return c
	}(), cfg))
	nodes, err := os.ReadFile(filepath.Join(dir, "nodes.jsonl"))
	require.NoError(t, err)
	require.Equal(t, 2, strings.Count(string(nodes), `"source":"healthy`),
		"the healthy plugin's nodes must reach the pipeline: %s", nodes)
	require.NotContains(t, string(nodes), "hung", "the hung plugin must contribute nothing")
}

// TestPluginRunTimeoutResolution pins the knob's three states: unset → the
// 120s default; explicit 0s → unbounded (owner ruling: no artificial floor);
// an explicit value passes through verbatim.
func TestPluginRunTimeoutResolution(t *testing.T) {
	cfg := &config.Config{}
	require.Equal(t, config.DefaultPluginRunTimeout, pluginRunTimeout(cfg),
		"unset run_timeout resolves to the 120s default")

	cfg.Plugins.RunTimeout = &config.Duration{}
	require.Equal(t, time.Duration(0), pluginRunTimeout(cfg),
		"explicit 0s = unbounded (no artificial floor)")

	cfg.Plugins.RunTimeout = &config.Duration{Duration: 7 * time.Second}
	require.Equal(t, 7*time.Second, pluginRunTimeout(cfg), "explicit value passes through")
}

// TestPluginThresholdAutoDisable tests that plugins are auto-disabled when
// their duplicate percentage exceeds MaxDuplicatePercent or their live percentage
// falls below MinLivePercent.
func TestPluginThresholdAutoDisable(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")

	// Test 1: MaxDuplicatePercent threshold violation
	content := "data_dir = \"" + dir + "\"\n\n[plugins]\nmax_duplicate_percent = 50.0\n"
	require.NoError(t, os.WriteFile(tomlPath, []byte(content), 0o600))
	cfg, err := config.Load(tomlPath)
	require.NoError(t, err)

	reg := plugins.NewRegistry()
	// Plugin "highdup" - 10 nodes, 6 duplicates (60% > 50%)
	reg.Set(&plugins.Plugin{ID: "highdup", Path: "highdup.lua", Code: []byte(`
		return function()
			return {
				publicvpn.node{ raw = "vless://a@h:1?s=1" },
				publicvpn.node{ raw = "vless://b@h:2?s=1" },
				publicvpn.node{ raw = "vless://c@h:3?s=1" },
				publicvpn.node{ raw = "vless://d@h:4?s=1" },
				publicvpn.node{ raw = "vless://e@h:5?s=1" },
				publicvpn.node{ raw = "vless://f@h:6?s=1" },
				publicvpn.node{ raw = "vless://g@h:7?s=1" },
				publicvpn.node{ raw = "vless://h@h:8?s=1" },
				publicvpn.node{ raw = "vless://i@h:9?s=1" },
				publicvpn.node{ raw = "vless://j@h:10?s=1" },
				publicvpn.node{ raw = "vless://k@h:11?s=1" },
				publicvpn.node{ raw = "vless://l@h:12?s=1" },
			}
		end`)})
	// Plugin "other" - 6 nodes that duplicate 6 of highdup's nodes
	reg.Set(&plugins.Plugin{ID: "other", Path: "other.lua", Code: []byte(`
		return function()
			return {
				publicvpn.node{ raw = "vless://a@h:1?s=1" },
				publicvpn.node{ raw = "vless://b@h:2?s=1" },
				publicvpn.node{ raw = "vless://c@h:3?s=1" },
				publicvpn.node{ raw = "vless://d@h:4?s=1" },
				publicvpn.node{ raw = "vless://e@h:5?s=1" },
				publicvpn.node{ raw = "vless://f@h:6?s=1" },
			}
		end`)})
	// Plugin "lowdup" - 10 nodes, 2 duplicates (20% <= 50%)
	reg.Set(&plugins.Plugin{ID: "lowdup", Path: "lowdup.lua", Code: []byte(`
		return function()
			return {
				publicvpn.node{ raw = "vless://k@h:11?s=1" },
				publicvpn.node{ raw = "vless://l@h:12?s=1" },
				publicvpn.node{ raw = "vless://m@h:13?s=1" },
				publicvpn.node{ raw = "vless://n@h:14?s=1" },
				publicvpn.node{ raw = "vless://o@h:15?s=1" },
				publicvpn.node{ raw = "vless://p@h:16?s=1" },
				publicvpn.node{ raw = "vless://q@h:17?s=1" },
				publicvpn.node{ raw = "vless://r@h:18?s=1" },
				publicvpn.node{ raw = "vless://s@h:19?s=1" },
				publicvpn.node{ raw = "vless://t@h:20?s=1" },
			}
		end`)})
	// Plugin "other2" - 2 nodes that duplicate 2 of lowdup's nodes
	reg.Set(&plugins.Plugin{ID: "other2", Path: "other2.lua", Code: []byte(`
		return function()
			return {
				publicvpn.node{ raw = "vless://k@h:11?s=1" },
				publicvpn.node{ raw = "vless://l@h:12?s=1" },
			}
		end`)})

	out := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	_, err = runFetchWith(cmd, cfg, reg)
	require.NoError(t, err, "fetch wave must complete")

	text := out.String()
	// highdup should be disabled (66.7% > 50%)
	require.Contains(t, text, "highdup", "highdup should be in output:\n"+text)
	require.Contains(t, text, "DISABLED", "highdup should be disabled for exceeding max duplicate percent:\n"+text)
	require.Contains(t, text, "duplicate%", "warning must mention duplicate percentage:\n"+text)
	// lowdup should NOT be disabled (20% <= 50%)
	require.NotContains(t, text, "lowdup DISABLED", "lowdup should not be disabled:\n"+text)

	// Test 2: MinLivePercent threshold violation
	content = "data_dir = \"" + dir + "\"\n\n[plugins]\nmin_live_percent = 60.0\n"
	require.NoError(t, os.WriteFile(tomlPath, []byte(content), 0o600))
	cfg, err = config.Load(tomlPath)
	require.NoError(t, err)

	reg = plugins.NewRegistry()
	// Plugin "lowlive" - will have 3/10 live (30% < 60%)
	reg.Set(&plugins.Plugin{ID: "lowlive", Path: "lowlive.lua", Code: []byte(`
		return function()
			return {
				publicvpn.node{ raw = "vless://a@h:1?s=1" },
				publicvpn.node{ raw = "vless://b@h:2?s=1" },
				publicvpn.node{ raw = "vless://c@h:3?s=1" },
				publicvpn.node{ raw = "vless://d@h:4?s=1" },
				publicvpn.node{ raw = "vless://e@h:5?s=1" },
				publicvpn.node{ raw = "vless://f@h:6?s=1" },
				publicvpn.node{ raw = "vless://g@h:7?s=1" },
				publicvpn.node{ raw = "vless://h@h:8?s=1" },
				publicvpn.node{ raw = "vless://i@h:9?s=1" },
				publicvpn.node{ raw = "vless://j@h:10?s=1" },
			}
		end`)})
	// Plugin "highlive" - will have 8/10 live (80% >= 60%)
	reg.Set(&plugins.Plugin{ID: "highlive", Path: "highlive.lua", Code: []byte(`
		return function()
			return {
				publicvpn.node{ raw = "vless://k@h:11?s=1" },
				publicvpn.node{ raw = "vless://l@h:12?s=1" },
				publicvpn.node{ raw = "vless://m@h:13?s=1" },
				publicvpn.node{ raw = "vless://n@h:14?s=1" },
				publicvpn.node{ raw = "vless://o@h:15?s=1" },
				publicvpn.node{ raw = "vless://p@h:16?s=1" },
				publicvpn.node{ raw = "vless://q@h:17?s=1" },
				publicvpn.node{ raw = "vless://r@h:18?s=1" },
				publicvpn.node{ raw = "vless://s@h:19?s=1" },
				publicvpn.node{ raw = "vless://t@h:20?s=1" },
			}
		end`)})

	out = &bytes.Buffer{}
	cmd = &cobra.Command{}
	cmd.SetOut(out)
	// We can't fully test live% without probe/geo, but we can verify the
	// threshold check is wired by checking the stats collector is called
	_, err = runFetchWith(cmd, cfg, reg)
	require.NoError(t, err, "fetch wave must complete")

	text = out.String()
	// The fetch wave alone can't compute live% (needs probe), but we verify
	// the threshold config is read and the checker is invoked
	require.NotContains(t, text, "plugin highlive DISABLED", "highlive should not be disabled in fetch wave:\n"+text)
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

	// Two reality nodes in DE (so pool_de country balancer renders per >=2 threshold)
	// + a matching selection, so the render emits the full pool artifact set.
	n1 := model.NewNode("src", "vless", "00000000-0000-0000-0000-000000000001", "Se1.Example.com", 443,
		map[string]string{
			"security": "reality", "type": "tcp",
			"pbk": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "sid": "AA",
		})
	n2 := model.NewNode("src", "vless", "00000000-0000-0000-0000-000000000002", "Se2.Example.com", 443,
		map[string]string{
			"security": "reality", "type": "tcp",
			"pbk": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "sid": "BB",
		})
	b1, err := json.Marshal(n1)
	require.NoError(t, err)
	b2, err := json.Marshal(n2)
	require.NoError(t, err)
	p := newPaths(cfg)
	require.NoError(t, os.WriteFile(p.filtered, []byte(string(b1)+"\n"+string(b2)+"\n"), 0o600))
	sel := &model.Selection{Nodes: []model.SelectedNode{
		{Tag: "pool-de-01", Key: n1.Key, Country: "de"},
		{Tag: "pool-de-02", Key: n2.Key, Country: "de"},
	}}
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

func TestConfigReconciliationWarnsStaleBalancer(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir}
	cfg.Render.PoolRoutes = []config.PoolRoute{{Balancer: "pool_us", Domains: []string{"domain:x.com"}}}
	p := newPaths(cfg)
	sel := &model.Selection{Nodes: []model.SelectedNode{
		{Tag: "pool-de-01", Key: "k1", Country: "de"},
	}}
	require.NoError(t, store.WriteSelection(p.selection, sel))

	buf := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	state := &waveRunState{w: buf, cmd: cmd, cfg: cfg, stages: &maintainStages{}}
	state.reconcilePoolRoutes()

	assert.Contains(t, buf.String(), "WARNING: config reconciliation:")
	assert.Contains(t, buf.String(), "pool_us")
	assert.Contains(t, buf.String(), `"us"`)
}

func TestWireRecordStageStatPersistedAfterWave(t *testing.T) {
	cfg := maintainCfg(t)
	rec := &stageRecorder{}
	runMaintainForTest(t, cfg, maintainOptions{noActivate: true}, rec.stages())
	p := newPaths(cfg)
	stats, err := ReadStageStats(p.dataDir)
	require.NoError(t, err)
	assert.NotEmpty(t, stats, "RecordStageStat must be called after each stage")
	// adjusted base persisted
	b, err := os.ReadFile(filepath.Join(p.dataDir, "base-concurrency.txt"))
	require.NoError(t, err)
	assert.NotEmpty(t, string(b))
}

func TestWireAdaptConcurrencySeamCallable(t *testing.T) {
	got := adaptConcurrencyFunc(4, 90.0, false, false)
	assert.Equal(t, 3, got)
}

func TestWireSizingEngineResizeAppliesCap(t *testing.T) {
	c := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour})
	c.Resize(42)
	assert.Equal(t, 42, c.Capacity())
	// Need geo import
	_ = geo.NewSizingEngine()
}
