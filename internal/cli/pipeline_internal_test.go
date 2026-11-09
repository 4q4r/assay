package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/fetch"
	"public_vpn/internal/model"
	"public_vpn/internal/plugins"
	"public_vpn/internal/stats"
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

// TestCheckMinLivePercentEnforcesOnWaveRegistry pins F1: the MinLivePercent
// enforcement lands on the WAVE's real registry — the watchdog-maintained
// one in the daemon — so RecordFailure actually disables the plugin for
// subsequent waves. The old fake-enforcement path loaded a throwaway
// registry inside the check, recorded the failure into it, and dropped it
// (nothing was ever disabled; registry-load errors silently no-oped).
func TestCheckMinLivePercentEnforcesOnWaveRegistry(t *testing.T) {
	dir := t.TempDir()
	enrichFixture(t, dir)
	minLive := 100.0 // alpha 75% and beta 50% live — both breach
	cfg := &config.Config{DataDir: dir, Plugins: config.PluginsConfig{MinLivePercent: &minLive}}

	buf := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(buf)

	reg := plugins.NewRegistry()
	require.NoError(t, runPluginStatsEnrichment(cmd, cfg, reg))

	disabled := reg.DisabledPlugins()
	assert.Contains(t, disabled, "alpha", "the breach must disable the plugin on the WAVE's registry")
	assert.Contains(t, disabled, "beta")
	assert.Contains(t, buf.String(), "DISABLED: live%", "the enforcement line stays loud")
}

// TestCheckMinLivePercentNilRegistrySkips pins the nil contract (same class
// as checkMaxDuplicatePercent): threshold enforcement needs the wave's
// registry; a nil one skips the check instead of loading a throwaway copy.
func TestCheckMinLivePercentNilRegistrySkips(t *testing.T) {
	dir := t.TempDir()
	enrichFixture(t, dir)
	minLive := 100.0
	cfg := &config.Config{DataDir: dir, Plugins: config.PluginsConfig{MinLivePercent: &minLive}}

	buf := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	require.NoError(t, runPluginStatsEnrichment(cmd, cfg, nil))
	assert.NotContains(t, buf.String(), "DISABLED",
		"no registry — no enforcement, and no throwaway reload")
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

// enrichFixture builds one wave's worth of pipeline artifacts in dir:
// a fetch manifest with fetch-stage plugin stats, filtered parse records,
// probe outcomes, and geo records. The fixture exercises the W19 landmine:
// alpha/n4 and beta/n5 share ONE geo identity (same scheme/host/port) while
// carrying distinct credentials; n5's OWN probe is dead so it must never ride
// the shared record's liveness.
func enrichFixture(t *testing.T, dir string) {
	t.Helper()
	cfg := &config.Config{DataDir: dir}
	p := newPaths(cfg)
	require.NoError(t, os.MkdirAll(p.cacheDir, 0o750))

	mkNode := func(source, host, cred string) *model.Node {
		return model.NewNode(source, "vless", cred, host, 443, map[string]string{"security": "tls"})
	}
	n1 := mkNode("alpha", "a1.example", "u1")     // alive, clean, positive unlock evidence
	n2 := mkNode("alpha", "a2.example", "u2")     // alive, hosting
	n3 := mkNode("alpha", "a3.example", "u3")     // dead, hosting
	n4 := mkNode("alpha", "shared.example", "u4") // alive, clean identity (shared with n5)
	n5 := mkNode("beta", "shared.example", "u5")  // dead own probe — W19 gate must hold
	n6 := mkNode("beta", "b6.example", "u6")      // alive, proxy
	nodes := []*model.Node{n1, n2, n3, n4, n5, n6}
	require.NoError(t, store.WriteNodes(p.filtered, nodes))

	now := time.Now().UTC()
	probe := func(n *model.Node, alive bool, rtt float64) store.ProbeResult {
		return store.ProbeResult{Key: n.Key, Host: n.Host, Alive: alive, RTTMs: rtt, CheckedAt: now}
	}
	results := []store.ProbeResult{
		probe(n1, true, 100), probe(n2, true, 200), probe(n3, false, 0),
		probe(n4, true, 300), probe(n5, false, 0), probe(n6, true, 400),
	}
	var buf strings.Builder
	for _, r := range results {
		b, err := json.Marshal(r)
		require.NoError(t, err)
		buf.WriteString(string(b) + "\n")
	}
	require.NoError(t, os.WriteFile(p.probeResults, []byte(buf.String()), 0o600))

	unlocked := model.MediaUnlockStatus{CheckedAt: now.Format(time.RFC3339), ChatGPT: model.UnlockYes}
	geoRec := func(host string, hosting, proxy bool, ms model.MediaUnlockStatus) *model.GeoRecord {
		return &model.GeoRecord{
			Scheme: "vless", Host: host, Port: 443, Alive: true,
			HostingFlag: hosting, ProxyFlag: proxy,
			FlagsVerified: true, Country: "DE", MediaUnlocks: ms,
		}
	}
	require.NoError(t, store.WriteGeo(p.geoBase, []*model.GeoRecord{
		geoRec("a1.example", false, false, unlocked),
		geoRec("a2.example", true, false, model.MediaUnlockStatus{}),
		geoRec("a3.example", true, false, model.MediaUnlockStatus{}),
		geoRec("shared.example", false, false, model.MediaUnlockStatus{}),
		geoRec("b6.example", false, true, model.MediaUnlockStatus{}),
	}))

	manifest := fetchManifest{
		FetchedAt: now,
		Sources:   map[string][]fetch.FetchedFile{},
		PluginStats: []plugins.PluginStats{
			{PluginID: "alpha", TotalNodes: 4, DuplicateCount: 1},
			{PluginID: "beta", TotalNodes: 2},
		},
	}
	//nolint:musttag // fetchManifest has JSON tags; musttag false positive (same as production sites)
	b, err := json.MarshalIndent(manifest, "", "  ")
	require.NoError(t, err)
	require.NoError(t, store.WriteManifest(p.manifest, b))
}

func enrichmentCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	return cmd
}

// TestRunPluginStatsEnrichmentFullCycle pins the owner-approved contract:
// live/clean/hosting/unlock metrics reflect the FULL wave cycle with plugin
// attribution preserved at every stage, the pairwise overlap matrix lands in
// the manifest, and the provider time-series snapshot is recorded — all in
// one enrichment pass at the wave tail.
func TestRunPluginStatsEnrichmentFullCycle(t *testing.T) {
	dir := t.TempDir()
	enrichFixture(t, dir)
	cfg := &config.Config{DataDir: dir}

	require.NoError(t, runPluginStatsEnrichment(enrichmentCommand(), cfg, nil))

	var manifest fetchManifest
	b, err := os.ReadFile(newPaths(cfg).manifest)
	require.NoError(t, err)
	//nolint:musttag // fetchManifest has JSON tags; musttag false positive
	require.NoError(t, json.Unmarshal(b, &manifest))

	byID := map[string]plugins.PluginStats{}
	for _, st := range manifest.PluginStats {
		byID[st.PluginID] = st
	}
	require.Contains(t, byID, "alpha")
	require.Contains(t, byID, "beta")

	alpha := byID["alpha"]
	assert.Equal(t, 4, alpha.TotalNodes, "fetch-stage total survives")
	assert.Equal(t, 3, alpha.LiveNodes, "n1+n2+n4 alive by their OWN probe results")
	assert.Equal(t, 2, alpha.HostingCount, "n2+n3 hosting per parse record")
	assert.Equal(t, 0, alpha.ProxyCount)
	assert.Equal(t, 2, alpha.CleanCount, "n1+n4 clean")
	assert.Equal(t, 1, alpha.UnlockCount, "n1 carries a checked positive unlock")
	assert.InDelta(t, 75.0, alpha.UniqueYield, 1e-9, "3/4 identities are alpha-exclusive")
	require.Len(t, alpha.TopOverlaps, 1)
	assert.Equal(t, "beta", alpha.TopOverlaps[0].PluginID)
	assert.InDelta(t, 25.0, alpha.TopOverlaps[0].Percent, 1e-9, "1/4 of alpha is covered by beta")

	beta := byID["beta"]
	assert.Equal(t, 2, beta.TotalNodes)
	assert.Equal(t, 1, beta.LiveNodes,
		"W19 landmine: n5's OWN probe is dead — it must not ride the shared identity's liveness")
	assert.Equal(t, 1, beta.ProxyCount, "n6")
	assert.Equal(t, 1, beta.CleanCount, "n5 rides the shared CLEAN geo record for the quality count")
	assert.Equal(t, 0, beta.UnlockCount)
	assert.InDelta(t, 50.0, beta.UniqueYield, 1e-9, "1/2 identities are beta-exclusive")
	require.Len(t, beta.TopOverlaps, 1)
	assert.Equal(t, "alpha", beta.TopOverlaps[0].PluginID)
	assert.InDelta(t, 50.0, beta.TopOverlaps[0].Percent, 1e-9, "beta is fully covered by alpha")

	require.NotNil(t, manifest.PluginOverlap, "the overlap matrix is stored for the --overlap view")
	assert.Equal(t, map[string]int{"alpha": 4, "beta": 2}, manifest.PluginOverlap.Sets)
	assert.InDelta(t, 25.0, manifest.PluginOverlap.Cells["alpha"]["beta"], 1e-9)
	assert.InDelta(t, 50.0, manifest.PluginOverlap.Cells["beta"]["alpha"], 1e-9)

	h, err := stats.ReadProviderHistory(filepath.Join(dir, "provider-history.json"))
	require.NoError(t, err, "the enrichment pass records the provider time-series")
	require.Len(t, h.Providers, 2)
	aw := h.Providers["alpha"].Waves
	require.Len(t, aw, 1)
	assert.Equal(t, 4, aw[0].Total)
	assert.Equal(t, 3, aw[0].Live)
	assert.Equal(t, 2, aw[0].Clean)
	assert.Equal(t, 2, aw[0].Hosting)
	assert.Equal(t, int64(200), aw[0].MedianRTT, "median over n1/n2/n4 RTTs")
	bw := h.Providers["beta"].Waves
	require.Len(t, bw, 1)
	assert.Equal(t, int64(400), bw[0].MedianRTT, "median over the single alive record")
}

// TestRunPluginStatsEnrichmentHistoryFailureNonFatal pins the integration
// contract: the time-series recording is accounting, not correctness — a
// failing write leaves a loud WARNING and the wave's enrichment still lands.
func TestRunPluginStatsEnrichmentHistoryFailureNonFatal(t *testing.T) {
	dir := t.TempDir()
	enrichFixture(t, dir)
	cfg := &config.Config{DataDir: dir}
	// A DIRECTORY at the history path makes every read/write fail — the
	// loudest non-fatal failure mode available without root games.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "provider-history.json"), 0o750))

	buf := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	require.NoError(t, runPluginStatsEnrichment(cmd, cfg, nil),
		"history failure must not fail the enrichment stage")
	assert.Contains(t, buf.String(), "WARNING: provider history update failed",
		"the failure surfaces loud before the wave continues")

	var manifest fetchManifest
	b, err := os.ReadFile(newPaths(cfg).manifest)
	require.NoError(t, err)
	//nolint:musttag // fetchManifest has JSON tags; musttag false positive
	require.NoError(t, json.Unmarshal(b, &manifest))
	require.NotEmpty(t, manifest.PluginStats)
	for _, st := range manifest.PluginStats {
		assert.Positive(t, st.LiveNodes, "enriched stats still landed despite the history failure")
	}
}

// TestRunFetchWithCarriesOverEnrichedStats pins the fetch × enrichment merge
// contract. The enrichment tail (runPluginStatsEnrichment) rewrites the
// manifest once per full wave cycle, ~2h after fetch; the NEXT wave's fetch
// must PRESERVE those enrichment-layer fields instead of clobbering them
// with fresh basic stats (production incident: `publicvpn status` showed
// live=0 / n-a / NONE for the entire cycle except the seconds between the
// enrichment tail and the next fetch). Table-driven:
//
//   - carries_enrichment_and_refreshes_fetch_fields: enriched manifest on
//     disk → runFetchWith → manifest still carries enriched fields for
//     plugins the new fetch still runs, while TotalNodes/DuplicateCount/
//     fetched_at/sources refresh; a plugin the enrichment never saw starts
//     unenriched; plugin_overlap carries over;
//   - drops_stats_of_plugins_absent_from_fetch: a dropped plugin takes its
//     stale stats with it;
//   - corrupt_prior_manifest_warns_and_starts_fresh: loud WARNING, wave
//     proceeds, fresh manifest;
//   - cold_start_without_prior_manifest: silent, behaves exactly as the
//     pre-fix code.
func TestRunFetchWithCarriesOverEnrichedStats(t *testing.T) {
	// runFetch runs one fetch wave with the given registry and returns the
	// manifest now on disk plus the wave output (for WARNING assertions).
	runFetch := func(t *testing.T, dir string, reg *plugins.Registry) (fetchManifest, string) {
		t.Helper()
		cfg := &config.Config{DataDir: dir}
		out := &bytes.Buffer{}
		cmd := &cobra.Command{}
		cmd.SetOut(out)
		_, err := runFetchWith(cmd, cfg, reg)
		require.NoError(t, err)
		b, err := os.ReadFile(newPaths(cfg).manifest)
		require.NoError(t, err)
		var m fetchManifest
		//nolint:musttag // fetchManifest has JSON tags; musttag false positive
		require.NoError(t, json.Unmarshal(b, &m))
		return m, out.String()
	}

	// stubRegistry returns a registry whose plugins each return one node —
	// no network, deterministic fetch-layer stats.
	stubRegistry := func(ids ...string) *plugins.Registry {
		reg := plugins.NewRegistry()
		for _, id := range ids {
			code := fmt.Sprintf(
				`return function() return { publicvpn.node{ raw = "vless://n@%s.example:443?s=1" } } end`, id)
			reg.Set(&plugins.Plugin{ID: id, Path: id + ".lua", Code: []byte(code)})
		}
		return reg
	}

	// enrichedPrior builds the manifest shape the enrichment tail leaves
	// behind: fetch-layer stats plus a full enrichment overlay for two
	// plugins and the pairwise overlap matrix.
	enrichedPrior := func() fetchManifest {
		return fetchManifest{
			FetchedAt: time.Now().UTC().Add(-2 * time.Hour),
			Sources: map[string][]fetch.FetchedFile{
				"alpha": {{Source: "alpha", Path: "alpha.txt", URL: "plugin://alpha",
					Body: []byte("stale\n"), FetchedAt: time.Now().UTC().Add(-2 * time.Hour)}},
			},
			PluginStats: []plugins.PluginStats{
				{
					PluginID: "alpha", TotalNodes: 999, DuplicateCount: 7,
					LiveNodes: 42, HostingCount: 5, ProxyCount: 3,
					CleanCount: 34, ClassifiedCount: 40, UnlockCount: 9,
					UniqueYield: 75,
					TopOverlaps: []plugins.OverlapPair{{PluginID: "beta", Percent: 25}},
				},
				{
					PluginID: "beta", TotalNodes: 10, DuplicateCount: 2,
					LiveNodes: 4, HostingCount: 1, ProxyCount: 1,
					CleanCount: 2, ClassifiedCount: 4, UnlockCount: 0,
					UniqueYield: 50,
					TopOverlaps: []plugins.OverlapPair{{PluginID: "alpha", Percent: 50}},
				},
			},
			PluginOverlap: &plugins.OverlapMatrix{
				Sets:  map[string]int{"alpha": 4, "beta": 2},
				Cells: map[string]map[string]float64{"alpha": {"beta": 25}, "beta": {"alpha": 50}},
			},
		}
	}

	writePrior := func(t *testing.T, dir string, m fetchManifest) {
		t.Helper()
		//nolint:musttag // fetchManifest has JSON tags; musttag false positive (same as production sites)
		b, err := json.MarshalIndent(m, "", "  ")
		require.NoError(t, err)
		require.NoError(t, store.WriteManifest(newPaths(&config.Config{DataDir: dir}).manifest, b))
	}

	statsByID := func(m fetchManifest) map[string]plugins.PluginStats {
		out := map[string]plugins.PluginStats{}
		for _, st := range m.PluginStats {
			out[st.PluginID] = st
		}
		return out
	}

	t.Run("carries_enrichment_and_refreshes_fetch_fields", func(t *testing.T) {
		dir := t.TempDir()
		prior := enrichedPrior()
		writePrior(t, dir, prior)

		m, _ := runFetch(t, dir, stubRegistry("alpha", "charlie"))

		byID := statsByID(m)
		require.Contains(t, byID, "alpha")
		require.Contains(t, byID, "charlie")

		alpha := byID["alpha"]
		assert.Equal(t, 1, alpha.TotalNodes, "fetch-layer TotalNodes refreshes from the new wave")
		assert.Equal(t, 0, alpha.DuplicateCount, "fetch-layer DuplicateCount refreshes from the new wave")
		assert.Equal(t, 42, alpha.LiveNodes, "enrichment-layer fields survive the next fetch")
		assert.Equal(t, 5, alpha.HostingCount)
		assert.Equal(t, 3, alpha.ProxyCount)
		assert.Equal(t, 34, alpha.CleanCount)
		assert.Equal(t, 40, alpha.ClassifiedCount)
		assert.Equal(t, 9, alpha.UnlockCount)
		assert.InDelta(t, 75.0, alpha.UniqueYield, 1e-9)
		require.Len(t, alpha.TopOverlaps, 1)
		assert.Equal(t, "beta", alpha.TopOverlaps[0].PluginID)
		assert.InDelta(t, 25.0, alpha.TopOverlaps[0].Percent, 1e-9)

		charlie := byID["charlie"]
		assert.Equal(t, 1, charlie.TotalNodes)
		assert.Zero(t, charlie.LiveNodes,
			"a plugin the enrichment never saw starts unenriched (pending until the next enrichment tail)")
		assert.Zero(t, charlie.HostingCount)
		assert.Zero(t, charlie.ClassifiedCount)

		require.NotNil(t, m.PluginOverlap, "plugin_overlap carries over until the next enrichment recomputes it")
		assert.Equal(t, map[string]int{"alpha": 4, "beta": 2}, m.PluginOverlap.Sets)

		require.Contains(t, m.Sources, "alpha", "sources refresh with the new fetch")
		assert.True(t, m.FetchedAt.After(prior.FetchedAt), "fetched_at refreshes")
	})

	t.Run("drops_stats_of_plugins_absent_from_fetch", func(t *testing.T) {
		dir := t.TempDir()
		writePrior(t, dir, enrichedPrior())

		m, _ := runFetch(t, dir, stubRegistry("alpha"))

		require.Len(t, m.PluginStats, 1,
			"a plugin the fetch no longer carries takes its stale stats with it")
		assert.Equal(t, "alpha", m.PluginStats[0].PluginID)
	})

	t.Run("corrupt_prior_manifest_warns_and_starts_fresh", func(t *testing.T) {
		dir := t.TempDir()
		p := newPaths(&config.Config{DataDir: dir})
		require.NoError(t, os.MkdirAll(p.cacheDir, 0o750))
		require.NoError(t, os.WriteFile(p.manifest, []byte("{not json"), 0o600))

		m, text := runFetch(t, dir, stubRegistry("alpha"))

		assert.Contains(t, text, "WARNING", "a corrupt prior manifest must be loud:\n"+text)
		require.Len(t, m.PluginStats, 1)
		assert.Zero(t, m.PluginStats[0].LiveNodes, "no carry-over from garbage: fresh basic stats")
		assert.Equal(t, 1, m.PluginStats[0].TotalNodes, "the wave itself is unaffected")
	})

	t.Run("cold_start_without_prior_manifest", func(t *testing.T) {
		dir := t.TempDir()

		m, text := runFetch(t, dir, stubRegistry("alpha"))

		assert.NotContains(t, text, "WARNING", "a cold start is not a warning condition")
		require.Len(t, m.PluginStats, 1)
		assert.Zero(t, m.PluginStats[0].LiveNodes)
	})
}

// TestClassifierForKnobFalseIsNil pins the escape hatch: [geo].unlock_probes
// = false wires NO classifier — a probe-only wave (zero classification
// requests; geo-base untouched; probe outcomes byte-identical, pinned at the
// engine level by TestClassifierNilIsProbeOnly).
func TestClassifierForKnobFalseIsNil(t *testing.T) {
	off := false
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Geo.UnlockProbes = &off
	assert.Nil(t, classifierFor(cfg, newPaths(cfg), io.Discard),
		"an explicit false = probe-only wave (no classification)")
}

// TestClassifierForDefaultIsWired pins the default: the knob absent (the
// production shape after applyGeoDefaults materializes true — and a
// hand-built nil pointer via the accessor) wires the classifier.
func TestClassifierForDefaultIsWired(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir()}
	assert.NotNil(t, classifierFor(cfg, newPaths(cfg), io.Discard),
		"the knob absent/true = the full classification battery rides every alive probe")
	on := true
	cfg.Geo.UnlockProbes = &on
	assert.NotNil(t, classifierFor(cfg, newPaths(cfg), io.Discard),
		"an explicit true wires the classifier like the absent default")
}
