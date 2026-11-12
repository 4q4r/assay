package render_test

// Own-target render tests (self-held core pivot, 2026-11-10 design D2/D7/S6/
// S7): RenderOwnConfig generates assay's OWN live config, and the pipeline
// render stage writes it to <data>/rendered/live.json with the two-layer
// empty-pool contract — bootstrap block-catch-all at the render level,
// keep-last-good + loud line at the pipeline level.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"assay/internal/cli"
	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/render"
	"assay/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownPair renders a fixed DE node plus one node per given country through
// the shared mkSelected helper (reality vless, tcp).
func ownPair(t *testing.T, ccB, tagB string) ([]*model.Node, *model.Selection) {
	t.Helper()
	nA, snA := mkSelected(t, "pool-de-01", "de", "Berlin", "a.example.com", 2053, nodeOpts{network: "tcp"})
	nB, snB := mkSelected(t, tagB, ccB, "Paris", "b.example.com", 2053, nodeOpts{network: "tcp"})
	return []*model.Node{nA, nB}, &model.Selection{Nodes: []model.SelectedNode{snA, snB}}
}

func ownByKey(nodes []*model.Node) map[string]*model.Node {
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	return byKey
}

func ownRender(t *testing.T, sel *model.Selection, core config.CoreConfig, routes []render.RouteRule,
	nodes map[string]*model.Node,
) map[string]any {
	t.Helper()
	b, _, err := render.RenderOwnConfig(sel, core, routes, nodes, nil, render.Config{})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func ownInbound(t *testing.T, m map[string]any, tag string) map[string]any {
	t.Helper()
	raw, ok := m["inbounds"].([]any)
	require.True(t, ok, "inbounds array present")
	for _, inb := range raw {
		if im, isMap := inb.(map[string]any); isMap && im["tag"] == tag {
			return im
		}
	}
	t.Fatalf("inbound %q not found", tag)
	return nil
}

func ownRules(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	routing, ok := m["routing"].(map[string]any)
	require.True(t, ok, "routing object present")
	raw, ok := routing["rules"].([]any)
	require.True(t, ok, "routing rules array present")
	rules := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		rules = append(rules, r.(map[string]any))
	}
	return rules
}

// ownCatchAll returns the catch-all rule: the field rule matching all
// tcp,udp traffic with no other matcher.
func ownCatchAll(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	for _, r := range ownRules(t, m) {
		if _, hasBalancer := r["balancerTag"]; hasBalancer && r["network"] == "tcp,udp" {
			return r
		}
		if r["network"] == "tcp,udp" {
			if _, hasOut := r["outboundTag"]; hasOut {
				return r
			}
		}
	}
	t.Fatalf("catch-all rule (network tcp,udp) not found")
	return nil
}

func ownBalancerTags(t *testing.T, m map[string]any) []string {
	t.Helper()
	routing, ok := m["routing"].(map[string]any)
	require.True(t, ok, "routing object present")
	raw, _ := routing["balancers"].([]any)
	tags := make([]string, 0, len(raw))
	for _, b := range raw {
		if bm, isMap := b.(map[string]any); isMap {
			tags = append(tags, bm["tag"].(string))
		}
	}
	return tags
}

// TestRenderOwnBootstrapBlockCatchAll pins the D7 render-level layer: an
// empty selection is the bootstrap posture — the catch-all routes to the
// block blackhole (A4: an empty pool NEVER routes to direct), the base
// socks/http inbounds still render so the core manager's health check can
// dial socks (S2), and the S7 log block is warning/none. No pool artifact
// (no balancers, no observatory) may render with an empty selection (L1).
func TestRenderOwnBootstrapBlockCatchAll(t *testing.T) {
	m := ownRender(t, &model.Selection{}, config.CoreConfig{}, nil, nil)

	catch := ownCatchAll(t, m)
	assert.Equal(t, "block", catch["outboundTag"],
		"D7 bootstrap posture: the catch-all must route to the block blackhole")

	in := ownInbound(t, m, "in")
	assert.Equal(t, "socks", in["protocol"], "base socks inbound")
	assert.InDelta(t, config.DefaultCoreSocksPort, in["port"], 0, "socks inbound on the default port")
	assert.Equal(t, config.CoreBindAddress, in["listen"], "loopback bind (D2/N1)")
	inHTTP := ownInbound(t, m, "in-http")
	assert.Equal(t, "http", inHTTP["protocol"], "base http inbound")
	assert.InDelta(t, config.DefaultCoreHTTPPort, inHTTP["port"], 0, "http inbound on the default port")

	log, ok := m["log"].(map[string]any)
	require.True(t, ok, "log block present")
	assert.Equal(t, "warning", log["loglevel"], "S7 default loglevel")
	assert.Equal(t, "none", log["access"], "S7 access: none (journald-flood lesson)")

	assert.Empty(t, ownBalancerTags(t, m), "no pool balancers with an empty selection")
	assert.Nil(t, m["observatory"], "L1: no observatory with an empty selection")
}

// TestRenderOwnFullPool pins the full-pool shape: pool outbounds, the
// pool_all balancer, the catch-all routed to it, the base inbounds on the
// configured ports, and the stats/API block on api_port (the build-facts
// shape the -test gate requires).
func TestRenderOwnFullPool(t *testing.T) {
	nodes, sel := ownPair(t, "nl", "pool-nl-01")
	m := ownRender(t, sel, config.CoreConfig{}, nil, ownByKey(nodes))

	poolOutbound(t, m, "pool-de-01")
	poolOutbound(t, m, "pool-nl-01")

	tags := ownBalancerTags(t, m)
	assert.Contains(t, tags, model.PoolAllBalancerTag, "the pool-wide balancer renders")

	catch := ownCatchAll(t, m)
	assert.Equal(t, model.PoolAllBalancerTag, catch["balancerTag"],
		"non-empty selection: the catch-all routes to pool_all")

	in := ownInbound(t, m, "in")
	assert.InDelta(t, config.DefaultCoreSocksPort, in["port"], 0)
	inHTTP := ownInbound(t, m, "in-http")
	assert.InDelta(t, config.DefaultCoreHTTPPort, inHTTP["port"], 0)

	api := ownInbound(t, m, "api-in")
	assert.InDelta(t, config.DefaultCoreAPIPort, api["port"], 0, "stats API on api_port")
	assert.NotNil(t, m["stats"], "stats object present (build facts: counters need it)")
	policy, ok := m["policy"].(map[string]any)
	require.True(t, ok, "policy block present")
	system, ok := policy["system"].(map[string]any)
	require.True(t, ok, "policy.system present")
	assert.Equal(t, true, system["statsOutboundUplink"], "per-tag counters need the policy switch")
	assert.Equal(t, true, system["statsOutboundDownlink"], "the downlink twin switch (build facts)")

	obs, ok := m["observatory"].(map[string]any)
	require.True(t, ok, "Plan A observatory present with a pool")
	assert.Equal(t, []any{"pool-"}, obs["subjectSelector"], "L2: the selector covers every pool outbound")
}

// TestRenderOwnPerCountryInbounds pins the D2 option: per_country_inbounds
// renders one socks inbound per alive-country balancer (tags in-<cc>, port
// base after the socks port, skipping the http port), each routed to its
// country balancer by a dedicated inbound-tag rule.
func TestRenderOwnPerCountryInbounds(t *testing.T) {
	nodes, sel := ownPair(t, "fr", "pool-fr-01")
	core := config.CoreConfig{
		SocksPort: 10810, HTTPPort: 10811, APIPort: 15491,
		PerCountryInbounds: true, Loglevel: "warning",
	}
	m := ownRender(t, sel, core, nil, ownByKey(nodes))

	inDE := ownInbound(t, m, "in-de")
	assert.Equal(t, "socks", inDE["protocol"], "per-country inbound is socks")
	assert.Equal(t, config.CoreBindAddress, inDE["listen"], "loopback bind")
	assert.InDelta(t, 10812, inDE["port"], 0, "first country port = socks_port+1 (http port skipped)")
	inFR := ownInbound(t, m, "in-fr")
	assert.InDelta(t, 10813, inFR["port"], 0, "next country port, distinct")

	for _, tc := range []struct{ tag, balancer string }{
		{"in-de", "pool_de"},
		{"in-fr", "pool_fr"},
	} {
		found := false
		for _, r := range ownRules(t, m) {
			tagged, _ := r["inboundTag"].([]any)
			if len(tagged) == 1 && tagged[0] == tc.tag {
				found = true
				assert.Equal(t, tc.balancer, r["balancerTag"],
					"in-%s traffic rides its own country balancer", tc.tag)
			}
		}
		assert.True(t, found, "routing rule binding in-%s to %s present", tc.tag, tc.balancer)
	}

	// The base inbounds stay (the country ports are additional, D2).
	ownInbound(t, m, "in")
	ownInbound(t, m, "in-http")
}

// TestRenderOwnNilSelectionBootstraps pins the nil-tolerance promise (review
// I-1): a nil selection IS the bootstrap posture — the D7 fail-closed shape,
// and no panic (the promise must hold at the entry, not just in the loop).
func TestRenderOwnNilSelectionBootstraps(t *testing.T) {
	b, _, err := render.RenderOwnConfig(nil, config.CoreConfig{}, nil, nil, nil, render.Config{})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	catch := ownCatchAll(t, m)
	assert.Equal(t, "block", catch["outboundTag"], "nil selection → bootstrap posture (D7/A4)")
	ownInbound(t, m, "in")
	ownInbound(t, m, "in-http")
	assert.Nil(t, m["observatory"], "no observatory in the bootstrap posture")
}

// TestRenderOwnPerCountryPortsSkipReserved pins the port walk skipping every
// reserved port (review M2): with the socks port based just under api_port,
// a country inbound must never land on the generated http inbound or the api
// dokodemo-door — a bind collision passes -test and only surfaces as a core
// crash-loop.
func TestRenderOwnPerCountryPortsSkipReserved(t *testing.T) {
	nodes, sel := ownPair(t, "nl", "pool-nl-01")
	core := config.CoreConfig{
		SocksPort: 15489, HTTPPort: 15490, APIPort: 15491,
		PerCountryInbounds: true, Loglevel: "warning",
	}
	m := ownRender(t, sel, core, nil, ownByKey(nodes))

	inDE := ownInbound(t, m, "in-de")
	assert.InDelta(t, 15492, inDE["port"], 0,
		"the walk skips http (15490) AND api (15491): first country port = 15492")
	assert.InDelta(t, 15493, ownInbound(t, m, "in-nl")["port"], 0, "the walk continues past the skips")
	assert.InDelta(t, 15491, ownInbound(t, m, "api-in")["port"], 0, "the api port is untouched")
}

// TestRenderPoolRoutesAboveCatchAll pins the S6 ordering: owner domain rules
// (matched against the GENERATED inbound tags) sit between the api rule and
// the catch-all, never shadowed by it.
func TestRenderPoolRoutesAboveCatchAll(t *testing.T) {
	nodes, sel := ownPair(t, "nl", "pool-nl-01")
	routes := []render.RouteRule{{Balancer: "pool_de", Domains: []string{"geosite:netflix"}}}
	m := ownRender(t, sel, config.CoreConfig{}, routes, ownByKey(nodes))

	rules := ownRules(t, m)
	apiIdx, domainIdx, catchIdx := -1, -1, -1
	for i, r := range rules {
		switch {
		case r["outboundTag"] == "api" && apiIdx == -1:
			apiIdx = i
		case r["network"] == "tcp,udp":
			catchIdx = i
		}
		domains, _ := r["domain"].([]any)
		if len(domains) > 0 && domains[0] == "geosite:netflix" {
			domainIdx = i
			tagged, _ := r["inboundTag"].([]any)
			assert.ElementsMatch(t, []any{"in", "in-http"}, tagged,
				"S6: the rule matches the generated base inbound tags")
		}
	}
	require.NotEqual(t, -1, apiIdx, "api rule present")
	require.NotEqual(t, -1, domainIdx, "pool route rule present")
	require.NotEqual(t, -1, catchIdx, "catch-all present")
	assert.Less(t, domainIdx, catchIdx, "S6: the domain rule must sit above the catch-all")
	assert.Less(t, apiIdx, domainIdx, "the api rule stays first (matches only its own inbound)")
}

// TestRenderOwnDegradesRoutesLoud pins the T4 report-channel widening (the
// T3 review's M1, folded into this task's wiring): an S6 domain route whose
// target balancer was not rendered (no live nodes there) degrades to block
// — fail-closed — AND reaches the caller through the warnings slice (the
// same strings the template path reports via Result.BlockedRoutes), so the
// cli render stage can print the WARNING lines again.
func TestRenderOwnDegradesRoutesLoud(t *testing.T) {
	nodes, sel := ownPair(t, "nl", "pool-nl-01") // de+nl nodes — no FR anywhere
	b, warnings, err := render.RenderOwnConfig(sel, config.CoreConfig{},
		[]render.RouteRule{{Balancer: "pool_fr", Domains: []string{"geosite:netflix"}}},
		ownByKey(nodes), nil, render.Config{})
	require.NoError(t, err)
	require.Len(t, warnings, 1, "the degraded route is reported, not swallowed")
	assert.Contains(t, warnings[0], `pool route balancer "pool_fr" not rendered -> block`)

	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	var degrade map[string]any
	for _, r := range ownRules(t, m) {
		domains, _ := r["domain"].([]any)
		if len(domains) > 0 && domains[0] == "geosite:netflix" {
			degrade = r
		}
	}
	require.NotNil(t, degrade, "the S6 rule is still rendered")
	assert.Equal(t, "block", degrade["outboundTag"], "fail-closed: the degraded route targets block, never direct")
}

// pipelineOwnFixture materializes a minimal render-capable data dir: a small
// template (the transitional template artifact still renders), an empty
// selection, and no geo base (the documented empty state).
func pipelineOwnFixture(t *testing.T, dir string) string {
	t.Helper()
	tmpl := filepath.Join(dir, "template.json")
	require.NoError(t, os.WriteFile(tmpl, []byte(`{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": true}},
    {"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": {}}
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {"rules": [
    {"type": "field", "inboundTag": ["socks-in", "http-in"], "network": "tcp,udp", "balancerTag": "best_rtt"}
  ], "balancers": [
    {"tag": "best_rtt", "selector": ["proxy-"], "strategy": {"type": "leastLoad", "settings": {"expected": 1}}, "fallbackTag": "proxy-0"}
  ]}
}`), 0o644))
	tomlPath := filepath.Join(dir, "config.toml")
	content := "data_dir = \"" + dir + "\"\n\n[render]\ntemplate = \"" + tmpl + "\"\n"
	require.NoError(t, os.WriteFile(tomlPath, []byte(content), 0o644))
	require.NoError(t, store.WriteSelection(filepath.Join(dir, "selection.json"), &model.Selection{}))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "filtered.jsonl"), []byte(""), 0o600))
	return tomlPath
}

// runPipelineRender drives the REAL render stage through the cli command
// tree (config.Load → runRender), capturing the stage output.
func runPipelineRender(t *testing.T, tomlPath string) string {
	t.Helper()
	root := cli.New()
	cmd, _, err := root.Find([]string{"render"})
	require.NoError(t, err)
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	root.SetArgs([]string{"render", "-c", tomlPath})
	require.NoError(t, root.Execute())
	return buf.String()
}

// TestPipelineKeepsLastGoodOnEmptySelection pins the D7 pipeline-level
// layer: with a prior live.json and an empty selection the stage skips the
// write and says so loud — the core keeps running on the last-good config.
func TestPipelineKeepsLastGoodOnEmptySelection(t *testing.T) {
	dir := t.TempDir()
	tomlPath := pipelineOwnFixture(t, dir)
	livePath := filepath.Join(dir, "rendered", "live.json")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "rendered"), 0o750))
	sentinel := []byte(`{"last":"good"}`)
	require.NoError(t, os.WriteFile(livePath, sentinel, 0o600))

	out := runPipelineRender(t, tomlPath)

	raw, err := os.ReadFile(livePath)
	require.NoError(t, err)
	assert.Equal(t, string(sentinel), string(raw), "last-good live.json must be untouched")
	assert.Contains(t, out, "render: empty selection — keeping last-good core config",
		"the loud keep-last-good line is required")
}

// TestPipelineWritesBootstrapWhenNoPriorLive pins the first-run contract:
// with no prior live.json the stage writes the bootstrap artifact (empty
// pool fail-closed) so the core manager can spawn per S2.
func TestPipelineWritesBootstrapWhenNoPriorLive(t *testing.T) {
	dir := t.TempDir()
	tomlPath := pipelineOwnFixture(t, dir)
	livePath := filepath.Join(dir, "rendered", "live.json")

	out := runPipelineRender(t, tomlPath)

	raw, err := os.ReadFile(livePath)
	require.NoError(t, err, "the bootstrap artifact must be written")
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	catch := ownCatchAll(t, m)
	assert.Equal(t, "block", catch["outboundTag"], "bootstrap catch-all → block (D7/A4)")
	ownInbound(t, m, "in")
	ownInbound(t, m, "in-http")
	assert.Contains(t, out, "bootstrap", "the first-run bootstrap write says so")
}

// TestRenderOwnPassesXrayTest validates the own-target generation against
// the real core binary (the golden-test precedent, skip-guarded so the gate
// stays hermetic where the binary is absent): the bootstrap, full-pool, and
// per-country shapes must all clear `xray run -test` — the contract the core
// manager's spawn and the activation -test gate depend on.
func TestRenderOwnPassesXrayTest(t *testing.T) {
	bin := "/usr/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("xray binary not present at %s", bin)
	}

	bootstrap, _, err := render.RenderOwnConfig(&model.Selection{}, config.CoreConfig{},
		nil, nil, nil, render.Config{})
	require.NoError(t, err)
	nodes, sel := ownPair(t, "nl", "pool-nl-01")
	fullPool, warnings, err := render.RenderOwnConfig(sel, config.CoreConfig{},
		[]render.RouteRule{{Balancer: "pool_fr", Domains: []string{"geosite:netflix"}}},
		ownByKey(nodes), nil, render.Config{})
	require.NoError(t, err)
	require.NotEmpty(t, warnings, "the pool_fr route degrades (no FR nodes) — the warning channel must carry it")
	perCountry, _, err := render.RenderOwnConfig(sel, config.CoreConfig{
		SocksPort: 10810, HTTPPort: 10811, APIPort: 15491,
		PerCountryInbounds: true, Loglevel: "warning",
	}, nil, ownByKey(nodes), nil, render.Config{})
	require.NoError(t, err)

	for name, cfg := range map[string][]byte{
		"bootstrap":   bootstrap,
		"full-pool":   fullPool,
		"per-country": perCountry,
	} {
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir()
			path := filepath.Join(tmp, "own.json")
			require.NoError(t, os.WriteFile(path, cfg, 0o600))
			cmd := exec.CommandContext(context.Background(), bin, "run", "-test", "-c", path)
			cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+tmp)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "xray run -test rejected the own %s config:\n%s", name, out)
			assert.Contains(t, string(out), "Configuration OK")
		})
	}
}

// TestRenderOwnSurfacesDroppedParams (T7 disposition C1 — SURFACE chosen):
// a non-material link param the renderer cannot place — the allowInsecure
// class, admitted by [filter].allow_insecure and capability-limited because
// the core removed the flag — must surface through the returned warnings.
// The renderer's own contract comment (buildTLSSettings) promises
// "capability-limitation surfaced in renderer", and config.example's
// [filter] block promises "a loud drop-report entry"; discarding the report
// silently (the pre-T7 `ob, _, err` discard) broke both promises. The
// material class keeps failing the render loud (pinned in
// TestXHTTPExtraNonObjectFailsLoud) — the warnings channel carries only the
// non-material remainder.
func TestRenderOwnSurfacesDroppedParams(t *testing.T) {
	nodes, sel := ownPair(t, "fr", "pool-fr-01")
	nodes[0].Params["allowInsecure"] = "1"

	_, warnings, err := render.RenderOwnConfig(sel, ownCore(),
		nil, ownByKey(nodes), nil, render.Config{})
	require.NoError(t, err)
	require.NotEmpty(t, warnings, "the drop report must surface through the warnings channel")
	joined := strings.Join(warnings, "\n")
	assert.Contains(t, joined, "pool-de-01", "the affected outbound's tag is named")
	assert.Contains(t, joined, "allowInsecure", "the dropped param is named")

	// The untouched node contributes no drop warning.
	assert.NotContains(t, joined, "pool-fr-01",
		"an outbound with no dropped params stays out of the drop report")
}
