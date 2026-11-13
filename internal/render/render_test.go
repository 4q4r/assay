package render_test

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Since the self-held-core pivot (D3) the renderer has ONE entry: the fully
// generated own config. These tests exercise the shared pool layer (outbound
// builders, balancer tree, pool routes, observatory, api/stats blocks)
// through that entry; the drop-report transport pins run through
// render.BuildOutbound — the SAME builder the own render and the site
// checker use (one literal, no drift).

type nodeOpts struct {
	scheme  string
	network string
	extra   map[string]string
}

func mkSelected(t *testing.T, tag, cc, city, host string, port int, o nodeOpts) (*model.Node, model.SelectedNode) {
	t.Helper()
	scheme := o.scheme
	if scheme == "" {
		scheme = "vless"
	}
	params := map[string]string{"type": o.network, "security": "reality", "sni": "donor.example", "pbk": "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M", "sid": "b1"}
	maps.Copy(params, o.extra)
	if o.network == "" {
		params["type"] = "tcp"
	}
	n := model.NewNode("s", scheme, "pool-uuid-1", host, port, params)
	return n, model.SelectedNode{Tag: tag, Key: n.Key, Country: cc, City: city, RTTMs: 100, Speed: 1_000_000, Checks: 3, Total: 3}
}

// ownCore is the fixture [core] block: explicit spec defaults so port
// assertions cannot drift with the constants.
func ownCore() config.CoreConfig {
	return config.CoreConfig{
		SocksPort: 10810,
		HTTPPort:  10811,
		APIPort:   15491,
		Loglevel:  "warning",
	}
}

// doOwnRender is the shared own-render entry: nodes/selection/geo/routes in,
// the parsed own config plus the route warnings out.
func doOwnRender(
	t *testing.T, nodes []*model.Node, sel *model.Selection, routes []render.PoolRoute,
) (map[string]any, []string) {
	t.Helper()
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	b, warnings, err := render.RenderOwnConfig(sel, ownCore(), routes, byKey, nil, render.Config{})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m, warnings
}

// doRender keeps the historical helper name: every pool-layer test renders
// through the own config (the only entry since D3).
func doRender(t *testing.T, nodes []*model.Node, sel *model.Selection, routes ...render.PoolRoute) map[string]any {
	t.Helper()
	m, _ := doOwnRender(t, nodes, sel, routes)
	return m
}

// doRenderErr is the loud variant: the render must fail and the error comes
// back for message assertions.
func doRenderErr(t *testing.T, nodes []*model.Node, sel *model.Selection, routes ...render.PoolRoute) error {
	t.Helper()
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	_, _, err := render.RenderOwnConfig(sel, ownCore(), routes, byKey, nil, render.Config{})
	return err
}

func twoCountrySelection(t *testing.T) ([]*model.Node, *model.Selection) {
	t.Helper()
	nl1, sn1 := mkSelected(t, "pool-nl-01", "nl", "Amsterdam", "nl1.example.com", 443, nodeOpts{network: "xhttp", extra: map[string]string{"mode": "packet-up", "host": "cdn.example", "path": "/pool"}})
	nl2, sn2 := mkSelected(t, "pool-nl-02", "nl", "Amsterdam", "nl2.example.com", 443, nodeOpts{network: "xhttp", extra: map[string]string{"mode": "packet-up", "host": "cdn.example", "path": "/pool"}})
	de1, sn3 := mkSelected(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", 2053, nodeOpts{network: "tcp", extra: map[string]string{"flow": "xtls-rprx-vision"}})
	de2, sn3b := mkSelected(t, "pool-de-02", "de", "Frankfurt", "de2.example.com", 2053, nodeOpts{network: "tcp", extra: map[string]string{"flow": "xtls-rprx-vision"}})
	us1, sn4 := mkSelected(t, "pool-us-01", "us", "Seattle", "us1.example.com", 443, nodeOpts{scheme: "trojan", network: "ws", extra: map[string]string{"path": "/tj", "host": "ws.example", "security": "tls"}})
	nodes := []*model.Node{nl1, nl2, de1, de2, us1}
	sel := &model.Selection{
		Nodes: []model.SelectedNode{sn1, sn2, sn3, sn3b, sn4},
	}
	return nodes, sel
}

func outboundsOf(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	raw, ok := m["outbounds"].([]any)
	require.True(t, ok, "outbounds array present")
	out := make([]map[string]any, 0, len(raw))
	for _, o := range raw {
		out = append(out, o.(map[string]any))
	}
	return out
}

func poolOutbound(t *testing.T, m map[string]any, tag string) map[string]any {
	t.Helper()
	for _, o := range outboundsOf(t, m) {
		if o["tag"] == tag {
			return o
		}
	}
	t.Fatalf("pool outbound %q not found", tag)
	return nil
}

func TestPoolOutboundVLESSRealityParamsPassThrough1to1(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)
	ob := poolOutbound(t, m, "pool-nl-01")

	assert.Equal(t, "vless", ob["protocol"])
	ss := ob["streamSettings"].(map[string]any)
	assert.Equal(t, "xhttp", ss["network"])
	assert.Equal(t, "reality", ss["security"])
	// Owner mandate: tcpMaxSeg 1440 + fingerprint firefox on EVERY pool outbound.
	sockopt := ss["sockopt"].(map[string]any)
	assert.InDelta(t, 1440, sockopt["tcpMaxSeg"], 0.001)
	rs := ss["realitySettings"].(map[string]any)
	assert.Equal(t, "firefox", rs["fingerprint"], "fingerprint is client-side overridden to firefox")
	// L9: auth/transport params verbatim.
	assert.Equal(t, "donor.example", rs["serverName"])
	assert.Equal(t, "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M", rs["publicKey"])
	assert.Equal(t, "b1", rs["shortId"])
	xs := ss["xhttpSettings"].(map[string]any)
	assert.Equal(t, "cdn.example", xs["host"])
	assert.Equal(t, "/pool", xs["path"])
	assert.Equal(t, "packet-up", xs["mode"])
	settings := ob["settings"].(map[string]any)
	vnext := settings["vnext"].([]any)[0].(map[string]any)
	assert.Equal(t, "nl1.example.com", vnext["address"])
	assert.InDelta(t, 443, vnext["port"], 0.001)
	user := vnext["users"].([]any)[0].(map[string]any)
	assert.Equal(t, "pool-uuid-1", user["id"])
	assert.Equal(t, "none", user["encryption"])
}

func TestPoolOutboundVLESSFlowPassthrough(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)
	ss := poolOutbound(t, m, "pool-de-01")["streamSettings"].(map[string]any)
	user := poolOutbound(t, m, "pool-de-01")["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	assert.Equal(t, "xtls-rprx-vision", user["flow"], "flow passes through verbatim")
	assert.Equal(t, "tcp", ss["network"])
}

func TestPoolOutboundTrojanWS(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)
	ob := poolOutbound(t, m, "pool-us-01")
	assert.Equal(t, "trojan", ob["protocol"])
	srv := ob["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	assert.Equal(t, "pool-uuid-1", srv["password"], "trojan password 1:1")
	ss := ob["streamSettings"].(map[string]any)
	assert.Equal(t, "ws", ss["network"])
	assert.Equal(t, "tls", ss["security"], "trojan defaults to tls security")
	ws := ss["wsSettings"].(map[string]any)
	assert.Equal(t, "/tj", ws["path"])
	sockopt := ss["sockopt"].(map[string]any)
	assert.InDelta(t, 1440, sockopt["tcpMaxSeg"], 0.001)
}

// TestPlanAObservatoryShape pins the own config's pool observatory: the
// subjectSelector covers exactly the pool namespace and concurrency is on
// (L2 coverage); the adaptive interval is pinned in the knobs test.
func TestPlanAObservatoryShape(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)

	obs, ok := m["observatory"].(map[string]any)
	require.True(t, ok, "Plan A: pool observatory rendered")
	assert.Equal(t, []any{"pool-"}, obs["subjectSelector"])
	assert.Equal(t, "1m0s", obs["probeInterval"], "W19: absent knob → adaptive (2 nodes ride the 60s floor)")
	assert.Equal(t, true, obs["enableConcurrency"])
}

func TestEmptyPoolRefusesObservatoryAndBalancers(t *testing.T) {
	// L1/L2 HARD GATES: empty pool → no pool observatory, no pool balancers
	// (the balancers key is absent entirely), no pool outbounds; the
	// bootstrap outbounds are exactly direct+block.
	m := doRender(t, nil, &model.Selection{})
	_, has := m["observatory"]
	assert.False(t, has, "L1: empty pool must not render an observatory (busy-loop on 26.3.27)")
	routing, ok := m["routing"].(map[string]any)
	require.True(t, ok)
	_, hasBalancers := routing["balancers"]
	assert.False(t, hasBalancers, "L2: the empty-pool config carries no balancers key at all")
	assert.Len(t, outboundsOf(t, m), 2, "only the direct/block pair on an empty pool")
	for _, o := range outboundsOf(t, m) {
		tag, _ := o["tag"].(string)
		assert.False(t, strings.HasPrefix(tag, "pool-"), "no pool outbounds on empty pool (got %s)", tag)
	}
}

func TestCountryAndCityBalancers(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)
	balancers := m["routing"].(map[string]any)["balancers"].([]any)

	var nl map[string]any
	var cities []map[string]any
	for _, b := range balancers {
		bm := b.(map[string]any)
		tag, _ := bm["tag"].(string)
		switch {
		case tag == "pool_nl":
			nl = bm
		case strings.HasPrefix(tag, "pool_") && strings.Count(tag, "_") >= 2:
			cities = append(cities, bm) // pool_<cc>_<city-slug>
		}
	}
	require.NotNil(t, nl, "country balancer pool_nl rendered")
	assert.Equal(t, []any{"pool-nl-"}, nl["selector"], "prefix selector covers the country's tags")
	strategy := nl["strategy"].(map[string]any)
	assert.Equal(t, "leastLoad", strategy["type"])
	st := strategy["settings"].(map[string]any)
	assert.InDelta(t, 1, st["expected"], 0.001)
	assert.InDelta(t, 0.2, st["tolerance"], 0.001)
	// Amsterdam has 2 live nodes → city balancer required (D5).
	// Frankfurt has 2 live nodes → city balancer required (D5).
	require.Len(t, cities, 2, "two city balancers (Amsterdam 2 nodes, Frankfurt 2 nodes)")
	cityTags := map[string]bool{}
	for _, c := range cities {
		cityTags[c["tag"].(string)] = true
	}
	assert.True(t, cityTags["pool_nl_amsterdam"], "Amsterdam city balancer rendered")
	assert.True(t, cityTags["pool_de_frankfurt"], "Frankfurt city balancer rendered")
	// Seattle has 1 node → no city balancer (direct tag override).
}

func TestPoolRulesInsertedBeforeCatchAll(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel,
		render.PoolRoute{Balancer: "pool_nl", Domains: []string{"geosite:netflix"}},
		render.PoolRoute{Balancer: "pool_de", Domains: []string{"domain:example.com"}},
	)
	rules := m["routing"].(map[string]any)["rules"].([]any)
	require.Greater(t, len(rules), 3)

	// The last rule stays the own catch-all (pool_all leastLoad).
	last := rules[len(rules)-1].(map[string]any)
	assert.Equal(t, "pool_all", last["balancerTag"])

	// Pool rules sit immediately before it, in config order.
	poolRule1 := rules[len(rules)-3].(map[string]any)
	poolRule2 := rules[len(rules)-2].(map[string]any)
	assert.Equal(t, "pool_nl", poolRule1["balancerTag"])
	assert.Equal(t, []any{"in", "in-http"}, poolRule1["inboundTag"],
		"pool rules carry the GENERATED own inbound tags")
	assert.Equal(t, []any{"geosite:netflix"}, poolRule1["domain"])
	assert.Equal(t, "pool_de", poolRule2["balancerTag"])

	// The api rule keeps precedence (first — it only matches its inbound).
	first := rules[0].(map[string]any)
	assert.Equal(t, "api", first["outboundTag"])
}

func TestAPIStatsBlockBoundToLoopback(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)

	api, ok := m["api"].(map[string]any)
	require.True(t, ok, "api/stats service block rendered")
	assert.Equal(t, "api", api["tag"])
	services := api["services"].([]any)
	require.Len(t, services, 1)
	assert.Equal(t, "StatsService", services[0], "xray api.services is a []string of service names")

	var apiIn map[string]any
	for _, in := range m["inbounds"].([]any) {
		im := in.(map[string]any)
		if im["tag"] == "api-in" {
			apiIn = im
		}
	}
	require.NotNil(t, apiIn, "api dokodemo inbound rendered")
	assert.Equal(t, "127.0.0.1", apiIn["listen"], "stats API binds loopback only")
	assert.InDelta(t, 15491, apiIn["port"], 0.001, "the api inbound binds core.api_port")

	rules := m["routing"].(map[string]any)["rules"].([]any)
	first := rules[0].(map[string]any)
	assert.Equal(t, []any{"api-in"}, first["inboundTag"], "api rule is FIRST (it only matches the api inbound)")
	assert.Equal(t, "api", first["outboundTag"])
}

// TestRenderIsDeterministicForGoldenRegression pins the byte determinism
// the golden regression relies on, and OWNS the golden's lifecycle (T7
// disposition C3, documented): on a fresh clone the golden ships tracked in
// testdata/ and this test compares against it; when the file is ABSENT
// (a deleted or renamed golden, or a new shape's first run), the
// write-on-first-run branch below MATERIALIZES it — an expected first-run
// behavior, not a bug or tampering. The materialized file is committed
// afterwards; regeneration after an intentional render change stays a
// DELIBERATE act (the failure text names it).
func TestRenderIsDeterministicForGoldenRegression(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	routes := []render.PoolRoute{
		{Balancer: "pool_nl", Domains: []string{"geosite:netflix"}},
	}
	// Phase-3 unlock evidence for the fixture exits: de1 qualifies for every
	// service pool, nl1 is netflix-full only (webonly chatgpt excluded),
	// nl2 is chatgpt only (originals netflix), de2 is UNCHECKED (fail-closed
	// pin), us1 is fully blocked. No node is flags-clean, so pool_clean
	// stays absent in this golden.
	geo := geoEvidence(nodes, map[string]model.GeoRecord{
		"nl1.example.com": {RiskScore: 55, MediaUnlocks: model.MediaUnlockStatus{
			ChatGPT: model.UnlockWebOnly, Netflix: model.UnlockNetflixFull, YouTubeRegion: "NL",
			CheckedAt: "2026-11-04T12:00:00Z",
		}},
		"nl2.example.com": {RiskScore: 40, MediaUnlocks: model.MediaUnlockStatus{
			ChatGPT: model.UnlockYes, Netflix: model.UnlockNetflixOriginals, YouTubeRegion: "NL",
			CheckedAt: "2026-11-04T12:00:00Z",
		}},
		"de1.example.com": {RiskScore: 10, MediaUnlocks: model.MediaUnlockStatus{
			ChatGPT: model.UnlockYes, Netflix: model.UnlockNetflixFull, YouTubeRegion: "DE",
			CheckedAt: "2026-11-04T12:00:00Z",
		}},
		"de2.example.com": {RiskScore: -1},
		"us1.example.com": {RiskScore: 70, MediaUnlocks: model.MediaUnlockStatus{
			ChatGPT: model.UnlockBlocked, Netflix: model.UnlockBlocked, YouTubeRegion: model.UnlockBlocked,
			CheckedAt: "2026-11-04T12:00:00Z",
		}},
	})
	b1, _, err := render.RenderOwnConfig(sel, ownCore(), routes, byKey, geo, render.Config{})
	require.NoError(t, err)
	b2, _, err := render.RenderOwnConfig(sel, ownCore(), routes, byKey, geo, render.Config{})
	require.NoError(t, err)
	assert.Equal(t, string(b1), string(b2), "render must be byte-deterministic (golden regression basis)")

	// Golden file comparison.
	goldenPath := filepath.Join("testdata", "golden-own-render.json")
	golden, err := os.ReadFile(goldenPath)
	if err == nil {
		// LF-normalized against windows checkout noise (.gitattributes pins
		// LF; the strip is the belt) — CRLF is never render content.
		assert.Equal(t, strings.ReplaceAll(string(golden), "\r\n", "\n"), string(b1),
			"rendered output diverged from the golden file — if intentional, regenerate testdata/golden-own-render.json deliberately")
	} else {
		t.Logf("golden file not found (%v) — write it on first run", err)
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(goldenPath, b1, 0o644), "first run materializes the golden")
	}
}

// TestPoolRouteDirectOutboundTagRendersOutboundTag pins the D5 spec surface:
// a single-node city has no city balancer, so a pool route may target the
// direct `pool-<cc>-NN` outbound tag — rendered as `outboundTag`, never
// `balancerTag` (final-review finding M-a).
func TestPoolRouteDirectOutboundTagRendersOutboundTag(t *testing.T) {
	n, sn := mkSelected(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", 2053, nodeOpts{network: "tcp"})
	m := doRender(t, []*model.Node{n}, &model.Selection{Nodes: []model.SelectedNode{sn}},
		render.PoolRoute{Balancer: "pool-de-01", Domains: []string{"geosite:netflix"}})

	rules := m["routing"].(map[string]any)["rules"].([]any)
	var direct map[string]any
	for _, r := range rules {
		rm := r.(map[string]any)
		if ot, _ := rm["outboundTag"].(string); ot == "pool-de-01" {
			direct = rm
		}
	}
	require.NotNil(t, direct, "direct-tag pool route must render a rule with outboundTag=pool-de-01")
	assert.Nil(t, direct["balancerTag"], "a direct-tag rule must not carry balancerTag")
	assert.Equal(t, []any{"in", "in-http"}, direct["inboundTag"])
	assert.Equal(t, []any{"geosite:netflix"}, direct["domain"])

	// The outbound itself was rendered and the rule precedes the catch-all.
	poolOutbound(t, m, "pool-de-01")
	last := rules[len(rules)-1].(map[string]any)
	assert.Equal(t, "pool_all", last["balancerTag"], "catch-all stays last")
	assert.NotEqual(t, direct, last, "the direct-tag rule sits before the catch-all")
}

func TestUnknownPoolRouteBalancerGraceful(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m, warnings := doOwnRender(t, nodes, sel,
		[]render.PoolRoute{{Balancer: "pool_fr", Domains: []string{"domain:x.com"}}})
	rules := m["routing"].(map[string]any)["rules"].([]any)
	found := false
	for _, r := range rules {
		rm := r.(map[string]any)
		if domains, _ := rm["domain"].([]any); len(domains) == 1 && domains[0] == "domain:x.com" {
			assert.Equal(t, "block", rm["outboundTag"])
			found = true
		}
	}
	assert.True(t, found, "blocked pool route rule must be present")
	assert.Contains(t, warnings, "pool route balancer \"pool_fr\" not rendered -> block",
		"the graceful degradation is reported through the warnings channel")
}

// TestUnknownPoolRouteDirectTagGraceful pins the graceful degradation for a
// direct-tag target that was not rendered (no live node there): block
// outbound, never a crash (M-a).
func TestUnknownPoolRouteDirectTagGraceful(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m, _ := doOwnRender(t, nodes, sel,
		[]render.PoolRoute{{Balancer: "pool-de-09", Domains: []string{"domain:x.com"}}})
	rules := m["routing"].(map[string]any)["rules"].([]any)
	found := false
	for _, r := range rules {
		rm := r.(map[string]any)
		if domains, _ := rm["domain"].([]any); len(domains) == 1 && domains[0] == "domain:x.com" {
			assert.Equal(t, "block", rm["outboundTag"])
			found = true
		}
	}
	assert.True(t, found)
}

// TestEmptyPoolStillValidatesPoolRoutes pins the W7 hoist: [render.pool_routes]
// target validation runs on EVERY render regardless of pool state. With an
// empty pool NO pool-prefixed target can exist — the own config carries no
// pool- outbound and no pool_ balancer — so a configured route there is
// necessarily a typo or dead reference, and every non-pool target fails loud
// naming it (the owner learns about the mistake immediately instead of a
// silent D2 fall-through to the catch-all). There is deliberately NO "valid
// target with an empty pool" success arm: the own config's own tags
// (direct/block/in/in-http) are namespace-walled for pool routes, so no
// pool-namespaced target can resolve while the pool is empty.
func TestEmptyPoolStillValidatesPoolRoutes(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"namespace violation", "best_rtt"},
		{"direct tag into the template", "proxy-0"},
		{"namespace violation direct", "direct"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := doRenderErr(t, nil, &model.Selection{},
				render.PoolRoute{Balancer: tc.target, Domains: []string{"domain:x.com"}})
			require.Error(t, err, "empty pool + route target %q must fail loud (namespace wall)", tc.target)
			assert.Contains(t, err.Error(), tc.target, "the loud failure must name the offending target")
		})
	}

	// pool-prefixed targets on an empty pool are not rendered -> graceful block.
	for _, target := range []string{"pool_de", "pool-de-01"} {
		t.Run("empty pool graceful "+target, func(t *testing.T) {
			m, _ := doOwnRender(t, nil, &model.Selection{},
				[]render.PoolRoute{{Balancer: target, Domains: []string{"domain:x.com"}}})
			rules := m["routing"].(map[string]any)["rules"].([]any)
			found := false
			for _, r := range rules {
				rm := r.(map[string]any)
				if domains, _ := rm["domain"].([]any); len(domains) == 1 && domains[0] == "domain:x.com" {
					assert.Equal(t, "block", rm["outboundTag"])
					found = true
				}
			}
			assert.True(t, found)
		})
	}

	t.Run("empty pool with zero routes is a no-op", func(t *testing.T) {
		// The default config carries no pool_routes: the validation must be a
		// no-op so empty-pool renders (and the goldens) stay byte-identical.
		m := doRender(t, nil, &model.Selection{})
		assert.NotNil(t, m)
	})
}

func TestNonPoolBalancerRouteRejected(t *testing.T) {
	for _, target := range []string{"best_rtt", "proxy-0", "direct"} {
		nodes, sel := twoCountrySelection(t)
		err := doRenderErr(t, nodes, sel,
			render.PoolRoute{Balancer: target, Domains: []string{"domain:x.com"}})
		require.Error(t, err, "pool routes may only target pool_ balancers or pool- outbound tags (D6 namespace wall), got target %q", target)
		assert.Contains(t, err.Error(), target, "the offending target must be named")
	}
}

func TestSelectionNodeMissingIsLoud(t *testing.T) {
	sel := &model.Selection{Nodes: []model.SelectedNode{{Tag: "pool-de-01", Key: "ghost"}}}
	err := doRenderErr(t, nil, sel)
	require.Error(t, err, "a selected node without node data cannot be rendered — fail loud")
}

// TestGoldenOwnRenderPassesXrayTest is the real-binary verdict: the xray core
// must accept the generated own config (inbounds, balancers, observatory,
// api/stats blocks, routes and the catch-all).
func TestGoldenOwnRenderPassesXrayTest(t *testing.T) {
	bin := "/usr/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("xray binary not present at %s", bin)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "golden-own-render.json"))
	if err != nil {
		t.Fatalf("golden render missing: run the suite once to materialize it: %v", err)
	}
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "rendered.json")
	require.NoError(t, os.WriteFile(cfgPath, golden, 0o644))

	cmd := exec.CommandContext(context.Background(), bin, "run", "-test", "-c", cfgPath)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+tmp)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "xray run -test rejected the own render:\n%s", out)
	assert.Contains(t, string(out), "Configuration OK")
}

// --- drop-report transport pins (through BuildOutbound — the SAME builder
// the own render and the site checker use) ---

// buildOne renders a single node through the exported builder seam.
func buildOne(t *testing.T, n *model.Node) (map[string]any, []string) {
	t.Helper()
	ob, dropped, err := render.BuildOutbound(n, "probe-out", render.Config{
		TCPMaxSeg:      config.DefaultTCPMaxSeg,
		TLSFingerprint: config.DefaultTLSFingerprint,
	})
	require.NoError(t, err)
	return ob, dropped
}

// TestUnrenderedLinkParamsAreReportedNotSilentlyDropped pins the structured
// drop report: params the chosen network/security cannot carry surface in the
// builder's dropped list (review finding 5).
func TestUnrenderedLinkParamsAreReportedNotSilentlyDropped(t *testing.T) {
	// xhttp node carrying a grpc-only param and an unknown one.
	n, _ := mkSelected(t, "pool-nl-01", "nl", "Amsterdam", "nl1.example.com", 443,
		nodeOpts{network: "xhttp", extra: map[string]string{
			"mode": "packet-up", "host": "cdn.example", "path": "/pool",
			"serviceName": "grpc-svc", "headerType": "none",
		}})
	_, dropped := buildOne(t, n)
	assert.ElementsMatch(t, []string{"serviceName", "headerType"}, dropped,
		"grpc-only and unknown params are reported for the xhttp outbound")
}

// TestFullyConsumedParamsProduceNoDropReport guards the whitelist against
// over-reporting: a node whose every param is consumed renders clean.
func TestFullyConsumedParamsProduceNoDropReport(t *testing.T) {
	n, _ := mkSelected(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", 2053,
		nodeOpts{network: "tcp", extra: map[string]string{
			"flow": "xtls-rprx-vision", "fp": "chrome", "spx": "/", "pqv": "AAAA",
		}})
	_, dropped := buildOne(t, n)
	assert.Empty(t, dropped,
		"flow/fp/spx/pqv are consumed (fp by mandated override) — no report")
}

// TestMaterialEarlyDataParamFailsLoud pins the hard gate: an early-data param
// that cannot be rendered for the chosen network materially changes transport
// behavior — the build must fail, naming the param (review finding 5).
func TestMaterialEarlyDataParamFailsLoud(t *testing.T) {
	for _, network := range []string{"tcp", "grpc", "xhttp"} {
		n, _ := mkSelected(t, "pool-nl-01", "nl", "Amsterdam", "nl1.example.com", 443,
			nodeOpts{network: network, extra: map[string]string{"ed": "2048"}})
		_, _, err := render.BuildOutbound(n, "probe-out", render.Config{})
		require.Error(t, err, "ed on %s must fail the render, not vanish", network)
		assert.Contains(t, err.Error(), `"ed"`, "the offending param must be named")
		assert.Contains(t, err.Error(), network)
	}
}

// TestVMESSUnparseableAidFailsLoud pins the M-f gate: aid is auth-adjacent
// link material — a value Atoi cannot parse must fail the render with the L9
// rationale, never silently coerce to alterId 0 (final-review finding M-f).
func TestVMESSUnparseableAidFailsLoud(t *testing.T) {
	n := model.NewNode("s", "vmess", "vmess-uuid-1", "de1.example.com", 2053,
		map[string]string{"type": "tcp", "security": "tls", "sni": "donor.example", "aid": "abc"})
	_, _, err := render.BuildOutbound(n, "probe-out", render.Config{
		TCPMaxSeg:      config.DefaultTCPMaxSeg,
		TLSFingerprint: config.DefaultTLSFingerprint,
	})
	require.Error(t, err, "unparseable aid must fail the render, not silently become alterId 0")
	assert.Contains(t, err.Error(), `"aid"`, "the offending param must be named")
	assert.Contains(t, err.Error(), "abc")
}

// TestVMESSParsedAidRendersAndConsumes guards the success path: a numeric aid
// renders as alterId verbatim and is consumed — it must not leak into the
// drop report (M-f: consumed only on successful placement).
func TestVMESSParsedAidRendersAndConsumes(t *testing.T) {
	n := model.NewNode("s", "vmess", "vmess-uuid-1", "de1.example.com", 2053,
		map[string]string{"type": "tcp", "security": "tls", "sni": "donor.example", "aid": "64"})
	ob, dropped := buildOne(t, n)
	assert.Empty(t, dropped, "a parsed aid is consumed — no drop report")
	user := ob["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	assert.InDelta(t, 64, user["alterId"], 0.001, "aid renders as alterId verbatim (L9)")
}

// TestCleanAndAllBalancers verifies the clean/all balancer separation:
// - Clean balancers only get nodes with IsClean=true (hosting=false && proxy=false).
// - All balancers get all nodes regardless of clean status.
// - Both country and city levels are split.
// - pool_all always renders; pool_all_clean renders when clean nodes exist.
func TestCleanAndAllBalancers(t *testing.T) {
	// Create nodes: 2 clean NL nodes, 1 dirty NL node, 2 clean DE nodes, 1 dirty US node
	nlClean1, sn1 := mkSelected(t, "pool-nl-01", "nl", "Amsterdam", "nl1.example.com", 443, nodeOpts{network: "xhttp"})
	nlClean2, sn2 := mkSelected(t, "pool-nl-02", "nl", "Amsterdam", "nl2.example.com", 443, nodeOpts{network: "xhttp"})
	nlDirty, sn3 := mkSelected(t, "pool-nl-03", "nl", "Amsterdam", "nl3.example.com", 443, nodeOpts{network: "xhttp"})
	deClean1, sn4 := mkSelected(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", 2053, nodeOpts{network: "tcp"})
	deClean2, sn5 := mkSelected(t, "pool-de-02", "de", "Frankfurt", "de2.example.com", 2053, nodeOpts{network: "tcp"})
	usDirty, sn6 := mkSelected(t, "pool-us-01", "us", "Seattle", "us1.example.com", 443, nodeOpts{network: "tcp"})

	// Mark clean nodes explicitly (mkSelected doesn't set IsClean, so we modify after)
	sn1.IsClean = true
	sn2.IsClean = true
	sn4.IsClean = true
	sn5.IsClean = true
	// sn3 (nlDirty), sn6 (usDirty) remain IsClean=false

	nodes := []*model.Node{nlClean1, nlClean2, nlDirty, deClean1, deClean2, usDirty}
	sel := &model.Selection{Nodes: []model.SelectedNode{sn1, sn2, sn3, sn4, sn5, sn6}}
	m := doRender(t, nodes, sel)

	balancers := m["routing"].(map[string]any)["balancers"].([]any)
	balancerTags := map[string]bool{}
	for _, b := range balancers {
		if bm, ok := b.(map[string]any); ok {
			if tag, _ := bm["tag"].(string); strings.HasPrefix(tag, "pool_") {
				balancerTags[tag] = true
			}
		}
	}

	// Clean country balancers (>=1 clean node per country)
	assert.True(t, balancerTags["pool_nl_clean"], "clean country balancer for NL (2 clean nodes)")
	assert.True(t, balancerTags["pool_de_clean"], "clean country balancer for DE (2 clean nodes)")
	assert.False(t, balancerTags["pool_us_clean"], "no clean country balancer for US (0 clean nodes)")

	// All country balancers (>=1 all nodes per country — restored: every
	// country with at least one node keeps its country balancer)
	assert.True(t, balancerTags["pool_nl"], "all country balancer for NL (3 all nodes)")
	assert.True(t, balancerTags["pool_de"], "all country balancer for DE (2 all nodes)")
	assert.True(t, balancerTags["pool_us"], "all country balancer for US (1 all node)")

	// Clean city balancers (>=2 clean nodes per city)
	assert.True(t, balancerTags["pool_nl_amsterdam_clean"], "clean city balancer for Amsterdam (2 clean nodes)")
	assert.True(t, balancerTags["pool_de_frankfurt_clean"], "clean city balancer for Frankfurt (2 clean nodes)")

	// All city balancers (>=2 all nodes per city)
	assert.True(t, balancerTags["pool_nl_amsterdam"], "all city balancer for Amsterdam (3 all nodes)")
	assert.True(t, balancerTags["pool_de_frankfurt"], "all city balancer for Frankfurt (2 all nodes)")

	// pool_all always renders
	assert.True(t, balancerTags["pool_all"], "pool_all always renders")

	// pool_all_clean renders when clean nodes exist
	assert.True(t, balancerTags["pool_all_clean"], "pool_all_clean renders when clean nodes exist")

	// Verify clean balancer selectors only contain clean node tags
	for _, b := range balancers {
		bm := b.(map[string]any)
		tag, _ := bm["tag"].(string)
		if strings.HasSuffix(tag, "_clean") && tag != "pool_all_clean" {
			selectors := bm["selector"].([]any)
			for _, s := range selectors {
				stag := s.(string)
				// Clean balancer selectors should only contain clean node tags
				assert.True(t, strings.HasPrefix(stag, "pool-nl-01") ||
					strings.HasPrefix(stag, "pool-nl-02") ||
					strings.HasPrefix(stag, "pool-de-01") ||
					strings.HasPrefix(stag, "pool-de-02"),
					"clean balancer %s should only select clean nodes, got %s", tag, stag)
			}
		}
	}
}
