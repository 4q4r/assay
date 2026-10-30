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

	"public_vpn/internal/model"
	"public_vpn/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTemplate mirrors the live xray-raw config structure (values anonymized):
// log, burstObservatory (Germans-only), 2 inbounds, 5 outbounds, 7 routing
// rules (last = catch-all best_rtt), 1 balancer.
func testTemplate(t *testing.T) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(`{
  "log": {"loglevel": "warning", "dnsLog": false},
  "dns": {"queryStrategy": "UseIPv4", "servers": ["https://dns.google/dns-query"]},
  "burstObservatory": {
    "subjectSelector": ["proxy-"],
    "pingConfig": {"destination": "http://1.1.1.1/cdn-cgi/trace", "connectivity": "http://1.0.0.1/cdn-cgi/trace", "interval": "10s", "sampling": 5, "timeout": "3s", "httpMethod": "GET"}
  },
  "inbounds": [
    {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": true}, "sniffing": {"enabled": true, "routeOnly": true}},
    {"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": {}, "sniffing": {"enabled": true, "routeOnly": true}}
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs"}},
    {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "none"}}},
    {"tag": "proxy-0", "protocol": "vless", "settings": {"vnext": [{"address": "198.51.100.1", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000001", "encryption": "none"}]}]}, "streamSettings": {"network": "xhttp", "security": "reality", "sockopt": {"tcpMaxSeg": 1440}, "realitySettings": {"fingerprint": "firefox", "serverName": "donor.example", "publicKey": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "shortId": "AA"}}},
    {"tag": "proxy-1", "protocol": "vless", "settings": {"vnext": [{"address": "198.51.100.2", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000001", "encryption": "none"}]}]}, "streamSettings": {"network": "xhttp", "security": "reality", "sockopt": {"tcpMaxSeg": 1440}, "realitySettings": {"fingerprint": "firefox", "serverName": "donor.example", "publicKey": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "shortId": "AA"}}}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "domainMatcher": "hybrid",
    "rules": [
      {"type": "field", "inboundTag": ["socks-in", "http-in"], "domain": ["domain:nvidia.com"], "outboundTag": "fox-proxy"},
      {"type": "field", "inboundTag": ["socks-in", "http-in"], "port": "25,465,587,2525", "outboundTag": "block"},
      {"type": "field", "inboundTag": ["socks-in", "http-in"], "protocol": ["bittorrent"], "outboundTag": "direct"},
      {"type": "field", "inboundTag": ["socks-in", "http-in"], "domain": ["geosite:youtube"], "outboundTag": "direct"},
      {"type": "field", "inboundTag": ["socks-in", "http-in"], "domain": ["domain:example.ru"], "outboundTag": "direct"},
      {"type": "field", "inboundTag": ["socks-in", "http-in"], "ip": ["geoip:private"], "outboundTag": "direct"},
      {"type": "field", "inboundTag": ["socks-in", "http-in"], "network": "tcp,udp", "balancerTag": "best_rtt"}
    ],
    "balancers": [
      {"tag": "best_rtt", "selector": ["proxy-"], "strategy": {"type": "leastLoad", "settings": {"expected": 1, "maxRTT": "1s", "tolerance": 0.2}}, "fallbackTag": "proxy-0"}
    ]
  }
}`), &m))
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

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

func renderCfg(poolRoutes []render.PoolRoute) render.Config {
	return render.Config{
		StatsPort:  15490,
		PoolRoutes: poolRoutes,
	}
}

func doRender(t *testing.T, nodes []*model.Node, sel *model.Selection, routes ...render.PoolRoute) map[string]any {
	t.Helper()
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	res, err := render.Render(render.Input{
		Template:   testTemplate(t),
		Selection:  sel,
		NodesByKey: byKey,
		Cfg:        renderCfg(routes),
	})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(res.Config, &m))
	return m
}

func twoCountrySelection(t *testing.T) ([]*model.Node, *model.Selection) {
	t.Helper()
	nl1, sn1 := mkSelected(t, "pool-nl-01", "nl", "Amsterdam", "nl1.example.com", 443, nodeOpts{network: "xhttp", extra: map[string]string{"mode": "packet-up", "host": "cdn.example", "path": "/pool"}})
	nl2, sn2 := mkSelected(t, "pool-nl-02", "nl", "Amsterdam", "nl2.example.com", 443, nodeOpts{network: "xhttp", extra: map[string]string{"mode": "packet-up", "host": "cdn.example", "path": "/pool"}})
	de1, sn3 := mkSelected(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", 2053, nodeOpts{network: "tcp", extra: map[string]string{"flow": "xtls-rprx-vision"}})
	us1, sn4 := mkSelected(t, "pool-us-01", "us", "Seattle", "us1.example.com", 443, nodeOpts{scheme: "trojan", network: "ws", extra: map[string]string{"path": "/tj", "host": "ws.example", "security": "tls"}})
	nodes := []*model.Node{nl1, nl2, de1, us1}
	sel := &model.Selection{
		Nodes: []model.SelectedNode{sn1, sn2, sn3, sn4},
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

func TestPlanAObservatoryCoexistsWithBurstObservatory(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)

	obs, ok := m["observatory"].(map[string]any)
	require.True(t, ok, "Plan A: legacy observatory rendered alongside burst")
	assert.Equal(t, []any{"pool-"}, obs["subjectSelector"])
	assert.Equal(t, "1m0s", obs["probeInterval"], "W19: absent knob → adaptive (2 nodes ride the 60s floor)")
	assert.Equal(t, true, obs["enableConcurrency"])

	burst, ok := m["burstObservatory"].(map[string]any)
	require.True(t, ok, "Germans burstObservatory must survive untouched")
	assert.Equal(t, []any{"proxy-"}, burst["subjectSelector"])
	assert.Equal(t, "10s", burst["pingConfig"].(map[string]any)["interval"])
}

func TestEmptyPoolRefusesObservatoryAndBalancers(t *testing.T) {
	// L1 HARD GATE: empty pool → no pool observatory, no balancers, no rules.
	m := doRender(t, nil, &model.Selection{})
	_, has := m["observatory"]
	assert.False(t, has, "L1: empty pool must not render an observatory (busy-loop on 26.3.27)")
	for _, b := range m["routing"].(map[string]any)["balancers"].([]any) {
		tag, _ := b.(map[string]any)["tag"].(string)
		assert.False(t, strings.HasPrefix(tag, "pool_"), "L2: no pool balancers without coverage (got %s)", tag)
	}
	// Template artifacts survive.
	assert.NotNil(t, m["burstObservatory"])
	for _, o := range outboundsOf(t, m) {
		tag, _ := o["tag"].(string)
		assert.False(t, strings.HasPrefix(tag, "pool-"), "no pool outbounds on empty pool (got %s)", tag)
	}
	assert.Len(t, outboundsOf(t, m), 4, "template outbounds intact")
}

func TestCountryAndCityBalancers(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)
	balancers := m["routing"].(map[string]any)["balancers"].([]any)

	var nl, best map[string]any
	var cities []map[string]any
	for _, b := range balancers {
		bm := b.(map[string]any)
		tag, _ := bm["tag"].(string)
		switch {
		case tag == "pool_nl":
			nl = bm
		case tag == "best_rtt":
			best = bm
		case strings.HasPrefix(tag, "pool_") && strings.Count(tag, "_") >= 2:
			cities = append(cities, bm) // pool_<cc>_<city-slug>
		}
	}
	require.NotNil(t, best, "Germans balancer survives")
	require.NotNil(t, nl, "country balancer pool_nl rendered")
	assert.Equal(t, []any{"pool-nl-"}, nl["selector"], "prefix selector covers the country's tags")
	strategy := nl["strategy"].(map[string]any)
	assert.Equal(t, "leastLoad", strategy["type"])
	st := strategy["settings"].(map[string]any)
	assert.InDelta(t, 1, st["expected"], 0.001)
	assert.InDelta(t, 0.2, st["tolerance"], 0.001)
	// Amsterdam has 2 live nodes → city balancer required (D5).
	require.Len(t, cities, 1, "one city balancer (Amsterdam, 2 nodes)")
	assert.Equal(t, "pool_nl_amsterdam", cities[0]["tag"])
	assert.ElementsMatch(t, []any{"pool-nl-01", "pool-nl-02"}, cities[0]["selector"], "city balancer pins exact tags")
	// Frankfurt/Seattle have 1 node each → no city balancer (direct tag override).
}

func TestPoolRulesInsertedBeforeCatchAll(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel,
		render.PoolRoute{Balancer: "pool_nl", Domains: []string{"geosite:netflix"}},
		render.PoolRoute{Balancer: "pool_de", Domains: []string{"domain:example.com"}},
	)
	rules := m["routing"].(map[string]any)["rules"].([]any)
	require.Greater(t, len(rules), 7)

	// The last rule stays the Germans catch-all.
	last := rules[len(rules)-1].(map[string]any)
	assert.Equal(t, "best_rtt", last["balancerTag"])

	// Pool rules sit immediately before it, in config order.
	poolRule1 := rules[len(rules)-3].(map[string]any)
	poolRule2 := rules[len(rules)-2].(map[string]any)
	assert.Equal(t, "pool_nl", poolRule1["balancerTag"])
	assert.Equal(t, []any{"socks-in", "http-in"}, poolRule1["inboundTag"])
	assert.Equal(t, []any{"geosite:netflix"}, poolRule1["domain"])
	assert.Equal(t, "pool_de", poolRule2["balancerTag"])

	// Rules keep precedence (D2): api rule first, then the nvidia rule.
	first := rules[0].(map[string]any)
	assert.Equal(t, "api", first["outboundTag"])
	second := rules[1].(map[string]any)
	assert.Equal(t, "fox-proxy", second["outboundTag"])
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
	assert.InDelta(t, 15490, apiIn["port"], 0.001)

	rules := m["routing"].(map[string]any)["rules"].([]any)
	first := rules[0].(map[string]any)
	assert.Equal(t, []any{"api-in"}, first["inboundTag"], "api rule is FIRST (it only matches the api inbound)")
	assert.Equal(t, "api", first["outboundTag"])
}

func TestRenderIsIdempotent(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	firstRes, err := render.Render(render.Input{Template: testTemplate(t), Selection: sel, NodesByKey: byKey, Cfg: renderCfg(nil)})
	require.NoError(t, err)

	// Re-render using the previous output as the template: pool artifacts must
	// not duplicate (activate replaces the live config; next wave reads it).
	second, err := render.Render(render.Input{Template: firstRes.Config, Selection: sel, NodesByKey: byKey, Cfg: renderCfg(nil)})
	require.NoError(t, err)
	var m2 map[string]any
	require.NoError(t, json.Unmarshal(second.Config, &m2))
	count := 0
	for _, o := range outboundsOf(t, m2) {
		if tag, _ := o["tag"].(string); len(tag) > 5 && tag[:5] == "pool-" {
			count++
		}
	}
	assert.Len(t, sel.Nodes, count, "re-render must not duplicate pool outbounds")
	rules := m2["routing"].(map[string]any)["rules"].([]any)
	apiRules := 0
	for _, r := range rules {
		if r.(map[string]any)["outboundTag"] == "api" {
			apiRules++
		}
	}
	assert.Equal(t, 1, apiRules, "api rule not duplicated")
	_, hasObs := m2["observatory"]
	assert.True(t, hasObs, "observatory still present exactly once (no stale copies)")
}

func TestRenderIsDeterministicForGoldenRegression(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	cfg := renderCfg([]render.PoolRoute{
		{Balancer: "pool_nl", Domains: []string{"geosite:netflix"}},
	})
	res1, err := render.Render(render.Input{Template: testTemplate(t), Selection: sel, NodesByKey: byKey, Cfg: cfg})
	require.NoError(t, err)
	res2, err := render.Render(render.Input{Template: testTemplate(t), Selection: sel, NodesByKey: byKey, Cfg: cfg})
	require.NoError(t, err)
	assert.Equal(t, string(res1.Config), string(res2.Config), "render must be byte-deterministic (golden regression basis)")

	// Golden file comparison.
	goldenPath := filepath.Join("testdata", "golden-render.json")
	golden, err := os.ReadFile(goldenPath)
	if err == nil {
		assert.Equal(t, string(golden), string(res1.Config),
			"rendered output diverged from the golden file — if intentional, regenerate testdata/golden-render.json deliberately")
	} else {
		t.Logf("golden file not found (%v) — write it on first run", err)
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(goldenPath, res1.Config, 0o644), "first run materializes the golden")
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
	assert.Equal(t, []any{"socks-in", "http-in"}, direct["inboundTag"])
	assert.Equal(t, []any{"geosite:netflix"}, direct["domain"])

	// The outbound itself was rendered and the rule precedes the catch-all.
	poolOutbound(t, m, "pool-de-01")
	last := rules[len(rules)-1].(map[string]any)
	assert.Equal(t, "best_rtt", last["balancerTag"], "catch-all stays last")
	assert.NotEqual(t, direct, last, "the direct-tag rule sits before the catch-all")
}

// TestPoolRouteDirectOutboundTagIsIdempotent pins the strip side of the
// direct-tag surface: re-rendering from a previous output must not duplicate
// the outboundTag rule (re-render idempotency, same contract as balancerTag
// rules).
func TestPoolRouteDirectOutboundTagIsIdempotent(t *testing.T) {
	n, sn := mkSelected(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", 2053, nodeOpts{network: "tcp"})
	byKey := map[string]*model.Node{n.Key: n}
	sel := &model.Selection{Nodes: []model.SelectedNode{sn}}
	cfg := renderCfg([]render.PoolRoute{{Balancer: "pool-de-01", Domains: []string{"geosite:netflix"}}})

	first, err := render.Render(render.Input{Template: testTemplate(t), Selection: sel, NodesByKey: byKey, Cfg: cfg})
	require.NoError(t, err)
	second, err := render.Render(render.Input{Template: first.Config, Selection: sel, NodesByKey: byKey, Cfg: cfg})
	require.NoError(t, err)

	var m2 map[string]any
	require.NoError(t, json.Unmarshal(second.Config, &m2))
	count := 0
	for _, r := range m2["routing"].(map[string]any)["rules"].([]any) {
		if ot, _ := r.(map[string]any)["outboundTag"].(string); ot == "pool-de-01" {
			count++
		}
	}
	assert.Equal(t, 1, count, "re-render must not duplicate the direct-tag pool rule")
}

func TestUnknownPoolRouteBalancerIsLoud(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	_, err := render.Render(render.Input{
		Template: testTemplate(t), Selection: sel, NodesByKey: byKey,
		Cfg: renderCfg([]render.PoolRoute{{Balancer: "pool_fr", Domains: []string{"domain:x.com"}}}),
	})
	require.Error(t, err, "routing to a balancer that was not rendered = dead rule — fail loud")
	assert.Contains(t, err.Error(), "pool_fr")
}

// TestUnknownPoolRouteDirectTagIsLoud pins the loud failure for a direct-tag
// target that was not rendered (no live node there): the error must name the
// tag and the not-rendered reason (M-a), not fall through to the namespace
// message.
func TestUnknownPoolRouteDirectTagIsLoud(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	_, err := render.Render(render.Input{
		Template: testTemplate(t), Selection: sel, NodesByKey: byKey,
		Cfg: renderCfg([]render.PoolRoute{{Balancer: "pool-de-09", Domains: []string{"domain:x.com"}}}),
	})
	require.Error(t, err, "routing to an outbound tag that was not rendered = dead rule — fail loud")
	assert.Contains(t, err.Error(), "pool-de-09")
	assert.Contains(t, err.Error(), "not rendered")
}

// TestEmptyPoolStillValidatesPoolRoutes pins the W7 hoist: [render.pool_routes]
// target validation runs on EVERY render regardless of pool state. With an
// empty pool NO pool-prefixed target can exist — stripPoolArtifacts removed
// every pool- outbound and no pool_ balancer is ever rendered — so a
// configured route there is necessarily a typo or dead reference, and every
// pool-prefixed target must fail loud naming it (the owner learns about the
// mistake immediately instead of a silent D2 fall-through to the catch-all).
// There is deliberately NO "valid target with an empty pool" success arm: the
// template's own tags (direct/block/proxy-*) are namespace-walled for pool
// routes, so no pool-namespaced target can resolve while the pool is empty.
func TestEmptyPoolStillValidatesPoolRoutes(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"balancer target not rendered", "pool_de"},
		{"direct tag target not rendered", "pool-de-01"},
		{"namespace violation", "best_rtt"},
		{"direct tag into the template", "proxy-0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := render.Render(render.Input{
				Template:   testTemplate(t),
				Selection:  &model.Selection{},
				NodesByKey: map[string]*model.Node{},
				Cfg:        renderCfg([]render.PoolRoute{{Balancer: tc.target, Domains: []string{"domain:x.com"}}}),
			})
			require.Error(t, err, "empty pool + route target %q must fail loud", tc.target)
			assert.Contains(t, err.Error(), tc.target, "the loud failure must name the offending target")
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
		byKey := map[string]*model.Node{}
		for _, n := range nodes {
			byKey[n.Key] = n
		}
		_, err := render.Render(render.Input{
			Template: testTemplate(t), Selection: sel, NodesByKey: byKey,
			Cfg: renderCfg([]render.PoolRoute{{Balancer: target, Domains: []string{"domain:x.com"}}}),
		})
		require.Error(t, err, "pool routes may only target pool_ balancers or pool- outbound tags (D6 namespace wall), got target %q", target)
		assert.Contains(t, err.Error(), target, "the offending target must be named")
	}
}

func TestSelectionNodeMissingIsLoud(t *testing.T) {
	sel := &model.Selection{Nodes: []model.SelectedNode{{Tag: "pool-de-01", Key: "ghost"}}}
	_, err := render.Render(render.Input{
		Template: testTemplate(t), Selection: sel, NodesByKey: map[string]*model.Node{}, Cfg: renderCfg(nil),
	})
	require.Error(t, err, "a selected node without node data cannot be rendered — fail loud")
}

// TestGoldenRenderPassesXrayTest is the Plan A coexistence verdict: the real
// xray binary (26.3.27) must accept the rendered config containing BOTH the
// legacy pool observatory and the Germans burstObservatory.
func TestGoldenRenderPassesXrayTest(t *testing.T) {
	bin := "/usr/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("xray binary not present at %s", bin)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "golden-render.json"))
	if err != nil {
		t.Fatalf("golden render missing: run the suite once to materialize it: %v", err)
	}
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "rendered.json")
	require.NoError(t, os.WriteFile(cfgPath, golden, 0o644))

	cmd := exec.CommandContext(context.Background(), bin, "run", "-test", "-c", cfgPath)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+tmp)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "xray run -test rejected the Plan A render:\n%s", out)
	assert.Contains(t, string(out), "Configuration OK")
}

// TestTemplateEmptySelectorObservatoryRefusedOnAnyPoolState pins the L1
// defense-in-depth gate: a template-carried legacy observatory whose
// subjectSelector can match zero tags busy-loops the 26.3.27 core (~100% CPU)
// regardless of pool state — it must be refused at render time with the L1
// rationale (review finding 4).
func TestTemplateEmptySelectorObservatoryRefusedOnAnyPoolState(t *testing.T) {
	templateWith := func(t *testing.T, observatory map[string]any) []byte {
		t.Helper()
		var m map[string]any
		require.NoError(t, json.Unmarshal(testTemplate(t), &m))
		m["observatory"] = observatory
		b, err := json.Marshal(m)
		require.NoError(t, err)
		return b
	}

	for _, tc := range []struct {
		name string
		obs  map[string]any
	}{
		{"empty array", map[string]any{"subjectSelector": []any{}, "probeInterval": "60s"}},
		{"missing field", map[string]any{"probeInterval": "60s"}},
	} {
		t.Run(tc.name+"/empty-pool", func(t *testing.T) {
			_, err := render.Render(render.Input{
				Template:   templateWith(t, tc.obs),
				Selection:  &model.Selection{},
				NodesByKey: map[string]*model.Node{},
				Cfg:        renderCfg(nil),
			})
			require.Error(t, err, "L1: empty-selector observatory must be refused even with an empty pool")
			assert.Contains(t, err.Error(), "subjectSelector")
			assert.Contains(t, err.Error(), "L1", "message must carry the L1 rationale")
		})
		t.Run(tc.name+"/non-empty-pool", func(t *testing.T) {
			nodes, sel := twoCountrySelection(t)
			byKey := map[string]*model.Node{}
			for _, n := range nodes {
				byKey[n.Key] = n
			}
			_, err := render.Render(render.Input{
				Template:   templateWith(t, tc.obs),
				Selection:  sel,
				NodesByKey: byKey,
				Cfg:        renderCfg(nil),
			})
			require.Error(t, err, "L1: refusal is unconditional, not pool-state dependent")
		})
	}
}

// TestUnrenderedLinkParamsAreReportedNotSilentlyDropped pins the structured
// drop report: params the chosen network/security cannot carry surface in
// Result.DroppedParams per outbound tag (review finding 5).
func TestUnrenderedLinkParamsAreReportedNotSilentlyDropped(t *testing.T) {
	// xhttp node carrying a grpc-only param and an unknown one.
	n, sn := mkSelected(t, "pool-nl-01", "nl", "Amsterdam", "nl1.example.com", 443,
		nodeOpts{network: "xhttp", extra: map[string]string{
			"mode": "packet-up", "host": "cdn.example", "path": "/pool",
			"serviceName": "grpc-svc", "headerType": "none",
		}})
	var m map[string]any
	res, err := render.Render(render.Input{
		Template:   testTemplate(t),
		Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
		NodesByKey: map[string]*model.Node{n.Key: n},
		Cfg:        renderCfg(nil),
	})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(res.Config, &m))

	require.Len(t, res.DroppedParams, 1)
	w := res.DroppedParams[0]
	assert.Equal(t, "pool-nl-01", w.Tag)
	assert.ElementsMatch(t, []string{"serviceName", "headerType"}, w.Params,
		"grpc-only and unknown params are reported for the xhttp outbound")
}

// TestFullyConsumedParamsProduceNoDropReport guards the whitelist against
// over-reporting: a node whose every param is consumed renders clean.
func TestFullyConsumedParamsProduceNoDropReport(t *testing.T) {
	n, sn := mkSelected(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", 2053,
		nodeOpts{network: "tcp", extra: map[string]string{
			"flow": "xtls-rprx-vision", "fp": "chrome", "spx": "/", "pqv": "AAAA",
		}})
	res, err := render.Render(render.Input{
		Template:   testTemplate(t),
		Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
		NodesByKey: map[string]*model.Node{n.Key: n},
		Cfg:        renderCfg(nil),
	})
	require.NoError(t, err)
	assert.Empty(t, res.DroppedParams,
		"flow/fp/spx/pqv are consumed (fp by mandated override) — no report")
}

// TestMaterialEarlyDataParamFailsLoud pins the hard gate: an early-data param
// that cannot be rendered for the chosen network materially changes transport
// behavior — the render must fail, naming the param (review finding 5).
func TestMaterialEarlyDataParamFailsLoud(t *testing.T) {
	for _, network := range []string{"tcp", "grpc", "xhttp"} {
		n, sn := mkSelected(t, "pool-nl-01", "nl", "Amsterdam", "nl1.example.com", 443,
			nodeOpts{network: network, extra: map[string]string{"ed": "2048"}})
		_, err := render.Render(render.Input{
			Template:   testTemplate(t),
			Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
			NodesByKey: map[string]*model.Node{n.Key: n},
			Cfg:        renderCfg(nil),
		})
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
	sn := model.SelectedNode{Tag: "pool-de-01", Key: n.Key, Country: "de", City: "Frankfurt"}
	_, err := render.Render(render.Input{
		Template:   testTemplate(t),
		Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
		NodesByKey: map[string]*model.Node{n.Key: n},
		Cfg:        renderCfg(nil),
	})
	require.Error(t, err, "unparseable aid must fail the render, not silently become alterId 0")
	assert.Contains(t, err.Error(), `"aid"`, "the offending param must be named")
	assert.Contains(t, err.Error(), "abc")
}

// TestVMESSParsedAidRendersAndConsumes guards the success path: a numeric aid
// renders as alterId verbatim and is consumed — it must not leak into the
// DroppedParams report (M-f: consumed only on successful placement).
func TestVMESSParsedAidRendersAndConsumes(t *testing.T) {
	n := model.NewNode("s", "vmess", "vmess-uuid-1", "de1.example.com", 2053,
		map[string]string{"type": "tcp", "security": "tls", "sni": "donor.example", "aid": "64"})
	sn := model.SelectedNode{Tag: "pool-de-01", Key: n.Key, Country: "de", City: "Frankfurt"}
	res, err := render.Render(render.Input{
		Template:   testTemplate(t),
		Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
		NodesByKey: map[string]*model.Node{n.Key: n},
		Cfg:        renderCfg(nil),
	})
	require.NoError(t, err)
	assert.Empty(t, res.DroppedParams, "a parsed aid is consumed — no drop report")
	ob := poolOutbound(t, func() map[string]any {
		t.Helper()
		var m map[string]any
		require.NoError(t, json.Unmarshal(res.Config, &m))
		return m
	}(), "pool-de-01")
	user := ob["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	assert.InDelta(t, 64, user["alterId"], 0.001, "aid renders as alterId verbatim (L9)")
}

// TestPoolRulesGoBeforeAllTrailingBalancerRules pins the insertion point: the
// catch-all class (balancerTag rules) can be several rules deep; pool rules
// must land after the last user-traffic rule and before the ENTIRE trailing
// balancer block, not between two balancer rules (review finding 12).
func TestPoolRulesGoBeforeAllTrailingBalancerRules(t *testing.T) {
	var m map[string]any
	require.NoError(t, json.Unmarshal(testTemplate(t), &m))
	routing := m["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	routing["rules"] = append(rules,
		map[string]any{"type": "field", "inboundTag": []any{"socks-in"}, "network": "tcp,udp", "balancerTag": "best_rtt"})

	nodes, sel := twoCountrySelection(t)
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	res, err := render.Render(render.Input{
		Template:   func() []byte { b, _ := json.Marshal(m); return b }(),
		Selection:  sel,
		NodesByKey: byKey,
		Cfg:        renderCfg([]render.PoolRoute{{Balancer: "pool_nl", Domains: []string{"geosite:netflix"}}}),
	})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(res.Config, &m))

	rules = m["routing"].(map[string]any)["rules"].([]any)
	firstPool, lastPool, firstGerman := -1, -1, -1
	for i, r := range rules {
		rm := r.(map[string]any)
		bt, ok := rm["balancerTag"].(string)
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(bt, "pool_"):
			if firstPool < 0 {
				firstPool = i
			}
			lastPool = i
		default:
			if firstGerman < 0 {
				firstGerman = i
			}
		}
	}
	require.NotEqual(t, -1, firstPool, "pool rule rendered")
	require.NotEqual(t, -1, firstGerman, "trailing german balancer rules present")
	assert.Greater(t, firstGerman, lastPool,
		"the german balancer block starts only AFTER the last pool rule — no wedging between balancerTag rules")
	assert.Less(t, firstPool, firstGerman, "pool rules precede the entire trailing balancer block")
}
