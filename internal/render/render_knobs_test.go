package render_test

import (
	"encoding/json"
	"strings"
	"testing"

	"public_vpn/internal/model"
	"public_vpn/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// knobFixture is a small selection + template with the socks-in/http-in
// inbounds (the default pool_inbound_tags) and one reality node.
func knobFixture(t *testing.T, inbounds string) (render.Input, func(t *testing.T) map[string]any) {
	t.Helper()
	tmpl := `{
  "log": {"loglevel": "warning"},
  "inbounds": ` + inbounds + `,
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
}`
	node := model.NewNode("s", "vless", "00000000-0000-0000-0000-000000000009", "knob.example.com", 443,
		map[string]string{"security": "reality", "type": "xhttp", "pbk": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "sid": "AA"})
	sel := &model.Selection{Nodes: []model.SelectedNode{{
		Tag: "pool-de-01", Key: node.Key, Country: "de",
	}}}
	in := render.Input{
		Template:   []byte(tmpl),
		Selection:  sel,
		NodesByKey: map[string]*model.Node{node.Key: node},
		Cfg: render.Config{
			StatsPort: 15490,
			PoolRoutes: []render.PoolRoute{{
				Balancer: "pool_de",
				Domains:  []string{"geosite:netflix"},
			}},
		},
	}
	return in, func(t *testing.T) map[string]any {
		t.Helper()
		res, err := render.Render(in)
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(res.Config, &m))
		return m
	}
}

const twoInbounds = `[
    {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks"},
    {"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http"}
  ]`

// TestKnobDefaultsPreserveW3Shape pins the default-preservation contract: an
// empty knob surface (zero-value Config fields beyond StatsPort/PoolRoutes)
// renders byte-identical pool artifacts to the W3 baseline — inboundTag
// [socks-in http-in], probeInterval 60s, tcpMaxSeg 1440, fingerprint firefox,
// tolerance 0.2.
func TestKnobDefaultsPreserveW3Shape(t *testing.T) {
	in, renderFn := knobFixture(t, twoInbounds)
	in.Cfg = render.Config{ // zero values everywhere except the W3-era fields
		StatsPort:  15490,
		PoolRoutes: in.Cfg.PoolRoutes,
	}
	m := renderFn(t)

	rules := m["routing"].(map[string]any)["rules"].([]any)
	var poolRule map[string]any
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if ok && rm["domain"] != nil {
			poolRule = rm
			break
		}
	}
	require.NotNil(t, poolRule)
	assert.Equal(t, []any{"socks-in", "http-in"}, poolRule["inboundTag"])

	obs := m["observatory"].(map[string]any)
	assert.Equal(t, "60s", obs["probeInterval"])

	outbounds := m["outbounds"].([]any)
	var pool map[string]any
	for _, o := range outbounds {
		if om, ok := o.(map[string]any); ok && om["tag"] == "pool-de-01" {
			pool = om
			break
		}
	}
	require.NotNil(t, pool)
	stream := pool["streamSettings"].(map[string]any)
	assert.InDelta(t, 1440, stream["sockopt"].(map[string]any)["tcpMaxSeg"], 1e-9)
	reality := stream["realitySettings"].(map[string]any)
	assert.Equal(t, "firefox", reality["fingerprint"])

	balancers := m["routing"].(map[string]any)["balancers"].([]any)
	var countryBal map[string]any
	for _, b := range balancers {
		if bm, ok := b.(map[string]any); ok && bm["tag"] == "pool_de" {
			countryBal = bm
			break
		}
	}
	require.NotNil(t, countryBal)
	tol := countryBal["strategy"].(map[string]any)["settings"].(map[string]any)["tolerance"]
	assert.InDelta(t, 0.2, tol, 1e-9)
}

// TestPoolInboundTagsRenamedFailsLoud pins the exact error shape: a template
// whose inbound was renamed must fail with the missing tag named.
func TestPoolInboundTagsRenamedFailsLoud(t *testing.T) {
	in, _ := knobFixture(t, `[
		{"tag": "socks-in2", "listen": "127.0.0.1", "port": 10808, "protocol": "socks"},
		{"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http"}
	]`)
	in.Cfg.PoolInboundTags = nil // nil → the render package default tags apply
	_, err := render.Render(in)
	require.Error(t, err, "a renamed template inbound must fail the render loud (D2 silent fall-through)")
	assert.Contains(t, err.Error(), "socks-in", "the missing tag must be named")
}

// TestPoolInboundTagsExtraValidTagIsCarried pins the consumption contract:
// an added, existing inbound tag appears in every rendered pool rule.
func TestPoolInboundTagsExtraValidTagIsCarried(t *testing.T) {
	in, _ := knobFixture(t, `[
		{"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks"},
		{"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http"},
		{"tag": "tun-in", "listen": "127.0.0.1", "port": 10910, "protocol": "socks"}
	]`)
	in.Cfg.PoolInboundTags = []string{"socks-in", "http-in", "tun-in"}
	res, err := render.Render(in)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(res.Config, &m))
	rules := m["routing"].(map[string]any)["rules"].([]any)
	found := 0
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if ok && rm["domain"] != nil && strings.Contains(rm["domain"].([]any)[0].(string), "netflix") {
			assert.Equal(t, []any{"socks-in", "http-in", "tun-in"}, rm["inboundTag"])
			found++
		}
	}
	assert.Equal(t, 1, found, "the single pool rule must carry all three tags")
}

// TestRenderKnobValuesRenderVerbatim pins the consumption contract for the
// value knobs: each configured value lands in the rendered config exactly.
func TestRenderKnobValuesRenderVerbatim(t *testing.T) {
	in, _ := knobFixture(t, twoInbounds)
	in.Cfg.ObservatoryInterval = "45s"
	in.Cfg.TCPMaxSeg = 1380
	in.Cfg.TLSFingerprint = "chrome"
	in.Cfg.BalancerTolerance = 0.55
	res, err := render.Render(in)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(res.Config, &m))

	assert.Equal(t, "45s", m["observatory"].(map[string]any)["probeInterval"],
		"observatory_interval is a verbatim string passthrough")

	var stream, reality, strategy map[string]any
	for _, o := range m["outbounds"].([]any) {
		if om, ok := o.(map[string]any); ok && om["tag"] == "pool-de-01" {
			stream = om["streamSettings"].(map[string]any)
			reality = stream["realitySettings"].(map[string]any)
		}
	}
	for _, b := range m["routing"].(map[string]any)["balancers"].([]any) {
		if bm, ok := b.(map[string]any); ok && bm["tag"] == "pool_de" {
			strategy = bm["strategy"].(map[string]any)["settings"].(map[string]any)
		}
	}
	require.NotNil(t, stream)
	assert.InDelta(t, 1380, stream["sockopt"].(map[string]any)["tcpMaxSeg"], 1e-9)
	assert.Equal(t, "chrome", reality["fingerprint"])
	assert.InDelta(t, 0.55, strategy["tolerance"], 1e-9)
}

// TestBalancerToleranceAppliesToCityBalancersToo pins the second consumption
// site of [render].balancer_tolerance: city balancers carry the same
// configured tolerance as country ones.
func TestBalancerToleranceAppliesToCityBalancersToo(t *testing.T) {
	in, _ := knobFixture(t, twoInbounds)
	in.Cfg.BalancerTolerance = 0.7
	// Two nodes in one city → a city balancer renders (D5).
	second := model.NewNode("s", "vless", "00000000-0000-0000-0000-000000000008", "knob2.example.com", 443,
		map[string]string{"security": "reality", "type": "xhttp", "pbk": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "sid": "AA"})
	in.NodesByKey[second.Key] = second
	in.Selection.Nodes = append(in.Selection.Nodes, model.SelectedNode{
		Tag: "pool-de-02", Key: second.Key, Country: "de", City: "Frankfurt",
	})
	in.Selection.Nodes[0].City = "Frankfurt"

	res, err := render.Render(in)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(res.Config, &m))
	cityTolerance := map[string]float64{}
	for _, b := range m["routing"].(map[string]any)["balancers"].([]any) {
		bm := b.(map[string]any)
		if tag, _ := bm["tag"].(string); strings.HasPrefix(tag, "pool_") {
			s := bm["strategy"].(map[string]any)["settings"].(map[string]any)["tolerance"]
			cityTolerance[tag] = s.(float64)
		}
	}
	assert.InDelta(t, 0.7, cityTolerance["pool_de"], 1e-9)
	assert.InDelta(t, 0.7, cityTolerance["pool_de_frankfurt"], 1e-9,
		"city balancer tolerance must follow the same knob")
}
