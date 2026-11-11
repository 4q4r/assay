package render_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"assay/internal/model"
	"assay/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// knobFixture is a small selection (two reality nodes in DE, so the pool_de
// country balancer renders per the >=2 threshold) rendered through the own
// config with the given knobs — the consumption contract for every surviving
// [render] knob.
func knobFixture(t *testing.T, knobs render.Config) func(t *testing.T) map[string]any {
	t.Helper()
	node1 := model.NewNode("s", "vless", "00000000-0000-0000-0000-000000000009", "knob1.example.com", 443,
		map[string]string{"security": "reality", "type": "xhttp", "pbk": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "sid": "AA"})
	node2 := model.NewNode("s", "vless", "00000000-0000-0000-0000-000000000010", "knob2.example.com", 443,
		map[string]string{"security": "reality", "type": "xhttp", "pbk": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "sid": "BB"})
	sel := &model.Selection{Nodes: []model.SelectedNode{
		{Tag: "pool-de-01", Key: node1.Key, Country: "de", City: "Frankfurt"},
		{Tag: "pool-de-02", Key: node2.Key, Country: "de", City: "Frankfurt"},
	}}
	byKey := map[string]*model.Node{node1.Key: node1, node2.Key: node2}
	routes := []render.PoolRoute{{
		Balancer: "pool_de",
		Domains:  []string{"geosite:netflix"},
	}}
	return func(t *testing.T) map[string]any {
		t.Helper()
		b, _, err := render.RenderOwnConfig(sel, ownCore(), routes, byKey, nil, knobs)
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))
		return m
	}
}

// TestKnobDefaultsPreserveShape pins the default-preservation contract: an
// empty knob surface renders the same pool artifacts the renderer has always
// emitted — tcpMaxSeg 1440, fingerprint firefox, tolerance 0.2 — with the
// W19 adaptive observatory interval spelling as Go duration "1m0s" at this
// pool size (same value the core parsed from the old fixed "60s" default),
// and the pool rules carrying the GENERATED own inbound tags.
func TestKnobDefaultsPreserveShape(t *testing.T) {
	m := knobFixture(t, render.Config{})(t)

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
	assert.Equal(t, []any{"in", "in-http"}, poolRule["inboundTag"])

	obs := m["observatory"].(map[string]any)
	assert.Equal(t, "1m0s", obs["probeInterval"], "W19: absent knob → adaptive interval (60s floor at this pool size)")

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

// TestRenderKnobValuesRenderVerbatim pins the consumption contract for the
// value knobs: each configured value lands in the rendered config exactly.
func TestRenderKnobValuesRenderVerbatim(t *testing.T) {
	m := knobFixture(t, render.Config{
		ObservatoryInterval: "45s",
		TCPMaxSeg:           1380,
		TLSFingerprint:      "chrome",
		BalancerTolerance:   0.55,
	})(t)

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

// TestObservatoryIntervalAdaptive pins the W19 load-engineering formula: an
// ABSENT observatory_interval makes the render compute the pool observatory
// probeInterval from the ACTIVE COUNT —
//
//	interval = max(60s, ceil(N × 200ms))   (200ms = 1 / 5 probes-per-sec target)
//
// so sustained observatory probes stay ≤ 5/s regardless of pool growth
// (code-owned budget, deliberately no new knob). An explicit interval keeps
// verbatim precedence (TestRenderKnobValuesRenderVerbatim). The
// subjectSelector is untouched by the scaling — ["pool-"] covers EVERY pool
// outbound regardless of count (L2).
func TestObservatoryIntervalAdaptive(t *testing.T) {
	build := func(t *testing.T, n int) map[string]any {
		t.Helper()
		sel := &model.Selection{}
		byKey := map[string]*model.Node{}
		for i := range n {
			node := model.NewNode("s", "vless", fmt.Sprintf("%032d", i),
				fmt.Sprintf("n%d.example.com", i), 443,
				map[string]string{"security": "tls", "type": "tcp"})
			byKey[node.Key] = node
			sel.Nodes = append(sel.Nodes, model.SelectedNode{
				Tag: fmt.Sprintf("pool-de-%02d", i+1), Key: node.Key, Country: "de",
			})
		}
		b, _, err := render.RenderOwnConfig(sel, ownCore(), nil, byKey, nil, render.Config{})
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))
		return m
	}

	for _, tc := range []struct {
		active int
		want   string
		note   string
	}{
		{3, "1m0s", "small pool rides the 60s floor (the old fixed default)"},
		{259, "1m0s", "the owner's live pool: 259×200ms=51.8s < 60s floor → 60s"},
		{1000, "3m20s", "1000×200ms=200s exactly"},
		{3001, "10m1s", "3001×200ms=600.2s, ceil → 601s (probes/sec ≤ 5)"},
	} {
		m := build(t, tc.active)
		obs, ok := m["observatory"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, tc.want, obs["probeInterval"], "active=%d: %s", tc.active, tc.note)
		assert.Equal(t, []any{"pool-"}, obs["subjectSelector"], "L2: coverage namespace never scales away")
	}
}

// TestBalancerToleranceAppliesToCityBalancersToo pins the second consumption
// site of [render].balancer_tolerance: city balancers carry the same
// configured tolerance as country ones.
func TestBalancerToleranceAppliesToCityBalancersToo(t *testing.T) {
	m := knobFixture(t, render.Config{BalancerTolerance: 0.7})(t)
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
