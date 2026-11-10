package render_test

import (
	"encoding/json"
	"testing"

	"assay/internal/model"
	"assay/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W4: the stats stage polls `outbound>>>pool-` counters through the api-in
// inbound rendered by W3. For the counters to exist at all, the config must
// (a) carry a "stats" object (otherwise xray registers stats.NoopManager and
// GetOrRegisterCounter returns nil) and (b) enable
// policy.system.statsOutboundUplink/Downlink (otherwise
// app/proxyman/outbound getStatCounter never registers the counters).
// Verified against Xray-core source (core/xray.go essentialFeatures,
// app/policy/manager.go ForSystem, app/proxyman/outbound/handler.go
// getStatCounter) and the owner's live template, which carries NEITHER.

func TestRenderEmitsStatsObjectAndOutboundPolicyKnobs(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)

	statsObj, ok := m["stats"].(map[string]any)
	require.True(t, ok, `"stats":{} must render — without it xray uses NoopManager and no counters exist`)
	require.Empty(t, statsObj, "StatsObject takes no parameters")

	policy, ok := m["policy"].(map[string]any)
	require.True(t, ok, "policy block must render")
	system, ok := policy["system"].(map[string]any)
	require.True(t, ok, "policy.system must render")
	assert.Equal(t, true, system["statsOutboundUplink"], "outbound uplink counters must be enabled")
	assert.Equal(t, true, system["statsOutboundDownlink"], "outbound downlink counters must be enabled")
}

func TestRenderPreservesTemplatePolicyFields(t *testing.T) {
	// A template that already carries policy/system fields (levels, other
	// knobs) keeps them — only the two stats knobs are ensured, additively.
	tpl := []byte(`{
		"outbounds": [],
		"policy": {
			"levels": {"0": {"handshake": 4}},
			"system": {"statsInboundUplink": true}
		}
	}`)
	nodes, sel := twoCountrySelection(t)
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	res, err := render.Render(render.Input{Template: tpl, Selection: sel, NodesByKey: byKey, Cfg: renderCfg(nil)})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(res.Config, &m))

	policy := m["policy"].(map[string]any)
	system := policy["system"].(map[string]any)
	assert.Equal(t, true, system["statsInboundUplink"], "template's own system knob preserved")
	assert.Equal(t, true, system["statsOutboundUplink"], "stats knob added additively")
	assert.Equal(t, true, system["statsOutboundDownlink"])
	require.NotNil(t, policy["levels"], "template's policy.levels preserved")
	levels := policy["levels"].(map[string]any)
	l0 := levels["0"].(map[string]any)
	assert.InDelta(t, float64(4), l0["handshake"], 0.001)
}

func TestRenderStatsEmissionIsIdempotent(t *testing.T) {
	// Re-render (previous output as template) must not duplicate or clobber
	// the stats/policy blocks.
	nodes, sel := twoCountrySelection(t)
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	first, err := render.Render(render.Input{Template: testTemplate(t), Selection: sel, NodesByKey: byKey, Cfg: renderCfg(nil)})
	require.NoError(t, err)
	second, err := render.Render(render.Input{Template: first.Config, Selection: sel, NodesByKey: byKey, Cfg: renderCfg(nil)})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(second.Config, &m))

	require.NotNil(t, m["stats"])
	policy := m["policy"].(map[string]any)
	require.Len(t, policy, 1, "exactly one policy.system block")
	system := policy["system"].(map[string]any)
	assert.Equal(t, true, system["statsOutboundUplink"])
}

// The L1 gate on the empty-pool path is unaffected: no pool observatory, but
// stats/policy emission stays (the Germans' outbounds are measurable too and
// the API block is unconditional since W3).
func TestRenderEmptyPoolStillCarriesStatsAndPolicy(t *testing.T) {
	_, sel := twoCountrySelection(t)
	sel.Nodes = nil
	m := doRender(t, nil, sel)
	_, hasObs := m["observatory"]
	assert.False(t, hasObs, "L1: empty pool must not render a pool observatory")
	require.NotNil(t, m["stats"])
	require.NotNil(t, m["policy"])
}
