package render_test

import (
	"testing"

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
// getStatCounter). The own render emits both unconditionally (the api block
// they feed is unconditional since W3).

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

// The L1 gate on the empty-pool path is unaffected: no pool observatory, but
// stats/policy emission stays (the API block is unconditional since W3).
func TestRenderEmptyPoolStillCarriesStatsAndPolicy(t *testing.T) {
	_, sel := twoCountrySelection(t)
	sel.Nodes = nil
	m := doRender(t, nil, sel)
	_, hasObs := m["observatory"]
	assert.False(t, hasObs, "L1: empty pool must not render a pool observatory")
	require.NotNil(t, m["stats"])
	require.NotNil(t, m["policy"])
}
