package render_test

import (
	"strings"
	"testing"

	"public_vpn/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPoolBalancersCarryBlockFallback pins the W9 owner security invariant:
// EVERY pool_* balancer the renderer emits — country pool_<cc> and city
// pool_<cc>_<city> — carries "fallbackTag": "block", so a location whose
// balancer has no healthy candidate blackholes its traffic (D2 trust wall:
// never direct, never the template's own balancer fallback). The template's
// best_rtt balancer is passthrough content and must stay byte-identical.
func TestPoolBalancersCarryBlockFallback(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)

	routing, ok := m["routing"].(map[string]any)
	require.True(t, ok, "routing object present")
	raw, ok := routing["balancers"].([]any)
	require.True(t, ok, "routing.balancers array present")

	poolSeen := map[string]bool{}
	for _, b := range raw {
		bal, ok := b.(map[string]any)
		require.True(t, ok, "balancer must be an object")
		tag, _ := bal["tag"].(string)
		if strings.HasPrefix(tag, "pool_") {
			poolSeen[tag] = true
			assert.Equal(t, "block", bal["fallbackTag"],
				"pool balancer %s must drop its traffic when no candidate is healthy", tag)
		}
		if tag == "best_rtt" {
			assert.Equal(t, "proxy-0", bal["fallbackTag"],
				"template balancer best_rtt keeps its own fallbackTag — the renderer never touches template balancers")
		}
	}
	// twoCountrySelection: nl = 2 Amsterdam nodes (country + city balancer),
	// de = 1 node, us = 1 node → 2 country balancers + 1 city balancer, plus
	// the W16 pool-wide balancer (pool_all renders with any non-empty pool).
	require.Equal(t, map[string]bool{
		model.CountryBalancerTag("nl"):           true,
		model.CityBalancerTag("nl", "Amsterdam"): true,
		model.CountryBalancerTag("de"):           true,
		model.CountryBalancerTag("us"):           true,
		model.PoolAllBalancerTag:                 true,
	}, poolSeen, "expected 2 country balancers + 1 city balancer + the pool-wide balancer")
}
