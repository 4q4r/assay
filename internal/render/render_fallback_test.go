package render_test

import (
	"strings"
	"testing"

	"assay/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPoolBalancerFallbackChain pins the never-empty fallback chain (owner
// contract 2026-11-18, amending the W9 all-block posture for the balancer
// case): every pool_* balancer's fallbackTag names its PARENT live set —
// city variants → their country balancer, country balancers → pool_all —
// and only the ROOT pool_all falls back to block (D7 preserved at the root;
// the bootstrap/empty-pool posture is a separate, untouched layer). Never
// direct: the chain stays inside the balancer tree and blackholes only when
// the whole pool is dead (W9 security invariant intact; the chaining
// semantics are verified live against the production core version — see
// blockOutboundTag). The template's best_rtt balancer is passthrough content
// and must stay byte-identical.
func TestPoolBalancerFallbackChain(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)

	routing, ok := m["routing"].(map[string]any)
	require.True(t, ok, "routing object present")
	raw, ok := routing["balancers"].([]any)
	require.True(t, ok, "routing.balancers array present")

	wantFallback := map[string]string{
		model.CountryBalancerTag("nl"):           model.PoolAllBalancerTag,
		model.CityBalancerTag("nl", "Amsterdam"): model.CountryBalancerTag("nl"),
		model.CountryBalancerTag("de"):           model.PoolAllBalancerTag,
		model.CityBalancerTag("de", "Frankfurt"): model.CountryBalancerTag("de"),
		model.CountryBalancerTag("us"):           model.PoolAllBalancerTag,
		model.PoolAllBalancerTag:                 "block",
		// The clean tiers widen on this flags-dirty fixture (empty strict
		// subsets) and chain to their parent live sets all the same.
		model.CleanCountryBalancerTag("nl"): model.CountryBalancerTag("nl"),
		model.CleanCountryBalancerTag("de"): model.CountryBalancerTag("de"),
		model.CleanCountryBalancerTag("us"): model.CountryBalancerTag("us"),
		model.CleanPoolAllBalancerTag:       model.PoolAllBalancerTag,
		"pool_clean":                        model.PoolAllBalancerTag,
	}
	poolSeen := map[string]bool{}
	for _, b := range raw {
		bal, ok := b.(map[string]any)
		require.True(t, ok, "balancer must be an object")
		tag, _ := bal["tag"].(string)
		if strings.HasPrefix(tag, "pool_") {
			poolSeen[tag] = true
			assert.Equal(t, wantFallback[tag], bal["fallbackTag"],
				"pool balancer %s must chain its fallback to its parent", tag)
			assert.NotEqual(t, "direct", bal["fallbackTag"],
				"pool balancer %s must never fall back to direct (W9)", tag)
		}
		if tag == "best_rtt" {
			assert.Equal(t, "proxy-0", bal["fallbackTag"],
				"template balancer best_rtt keeps its own fallbackTag — the renderer never touches template balancers")
		}
	}
	// twoCountrySelection: nl = 2 Amsterdam nodes (country + city balancer),
	// de = 2 Frankfurt nodes (country + city balancer), us = 1 node →
	// 3 country balancers (nl, de, us) + 2 city balancers + pool_all, and
	// (never-empty widening; the fixture's nodes are all flags-dirty, so the
	// clean tiers widen to their parent live sets) the 3 country clean tiers
	// + pool_all_clean + pool_clean.
	require.Equal(t, map[string]bool{
		model.CountryBalancerTag("nl"):           true,
		model.CityBalancerTag("nl", "Amsterdam"): true,
		model.CountryBalancerTag("de"):           true,
		model.CityBalancerTag("de", "Frankfurt"): true,
		model.CountryBalancerTag("us"):           true,
		model.PoolAllBalancerTag:                 true,
		model.CleanCountryBalancerTag("nl"):      true,
		model.CleanCountryBalancerTag("de"):      true,
		model.CleanCountryBalancerTag("us"):      true,
		model.CleanPoolAllBalancerTag:            true,
		"pool_clean":                             true,
	}, poolSeen, "3 country + 2 city + pool_all + the widened clean tiers")
}
