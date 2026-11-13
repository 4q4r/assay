package render_test

import (
	"testing"

	"assay/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// T1 (hot-apply plan): the rendered api inbound is the hot-apply surface.
// The services list must enable RoutingService (adrules/lsrules) and
// HandlerService (future outbound work, registered but unused in V1) next to
// the production-proven StatsService. infra/conf/api.go matches service
// names CASE-INSENSITIVELY and SILENTLY ignores unrecognized strings — a
// typo would quietly leave the service unregistered, so the exact strings
// are pinned here (R2).

func TestAPIServicesEnableRoutingAndHandlerService(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)

	api, ok := m["api"].(map[string]any)
	require.True(t, ok, "api/stats service block rendered")
	raw, ok := api["services"].([]any)
	require.True(t, ok, "api.services is an array")
	got := make([]string, 0, len(raw))
	for _, s := range raw {
		got = append(got, s.(string))
	}
	want := []string{"StatsService", "RoutingService", "HandlerService"}
	require.Len(t, got, len(want), "exactly the three pinned services (silent-ignore hazard: no extras)")
	assert.ElementsMatch(t, want, got, "exact service strings, order-insensitive")
}

// R6: ruleTags must be a pure function of the route set in render order —
// identical routes re-render to identical tags; tags are unique per rule;
// the api rule and the catch-all stay untagged (they are not individually
// addressable by design: the api rule is render-owned, the catch-all is the
// terminator).

func TestPoolRouteRuleTagsDeterministicAndStable(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	routes := []render.PoolRoute{
		{Balancer: "pool_nl", Domains: []string{"domain:nyaa.si"}},
		{Balancer: "pool_us", Domains: []string{"domain:nvidia.com", "domain:geosite:nvidia"}},
		{Balancer: "pool_de", Domains: []string{"geosite:stripe"}},
	}
	m1 := doRender(t, nodes, sel, routes...)
	m2 := doRender(t, nodes, sel, routes...)

	tags1 := poolRuleTags(t, m1)
	tags2 := poolRuleTags(t, m2)
	assert.Equal(t, tags1, tags2, "two renders of identical routes → identical tags")
	assert.Len(t, tags1, len(routes), "every pool route carries a ruleTag")

	seen := map[string]bool{}
	for _, tg := range tags1 {
		require.False(t, seen[tg], "ruleTag %q must be unique per rule", tg)
		seen[tg] = true
	}

	// The api rule (first) and the catch-all (last) stay untagged.
	rules := rulesOf(t, m1)
	first := rules[0]
	_, hasTag := first["ruleTag"]
	require.False(t, hasTag, "the api rule stays untagged")
	last := rules[len(rules)-1]
	_, hasTag = last["ruleTag"]
	require.Falsef(t, hasTag, "the catch-all stays untagged (got %v)", last["ruleTag"])
}

// The tags are the render order made visible (pool-route-N): inserting a
// route at the front re-tags every rule to the new canonical order — the tag
// set always tracks the CURRENT route set, which is what the hot-apply
// verification compares against.

func TestPoolRouteRuleTagsTrackRenderOrder(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	base := []render.PoolRoute{
		{Balancer: "pool_nl", Domains: []string{"domain:nyaa.si"}},
		{Balancer: "pool_us", Domains: []string{"domain:nvidia.com"}},
	}
	mBase := doRender(t, nodes, sel, base...)
	assert.Equal(t, []string{"pool-route-0", "pool-route-1"}, poolRuleTags(t, mBase))

	withFront := append([]render.PoolRoute{{Balancer: "pool_de", Domains: []string{"geosite:stripe"}}}, base...)
	mFront := doRender(t, nodes, sel, withFront...)
	assert.Equal(t, []string{"pool-route-0", "pool-route-1", "pool-route-2"},
		poolRuleTags(t, mFront), "tags follow the canonical render order of the current route set")

	withoutFirst := base[1:]
	mOne := doRender(t, nodes, sel, withoutFirst...)
	assert.Equal(t, []string{"pool-route-0"}, poolRuleTags(t, mOne),
		"removing a route collapses the tags back to the canonical order")
}

// R6: a pool route whose target balancer was not rendered degrades to the
// block outbound (graceful fail-closed) — the rule KEEPS its ruleTag, so the
// hot-apply verification is stable across degradation.

func TestBlockDegradedRuleKeepsRuleTag(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel,
		render.PoolRoute{Balancer: "pool_fr", Domains: []string{"domain:dead.example"}}, // pool_fr not rendered
		render.PoolRoute{Balancer: "pool_nl", Domains: []string{"domain:nyaa.si"}},
	)

	rules := rulesOf(t, m)
	var degraded, healthy map[string]any
	for _, r := range rules {
		rm := r
		if domains, ok := rm["domain"].([]any); ok && len(domains) > 0 {
			switch domains[0] {
			case "domain:dead.example":
				degraded = rm
			case "domain:nyaa.si":
				healthy = rm
			}
		}
	}
	require.NotNil(t, degraded, "degraded rule present")
	require.NotNil(t, healthy, "healthy rule present")
	assert.Equal(t, "block", degraded["outboundTag"], "unrendered target degrades to block")
	assert.Equal(t, "pool-route-0", degraded["ruleTag"], "degradation keeps the ruleTag")
	assert.Equal(t, "pool-route-1", healthy["ruleTag"])
}

// poolRuleTags extracts the ruleTag sequence of the pool-route rules in rule
// order (api rule and catch-all excluded — they carry no ruleTag).
func poolRuleTags(t *testing.T, m map[string]any) []string {
	t.Helper()
	var tags []string
	for _, r := range rulesOf(t, m) {
		if tg, ok := r["ruleTag"].(string); ok {
			tags = append(tags, tg)
		}
	}
	return tags
}

// rulesOf returns the rendered routing rules as maps.
func rulesOf(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	routing, ok := m["routing"].(map[string]any)
	require.True(t, ok, "routing section present")
	raw, ok := routing["rules"].([]any)
	require.True(t, ok, "routing.rules array present")
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}
