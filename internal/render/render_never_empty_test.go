package render_test

import (
	"strings"
	"testing"

	"assay/internal/model"
	"assay/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Owner contract 2026-11-18 («балансиры никогда не пустуют»): live nodes are
// never dropped from balancer membership for media-check reasons — only
// probe-dead nodes leave (dead-only removal); live nodes with unknown/semi
// media verdicts are spread into the balancer variants their resolved
// attributes imply; a node confirmed dirty for a service is excluded from
// THAT service's variant only; every balancer's fallbackTag chains to its
// parent (clean/city/service variant → parent country balancer, country →
// pool_all, pool_all → block at the root — D7 bootstrap posture untouched);
// a clean/service variant whose strict subset is empty widens to the parent
// live set with a loud warning; and balancer members derive ONLY from the
// current selection.

// neverEmptyGeo joins geo evidence for hosts; every record passes
// CheckedAt so the verdicts count as CHECKED (the contract's media-check
// axis; unchecked records stay out of the unlock pools — fail-closed
// evidence classes unchanged).
func neverEmptyGeo(nodes []*model.Node, byHost map[string]model.GeoRecord) map[string]*model.GeoRecord {
	out := map[string]*model.GeoRecord{}
	for _, n := range nodes {
		rec, ok := byHost[n.Host]
		if !ok {
			continue
		}
		if rec.MediaUnlocks.CheckedAt == "" {
			rec.MediaUnlocks.CheckedAt = "2026-11-18T12:00:00Z"
		}
		out[model.GeoIdentity(&model.GeoRecord{Scheme: n.Scheme, Host: n.Host, Port: n.Port})] = &rec
	}
	return out
}

// mkNE builds one selected vless-tcp node with flags and a geo record.
func mkNE(
	t *testing.T, tag, cc, city, host string, clean bool, risk int,
	mu model.MediaUnlockStatus,
) (*model.Node, model.SelectedNode, model.GeoRecord) {
	t.Helper()
	n, sn := mkSelected(t, tag, cc, city, host, 2053, nodeOpts{
		network: "tcp", extra: map[string]string{"flow": "xtls-rprx-vision"},
	})
	sn.IsClean = clean
	if mu.CheckedAt == "" {
		mu.CheckedAt = "2026-11-18T12:00:00Z"
	}
	return n, sn, model.GeoRecord{RiskScore: risk, MediaUnlocks: mu}
}

// selectorContains reports whether the balancer's selector list contains tag.
func selectorContains(t *testing.T, m map[string]any, tag, want string) bool {
	t.Helper()
	bal := balancerByTag(t, m, tag)
	if bal == nil {
		return false
	}
	sel, ok := bal["selector"].([]any)
	require.True(t, ok, "balancer %s selector must be a list", tag)
	for _, s := range sel {
		if s == want {
			return true
		}
	}
	return false
}

// TestLiveSemiUnknownNodesStayInCleanVariants pins dead-only removal and the
// unknown spread: a CHECKED unknown or partial (semi) media verdict never
// excludes a live node from any balancer variant — it rides its resolved
// country/city balancers, the clean family (flags+risk axis, media-blind),
// AND the service variants of the dimension that did not come back dirty.
func TestLiveSemiUnknownNodesStayInCleanVariants(t *testing.T) {
	// us-01: Netflix CHECKED unknown — live, media-unknown.
	n1, sn1, g1 := mkNE(t, "pool-us-01", "us", "Ashburn", "us1.example.com", true, -1,
		model.MediaUnlockStatus{Netflix: model.UnlockUnknown})
	// us-02: ChatGPT webonly — a SEMI unlock, not a full pass.
	n2, sn2, g2 := mkNE(t, "pool-us-02", "us", "Ashburn", "us2.example.com", true, -1,
		model.MediaUnlockStatus{ChatGPT: model.UnlockWebOnly})
	// nl-01: Netflix originals — the semi netflix verdict.
	n3, sn3, g3 := mkNE(t, "pool-nl-01", "nl", "Amsterdam", "nl1.example.com", true, -1,
		model.MediaUnlockStatus{Netflix: model.UnlockNetflixOriginals})
	// us-03: flags-dirty live node — keeps onlyCleanMode off so the clean
	// tiers render (the fixture must isolate the MEDIA axis, not the skip).
	n4, sn4, g4 := mkNE(t, "pool-us-03", "us", "Dallas", "us3.example.com", false, -1,
		model.MediaUnlockStatus{})
	nodes := []*model.Node{n1, n2, n3, n4}
	sel := &model.Selection{Nodes: []model.SelectedNode{sn1, sn2, sn3, sn4}}
	m := doRenderGeo(t, nodes, sel, neverEmptyGeo(nodes, map[string]model.GeoRecord{
		"us1.example.com": g1, "us2.example.com": g2, "nl1.example.com": g3, "us3.example.com": g4,
	}))

	// The country/city base tiers carry every live node (already true; the
	// pin guards the dead-only contract). Country balancers select by the
	// country prefix; city balancers carry the explicit member tags.
	assert.Equal(t, []any{"pool-us-"}, serviceSelector(t, m, "pool_us"),
		"the country tier covers the whole live country set")
	assert.True(t, selectorContains(t, m, "pool_us_ashburn", "pool-us-01"),
		"media-unknown node stays in its resolved city balancer")

	// Media-UNKNOWN node spreads into the netflix variants of its resolved
	// country/city — NOT confirmed dirty anywhere.
	assert.True(t, selectorContains(t, m, "pool_netflix", "pool-us-01"),
		"checked-unknown Netflix verdict must enter the global netflix pool")
	assert.True(t, selectorContains(t, m, "pool_us_netflix", "pool-us-01"),
		"checked-unknown Netflix verdict must enter the country netflix variant")

	// SEMI verdicts spread the same way.
	assert.True(t, selectorContains(t, m, "pool_chatgpt", "pool-us-02"),
		"webonly (semi) ChatGPT must enter the global chatgpt pool")
	assert.True(t, selectorContains(t, m, "pool_us_chatgpt", "pool-us-02"),
		"webonly (semi) ChatGPT must enter the country chatgpt variant")
	assert.True(t, selectorContains(t, m, "pool_netflix", "pool-nl-01"),
		"originals (semi) Netflix must enter the global netflix pool")
	assert.True(t, selectorContains(t, m, "pool_nl_netflix", "pool-nl-01"),
		"originals (semi) Netflix must enter the country netflix variant")

	// The clean family stays media-blind: clean flags + in-band/unchecked
	// risk keep all three live nodes in every clean tier.
	assert.True(t, selectorContains(t, m, "pool_clean", "pool-us-01"))
	assert.True(t, selectorContains(t, m, "pool_us_clean", "pool-us-01"))
	assert.True(t, selectorContains(t, m, "pool_all_clean", "pool-nl-01"))
}

// TestNetflixDirtyExcludedFromNetflixOnly pins the per-service exclusion
// scope: a node CONFIRMED dirty for netflix (checked blocked verdict) is
// excluded from the netflix variants ONLY — it stays in its country/city
// balancers, the clean family, and every other service's variants.
func TestNetflixDirtyExcludedFromNetflixOnly(t *testing.T) {
	n1, sn1, g1 := mkNE(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", true, 10,
		model.MediaUnlockStatus{Netflix: model.UnlockBlocked, ChatGPT: model.UnlockYes})
	// Flags-dirty netflix-full sibling: keeps onlyCleanMode off (the clean
	// tiers must render for the presence pins) and isolates the media axis.
	n2, sn2, g2 := mkNE(t, "pool-de-02", "de", "Frankfurt", "de2.example.com", false, 10,
		model.MediaUnlockStatus{Netflix: model.UnlockNetflixFull})
	nodes := []*model.Node{n1, n2}
	sel := &model.Selection{Nodes: []model.SelectedNode{sn1, sn2}}
	m := doRenderGeo(t, nodes, sel, neverEmptyGeo(nodes, map[string]model.GeoRecord{
		"de1.example.com": g1, "de2.example.com": g2,
	}))

	assert.False(t, selectorContains(t, m, "pool_netflix", "pool-de-01"),
		"netflix-dirty node must stay out of the global netflix pool")
	assert.False(t, selectorContains(t, m, "pool_de_netflix", "pool-de-01"),
		"netflix-dirty node must stay out of the country netflix variant")
	assert.True(t, selectorContains(t, m, "pool_netflix", "pool-de-02"))

	// Exclusion is netflix-ONLY: the same node rides everything else.
	assert.Equal(t, []any{"pool-de-"}, serviceSelector(t, m, "pool_de"),
		"netflix-dirty node stays in its country balancer (prefix covers the live set)")
	assert.True(t, selectorContains(t, m, "pool_chatgpt", "pool-de-01"),
		"netflix-dirty node stays in the chatgpt pool its other verdicts earn")
	assert.True(t, selectorContains(t, m, "pool_clean", "pool-de-01"),
		"netflix-dirty node stays in the clean family (flags+risk clean)")
	assert.True(t, selectorContains(t, m, "pool_all_clean", "pool-de-01"))
}

// TestEmptyStrictCleanVariantWidensToCountryLiveSet pins render-time
// never-empty: when a clean/service variant's strict subset is empty while
// the parent live set exists, the variant renders WIDENED to the parent live
// set with the loud warning line (exact contract wording), so pool_routes
// targeting it never degrade to block.
func TestEmptyStrictCleanVariantWidensToCountryLiveSet(t *testing.T) {
	// Three live US nodes, none qualifying for the clean family (checked
	// risk above the approved band): strict pool_us_clean subset is EMPTY.
	n1, sn1, g1 := mkNE(t, "pool-us-01", "us", "Ashburn", "us1.example.com", true, 30,
		model.MediaUnlockStatus{Netflix: model.UnlockUnknown})
	n2, sn2, g2 := mkNE(t, "pool-us-02", "us", "Ashburn", "us2.example.com", true, 30,
		model.MediaUnlockStatus{})
	n3, sn3, g3 := mkNE(t, "pool-us-03", "us", "Dallas", "us3.example.com", false, 10,
		model.MediaUnlockStatus{})
	nodes := []*model.Node{n1, n2, n3}
	sel := &model.Selection{Nodes: []model.SelectedNode{sn1, sn2, sn3}}
	geo := neverEmptyGeo(nodes, map[string]model.GeoRecord{
		"us1.example.com": g1, "us2.example.com": g2, "us3.example.com": g3,
	})

	warnings, _, m := renderGeo(t, nodes, sel, geo, []render.PoolRoute{
		{Balancer: "pool_us_clean", Domains: []string{"domain:v0.example"}},
	})
	usLive := []any{"pool-us-01", "pool-us-02", "pool-us-03"}

	widened := balancerByTag(t, m, "pool_us_clean")
	require.NotNil(t, widened,
		"empty strict clean subset must widen to the country live set, not stay absent")
	assert.Equal(t, usLive, widened["selector"],
		"widened pool_us_clean must carry exactly the pool_us live set in selection order")
	assert.Contains(t, warnings,
		"balancer pool_us_clean empty in selection — widened to pool_us live set (3 nodes)")

	// The global clean tiers widen to the pool-wide live set.
	globalWidened := balancerByTag(t, m, "pool_clean")
	require.NotNil(t, globalWidened, "empty global clean subset widens to pool_all live set")
	assert.Equal(t, usLive, globalWidened["selector"])
	assert.Contains(t, warnings,
		"balancer pool_clean empty in selection — widened to pool_all live set (3 nodes)")
	allCleanWidened := balancerByTag(t, m, "pool_all_clean")
	require.NotNil(t, allCleanWidened, "empty pool_all_clean widens to pool_all live set")
	assert.Equal(t, usLive, allCleanWidened["selector"])
	assert.Contains(t, warnings,
		"balancer pool_all_clean empty in selection — widened to pool_all live set (3 nodes)")
}

// TestTargetedCityAndServiceVariantsWiden pins the route-targeted widening:
// a pool_route into a city-clean or service variant whose strict subset is
// empty renders that variant widened to the parent country's live set, while
// UNTARGETED empty variants stay absent (no config bloat).
func TestTargetedCityAndServiceVariantsWiden(t *testing.T) {
	// de country: two live Frankfurt nodes, none netflix-qualifying (both
	// checked blocked), none clean-qualifying (risk above band).
	n1, sn1, g1 := mkNE(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", true, 30,
		model.MediaUnlockStatus{Netflix: model.UnlockBlocked})
	n2, sn2, g2 := mkNE(t, "pool-de-02", "de", "Frankfurt", "de2.example.com", true, 30,
		model.MediaUnlockStatus{Netflix: model.UnlockBlocked})
	// nl country: live node with netflix evidence — netflix tiers render from it.
	n3, sn3, g3 := mkNE(t, "pool-nl-01", "nl", "Amsterdam", "nl1.example.com", true, -1,
		model.MediaUnlockStatus{Netflix: model.UnlockNetflixFull})
	nodes := []*model.Node{n1, n2, n3}
	sel := &model.Selection{Nodes: []model.SelectedNode{sn1, sn2, sn3}}
	geo := neverEmptyGeo(nodes, map[string]model.GeoRecord{
		"de1.example.com": g1, "de2.example.com": g2, "nl1.example.com": g3,
	})
	routes := []render.PoolRoute{
		{Balancer: "pool_de_frankfurt_clean", Domains: []string{"domain:a.example"}},
		{Balancer: "pool_de_netflix", Domains: []string{"domain:b.example"}},
	}
	warnings, _, m := renderGeo(t, nodes, sel, geo, routes)
	deLive := []any{"pool-de-01", "pool-de-02"}

	cityClean := balancerByTag(t, m, "pool_de_frankfurt_clean")
	require.NotNil(t, cityClean,
		"route-targeted city-clean variant with empty strict subset must widen")
	assert.Equal(t, deLive, cityClean["selector"],
		"widened city-clean variant carries the parent country's live set")
	assert.Contains(t, warnings,
		"balancer pool_de_frankfurt_clean empty in selection — widened to pool_de live set (2 nodes)")

	netflixWidened := balancerByTag(t, m, "pool_de_netflix")
	require.NotNil(t, netflixWidened,
		"route-targeted service variant with empty strict subset must widen")
	assert.Equal(t, deLive, netflixWidened["selector"])
	assert.Contains(t, warnings,
		"balancer pool_de_netflix empty in selection — widened to pool_de live set (2 nodes)")

	// Untargeted empty variants stay absent: no nl city clean subset exists
	// (single node city, no clean sibling) and nothing routes into it.
	assert.Nil(t, balancerByTag(t, m, "pool_nl_amsterdam_clean"),
		"untargeted empty city-clean variants must not render")
}

// TestBalancerFallbackChain pins the runtime never-empty chain: every
// non-root balancer's fallbackTag names its PARENT (clean/city/service
// variant → parent country balancer; country → pool_all), and only the root
// pool_all falls back to block (D7 preserved at the root; the bootstrap
// empty-pool posture is a separate, untouched layer).
func TestBalancerFallbackChain(t *testing.T) {
	n1, sn1, g1 := mkNE(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", true, 10,
		model.MediaUnlockStatus{ChatGPT: model.UnlockYes, Netflix: model.UnlockNetflixFull, YouTubeRegion: "DE"})
	n2, sn2, g2 := mkNE(t, "pool-de-02", "de", "Frankfurt", "de2.example.com", true, -1,
		model.MediaUnlockStatus{})
	n3, sn3, g3 := mkNE(t, "pool-us-01", "us", "Ashburn", "us1.example.com", false, -1,
		model.MediaUnlockStatus{})
	n4, sn4, _ := mkNE(t, "pool-xx-01", "", "", "xx1.example.com", true, -1, model.MediaUnlockStatus{})
	nodes := []*model.Node{n1, n2, n3, n4}
	sel := &model.Selection{Nodes: []model.SelectedNode{sn1, sn2, sn3, sn4}}
	m := doRenderGeo(t, nodes, sel, neverEmptyGeo(nodes, map[string]model.GeoRecord{
		"de1.example.com": g1, "de2.example.com": g2, "us1.example.com": g3,
	}))

	want := map[string]string{
		// Base tiers.
		"pool_de":                model.PoolAllBalancerTag,
		"pool_us":                model.PoolAllBalancerTag,
		"pool_unknown":           model.PoolAllBalancerTag,
		"pool_de_frankfurt":      model.CountryBalancerTag("de"),
		model.PoolAllBalancerTag: "block",
		// Clean family.
		"pool_de_clean":           model.CountryBalancerTag("de"),
		"pool_de_frankfurt_clean": model.CountryBalancerTag("de"),
		"pool_us_clean":           model.CountryBalancerTag("us"),
		"pool_unknown_clean":      model.UnknownBalancerTag,
		"pool_all_clean":          model.PoolAllBalancerTag,
		"pool_clean":              model.PoolAllBalancerTag,
		// Service tiers.
		"pool_chatgpt":              model.PoolAllBalancerTag,
		"pool_netflix":              model.PoolAllBalancerTag,
		"pool_youtube":              model.PoolAllBalancerTag,
		"pool_de_chatgpt":           model.CountryBalancerTag("de"),
		"pool_de_netflix":           model.CountryBalancerTag("de"),
		"pool_de_frankfurt_chatgpt": model.CountryBalancerTag("de"),
		"pool_de_frankfurt_netflix": model.CountryBalancerTag("de"),
	}
	for tag, fb := range want {
		bal := balancerByTag(t, m, tag)
		require.NotNil(t, bal, "balancer %s must render in this fixture", tag)
		assert.Equal(t, fb, bal["fallbackTag"],
			"balancer %s must chain its fallback to its parent", tag)
	}
}

// TestBalancerMembersSubsetOfSelection pins the stale-corpses class: every
// selector entry of every rendered pool_ balancer names an outbound of the
// CURRENT selection — balancer membership is selection-derived, never
// known-alive- or geo-derived, so a rendered balancer can never reference a
// node the current selection dropped.
func TestBalancerMembersSubsetOfSelection(t *testing.T) {
	n1, sn1, g1 := mkNE(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", true, 10,
		model.MediaUnlockStatus{Netflix: model.UnlockUnknown})
	n2, sn2, g2 := mkNE(t, "pool-de-02", "de", "Frankfurt", "de2.example.com", false, 30,
		model.MediaUnlockStatus{Netflix: model.UnlockBlocked})
	n3, sn3, g3 := mkNE(t, "pool-us-01", "us", "Ashburn", "us1.example.com", true, -1,
		model.MediaUnlockStatus{})
	nodes := []*model.Node{n1, n2, n3}
	sel := &model.Selection{Nodes: []model.SelectedNode{sn1, sn2, sn3}}
	geo := neverEmptyGeo(nodes, map[string]model.GeoRecord{
		"de1.example.com": g1, "de2.example.com": g2, "us1.example.com": g3,
	})

	_, _, m := renderGeo(t, nodes, sel, geo, []render.PoolRoute{
		{Balancer: "pool_de_frankfurt_clean", Domains: []string{"domain:a.example"}},
		{Balancer: "pool_us_clean", Domains: []string{"domain:b.example"}},
	})
	selectionTags := map[string]bool{}
	for _, sn := range sel.Nodes {
		selectionTags[sn.Tag] = true
	}
	for _, b := range balancersOf(t, m) {
		tag, _ := b["tag"].(string)
		selList, ok := b["selector"].([]any)
		require.True(t, ok, "balancer %s selector must be a list", tag)
		for _, s := range selList {
			st, _ := s.(string)
			if strings.HasSuffix(st, "-") {
				// Prefix selector (pool-<cc>- / pool-): matches only outbounds
				// THIS render emitted — selection-derived by construction.
				continue
			}
			assert.True(t, selectionTags[st],
				"balancer %s selector references %q outside the current selection (stale-corpses class)", tag, st)
		}
	}
}
