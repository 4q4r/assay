package render_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"assay/internal/model"
	"assay/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Phase-3 service-quality pool tests: membership matrix over the unlock
// vocabulary, tier minimums (>= 1 for service pools vs >= 2 base city rule,
// D5 preserved), absence-when-unchecked (fail-closed), the clean risk band,
// the only-clean skip, and pool_routes targeting service pools.

// geoEvidence builds an Input.GeoByKey map for the given nodes: evidence is
// keyed by node host (unique in every fixture) and joined through
// model.GeoIdentity — the same join the renderer performs against the
// pipeline-built map.
func geoEvidence(nodes []*model.Node, byHost map[string]model.GeoRecord) map[string]*model.GeoRecord {
	out := make(map[string]*model.GeoRecord, len(byHost))
	for _, n := range nodes {
		rec, ok := byHost[n.Host]
		if !ok {
			continue
		}
		out[model.GeoIdentity(&model.GeoRecord{Scheme: n.Scheme, Host: n.Host, Port: n.Port})] = &rec
	}
	return out
}

// renderGeo is the geo-aware render helper: the own config + evidence map +
// pool routes, returning the route warnings, the raw bytes and the parsed
// config.
func renderGeo(
	t *testing.T, nodes []*model.Node, sel *model.Selection,
	geo map[string]*model.GeoRecord, routes []render.PoolRoute,
) ([]string, []byte, map[string]any) {
	t.Helper()
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	b, warnings, err := render.RenderOwnConfig(sel, ownCore(), routes, byKey, geo, render.Config{})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return warnings, b, m
}

// doRenderGeo renders and parses (the geo-aware doRender counterpart; no
// pool routes — routes coverage lives in renderGeo's callers that need it).
func doRenderGeo(
	t *testing.T, nodes []*model.Node, sel *model.Selection,
	geo map[string]*model.GeoRecord,
) map[string]any {
	t.Helper()
	_, _, m := renderGeo(t, nodes, sel, geo, nil)
	return m
}

// mkUnlocked builds one selected node plus its Phase-1 evidence row. clean
// sets the selection-carried flags verdict (sn.IsClean); the geo record
// carries the risk score and the three service unlock verdicts.
func mkUnlocked(
	t *testing.T, tag, cc, city, host string, clean bool, risk int,
	chatgpt, netflix, youtube string,
) (*model.Node, model.SelectedNode, model.GeoRecord) {
	t.Helper()
	n, sn := mkSelected(t, tag, cc, city, host, 2053, nodeOpts{
		network: "tcp", extra: map[string]string{"flow": "xtls-rprx-vision"},
	})
	sn.IsClean = clean
	gr := model.GeoRecord{
		RiskScore: risk,
		MediaUnlocks: model.MediaUnlockStatus{
			ChatGPT:       chatgpt,
			Netflix:       netflix,
			YouTubeRegion: youtube,
			CheckedAt:     "2026-11-04T12:00:00Z",
		},
	}
	return n, sn, gr
}

// TestServicePoolVerdictMatrix pins the not-confirmed-dirty membership rules
// through the full render (owner contract 2026-11-18, superseding the
// 2026-11-04 exact-positive ruling for membership breadth): one node, one
// verdict dimension per subtest (the other dimensions stay unchecked so
// they cannot qualify), the service balancer present for every CHECKED
// verdict except "blocked" — unknown and the partial passes are live
// живчики that ride the spread — and absent for unchecked (fail-closed
// evidence classes unchanged; the never-empty guarantee for that case is
// the widening + fallback chain, not fabricated membership).
func TestServicePoolVerdictMatrix(t *testing.T) {
	type verdictCase struct {
		verdict string
		want    bool
	}
	chatgptCases := []verdictCase{
		{model.UnlockYes, true},
		{model.UnlockWebOnly, true},  // semi unlock — живчик rides the spread
		{model.UnlockAppOnly, true},  // ditto
		{model.UnlockBlocked, false}, // confirmed dirty for chatgpt only
		{model.UnlockUnknown, true},  // checked-unknown — never confirmed dirty
		{"", false},                  // unchecked = probes off = absent
	}
	netflixCases := []verdictCase{
		{model.UnlockNetflixFull, true},
		{model.UnlockNetflixOriginals, true}, // semi unlock — rides the spread
		{model.UnlockBlocked, false},         // confirmed dirty for netflix only
		{model.UnlockUnknown, true},          // checked-unknown — never confirmed dirty
		{"", false},
	}
	youtubeCases := []verdictCase{
		{"US", true},
		{"de", true}, // any checked region the engine emits (ISO-2)
		{model.UnlockBlocked, false},
		{model.UnlockUnknown, true}, // checked-unknown region rides the spread
		{"", false},
	}
	run := func(t *testing.T, kind string, cases []verdictCase) {
		t.Helper()
		for _, tc := range cases {
			t.Run(kind+"="+fmt.Sprintf("%q", tc.verdict), func(t *testing.T) {
				n, sn := mkSelected(t, "pool-de-01", "de", "Frankfurt", "de1.example.com",
					2053, nodeOpts{network: "tcp", extra: map[string]string{"flow": "xtls-rprx-vision"}})
				mu := model.MediaUnlockStatus{CheckedAt: "2026-11-04T12:00:00Z"}
				switch kind {
				case "chatgpt":
					mu.ChatGPT = tc.verdict
				case "netflix":
					mu.Netflix = tc.verdict
				case "youtube":
					mu.YouTubeRegion = tc.verdict
				}
				geo := map[string]*model.GeoRecord{
					model.GeoIdentity(&model.GeoRecord{
						Scheme: n.Scheme, Host: n.Host, Port: n.Port,
					}): {RiskScore: -1, MediaUnlocks: mu},
				}
				m := doRenderGeo(t, []*model.Node{n}, &model.Selection{Nodes: []model.SelectedNode{sn}}, geo)
				chatgpt := balancerByTag(t, m, "pool_chatgpt")
				netflix := balancerByTag(t, m, "pool_netflix")
				youtube := balancerByTag(t, m, "pool_youtube")
				switch kind {
				case "chatgpt":
					assertServicePresence(t, tc.want, chatgpt, balancerByTag(t, m, "pool_de_chatgpt"))
					assert.Nil(t, netflix)
					assert.Nil(t, youtube)
				case "netflix":
					assertServicePresence(t, tc.want, netflix, balancerByTag(t, m, "pool_de_netflix"))
					assert.Nil(t, chatgpt)
					assert.Nil(t, youtube)
				case "youtube":
					assertServicePresence(t, tc.want, youtube, nil)
					assert.Nil(t, chatgpt)
					assert.Nil(t, netflix)
					assert.Nil(t, balancerByTag(t, m, "pool_de_youtube"),
						"youtube has no country tier (global-only)")
				}
			})
		}
	}
	run(t, "chatgpt", chatgptCases)
	run(t, "netflix", netflixCases)
	run(t, "youtube", youtubeCases)
}

// assertServicePresence asserts the service balancer exists (or not) at the
// global tier and the extra tier passed in (nil = no extra assert).
func assertServicePresence(t *testing.T, want bool, global, extra map[string]any) {
	t.Helper()
	if want {
		require.NotNil(t, global, "the exact positive verdict must render the service pool")
		if extra != nil {
			require.NotNil(t, extra, "the country tier must render alongside the global one")
		}
		return
	}
	assert.Nil(t, global, "a non-positive verdict must leave the service pool absent")
	if extra != nil {
		assert.Nil(t, extra)
	}
}

// TestServicePoolMembershipMatrix renders one selection whose nodes embody
// the cross-product of the interesting evidence shapes and pins every
// service pool's exact selector contents (clean flags × risk band × unlock
// verdicts × unknown-geo).
func TestServicePoolMembershipMatrix(t *testing.T) {
	type nodeRow struct {
		n   *model.Node
		sn  model.SelectedNode
		geo model.GeoRecord
	}
	mk := func(tag, cc, city, host string, clean bool, risk int, chatgpt, netflix, youtube string) nodeRow {
		n, sn, gr := mkUnlocked(t, tag, cc, city, host, clean, risk, chatgpt, netflix, youtube)
		return nodeRow{n: n, sn: sn, geo: gr}
	}
	rows := []nodeRow{
		// The all-qualifying clean node: every tier, every pool.
		mk("pool-de-01", "de", "Frankfurt", "de1.example.com", true, 10,
			model.UnlockYes, model.UnlockNetflixFull, "DE"),
		// Clean flags but risk ABOVE the approved 0-25 band: pool_clean rejects
		// it; no unlock verdicts, so it lands in no service pool at all.
		mk("pool-de-02", "de", "Frankfurt", "de2.example.com", true, 30, "", "", ""),
		// The near-miss row: webonly ChatGPT + originals Netflix + blocked
		// YouTube — every verdict positive-looking but NOT the exact member.
		mk("pool-de-03", "de", "Frankfurt", "de3.example.com", false, 0,
			model.UnlockWebOnly, model.UnlockNetflixOriginals, model.UnlockBlocked),
		// Hosting-flagged node with heavy risk and no unlocks: nothing.
		mk("pool-nl-01", "nl", "Amsterdam", "nl1.example.com", false, 55,
			model.UnlockBlocked, model.UnlockBlocked, ""),
		// Unknown-geo node: qualifies for GLOBAL pools only (chatgpt yes +
		// checked US region + flags-only clean via unchecked risk).
		mk("pool-xx-01", "", "", "xx1.example.com", true, -1,
			model.UnlockYes, "", "US"),
	}

	nodes := make([]*model.Node, 0, len(rows))
	selNodes := make([]model.SelectedNode, 0, len(rows))
	byHost := map[string]model.GeoRecord{}
	for _, r := range rows {
		nodes = append(nodes, r.n)
		selNodes = append(selNodes, r.sn)
		byHost[r.n.Host] = r.geo
	}
	sel := &model.Selection{Nodes: selNodes}
	m := doRenderGeo(t, nodes, sel, geoEvidence(nodes, byHost))

	// Global tier: exact selector contents (selection order). Membership is
	// not-confirmed-dirty (owner contract 2026-11-18): checked-unknown and
	// the partial passes ride the spread; only "blocked" and unchecked stay
	// out.
	assert.Equal(t, []any{"pool-de-01", "pool-xx-01"},
		serviceSelector(t, m, "pool_clean"), "pool_clean = flags-clean ∩ risk band (30 rejected, -1 flags-only)")
	assert.Equal(t, []any{"pool-de-01", "pool-de-03", "pool-xx-01"},
		serviceSelector(t, m, "pool_chatgpt"), "pool_chatgpt = checked, not blocked (yes + webonly semi)")
	assert.Equal(t, []any{"pool-de-01", "pool-de-03"},
		serviceSelector(t, m, "pool_netflix"), "pool_netflix = checked, not blocked (full + originals semi)")
	assert.Equal(t, []any{"pool-de-01", "pool-xx-01"},
		serviceSelector(t, m, "pool_youtube"), "pool_youtube = checked non-blocked regions (de-03 blocked out)")

	// Country tier (chatgpt/netflix only — no country youtube, none for nl).
	assert.Equal(t, []any{"pool-de-01", "pool-de-03"}, serviceSelector(t, m, "pool_de_chatgpt"))
	assert.Equal(t, []any{"pool-de-01", "pool-de-03"}, serviceSelector(t, m, "pool_de_netflix"))

	// Clean family (owner ruling 2026-11-04, option 2): the country/city
	// clean tiers run the SAME predicate as pool_clean. Risk-30 de-02 drops
	// out of the country tier, flags-dirty de-03 stays out despite its
	// in-band score 0, and the Frankfurt city tier falls below its >= 2
	// minimum with only de-01 qualifying. The xx pseudo-location's country
	// tier rides the same predicate (unchecked -1 → flags-only). The
	// never-empty widening: nl has zero clean nodes but a live node — its
	// clean tier renders WIDENED to the nl live set (loud warning line).
	assert.Equal(t, []any{"pool-de-01"}, serviceSelector(t, m, "pool_de_clean"),
		"pool_de_clean shares the pool_clean predicate (risk-30 de-02 rejected)")
	assert.Nil(t, balancerByTag(t, m, "pool_de_frankfurt_clean"),
		"only one qualifying clean node left in Frankfurt: untargeted, stays absent")
	assert.Equal(t, []any{"pool-xx-01"}, serviceSelector(t, m, "pool_unknown_clean"),
		"the xx clean country tier qualifies through the same predicate")
	assert.Equal(t, []any{"pool-nl-01"}, serviceSelector(t, m, "pool_nl_clean"),
		"nl clean tier widens to the nl live set (zero clean nodes, one live node)")

	for _, absent := range []string{
		"pool_de_youtube", "pool_nl_chatgpt", "pool_nl_netflix",
		"pool_nl_amsterdam_chatgpt", "pool_nl_amsterdam_netflix",
		"pool_de_frankfurt_youtube",
	} {
		assert.Nil(t, balancerByTag(t, m, absent),
			"%s must not render (empty strict subset, untargeted — no widening)", absent)
	}

	// City tier.
	assert.Equal(t, []any{"pool-de-01", "pool-de-03"}, serviceSelector(t, m, "pool_de_frankfurt_chatgpt"))
	assert.Equal(t, []any{"pool-de-01", "pool-de-03"}, serviceSelector(t, m, "pool_de_frankfurt_netflix"))

	// The unknown-geo node carries NO country/city service tier: the xx
	// pseudo-location never forms pool_<cc>_<svc> variants.
	for _, b := range balancersOf(t, m) {
		tag, _ := b["tag"].(string)
		assert.NotContains(t, tag, "pool__", "no empty-cc service tag may form")
	}

	// Security invariant extends to the service layer: every pool balancer
	// (base and service) chains its fallback to the parent live set — never
	// direct — and only the ROOT pool_all pins block (owner contract
	// 2026-11-18; D7 preserved at the root).
	for _, b := range balancersOf(t, m) {
		tag, _ := b["tag"].(string)
		if len(tag) > 5 && tag[:5] == "pool_" {
			strategy, ok := b["strategy"].(map[string]any)
			require.True(t, ok, "balancer %s must carry a strategy", tag)
			assert.Equal(t, "leastLoad", strategy["type"])
			fb, _ := b["fallbackTag"].(string)
			assert.NotEqual(t, "direct", fb, "balancer %s must never fall back to direct", tag)
			if tag == model.PoolAllBalancerTag {
				assert.Equal(t, "block", fb, "pool_all is the chain root — block")
				continue
			}
			assert.Contains(t, []string{"pool_all", "pool_de", "pool_nl", "pool_unknown"}, fb,
				"balancer %s must chain to a parent live set (got %q)", tag, fb)
		}
	}

	// Determinism: identical input renders byte-identical output.
	_, raw1, _ := renderGeo(t, nodes, sel, geoEvidence(nodes, byHost), nil)
	_, raw2, _ := renderGeo(t, nodes, sel, geoEvidence(nodes, byHost), nil)
	assert.Equal(t, string(raw1), string(raw2), "service pools must render deterministically")

	// Single-emission: every service balancer renders EXACTLY ONCE per render
	// (the own render regenerates from scratch each wave — the emission
	// contract that survives the template merge).
	m1 := m
	serviceTags := map[string]int{}
	for _, b := range balancersOf(t, m1) {
		tag, _ := b["tag"].(string)
		for _, want := range []string{
			"pool_clean", "pool_chatgpt", "pool_netflix", "pool_youtube",
			"pool_de_chatgpt", "pool_de_netflix", "pool_de_frankfurt_chatgpt", "pool_de_frankfurt_netflix",
			"pool_de_clean", "pool_unknown_clean", "pool_nl_clean",
		} {
			if tag == want {
				serviceTags[tag]++
			}
		}
	}
	assert.Equal(t, map[string]int{
		"pool_clean": 1, "pool_chatgpt": 1, "pool_netflix": 1, "pool_youtube": 1,
		"pool_de_chatgpt": 1, "pool_de_netflix": 1,
		"pool_de_frankfurt_chatgpt": 1, "pool_de_frankfurt_netflix": 1,
		"pool_de_clean": 1, "pool_unknown_clean": 1, "pool_nl_clean": 1,
	}, serviceTags, "every service balancer renders exactly once per render")
}

// serviceSelector fetches one service balancer's selector list.
func serviceSelector(t *testing.T, m map[string]any, tag string) []any {
	t.Helper()
	bal := balancerByTag(t, m, tag)
	require.NotNil(t, bal, "service balancer %s must render", tag)
	sel, ok := bal["selector"].([]any)
	require.True(t, ok, "selector must be a list")
	return sel
}

// toStrs coerces a stored []any of strings (empty when the shape differs).
func toStrs(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := r.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// TestServicePoolTiersMinimums pins the tier minimums: service pools render
// at >= 1 qualifying node (owner ruling 2026-11-04) while the BASE city
// balancer keeps its >= 2 rule (D5 undisturbed).
func TestServicePoolTiersMinimums(t *testing.T) {
	chat, snChat, geoChat := mkUnlocked(t, "pool-de-01", "de", "Frankfurt",
		"de1.example.com", false, 10, model.UnlockYes, "", "")
	cleanOnly, snClean, _ := mkUnlocked(t, "pool-de-02", "de", "Munich",
		"de2.example.com", true, -1, "", "", "")
	nodes := []*model.Node{chat, cleanOnly}
	sel := &model.Selection{Nodes: []model.SelectedNode{snChat, snClean}}
	geo := geoEvidence(nodes, map[string]model.GeoRecord{"de1.example.com": geoChat})

	m := doRenderGeo(t, nodes, sel, geo)

	// >= 1 service rule: the single-node city still gets its service pool.
	assert.NotNil(t, balancerByTag(t, m, "pool_de_chatgpt"), "country service pool renders at 1 node")
	assert.NotNil(t, balancerByTag(t, m, "pool_de_frankfurt_chatgpt"),
		"city service pool renders at 1 node (owner ruling: >= 1, not >= 2)")
	assert.Equal(t, []any{"pool-de-01"}, serviceSelector(t, m, "pool_de_frankfurt_chatgpt"))

	// D5 untouched: the single-node cities render NO base city balancer.
	assert.Nil(t, balancerByTag(t, m, "pool_de_frankfurt"), "base city balancer stays >= 2 (D5)")
	assert.Nil(t, balancerByTag(t, m, "pool_de_munich"), "base city balancer stays >= 2 (D5)")
	assert.Nil(t, balancerByTag(t, m, "pool_de_frankfurt_netflix"), "no netflix evidence — absent")

	// pool_clean rides the clean flags node (risk unchecked → flags-only).
	assert.Equal(t, []any{"pool-de-02"}, serviceSelector(t, m, "pool_clean"))
}

// TestServicePoolsAbsentWithoutEvidence pins the fail-closed contract: with
// no evidence map (nil GeoByKey) or all-unchecked records, the UNLOCK pools
// (chatgpt/netflix/youtube and their country/city variants) render — ABSENT,
// not empty. pool_clean is the exception since the never-empty widening
// (owner contract 2026-11-18): its strict subset rides flags only, and an
// empty strict subset widens to the pool-wide live set rather than going
// absent — availability never fabricates unlock membership, the widening is
// loud (warning line) and the fallback chain covers runtime death.
func TestServicePoolsAbsentWithoutEvidence(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	unlockPoolTags := []string{"pool_chatgpt", "pool_netflix", "pool_youtube"}

	// nil map = the knob-off pipeline state.
	mNil := doRenderGeo(t, nodes, sel, nil)
	for _, tag := range unlockPoolTags {
		assert.Nil(t, balancerByTag(t, mNil, tag), "%s must be absent without geo evidence", tag)
	}
	assert.Nil(t, balancerByTag(t, mNil, "pool_nl_chatgpt"))
	assert.Nil(t, balancerByTag(t, mNil, "pool_de_frankfurt_netflix"))

	// Evidence present but every record unchecked (-1 / empty verdicts):
	// identical absence for the unlock pools — they need CHECKED verdicts.
	byHost := map[string]model.GeoRecord{}
	for _, n := range nodes {
		byHost[n.Host] = model.GeoRecord{RiskScore: -1}
	}
	mUnchecked := doRenderGeo(t, nodes, sel, geoEvidence(nodes, byHost))
	for _, tag := range unlockPoolTags {
		assert.Nil(t, balancerByTag(t, mUnchecked, tag), "%s must be absent when unchecked", tag)
	}

	// pool_clean in both states: every node is flags-dirty in this fixture
	// (mkSelected leaves IsClean false), so the strict subset is empty and
	// the never-empty widening renders it with the pool-wide live set.
	allTags := make([]any, 0, len(sel.Nodes))
	for _, sn := range sel.Nodes {
		allTags = append(allTags, sn.Tag)
	}
	assert.Equal(t, allTags, serviceSelector(t, mNil, "pool_clean"),
		"pool_clean widens to the pool-wide live set when the strict subset is empty")
	assert.Equal(t, allTags, serviceSelector(t, mUnchecked, "pool_clean"),
		"unchecked evidence changes nothing: pool_clean widened in both states")
}

// TestPoolCleanRiskBandAndOnlyCleanSkip pins pool_clean's rules: the checked
// risk must sit in the approved 0-25 band for STRICT membership (out-of-band
// risk empties the strict subset → the never-empty widening renders the
// tier with the live set, loud warning), and the pool is skipped in
// only-clean mode (identical selector to pool_all — the owner's
// «балансиры только общие» ruling).
func TestPoolCleanRiskBandAndOnlyCleanSkip(t *testing.T) {
	bandCases := []struct {
		risk int
		want bool
	}{
		{-1, true}, // unchecked → flags-only clean
		{0, true},
		{10, true},
		{25, true}, // band boundary inclusive
		{26, false},
		{30, false},
	}
	for _, tc := range bandCases {
		t.Run(fmt.Sprintf("risk=%d", tc.risk), func(t *testing.T) {
			n, sn, _ := mkUnlocked(t, "pool-de-01", "de", "Frankfurt",
				"de1.example.com", true, tc.risk, "", "", "")
			nNonClean, snNonClean, _ := mkUnlocked(t, "pool-de-02", "de", "Frankfurt",
				"de2.example.com", false, 0, "", "", "")
			nodes := []*model.Node{n, nNonClean}
			sel := &model.Selection{Nodes: []model.SelectedNode{sn, snNonClean}}
			geo := geoEvidence(nodes, map[string]model.GeoRecord{
				"de1.example.com": {RiskScore: tc.risk},
				// de2 has NO record: nil geo must not admit a non-clean node.
			})
			m := doRenderGeo(t, nodes, sel, geo)
			if tc.want {
				assert.Equal(t, []any{"pool-de-01"}, serviceSelector(t, m, "pool_clean"))
			} else {
				// Out-of-band risk empties the STRICT subset; since the
				// never-empty widening (owner contract 2026-11-18) the tier
				// renders WIDENED to the live set (loud warning) instead of
				// going absent — a routed pool_clean never dead-ends.
				assert.Equal(t, []any{"pool-de-01", "pool-de-02"}, serviceSelector(t, m, "pool_clean"),
					"risk %d empties the strict subset — pool_clean widens to the live set", tc.risk)
			}
		})
	}

	// Only-clean mode: every node clean → pool_clean's selector would equal
	// pool_all's; the owner's only-clean ruling suppresses it.
	n1, sn1, g1 := mkUnlocked(t, "pool-de-01", "de", "Frankfurt",
		"de1.example.com", true, 5, model.UnlockYes, "", "")
	n2, sn2, _ := mkUnlocked(t, "pool-de-02", "de", "Frankfurt",
		"de2.example.com", true, 5, "", "", "")
	allCleanNodes := []*model.Node{n1, n2}
	allClean := &model.Selection{Nodes: []model.SelectedNode{sn1, sn2}}
	m := doRenderGeo(t, allCleanNodes, allClean, geoEvidence(allCleanNodes, map[string]model.GeoRecord{
		"de1.example.com": g1,
	}))
	assert.Nil(t, balancerByTag(t, m, "pool_clean"),
		"only-clean mode: pool_clean is redundant with pool_all and must not render")
	assert.NotNil(t, balancerByTag(t, m, "pool_chatgpt"), "unlock pools are NOT subject to only-clean skip")
	assert.NotNil(t, balancerByTag(t, m, "pool_all"), "pool_all still renders")
}

// TestCleanFamilyRiskBandUnified pins owner ruling 2026-11-04 (option 2):
// ONE clean-family rule everywhere — the global pool_clean, the country
// pool_<cc>_clean, the city pool_<cc>_<city>_clean, and the pool-wide
// pool_all_clean all qualify a node by the flags verdict AND, when the
// RiskScore is CHECKED, the approved 0-25 band (-1/0/10/25 in; 26/30 out).
// A flags-dirty node never enters any clean pool even with a perfect in-band
// score, and the base (all) tiers keep their own flags-independent membership.
func TestCleanFamilyRiskBandUnified(t *testing.T) {
	bandCases := []struct {
		risk int
		want bool
	}{
		{-1, true}, // unchecked → flags-only membership (probes off)
		{0, true},  // band floor inclusive
		{10, true},
		{25, true},  // band ceiling inclusive
		{26, false}, // first rejected score
		{30, false},
	}
	for _, tc := range bandCases {
		t.Run(fmt.Sprintf("risk=%d", tc.risk), func(t *testing.T) {
			c1, sn1, _ := mkUnlocked(t, "pool-de-01", "de", "Frankfurt",
				"de1.example.com", true, tc.risk, "", "", "")
			c2, sn2, _ := mkUnlocked(t, "pool-de-02", "de", "Frankfurt",
				"de2.example.com", true, tc.risk, "", "", "")
			// Flags-dirty node with a perfect in-band score: the flags gate
			// (not hosting, not proxy) must keep it out of every clean pool.
			dirty, snDirty, _ := mkUnlocked(t, "pool-de-03", "de", "Frankfurt",
				"de3.example.com", false, 0, "", "", "")
			nodes := []*model.Node{c1, c2, dirty}
			sel := &model.Selection{Nodes: []model.SelectedNode{sn1, sn2, snDirty}}
			geo := geoEvidence(nodes, map[string]model.GeoRecord{
				"de1.example.com": {RiskScore: tc.risk},
				"de2.example.com": {RiskScore: tc.risk},
				"de3.example.com": {RiskScore: 0},
			})
			m := doRenderGeo(t, nodes, sel, geo)

			cleanSelector := []any{"pool-de-01", "pool-de-02"}
			if tc.want {
				assert.Equal(t, cleanSelector, serviceSelector(t, m, "pool_clean"),
					"pool_clean (global tier) admits checked risk %d", tc.risk)
				assert.Equal(t, cleanSelector, serviceSelector(t, m, "pool_de_clean"),
					"pool_de_clean (country tier) admits checked risk %d under the SAME predicate", tc.risk)
				assert.Equal(t, cleanSelector, serviceSelector(t, m, "pool_de_frankfurt_clean"),
					"pool_de_frankfurt_clean (city tier) admits checked risk %d under the SAME predicate", tc.risk)
				assert.Equal(t, cleanSelector, serviceSelector(t, m, "pool_all_clean"),
					"pool_all_clean (pool-wide tier) admits checked risk %d under the SAME predicate", tc.risk)
			} else {
				// Out-of-band risk empties the strict subsets; since the
				// never-empty widening (owner contract 2026-11-18) the
				// global/country/pool-wide clean tiers render WIDENED to the
				// live set (loud warning) instead of going absent. The city
				// tier is untargeted here — it stays absent.
				widened := []any{"pool-de-01", "pool-de-02", "pool-de-03"}
				assert.Equal(t, widened, serviceSelector(t, m, "pool_clean"),
					"risk %d empties the strict subset — pool_clean widens to the live set", tc.risk)
				assert.Equal(t, widened, serviceSelector(t, m, "pool_de_clean"),
					"risk %d empties the strict subset — pool_de_clean widens to the live set", tc.risk)
				assert.Equal(t, widened, serviceSelector(t, m, "pool_all_clean"),
					"risk %d empties the strict subset — pool_all_clean widens to the live set", tc.risk)
				assert.Nil(t, balancerByTag(t, m, "pool_de_frankfurt_clean"),
					"untargeted city clean tier with an empty strict subset stays absent")
			}
			// The dirty node stays out of every STRICT clean tier at any
			// score; in the widened case it rides the widened live set by
			// contract (it is alive — availability beats strictness).
			for _, tag := range []string{"pool_clean", "pool_de_clean", "pool_de_frankfurt_clean", "pool_all_clean"} {
				if bal := balancerByTag(t, m, tag); bal != nil && tc.want {
					assert.NotContains(t, bal["selector"], "pool-de-03",
						"flags-dirty node must never enter strict %s", tag)
				}
			}
			// The base (all) tiers are untouched by the clean gate.
			assert.Equal(t, []any{"pool-de-"}, serviceSelector(t, m, "pool_de"))
			assert.NotNil(t, balancerByTag(t, m, "pool_de_frankfurt"),
				"base city tier keeps its own flags-independent membership")
		})
	}
}

// TestCleanFamilyUncheckedIsByteIdentical proves the [geo].unlock_probes
// = false behavioral note: with the unlock stage off every RiskScore is
// unchecked, and the clean family must behave byte-identically to the
// pre-Phase-3 flags-only state. Rendering the same clean selection with NO
// evidence map (the knob-off pipeline shape) and with an ALL-UNCHECKED
// evidence map must produce byte-identical configs — unchecked evidence
// never changes the render — and the clean pools (including the pool-wide
// pool_all_clean tier) carry exactly the flags sets the W16 renderer
// produced before the evidence join existed.
func TestCleanFamilyUncheckedIsByteIdentical(t *testing.T) {
	n1, sn1, _ := mkUnlocked(t, "pool-de-01", "de", "Frankfurt",
		"de1.example.com", true, -1, "", "", "")
	n2, sn2, _ := mkUnlocked(t, "pool-de-02", "de", "Frankfurt",
		"de2.example.com", true, -1, "", "", "")
	n3, sn3, _ := mkUnlocked(t, "pool-nl-01", "nl", "Amsterdam",
		"nl1.example.com", true, -1, "", "", "")
	// One flags-dirty node keeps onlyCleanMode off, so the clean tiers render.
	n4, sn4, _ := mkUnlocked(t, "pool-nl-02", "nl", "Amsterdam",
		"nl2.example.com", false, -1, "", "", "")
	nodes := []*model.Node{n1, n2, n3, n4}
	sel := &model.Selection{Nodes: []model.SelectedNode{sn1, sn2, sn3, sn4}}

	// The knob-off pipeline shape: no evidence map at all.
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	knobOff, _, err := render.RenderOwnConfig(sel, ownCore(), nil, byKey, nil, render.Config{})
	require.NoError(t, err)

	// Evidence present but EVERY record unchecked (-1): identical bytes.
	byHost := map[string]model.GeoRecord{}
	for _, n := range nodes {
		byHost[n.Host] = model.GeoRecord{RiskScore: -1}
	}
	allUnchecked, _, err := render.RenderOwnConfig(sel, ownCore(), nil, byKey,
		geoEvidence(nodes, byHost), render.Config{})
	require.NoError(t, err)

	assert.Equal(t, string(knobOff), string(allUnchecked),
		"all-unchecked evidence must render byte-identically to the knob-off state")

	// In that state the clean family is exactly the W16 flags-only sets.
	m := doRenderGeo(t, nodes, sel, geoEvidence(nodes, byHost))
	assert.Equal(t, []any{"pool-de-01", "pool-de-02"}, serviceSelector(t, m, "pool_de_clean"))
	assert.Equal(t, []any{"pool-de-01", "pool-de-02"}, serviceSelector(t, m, "pool_de_frankfurt_clean"))
	assert.Equal(t, []any{"pool-nl-01"}, serviceSelector(t, m, "pool_nl_clean"))
	assert.Equal(t, []any{"pool-de-01", "pool-de-02", "pool-nl-01"},
		serviceSelector(t, m, "pool_clean"), "pool_clean falls back to the flags-only set")
	assert.Equal(t, []any{"pool-de-01", "pool-de-02", "pool-nl-01"},
		serviceSelector(t, m, "pool_all_clean"), "pool_all_clean falls back to the flags-only set")
}

// TestPoolRoutesServicePoolTargets extends pool_routes validation to the
// service pools: rendered service tags are first-class balancer targets,
// unrendered ones degrade to block with a warning, and the D6 namespace wall
// still rejects non-pool targets.
func TestPoolRoutesServicePoolTargets(t *testing.T) {
	n, sn, gr := mkUnlocked(t, "pool-de-01", "de", "Frankfurt",
		"de1.example.com", false, 10, model.UnlockYes, model.UnlockNetflixFull, "DE")
	nodes := []*model.Node{n}
	sel := &model.Selection{Nodes: []model.SelectedNode{sn}}
	geo := geoEvidence(nodes, map[string]model.GeoRecord{"de1.example.com": gr})

	routes := []render.PoolRoute{
		{Balancer: "pool_chatgpt", Domains: []string{"domain:chat.openai.com"}},
		{Balancer: "pool_de_netflix", Domains: []string{"geosite:netflix"}},
		{Balancer: "pool_youtube", Domains: []string{"geosite:youtube"}},
		// Typo'd and nonexistent-tier targets: graceful degradation pins.
		{Balancer: "pool_chatgptt", Domains: []string{"domain:typo.example"}},
		{Balancer: "pool_unknown_chatgpt", Domains: []string{"domain:x.example"}},
	}
	res, _, m := renderGeo(t, nodes, sel, geo, routes)

	for _, target := range []string{"pool_chatgpt", "pool_de_netflix", "pool_youtube"} {
		var rule map[string]any
		for _, r := range m["routing"].(map[string]any)["rules"].([]any) {
			rm := r.(map[string]any)
			if bt, _ := rm["balancerTag"].(string); bt == target {
				rule = rm
			}
		}
		require.NotNil(t, rule, "pool route to %s must render a balancerTag rule", target)
		assert.Equal(t, []any{"in", "in-http"}, rule["inboundTag"])
	}

	// Unrendered service targets degrade to block, each with a warning. The
	// never-empty widening disclosures ride the same channel (this fixture's
	// single-node country yields empty strict clean tiers → 3 widening lines),
	// so the two degradation lines are asserted by content.
	require.Len(t, res, 5, "2 degradation lines + 3 never-empty widening disclosures")
	assert.Contains(t, res, `pool route balancer "pool_chatgptt" not rendered -> block`)
	assert.Contains(t, res, `pool route balancer "pool_unknown_chatgpt" not rendered -> block`)
	// The degraded rules keep their route domains (they blackhole exactly
	// the domains the owner routed, nothing else).
	degradedDomains := map[string]bool{}
	for _, r := range m["routing"].(map[string]any)["rules"].([]any) {
		rm := r.(map[string]any)
		if ot, _ := rm["outboundTag"].(string); ot != "block" {
			continue
		}
		for _, d := range toStrs(rm["domain"]) {
			degradedDomains[d] = true
		}
	}
	assert.True(t, degradedDomains["domain:typo.example"], "the typo route degrades with its own domain")
	assert.True(t, degradedDomains["domain:x.example"], "the absent-tier route degrades with its own domain")

	// D6 namespace wall: a non-pool target still fails the render loud.
	byKey := map[string]*model.Node{n.Key: n}
	_, _, err := render.RenderOwnConfig(sel, ownCore(),
		[]render.PoolRoute{{Balancer: "chatgpt", Domains: []string{"domain:x.com"}}}, byKey, geo, render.Config{})
	require.Error(t, err, "non-pool route targets must fail loud (D6)")
	assert.Contains(t, err.Error(), "namespace wall D6")
}
