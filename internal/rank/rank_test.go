package rank_test

import (
	"fmt"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/rank"
	"assay/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var seq int

type fixture struct {
	nodes []*model.Node
	geo   []*model.GeoRecord
	probe map[string]store.ProbeResult
}

func (f *fixture) add(t *testing.T, country, city string, alive bool, checks int, speed int64, rtt float64) *model.Node {
	t.Helper()
	seq++
	n := model.NewNode("s", "vless", fmt.Sprintf("u-%d", seq), fmt.Sprintf("n%d.example.com", seq), 443, map[string]string{"security": "tls", "type": "tcp"})
	f.nodes = append(f.nodes, n)
	f.geo = append(f.geo, &model.GeoRecord{
		Source: "s", Scheme: n.Scheme, Host: n.Host, Port: n.Port,
		Country: country, City: city, Alive: alive, RTTMs: rtt, SpeedBPS: speed,
	})
	f.probe[n.Key] = store.ProbeResult{Key: n.Key, Alive: alive, Checks: checks, TotalChecks: 3, RTTMs: rtt, SpeedBPS: speed}
	return n
}

func newFixture() *fixture {
	return &fixture{probe: map[string]store.ProbeResult{}}
}

func cfg(perCountry int) config.SelectConfig {
	return config.SelectConfig{PerCountryCap: perCountry, SoftCap: 25, CityExpandThreshold: 25, Ceiling: 40}
}

func TestRankingIsAliveThenChecksThenSpeed(t *testing.T) {
	f := newFixture()
	f.add(t, "de", "Berlin", false, 3, 10_000_000, 10) // dead: excluded despite best metrics
	f.add(t, "de", "Munich", true, 3, 1_000_000, 300)  // alive, 3 checks, slow
	f.add(t, "de", "Hamburg", true, 3, 8_000_000, 80)  // alive, 3 checks, fast
	f.add(t, "de", "Cologne", true, 1, 9_000_000, 50)  // alive, 1 check, fastest

	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	require.Len(t, sel.Nodes, 3, "dead excluded, K=3")
	assert.Equal(t, "Hamburg", sel.Nodes[0].City, "3 checks: speed decides")
	assert.Equal(t, "Munich", sel.Nodes[1].City, "3 checks: slower")
	assert.Equal(t, "Cologne", sel.Nodes[2].City, "fewer checks rank below")
}

func TestChecksBeatSpeedButAliveFirst(t *testing.T) {
	f := newFixture()
	a := f.add(t, "de", "A", true, 1, 9_000_000, 50)
	b := f.add(t, "de", "B", true, 3, 1_000_000, 400)
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(2), 0)
	require.Len(t, sel.Nodes, 2)
	assert.Equal(t, b.Key, sel.Nodes[0].Key, "3 checks beat 1 check even at 9x speed deficit")
	assert.Equal(t, a.Key, sel.Nodes[1].Key)
}

func TestPerCountryCapK(t *testing.T) {
	f := newFixture()
	for i := range 8 {
		f.add(t, "nl", fmt.Sprintf("City%d", i), true, 3, int64(1_000_000+i), 100)
	}
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	assert.Len(t, sel.Nodes, 3, "K=3 per country")
	for i, sn := range sel.Nodes {
		assert.Equal(t, fmt.Sprintf("pool-nl-%02d", i+1), sn.Tag, "stable NN sequence by rank")
	}
	assert.Equal(t, int64(1_000_007), sel.Nodes[0].Speed)
	assert.Equal(t, int64(1_000_006), sel.Nodes[1].Speed)
	assert.Equal(t, int64(1_000_005), sel.Nodes[2].Speed)
}

func TestGlobalCapExpandsForCityDiversity(t *testing.T) {
	f := newFixture()
	countries := []string{"us", "de", "fr", "nl", "gb", "jp", "sg", "au", "ca", "br", "pl", "se", "ch", "at", "es", "it", "fi", "dk", "no", "ie", "be", "cz", "pt", "gr", "hu", "ro", "bg", "hr", "ee", "lv"}
	for i, cc := range countries {
		f.add(t, cc, fmt.Sprintf("City%d", i), true, 3, int64(5_000_000-i*1000), 100)
	}
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	assert.Len(t, sel.Nodes, 30, "cap expands to cover 30 distinct cities (D7)")
	assert.Equal(t, 30, sel.CitiesAlive)
	assert.Equal(t, 30, sel.CapApplied)
}

func TestGlobalCapHoldsWhenFewCities(t *testing.T) {
	f := newFixture()
	// 10 countries × 3 nodes in one city each = 10 distinct cities (< threshold 25),
	// K=5 would allow 50 → the soft cap 25 must bind.
	countries := []string{"us", "de", "fr", "nl", "gb", "jp", "sg", "au", "ca", "br"}
	for _, cc := range countries {
		for i := range 3 {
			f.add(t, cc, cc+"City", true, 3, int64(1_000_000-i), 100)
		}
	}
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(5), 0)
	assert.Len(t, sel.Nodes, 25, "soft cap holds when city diversity is below the threshold")
	assert.Equal(t, 25, sel.CapApplied)
}

func TestExpansionRespectsCeiling(t *testing.T) {
	f := newFixture()
	for i := range 50 {
		f.add(t, fmt.Sprintf("c%02d", i), fmt.Sprintf("City%d", i), true, 3, 1_000_000, 100)
	}
	ceilingCfg := config.SelectConfig{PerCountryCap: 3, SoftCap: 25, CityExpandThreshold: 25, Ceiling: 40}
	sel := rank.Select(f.nodes, f.geo, f.probe, ceilingCfg, 0)
	assert.Len(t, sel.Nodes, 40, "ceiling 40 bounds the expansion")
}

func TestCityDiversityTieBreak(t *testing.T) {
	f := newFixture()
	f.add(t, "nl", "Amsterdam", true, 3, 5_000_000, 100)
	f.add(t, "nl", "Amsterdam", true, 3, 5_000_000, 100)
	f.add(t, "nl", "Rotterdam", true, 3, 5_000_000, 100)
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(2), 0)
	require.Len(t, sel.Nodes, 2)
	cities := map[string]bool{sel.Nodes[0].City: true, sel.Nodes[1].City: true}
	assert.Len(t, cities, 2, "identical metrics: tie broken toward city diversity")
}

func TestSelectIsDeterministic(t *testing.T) {
	f := newFixture()
	for i := range 20 {
		f.add(t, []string{"de", "nl", "fr"}[i%3], fmt.Sprintf("City%d", i%7), true, 3, int64(1_000_000+i*7777), float64(50+i*13))
	}
	s1 := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	s2 := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	assert.Equal(t, s1.Nodes, s2.Nodes, "identical input must yield an identical selection")
	assert.Equal(t, s1.CapApplied, s2.CapApplied)
}

// TestUnknownGeoNodeIsAdmittedUnderUnknownCapGroup pins the W16 flip (owner
// item 14a): an alive node with NO geo evidence is admitted into the active
// selection — "unknown" acts as a cap group like a country (D7 K applies),
// the D5 tag grammar stays intact with the xx pseudo-code (pool-xx-NN), and
// SelectedNode.Country mirrors resolved geo presence (raw empty string — the
// balancer grouping is a render-time concern).
func TestUnknownGeoNodeIsAdmittedUnderUnknownCapGroup(t *testing.T) {
	f := newFixture()
	f.add(t, "", "", true, 3, 1_000_000, 100)
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	require.Len(t, sel.Nodes, 1, "unknown geo never drops a usable node from the selection")
	assert.Equal(t, "pool-xx-01", sel.Nodes[0].Tag, "unknown-geo nodes keep the D5 grammar with the xx pseudo-code")
	assert.Empty(t, sel.Nodes[0].Country, "Selection carries the raw empty country — grouping is render-time")
	assert.Empty(t, sel.Nodes[0].City, "no geo evidence: city stays empty too")
}

// TestUnknownGeoNodesShareOneCapGroup pins the cap semantics: the unknown
// group is capped by K exactly like a country, and known countries are
// unaffected by unknown nodes competing for the global cap.
func TestUnknownGeoNodesShareOneCapGroup(t *testing.T) {
	f := newFixture()
	for i := range 5 {
		f.add(t, "", "", true, 3, int64(2_000_000+i), 100)
	}
	f.add(t, "de", "Berlin", true, 3, 1_000_000, 100)
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	unknown, de := 0, 0
	var unknownTags []string
	for _, sn := range sel.Nodes {
		switch sn.Country {
		case "":
			unknown++
			unknownTags = append(unknownTags, sn.Tag)
		case "de":
			de++
		}
	}
	assert.Equal(t, 3, unknown, "K=3 caps the unknown group like a country")
	assert.Equal(t, 1, de, "known countries are unaffected")
	assert.Equal(t, []string{"pool-xx-01", "pool-xx-02", "pool-xx-03"}, unknownTags,
		"stable NN sequence inside the unknown group")
}

// TestUnknownGeoNodesDoNotInflateCityDiversity pins the D7 expansion input:
// unknown-geo nodes carry no city, so they must not widen the soft cap
// through the city-diversity expansion.
func TestUnknownGeoNodesDoNotInflateCityDiversity(t *testing.T) {
	f := newFixture()
	for i := range 6 {
		f.add(t, "", "", true, 3, int64(3_000_000+i), 100)
	}
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	assert.Equal(t, 0, sel.CitiesAlive, "unknown nodes contribute no city diversity")
	assert.Equal(t, 25, sel.CapApplied, "soft cap holds — no expansion from unknown nodes")
	assert.Len(t, sel.Nodes, 3, "the unknown group is capped by K like a country")
}

func TestDeadNodeDoesNotRank(t *testing.T) {
	f := newFixture()
	f.add(t, "de", "Berlin", true, 3, 1_000_000, 100)
	f.geo[0].Alive = false
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	assert.Empty(t, sel.Nodes)
}

func TestSelectionMetadata(t *testing.T) {
	f := newFixture()
	f.add(t, "de", "Berlin", true, 3, 1_000_000, 100)
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	assert.False(t, sel.GeneratedAt.IsZero())
	assert.Equal(t, 25, sel.CapApplied)
	assert.Equal(t, 1, sel.CitiesAlive)
}

func TestSelectJoinsGeoRecordsToNodesByIdentity(t *testing.T) {
	// Regression pin for the live-run defect: select joins filtered NODES to
	// GEO records via scheme|host|port and to probe results via node key —
	// the CLI passes all three sets.
	f := newFixture()
	n := f.add(t, "de", "Berlin", true, 3, 1_000_000, 100)
	f.geo[0].Alive = true
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	require.Len(t, sel.Nodes, 1)
	assert.Equal(t, n.Key, sel.Nodes[0].Key)
	assert.Equal(t, "pool-de-01", sel.Nodes[0].Tag)
}

// TestStaleAliveDataIsNotSelectable pins the geo.ttl wiring: alive flags
// older than the ttl are stale liveness evidence — the node must not enter
// the selection until it is re-probed (review finding 7; W4 pruning extends
// this into physical removal).
func TestStaleAliveDataIsNotSelectable(t *testing.T) {
	f := newFixture()
	fresh := f.add(t, "de", "Berlin", true, 3, 1_000_000, 50)
	f.add(t, "de", "Munich", true, 3, 2_000_000, 60)
	// Stamp the probe ages directly on the cold record.
	f.geo[0].LastProbe = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)      // fresh
	f.geo[1].LastProbe = time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339) // past ttl

	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 24*time.Hour)
	require.Len(t, sel.Nodes, 1, "only the fresh record is selectable")
	assert.Equal(t, fresh.Key, sel.Nodes[0].Key, "the stale-alive Munich node must not enter the selection")

	// ttl 0 = no expiry: both alive records are selectable again.
	sel = rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	assert.Len(t, sel.Nodes, 2, "no ttl: stale alive data is not expired")
}

// TestUnprobedAliveRecordIsStaleUnderTTL: an alive record with no probe
// timestamp carries no fresh liveness evidence — under a ttl it is not
// selectable (only a hand-seeded base can look like this).
func TestUnprobedAliveRecordIsStaleUnderTTL(t *testing.T) {
	f := newFixture()
	f.add(t, "de", "Berlin", true, 3, 1_000_000, 50)
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 24*time.Hour)
	assert.Empty(t, sel.Nodes, "alive without last_probe = no fresh evidence")
}

// TestCityCaseVariantsCountAsOneCity pins the M-b fix on the routing-
// semantics surface: two case variants of one city count as ONE distinct
// city toward D7 — model.CityKey is the distinctness unit for the caps
// arithmetic and the city-diversity tie-break, never the raw spelling.
func TestCityCaseVariantsCountAsOneCity(t *testing.T) {
	f := newFixture()
	f.add(t, "de", "Frankfurt am Main", true, 3, 5_000_000, 100)
	f.add(t, "de", "Frankfurt Am Main", true, 3, 5_000_000, 100)
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	require.Len(t, sel.Nodes, 2, "both variant nodes are alive and within K")
	assert.Equal(t, 1, sel.CitiesAlive, "a case-variant pair is ONE alive city, not two")
}

// TestCapArithmeticFoldsCaseVariants pins the D7 caps arithmetic over a
// variant-pair fixture: 24 distinct cities plus one case-variant pair reach
// the expansion threshold as 25 folded cities (26 raw spellings), the cap
// expands to exactly 25 — not 26 — and the pair competes for ONE slot of
// the expanded cap.
func TestCapArithmeticFoldsCaseVariants(t *testing.T) {
	f := newFixture()
	countries := []string{"us", "fr", "nl", "gb", "jp", "sg", "au", "ca", "br", "pl", "se", "ch", "at", "es", "it", "fi", "dk", "no", "ie", "be", "cz", "pt", "gr", "hu"}
	for i, cc := range countries {
		f.add(t, cc, fmt.Sprintf("City%02d", i), true, 3, int64(9_000_000-i*1000), 100)
	}
	f.add(t, "de", "Frankfurt am Main", true, 3, 1_000_000, 100) // variant pair ranks last:
	f.add(t, "de", "Frankfurt Am Main", true, 3, 1_000_000, 100) // they compete for one slot
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	assert.Equal(t, 25, sel.CitiesAlive, "26 raw city spellings fold to 25 distinct cities")
	assert.Equal(t, 25, sel.CapApplied, "the expansion triggers on the folded count: 25, not 26")
	assert.Len(t, sel.Nodes, 25, "the variant pair fills ONE slot of the expanded cap")
}

// TestCityDiversityTieBreakFoldsCaseVariants pins the tie-break half of the
// fold: within a metric tie-band the unrepresented-city preference counts
// DISTINCT cities through the folded key — a case-variant pair of one city
// does not burn both K slots on the same real city.
func TestCityDiversityTieBreakFoldsCaseVariants(t *testing.T) {
	f := newFixture()
	f.add(t, "de", "Frankfurt am Main", true, 3, 5_000_000, 100)
	f.add(t, "de", "Frankfurt Am Main", true, 3, 5_000_000, 100) // same real city as node 1
	f.add(t, "de", "Munich", true, 3, 5_000_000, 100)
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(2), 0)
	require.Len(t, sel.Nodes, 2)
	cities := map[string]bool{}
	for _, sn := range sel.Nodes {
		cities[model.CityKey(sn.City)] = true
	}
	assert.Len(t, cities, 2,
		"K=2 must cover two DISTINCT cities: the variant pair must not consume both slots")
}

// --- W19: unbounded selection (owner order «259 живых, значит 259
// раскидываются по балансирам стран и городов») — absent/0 = ALL alive nodes
// go active; an explicit positive number stays a cap. ---

// TestUnboundedByDefault pins the W19 flip: a zero-value SelectConfig selects
// EVERY alive candidate — no soft cap, no ceiling, no K, unknown group
// included. CapApplied equals the alive count (the bound actually applied).
func TestUnboundedByDefault(t *testing.T) {
	f := newFixture()
	for i := range 50 {
		f.add(t, fmt.Sprintf("c%02d", i), fmt.Sprintf("City%02d", i), true, 3, 1_000_000, 100)
	}
	f.add(t, "", "", true, 3, 1_000_000, 100) // unknown-geo: admitted (W16)
	sel := rank.Select(f.nodes, f.geo, f.probe, config.SelectConfig{}, 0)
	require.Len(t, sel.Nodes, 51, "zero config = ALL alive nodes go active (owner W19)")
	assert.Equal(t, 51, sel.CapApplied, "cap applied = the alive count when unbounded")
	assert.Equal(t, 50, sel.CitiesAlive, "the unknown-geo node carries no city (W16 semantics)")
}

// TestPerCountryCapAbsentMeansUnlimited pins the K flip: absent per_country_cap
// never trims a country; an explicit K still caps it (old D7 semantics on an
// explicit knob).
func TestPerCountryCapAbsentMeansUnlimited(t *testing.T) {
	f := newFixture()
	for i := range 10 {
		f.add(t, "de", fmt.Sprintf("City%02d", i), true, 3, 1_000_000, 100)
		f.add(t, "fr", fmt.Sprintf("Ville%02d", i), true, 3, 1_000_000, 100)
		f.add(t, "nl", fmt.Sprintf("Stad%02d", i), true, 3, 1_000_000, 100)
	}
	sel := rank.Select(f.nodes, f.geo, f.probe, config.SelectConfig{}, 0)
	require.Len(t, sel.Nodes, 30, "no K: every alive node of every country lands in the render")

	sel = rank.Select(f.nodes, f.geo, f.probe, config.SelectConfig{PerCountryCap: 3}, 0)
	require.Len(t, sel.Nodes, 9, "explicit K=3 still caps each country at 3")
}

// TestSoftCapUnboundedWhenAbsent pins the global-cap flip: absent soft_cap
// never binds regardless of pool size; an explicit soft_cap still caps (and
// the city-expansion machinery keeps its old D7 semantics on explicit knobs).
func TestSoftCapUnboundedWhenAbsent(t *testing.T) {
	f := newFixture()
	for i := range 300 {
		f.add(t, fmt.Sprintf("c%02d", i%40), fmt.Sprintf("City%03d", i), true, 3, 1_000_000, 100)
	}
	sel := rank.Select(f.nodes, f.geo, f.probe, config.SelectConfig{}, 0)
	require.Len(t, sel.Nodes, 300, "absent soft_cap: 300 alive → 300 active (D7 expansion moot when unbounded)")

	// Explicit caps on the same 300-city fixture: the threshold 301 never
	// fires, so the explicit soft cap binds exactly (D7 intact on explicit
	// knobs).
	sel = rank.Select(f.nodes, f.geo, f.probe, config.SelectConfig{SoftCap: 25, CityExpandThreshold: 301, Ceiling: 40}, 0)
	assert.Len(t, sel.Nodes, 25, "explicit soft cap still caps when city diversity is below the threshold")
}

// TestCityExpansionNeedsExplicitThreshold pins the sub-flip: with an explicit
// soft_cap but an ABSENT city_expand_threshold, no expansion happens (0 =
// the feature is off — absent imposes no constraint, and expansion is one).
// An explicit threshold expands the cap, bounded by the ceiling only when
// the ceiling is itself present.
func TestCityExpansionNeedsExplicitThreshold(t *testing.T) {
	f := newFixture()
	for i := range 12 {
		f.add(t, fmt.Sprintf("c%02d", i), fmt.Sprintf("City%02d", i), true, 3, 1_000_000, 100)
	}
	sel := rank.Select(f.nodes, f.geo, f.probe, config.SelectConfig{SoftCap: 5}, 0)
	require.Len(t, sel.Nodes, 5, "soft cap without a threshold never expands")

	sel = rank.Select(f.nodes, f.geo, f.probe, config.SelectConfig{SoftCap: 5, CityExpandThreshold: 3}, 0)
	assert.Len(t, sel.Nodes, 12, "explicit threshold expands to city diversity; absent ceiling = bounded only by alive count")

	sel = rank.Select(f.nodes, f.geo, f.probe, config.SelectConfig{SoftCap: 5, CityExpandThreshold: 3, Ceiling: 8}, 0)
	assert.Len(t, sel.Nodes, 8, "explicit ceiling still bounds the expansion (D7 intact)")
}

// TestUnboundedFastPathPreservesRankOrder pins the O(N log N) guarantee of
// the unbounded path: the selection is exactly the candidates in the primary
// sort order (checks desc, speed desc, rtt asc, key asc) — the greedy loop is
// bypassed, tags follow the same stable per-country NN scheme.
func TestUnboundedFastPathPreservesRankOrder(t *testing.T) {
	f := newFixture()
	a := f.add(t, "de", "Slow", true, 3, 1_000_000, 400)
	b := f.add(t, "de", "Fast", true, 3, 9_000_000, 50)
	sel := rank.Select(f.nodes, f.geo, f.probe, config.SelectConfig{}, 0)
	require.Len(t, sel.Nodes, 2)
	assert.Equal(t, b.Key, sel.Nodes[0].Key, "speed ranks first")
	assert.Equal(t, a.Key, sel.Nodes[1].Key)
	assert.Equal(t, "pool-de-01", sel.Nodes[0].Tag, "stable NN sequence survives the fast path")
	assert.Equal(t, "pool-de-02", sel.Nodes[1].Tag)
}

// TestOwnProbeFailureNeverRidesSharedIdentity pins the W19 liveness gate:
// one geo identity (scheme+host+port) can carry MULTIPLE link-variant node
// records (parse keeps distinct param sets), and the geo record is PER
// IDENTITY — a variant whose OWN latest probe failed (e.g. an extra=null
// link the renderer refuses: the live 16:04-wave case) must never ride the
// sibling's alive geo record into the selection. Under the old caps the dead
// variant ranked last and the cap hid it; unbounded, it would reach the
// renderer and fail the whole wave loud (L9).
func TestOwnProbeFailureNeverRidesSharedIdentity(t *testing.T) {
	f := newFixture()
	// Three records, ONE identity: same scheme/host/port, different uuids.
	good1 := model.NewNode("s", "vless", "11111111-1111-1111-1111-111111111111", "shared.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	good2 := model.NewNode("s", "vless", "22222222-2222-2222-2222-222222222222", "shared.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	dead := model.NewNode("s", "vless", "33333333-3333-3333-3333-333333333333", "shared.example.com", 443,
		map[string]string{"security": "tls", "type": "xhttp", "extra": "null"})
	f.nodes = append(f.nodes, good1, good2, dead)
	// ONE alive geo record for the shared identity (the store's real shape).
	f.geo = append(f.geo, &model.GeoRecord{
		Source: "s", Scheme: "vless", Host: "shared.example.com", Port: 443,
		Country: "nl", City: "Eygelshoven", Alive: true, RTTMs: 430, SpeedBPS: 300_000,
	})
	f.probe[good1.Key] = store.ProbeResult{Key: good1.Key, Alive: true, Checks: 3, TotalChecks: 3}
	f.probe[good2.Key] = store.ProbeResult{Key: good2.Key, Alive: true, Checks: 3, TotalChecks: 3}
	f.probe[dead.Key] = store.ProbeResult{Key: dead.Key, Alive: false, Checks: 0, TotalChecks: 3}

	sel := rank.Select(f.nodes, f.geo, f.probe, config.SelectConfig{}, 0)
	require.Len(t, sel.Nodes, 2, "the failed variant must not ride the shared identity's alive geo record")
	for _, sn := range sel.Nodes {
		assert.NotEqual(t, dead.Key, sn.Key, "a node whose own probe failed is never selectable")
	}
}

// TestProbeAllowsOwnProbeBranches pins F7 (owner ruling 2026-11-04: KEEP
// the knownAlive escape) at all three own-probe branches of probeAllows:
// the node's geo record says alive, the OWN latest probe decides.
//   - own probe alive → admitted;
//   - own probe dead + a known-alive record → admitted (anti-flake for
//     temp-xray boots; the in-client observatory is the second dead-node
//     layer);
//   - own probe dead + no known-alive record → rejected (fail-closed).
func TestProbeAllowsOwnProbeBranches(t *testing.T) {
	f := newFixture()
	live := f.add(t, "de", "Berlin", true, 3, 1_000_000, 100)
	escape := f.add(t, "de", "Munich", true, 3, 1_000_000, 100)
	dropped := f.add(t, "de", "Hamburg", true, 3, 1_000_000, 100)
	// All three geo records say alive; the OWN latest probes decide.
	f.probe[live.Key] = store.ProbeResult{Key: live.Key, Alive: true, Checks: 3, TotalChecks: 3}
	f.probe[escape.Key] = store.ProbeResult{Key: escape.Key, Alive: false, Checks: 0, TotalChecks: 3}
	f.probe[dropped.Key] = store.ProbeResult{Key: dropped.Key, Alive: false, Checks: 0, TotalChecks: 3}

	ka := map[string]store.KnownAliveRecord{
		escape.Key: {Key: escape.Key, Host: escape.Host, LastSeen: time.Now().UTC()},
	}
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(5), 0, ka)
	active := map[string]bool{}
	for _, sn := range sel.Nodes {
		active[sn.Key] = true
	}
	assert.True(t, active[live.Key], "own probe alive → admitted")
	assert.True(t, active[escape.Key],
		"own probe dead + known-alive record → admitted (the owner-ruled anti-flake escape)")
	assert.False(t, active[dropped.Key],
		"own probe dead + no known-alive record → rejected (fail-closed)")
}

// TestSharedGeoRecordMutationIsolation pins WP-2.1:
// Two candidates share an identical GeoRecord pointer with Alive=false.
// Candidate A has a knownAlive record (or is verified alive), while Candidate B has no knownAlive and no probe success.
// Evaluating/admitting candidate A must NOT mutate the shared *model.GeoRecord in a way that falsely
// marks candidate B as alive. Candidate A must be selected and candidate B must be filtered out.
func TestSharedGeoRecordMutationIsolation(t *testing.T) {
	nodeA := model.NewNode("s", "vless", "uuid-a", "shared-host.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	nodeB := model.NewNode("s", "vless", "uuid-b", "shared-host.example.com", 443,
		map[string]string{"security": "tls", "type": "ws"})

	sharedGeo := &model.GeoRecord{
		Source:  "s",
		Scheme:  "vless",
		Host:    "shared-host.example.com",
		Port:    443,
		Country: "de",
		City:    "Frankfurt",
		Alive:   false, // Initially not alive in cold base
	}

	nodes := []*model.Node{nodeA, nodeB}
	geo := []*model.GeoRecord{sharedGeo}

	// Candidate A is known alive, Candidate B is not.
	ka := map[string]store.KnownAliveRecord{
		nodeA.Key: {
			Key:      nodeA.Key,
			Host:     nodeA.Host,
			LastSeen: time.Now().UTC(),
		},
	}

	sel := rank.Select(nodes, geo, nil, config.SelectConfig{}, 0, ka)
	require.Len(t, sel.Nodes, 1, "only candidate A should be admitted; candidate B must not ride candidate A's knownAlive mutation")
	assert.Equal(t, nodeA.Key, sel.Nodes[0].Key, "candidate A must be selected")
	assert.False(t, sharedGeo.Alive, "original input GeoRecord must not be mutated in-place by Select")
}

// TestProbeAllowsFailClosedOnUnprobedWhenProbesActive pins WP-2.2:
// When probeByKey is non-empty (probes ran for this wave), unprobed nodes whose keys are
// absent from probeByKey MUST fail-closed: return true ONLY if ka[n.Key] exists.
// If absent from probeByKey AND absent from ka, the unprobed node MUST be rejected.
// When probeByKey is nil or empty, cold base / bootstrap behavior is preserved.
func TestProbeAllowsFailClosedOnUnprobedWhenProbesActive(t *testing.T) {
	nodeProbedAlive := model.NewNode("s", "vless", "uuid-probed-alive", "probed-alive.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	nodeUnprobed := model.NewNode("s", "vless", "uuid-unprobed", "unprobed.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	nodeUnprobedKnownAlive := model.NewNode("s", "vless", "uuid-unprobed-ka", "unprobed-ka.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})

	geoProbedAlive := &model.GeoRecord{
		Source:  "s",
		Scheme:  "vless",
		Host:    "probed-alive.example.com",
		Port:    443,
		Country: "de",
		City:    "Berlin",
		Alive:   true,
	}
	geoUnprobed := &model.GeoRecord{
		Source:  "s",
		Scheme:  "vless",
		Host:    "unprobed.example.com",
		Port:    443,
		Country: "nl",
		City:    "Amsterdam",
		Alive:   true,
	}
	geoUnprobedKA := &model.GeoRecord{
		Source:  "s",
		Scheme:  "vless",
		Host:    "unprobed-ka.example.com",
		Port:    443,
		Country: "fr",
		City:    "Paris",
		Alive:   true,
	}

	nodes := []*model.Node{nodeProbedAlive, nodeUnprobed, nodeUnprobedKnownAlive}
	geo := []*model.GeoRecord{geoProbedAlive, geoUnprobed, geoUnprobedKA}

	// Active wave with at least one probe result
	probeByKey := map[string]store.ProbeResult{
		nodeProbedAlive.Key: {
			Key:         nodeProbedAlive.Key,
			Alive:       true,
			Checks:      3,
			TotalChecks: 3,
		},
	}

	// knownAlive contains only nodeUnprobedKnownAlive
	ka := map[string]store.KnownAliveRecord{
		nodeUnprobedKnownAlive.Key: {
			Key:      nodeUnprobedKnownAlive.Key,
			Host:     nodeUnprobedKnownAlive.Host,
			LastSeen: time.Now().UTC(),
		},
	}

	// 1. When probes ran (probeByKey non-empty):
	// - nodeProbedAlive is admitted (pr.Alive == true)
	// - nodeUnprobedKnownAlive is admitted (absent from probeByKey, but present in ka)
	// - nodeUnprobed MUST be rejected (absent from probeByKey, absent from ka -> fail-closed)
	selActive := rank.Select(nodes, geo, probeByKey, config.SelectConfig{}, 0, ka)
	require.Len(t, selActive.Nodes, 2, "unprobed node absent from ka must be rejected in active wave")
	keysActive := map[string]bool{}
	for _, sn := range selActive.Nodes {
		keysActive[sn.Key] = true
	}
	assert.True(t, keysActive[nodeProbedAlive.Key], "probed alive node must be selected")
	assert.True(t, keysActive[nodeUnprobedKnownAlive.Key], "unprobed node with fresh knownAlive record must be admitted")
	assert.False(t, keysActive[nodeUnprobed.Key], "unprobed node without probe or knownAlive must be rejected (fail-closed)")

	// 2. When probeByKey is nil (bootstrap / cold base):
	// All nodes with alive geo records can be admitted
	selBootstrapNil := rank.Select(nodes, geo, nil, config.SelectConfig{}, 0, ka)
	assert.Len(t, selBootstrapNil.Nodes, 3, "bootstrap path with nil probeByKey preserves admission for valid geo nodes")

	// 3. When probeByKey is empty map (bootstrap / cold base):
	selBootstrapEmpty := rank.Select(nodes, geo, map[string]store.ProbeResult{}, config.SelectConfig{}, 0, ka)
	assert.Len(t, selBootstrapEmpty.Nodes, 3, "bootstrap path with empty probeByKey preserves admission for valid geo nodes")
}

// TestHijackExitIsExcludedFromSelection pins the owner-ordered safety cut
// (2026-11-07): a selection candidate whose OWN geo evidence carries
// MediaUnlocks.Hijack=true is excluded from selection entirely — not
// selected (absent from Selection.Nodes, so never rendered into any
// pool/balancer/outbound) even with the best metrics in the wave — and the
// exclusion is counted loud (Selection.HijackExcluded), never silent. The
// geo record itself stays in the cold base: the cut is selection-level
// only (classification history / dashboard visibility preserved).
func TestHijackExitIsExcludedFromSelection(t *testing.T) {
	f := newFixture()
	f.add(t, "nl", "Amsterdam", true, 3, 5_000_000, 50)
	hijack := f.add(t, "us", "Ashburn", true, 3, 9_000_000, 20) // best checks+speed: must still drop
	f.geo[len(f.geo)-1].MediaUnlocks = model.MediaUnlockStatus{
		ChatGPT: model.UnlockBlocked, Hijack: true, Rotating: true, BatteryVersion: 2,
	}

	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(5), 0)
	require.Len(t, sel.Nodes, 1, "the hijack exit is excluded despite the best metrics")
	for _, sn := range sel.Nodes {
		assert.NotEqual(t, hijack.Key, sn.Key, "a TLS-intercepting exit is never selectable")
	}
	assert.Equal(t, "Amsterdam", sel.Nodes[0].City, "the clean candidate keeps its slot")
	assert.Equal(t, 1, sel.HijackExcluded, "the exclusion is counted, not silent")
}

// TestHijackGateFailsClosedOnPositiveEvidenceOnly pins the fail-closed
// semantics (absence of evidence is not hijack): a candidate whose geo
// record carries no unlock verdicts at all (never unlock-probed —
// MediaUnlocks zero value) passes the gate, and so does a record that was
// checked with Hijack=false. The W16 unknown-geo admission (empty country,
// zero MediaUnlocks) is the same fail-closed shape. A node with NO geo
// record at all never reaches this gate — the pre-existing identity-join
// admission boundary is untouched.
func TestHijackGateFailsClosedOnPositiveEvidenceOnly(t *testing.T) {
	f := newFixture()
	noEvidence := f.add(t, "de", "Berlin", true, 3, 1_000_000, 100) // MediaUnlocks zero value
	unknownGeo := f.add(t, "", "", true, 3, 1_000_000, 100)         // W16: no country, no verdicts
	hijackFalse := f.add(t, "de", "Munich", true, 3, 1_000_000, 100)
	f.geo[len(f.geo)-1].MediaUnlocks = model.MediaUnlockStatus{
		ChatGPT: model.UnlockYes, BatteryVersion: 2, // checked; Hijack stays false
	}

	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(5), 0)
	require.Len(t, sel.Nodes, 3, "absence of hijack evidence never drops a candidate")
	active := map[string]bool{}
	for _, sn := range sel.Nodes {
		active[sn.Key] = true
	}
	assert.True(t, active[noEvidence.Key], "no unlock evidence at all → passes (not hijack)")
	assert.True(t, active[unknownGeo.Key], "unknown-geo candidate without verdicts → passes (W16 intact)")
	assert.True(t, active[hijackFalse.Key], "checked with hijack=false → passes")
	assert.Equal(t, 0, sel.HijackExcluded)
}

// TestMixedWaveHijackExcludedCleanSelected pins the wave-level contract:
// in a mixed wave the clean candidate is selected while the hijack
// candidate is counted and excluded; the exclusion happens at candidate
// admission (per-candidate evidence gate, joined to probeAllows), so it
// composes with explicit caps — the hijack node consumes no per-country
// slot and the clean node takes it.
func TestMixedWaveHijackExcludedCleanSelected(t *testing.T) {
	f := newFixture()
	cleanUS := f.add(t, "us", "Ashburn", true, 3, 5_000_000, 50)
	hijackUS := f.add(t, "us", "Dallas", true, 3, 5_000_000, 60)
	f.geo[len(f.geo)-1].MediaUnlocks = model.MediaUnlockStatus{Hijack: true, BatteryVersion: 2}
	f.add(t, "nl", "Amsterdam", true, 2, 1_000_000, 200)

	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(1), 0) // explicit K=1 per country
	require.Len(t, sel.Nodes, 2, "one per country: the clean US node survives, the hijack US node is gone")
	active := map[string]bool{}
	for _, sn := range sel.Nodes {
		active[sn.Key] = true
	}
	assert.True(t, active[cleanUS.Key], "the clean candidate is selected")
	assert.False(t, active[hijackUS.Key], "the hijack candidate is excluded")
	assert.Equal(t, 1, sel.HijackExcluded, "the hijack drop is counted even under an explicit cap")
	assert.Equal(t, "pool-us-01", sel.Nodes[0].Tag, "the clean node takes the US slot (stable tag sequence intact)")
}
