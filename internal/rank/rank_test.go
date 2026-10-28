package rank_test

import (
	"fmt"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/rank"
	"public_vpn/internal/store"

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

func TestNodeWithoutCountryIsExcluded(t *testing.T) {
	f := newFixture()
	f.add(t, "", "Nowhere", true, 3, 1_000_000, 100)
	sel := rank.Select(f.nodes, f.geo, f.probe, cfg(3), 0)
	assert.Empty(t, sel.Nodes, "no country = no pool-<cc> tag possible = excluded")
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
