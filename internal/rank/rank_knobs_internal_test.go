package rank

import (
	"os"
	"path/filepath"
	"testing"

	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bandNode builds one candidate's node+geo pair with a fixed RTT.
func bandNode(t *testing.T, host string, rtt float64, city string) (*model.Node, *model.GeoRecord) {
	t.Helper()
	n := model.NewNode("s", "vless", "uuid-"+host, host, 443, map[string]string{"security": "tls", "type": "tcp"})
	g := &model.GeoRecord{
		Scheme: "vless", Host: host, Port: 443, Country: "de", City: city,
		Alive: true, RTTMs: rtt, LastProbe: "2026-10-28T00:00:00Z",
	}
	return n, g
}

// TestSameBandToleranceIsTheKnob pins [select].tie_band_rtt_tolerance at the
// consumption site: the band boundary is head·tolerance — 1.2 (default)
// admits 110 against a 100 head but not 130; 1.4 admits 130 too.
func TestSameBandToleranceIsTheKnob(t *testing.T) {
	head := candidate{rec: &model.GeoRecord{RTTMs: 100}}
	near := candidate{rec: &model.GeoRecord{RTTMs: 110}}
	far := candidate{rec: &model.GeoRecord{RTTMs: 130}}

	assert.True(t, sameBand(head, near, config.DefaultTieBandRTTTolerance), "110 ≤ 100·1.2: same band")
	assert.False(t, sameBand(head, far, config.DefaultTieBandRTTTolerance), "130 > 100·1.2: outside the default band")
	assert.True(t, sameBand(head, far, 1.4), "130 ≤ 100·1.4: a wider knob widens the band")
	assert.True(t, sameBand(head, near, 100.0), "unbounded per owner ruling — a huge tolerance is legal")
}

// TestSelectZeroToleranceFallsBackToDefault pins the normalization: a zero
// (unset) TieBandRTTTolerance behaves exactly like the 1.2 default.
func TestSelectZeroToleranceFallsBackToDefault(t *testing.T) {
	nodes := make([]*model.Node, 0, 3)
	geo := make([]*model.GeoRecord, 0, 3)
	for _, h := range []string{"a", "b", "c"} {
		n, g := bandNode(t, h, 100, "")
		nodes, geo = append(nodes, n), append(geo, g)
	}
	sel := Select(nodes, geo, map[string]store.ProbeResult{}, config.SelectConfig{
		PerCountryCap: 3, SoftCap: 3, Ceiling: 3,
		TieBandRTTTolerance: 0,
	}, 0)
	require.Len(t, sel.Nodes, 3)
}

// TestSameBandZeroChecksMatches pins the rtt<=0 head case surviving the knob
// plumbing: an unmeasured head (rtt 0) bands with everything.
func TestSameBandZeroChecksMatches(t *testing.T) {
	head := candidate{rec: &model.GeoRecord{RTTMs: 0}}
	other := candidate{rec: &model.GeoRecord{RTTMs: 999}}
	assert.True(t, sameBand(head, other, 1.2))
}

// Guard: the stats inner fallback guard must reference the ONE knob default
// (config.DefaultStatsTimeout) — the old hardcoded 5s/10s inconsistency class
// is structurally banned (same pattern as the no-systemctl guard).
func TestStatsGuardReferencesTheKnobDefault(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "stats", "stats.go"))
	require.NoError(t, err)
	assert.NotContains(t, string(src), "5 * time.Second",
		"the old 5s fallback literal must be gone")
	assert.Contains(t, string(src), "config.DefaultStatsTimeout",
		"the inner guard must reference the [maintain].stats_timeout default")
}
