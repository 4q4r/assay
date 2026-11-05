package plugins

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// idSet builds an identity set from a literal list.
func idSet(keys ...string) map[string]bool {
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out
}

// TestComputeOverlapMatrix pins the pairwise model: overlap(A→B) is the share
// of A's DISTINCT identities that B also carries; the diagonal is always 100
// (a plugin trivially contains itself); empty sets never divide by zero.
func TestComputeOverlapMatrix(t *testing.T) {
	identities := map[string]map[string]bool{
		"matin": idSet("vless|a.com|443", "vless|b.com|443", "vless|c.com|443", "vless|d.com|443", "vless|e.com|443"),
		"mhd":   idSet("vless|a.com|443"),
		"solo":  idSet("vless|z.com|443"),
		"void":  idSet(),
	}

	m := ComputeOverlapMatrix(identities)

	assert.Equal(t, map[string]int{"matin": 5, "mhd": 1, "solo": 1, "void": 0}, m.Sets,
		"sets count DISTINCT identities (dedupe within plugin)")
	assert.InDelta(t, 20.0, m.Cells["matin"]["mhd"], 1e-9, "1/5 of matin's identities live in mhd")
	assert.InDelta(t, 100.0, m.Cells["mhd"]["matin"], 1e-9, "mhd's only identity is shared → 100%")
	assert.InDelta(t, 0.0, m.Cells["matin"]["solo"], 1e-9, "disjoint pairs overlap zero")
	assert.InDelta(t, 0.0, m.Cells["solo"]["matin"], 1e-9)
	assert.InDelta(t, 100.0, m.Cells["matin"]["matin"], 1e-9, "diagonal is trivially 100")
	assert.InDelta(t, 0.0, m.Cells["void"]["matin"], 1e-9, "empty set never divides by zero")
	assert.Len(t, m.Cells, 4, "every plugin gets a row")
}

// TestComputeOverlapMatrixAsymmetric pins the directionality: overlap is
// |A∩B|/|A|, so a big plugin swallowed by a bigger one reads 100% forward and
// a small fraction backward.
func TestComputeOverlapMatrixAsymmetric(t *testing.T) {
	big := idSet("h1", "h2", "h3", "h4")
	small := idSet("h1")
	m := ComputeOverlapMatrix(map[string]map[string]bool{"big": big, "small": small})
	assert.InDelta(t, 25.0, m.Cells["big"]["small"], 1e-9)
	assert.InDelta(t, 100.0, m.Cells["small"]["big"], 1e-9)
}

// TestApplyOverlapUniqueYieldAndTopPartners pins UniqueYield and the top-2
// overlap-partner selection with deterministic tie-breaking.
func TestApplyOverlapUniqueYieldAndTopPartners(t *testing.T) {
	collector := NewPluginStatsCollector(nil)
	collector.Stats["matin"] = &PluginStats{PluginID: "matin"}
	collector.Stats["mhd"] = &PluginStats{PluginID: "mhd"}
	collector.Stats["solo"] = &PluginStats{PluginID: "solo"}
	collector.Stats["twin"] = &PluginStats{PluginID: "twin"}

	identities := map[string]map[string]bool{
		// matin: 4 unique + 1 shared with mhd + 1 shared with twin → 2/6 unique.
		"matin": idSet("m1", "m2", "m3", "m4", "shared-mhd", "shared-twin"),
		// mhd: 1 unique + the shared one → 1/2 unique.
		"mhd": idSet("h1", "shared-mhd"),
		// twin: shares everything with matin → 0 unique of 1.
		"twin": idSet("shared-twin"),
		// solo: fully unique → 100%.
		"solo": idSet("s1", "s2"),
	}
	m := ComputeOverlapMatrix(identities)
	collector.ApplyOverlap(m, identities)

	matin := collector.Stats["matin"]
	require.NotNil(t, matin)
	assert.InDelta(t, 66.667, matin.UniqueYield, 0.01, "4/6 identities are unique")
	require.Len(t, matin.TopOverlaps, 2, "top-2 partners surface")
	// Overlaps: mhd 1/6≈16.7%, twin 1/6≈16.7% — tie broken by plugin id asc.
	assert.Equal(t, "mhd", matin.TopOverlaps[0].PluginID)
	assert.Equal(t, "twin", matin.TopOverlaps[1].PluginID)

	mhd := collector.Stats["mhd"]
	assert.InDelta(t, 50.0, mhd.UniqueYield, 1e-9, "1/2 unique")
	require.Len(t, mhd.TopOverlaps, 1)
	assert.Equal(t, "matin", mhd.TopOverlaps[0].PluginID)
	assert.InDelta(t, 50.0, mhd.TopOverlaps[0].Percent, 1e-9)

	twin := collector.Stats["twin"]
	assert.InDelta(t, 0.0, twin.UniqueYield, 1e-9, "twin adds nothing unique")
	require.Len(t, twin.TopOverlaps, 1)
	assert.InDelta(t, 100.0, twin.TopOverlaps[0].Percent, 1e-9)

	solo := collector.Stats["solo"]
	assert.InDelta(t, 100.0, solo.UniqueYield, 1e-9, "fully unique provider")
	assert.Empty(t, solo.TopOverlaps, "no partners → no overlap list")
}

// TestApplyOverlapWithMoreThanTwoPartners pins the top-2 truncation and the
// descending-percent ordering.
func TestApplyOverlapWithMoreThanTwoPartners(t *testing.T) {
	collector := NewPluginStatsCollector(nil)
	collector.Stats["main"] = &PluginStats{PluginID: "main"}

	identities := map[string]map[string]bool{
		"main": idSet("a", "b", "c", "d", "e", "f", "g", "h", "i", "j"),
		// Overlaps with main: 60%, 30%, 10% (tie-broken by id when equal).
		"alpha": idSet("a", "b", "c", "d", "e", "f"),
		"beta":  idSet("a", "b", "c"),
		"gamma": idSet("a"),
		"delta": idSet("a"),
	}
	m := ComputeOverlapMatrix(identities)
	collector.ApplyOverlap(m, identities)

	main := collector.Stats["main"]
	require.Len(t, main.TopOverlaps, 2)
	assert.Equal(t, "alpha", main.TopOverlaps[0].PluginID, "highest overlap first")
	assert.InDelta(t, 60.0, main.TopOverlaps[0].Percent, 1e-9)
	assert.Equal(t, "beta", main.TopOverlaps[1].PluginID)
	assert.InDelta(t, 30.0, main.TopOverlaps[1].Percent, 1e-9)
}

// TestOverlapTieBreakDeterministic pins the plugin-id tie-break so identical
// inputs always produce identical top-2 lists.
func TestOverlapTieBreakDeterministic(t *testing.T) {
	run := func() []OverlapPair {
		collector := NewPluginStatsCollector(nil)
		collector.Stats["main"] = &PluginStats{PluginID: "main"}
		identities := map[string]map[string]bool{
			"main": idSet("a", "b", "c", "d"),
			"zzz":  idSet("a", "b"),
			"aaa":  idSet("a", "b"),
			"mmm":  idSet("a", "b"),
		}
		m := ComputeOverlapMatrix(identities)
		collector.ApplyOverlap(m, identities)
		return collector.Stats["main"].TopOverlaps
	}
	first := run()
	require.Len(t, first, 2)
	assert.Equal(t, "aaa", first[0].PluginID)
	assert.Equal(t, "mmm", first[1].PluginID)
	for range 20 {
		assert.Equal(t, first, run(), "tie-break is deterministic across runs")
	}
}
