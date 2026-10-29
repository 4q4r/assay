package checker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func mkRow(tag, cc, city string, verdicts ...Verdict) *NodeResult {
	r := &NodeResult{Tag: tag, Country: cc, City: city}
	for _, v := range verdicts {
		r.Attempts = append(r.Attempts, Attempt{Verdict: v, TotalMS: 100, SpeedBPS: 1000})
	}
	r.Aggregate()
	return r
}

func TestAggregateNodeVerdicts(t *testing.T) {
	t.Parallel()
	require.Equal(t, VerdictSuccess, mkRow("a", "DE", "", VerdictSuccess, VerdictSuccess, VerdictSuccess).Verdict)
	require.Equal(t, VerdictPartial, mkRow("b", "DE", "", VerdictSuccess, VerdictBlockedHTTP, VerdictSuccess).Verdict)
	require.Equal(t, VerdictBlocked, mkRow("c", "DE", "", VerdictBlockedHTTP, VerdictBlockedHTTP, VerdictBlockedHTTP).Verdict)
	require.Equal(t, VerdictFail, mkRow("d", "DE", "", VerdictDialFail, VerdictTimeout, VerdictDNSFail).Verdict)
	r := &NodeResult{Tag: "e", InstanceFailed: true}
	r.Aggregate()
	require.Equal(t, VerdictError, r.Verdict)
}

func TestAggregateNumbers(t *testing.T) {
	t.Parallel()
	r := &NodeResult{Tag: "n", Country: "NL"}
	for i, ms := range []float64{100, 200, 300} {
		r.Attempts = append(r.Attempts, Attempt{
			Verdict: VerdictSuccess, Status: 200, TotalMS: ms,
			ConnectMS: 10, TTFBMS: float64(20 * (i + 1)), Bytes: 1000, SpeedBPS: float64(100 * (i + 1)),
		})
	}
	r.Attempts = append(r.Attempts, Attempt{Verdict: VerdictBlockedHTTP, Status: 403})
	r.Aggregate()
	require.Equal(t, 3, r.OK)
	require.Equal(t, 4, r.Total)
	require.Equal(t, []int{200, 403}, r.Statuses)
	require.InDelta(t, 200.0, r.AvgMS, 0.001)
	require.InDelta(t, 200.0, r.MedianTotalMS, 0.001)
	require.InDelta(t, 40.0, r.AvgTTFBMS, 0.001)
	require.InDelta(t, 200.0, r.AvgSpeedBPS, 0.001)
}

func TestMedian(t *testing.T) {
	t.Parallel()
	require.InDelta(t, 0.0, Median(nil), 0.001)
	require.InDelta(t, 5.0, Median([]float64{5}), 0.001)
	require.InDelta(t, 2.0, Median([]float64{3, 1, 2}), 0.001)
	require.InDelta(t, 2.5, Median([]float64{4, 1, 3, 2}), 0.001)
}

func TestGroupAndRank(t *testing.T) {
	t.Parallel()
	rows := []*NodeResult{
		mkRow("nl-01", "NL", "Amsterdam", VerdictSuccess, VerdictSuccess),
		mkRow("nl-02", "NL", "Rotterdam", VerdictSuccess, VerdictBlockedHTTP),
		mkRow("de-01", "DE", "Frankfurt", VerdictBlockedHTTP, VerdictBlockedHTTP),
		mkRow("us-01", "US", "Dallas", VerdictSuccess, VerdictSuccess),
	}
	countries := GroupByCountry(rows)
	require.Len(t, countries, 3)
	byCC := map[string]GroupStat{}
	for _, g := range countries {
		byCC[g.Country] = g
	}
	require.InDelta(t, 0.75, byCC["NL"].SuccessRate, 0.0001)
	require.InDelta(t, 0.0, byCC["DE"].SuccessRate, 0.0001)
	require.InDelta(t, 1.0, byCC["US"].SuccessRate, 0.0001)

	ranked := RankGroups(countries)
	require.Equal(t, "US", ranked[0].Country, "full success outranks partial")
	require.Equal(t, "NL", ranked[1].Country, "partial success second")
	require.Equal(t, "DE", ranked[2].Country, "no success last")

	// Ties on success rate break by median ms (lower first), then speed.
	fast := &NodeResult{Tag: "f", Country: "FR", Attempts: []Attempt{{Verdict: VerdictSuccess, TotalMS: 50}}}
	slow := &NodeResult{Tag: "s", Country: "JP", Attempts: []Attempt{{Verdict: VerdictSuccess, TotalMS: 900}}}
	fast.Aggregate()
	slow.Aggregate()
	two := RankGroups(GroupByCountry([]*NodeResult{slow, fast}))
	require.Equal(t, "FR", two[0].Country)
	require.Equal(t, "JP", two[1].Country)
}

func TestGroupByCity(t *testing.T) {
	t.Parallel()
	rows := []*NodeResult{
		mkRow("nl-01", "NL", "Amsterdam", VerdictSuccess, VerdictSuccess),
		mkRow("nl-02", "NL", "Amsterdam", VerdictSuccess, VerdictSuccess),
		mkRow("nl-03", "NL", "Rotterdam", VerdictBlockedHTTP),
	}
	cities := GroupByCity(rows)
	require.Len(t, cities, 2)
	require.Equal(t, "Amsterdam", cities[0].City, "equal success rates break by median ms")
	require.InDelta(t, 1.0, cities[0].SuccessRate, 0.0001)
	require.Equal(t, "Rotterdam", cities[1].City)
}

// M-b pin: geo sources emit case variants of one city ("Frankfurt am Main"
// vs "Frankfurt Am Main"); the grouping key folds case, the displayed City
// is the deterministic lowest-string variant of the group, and the timing
// buckets fold through the same key (the group median reads BOTH rows).
func TestGroupByCityFoldsCaseVariants(t *testing.T) {
	t.Parallel()
	fra := mkRow("de-01", "de", "Frankfurt am Main", VerdictSuccess, VerdictSuccess)
	fraAlt := mkRow("de-02", "de", "Frankfurt Am Main", VerdictSuccess, VerdictSuccess)
	cities := GroupByCity([]*NodeResult{fra, fraAlt})
	require.Len(t, cities, 1, "case variants of one city group into ONE city")
	require.Equal(t, "Frankfurt Am Main", cities[0].City,
		"display = lowest string variant of the group, deterministic")
	require.Equal(t, 2, cities[0].Nodes, "counts merge across case variants")

	// Order independence: whichever variant arrives first, the displayed
	// spelling is the same lowest-string variant.
	flipped := GroupByCity([]*NodeResult{fraAlt, fra})
	require.Len(t, flipped, 1)
	require.Equal(t, cities[0].City, flipped[0].City, "display is order-independent")

	// fillTimings keys through the folded city too: the bucket's median is
	// over BOTH rows (10ms + 30ms → 20ms), never the 0 of a missed lookup.
	fast := &NodeResult{
		Tag: "de-03", Country: "de", City: "Frankfurt am Main",
		Attempts: []Attempt{{Verdict: VerdictSuccess, TotalMS: 10}},
	}
	fast.Aggregate()
	slow := &NodeResult{
		Tag: "de-04", Country: "de", City: "Frankfurt Am Main",
		Attempts: []Attempt{{Verdict: VerdictSuccess, TotalMS: 30}},
	}
	slow.Aggregate()
	timed := GroupByCity([]*NodeResult{fast, slow})
	require.Len(t, timed, 1)
	require.InDelta(t, 20.0, timed[0].MedianMS, 0.001,
		"group median folds across case variants (median of [10,30])")
}
