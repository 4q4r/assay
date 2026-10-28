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
