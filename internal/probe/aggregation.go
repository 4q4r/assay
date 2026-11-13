package probe

import (
	"sort"
	"time"

	"assay/internal/store"
)

// OutcomeAggregation aggregates a probe wave's outcomes for calibration.
type OutcomeAggregation struct {
	ObservedRTTMs []float64
	TimedOutCount int
}

// Aggregate builds an OutcomeAggregation from probe results.
func Aggregate(results []store.ProbeResult) OutcomeAggregation {
	return AggregateProbeResults(results)
}

// AggregateProbeResults builds an aggregation from probe results.
func AggregateProbeResults(results []store.ProbeResult) OutcomeAggregation {
	agg := OutcomeAggregation{ObservedRTTMs: []float64{}}
	for _, r := range results {
		if r.Alive {
			agg.ObservedRTTMs = append(agg.ObservedRTTMs, r.RTTMs)
		}
		if r.FailureKind == dialClassTimeout {
			agg.TimedOutCount++
		}
	}
	return agg
}

// ProbeSummary is an alias for OutcomeAggregation.
//
//nolint:revive // keep stuttering alias for compatibility with callers
type ProbeSummary = OutcomeAggregation

// Summary is an alias for OutcomeAggregation.
type Summary = OutcomeAggregation

// CalibratedTimeout computes p95(observed RTTs) + margin from an aggregation.
func CalibratedTimeout(agg OutcomeAggregation, margin time.Duration) time.Duration {
	if len(agg.ObservedRTTMs) == 0 {
		return margin
	}
	sorted := append([]float64(nil), agg.ObservedRTTMs...)
	sort.Float64s(sorted)
	p95 := percentileFloat(sorted, 0.95)
	ms := p95 + float64(margin.Milliseconds())
	if ms < 3000 {
		ms = 3000
	}
	if ms > 60000 {
		ms = 60000
	}
	return time.Duration(ms) * time.Millisecond
}

func percentileFloat(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	pos := p * float64(len(sorted)-1)
	lo := int(pos)
	hi := lo + 1
	if hi >= len(sorted) {
		hi = len(sorted) - 1
	}
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo] + (sorted[hi]-sorted[lo])*frac
}
