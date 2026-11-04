package probe

import (
	"testing"
	"time"

	"public_vpn/internal/store"
)

func TestAggregateObservedRTTMs(t *testing.T) {
	results := []store.ProbeResult{
		{Key: "a", Alive: true, RTTMs: 100, FailureKind: ""},
		{Key: "b", Alive: true, RTTMs: 200, FailureKind: ""},
		{Key: "c", Alive: false, RTTMs: 0, FailureKind: "timeout"},
	}
	agg := Aggregate(results)
	if len(agg.ObservedRTTMs) != 2 {
		t.Fatalf("observed = %d want 2", len(agg.ObservedRTTMs))
	}
	if agg.TimedOutCount != 1 {
		t.Fatalf("timedOut = %d want 1", agg.TimedOutCount)
	}
}

func TestAggregateEmpty(t *testing.T) {
	agg := Aggregate(nil)
	if len(agg.ObservedRTTMs) != 0 {
		t.Fatal("expected empty")
	}
	if agg.TimedOutCount != 0 {
		t.Fatal("expected 0")
	}
}

func TestAdaptiveLimiterWiring(t *testing.T) {
	limiter := NewAdaptiveLimiter(AdaptiveLimiterConfig{
		MinLimit:        2,
		MaxLimit:        10,
		Initial:         10,
		WindowSize:      10,
		HighTimeoutRate: 0.15,
		HighCVThreshold: 0.40,
		LowTimeoutRate:  0.05,
		LowCVThreshold:  0.15,
	})
	// Simulate bad network outcomes: high latency and timeouts
	for range 20 {
		limiter.RecordOutcome(500*time.Millisecond, true)
	}
	if limiter.Current() > 5 {
		t.Fatalf("expected reduced concurrency on high timeout rate, got %d", limiter.Current())
	}
}
