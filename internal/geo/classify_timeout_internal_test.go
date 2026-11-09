package geo

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The RTT-adaptive per-request classification timeout (owner order
// 2026-11-08): the fixed per-request timeout had no headroom for the slow
// band of public nodes (evening alive RTT median ~1.1s, ladder/media
// endpoints up to ~5-8x slower per-request than the CF-trace probe anchor
// through the same tunnel), so the effective timeout derives from the
// node's own measured probe RTT. These tests pin the derivation and the
// budget constant; the behavioral pins live in classify_adaptive_test.go
// (external package — the through-tunnel harness).

// TestAdaptiveClassifyTimeoutDerivation pins classifyTimeout as the single
// source of truth: raw = 10x the node's probe RTT, clamped into
// [floor, 30s]; rttMs <= 0 or NaN fails safe to the floor (byte-stable with
// the pre-adaptive behavior).
func TestAdaptiveClassifyTimeoutDerivation(t *testing.T) {
	floorTen := 10 * time.Second
	cases := []struct {
		name  string
		rttMs float64
		floor time.Duration
		want  time.Duration
	}{
		{"evening median RTT scales above the floor", 1100, floorTen, 11 * time.Second},
		{"fast RTT lifts to the floor", 200, floorTen, floorTen},
		{"slow band clamps at the ceiling", 3500, floorTen, 30 * time.Second},
		{"zero RTT fails safe to the floor", 0, floorTen, floorTen},
		{"NaN RTT fails safe to the floor", math.NaN(), floorTen, floorTen},
		{"default-floor config keeps today's timeout", 500, DefaultClassifyTimeout, DefaultClassifyTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, classifyTimeout(tc.rttMs, tc.floor))
		})
	}
}

// TestZeroRTTKeepsTodaysExactBehavior pins byte-stability (T5): a 0-RTT
// node under the production default (no [geo].timeout in the config)
// produces exactly today's effective per-request timeout.
func TestZeroRTTKeepsTodaysExactBehavior(t *testing.T) {
	require.Equal(t, DefaultClassifyTimeout, classifyTimeout(0, DefaultClassifyTimeout))
	require.Equal(t, DefaultClassifyTimeout, classifyTimeout(math.NaN(), DefaultClassifyTimeout))
}

// TestUnlockProbeRequestTimeoutFailSafe pins the request-side guard of the
// battery's derived adaptive window (owner decision, option (а),
// 2026-11-09): an unset or negative probe window (hand-built configs and
// tests) fails safe to DefaultClassifyTimeout — never a zero/negative
// context deadline, which would kill every request instantly; a positive
// window passes through verbatim (the clamp output actually governs).
func TestUnlockProbeRequestTimeoutFailSafe(t *testing.T) {
	const delay = 1500 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(delay)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	cases := []struct {
		name   string
		window time.Duration // <= 0 = unset (the hand-built probe shape)
		wantOK bool
	}{
		{"unset field fails safe to the default floor — never a zero deadline", 0, true},
		{"negative field fails safe equally", -time.Second, true},
		{"positive window is honored verbatim", 500 * time.Millisecond, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &unlockProbe{
				cl: srv.Client(), ua: "fail-safe-test",
				pac: &pacer{minDelay: 0, now: time.Now}, now: time.Now,
				requestTimeout: tc.window,
			}
			st, _, err := p.getRetry(context.Background(), srv.URL, nil)
			if tc.wantOK {
				require.NoError(t, err, "the fail-safe window must cover the 1.5s answer")
				require.Equal(t, http.StatusNoContent, st)
			} else {
				require.Error(t, err, "a positive window below the delay must time out")
			}
		})
	}
}

// TestClassifyNodeBudgetPinned pins the node budget at 20 minutes: the
// worst-case battery arithmetic at the 30s per-request ceiling (~38 request
// slots + pacing/retry stagger ≈ 1150s) leaves a ≈1.04x margin, and the
// merged batch lifecycle waits on every battery — the constant is the only
// bound.
func TestClassifyNodeBudgetPinned(t *testing.T) {
	require.Equal(t, 20*time.Minute, classifyNodeBudget)
}
