package geo_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/geo"
	"assay/internal/model"
	"assay/internal/store"

	"github.com/stretchr/testify/require"
)

// The RTT-adaptive per-request classification timeout (owner order
// 2026-11-08), pinned behaviorally through the production harness: the
// socks test server relays to a target whose every answer carries an
// injected delay, and the node's probe RTT selects the effective per-node
// client timeout (10x RTT clamped into [floor, 30s]). Floor 1s keeps the
// whole scenario hermetic and fast; the derivation table lives in
// classify_timeout_internal_test.go.

// adaptiveHarness wires one node's full through-tunnel classification path:
// socksServer → delayed self-report target, floor from [geo].timeout, every
// other endpoint a dead loopback (hermetic; no real network).
func adaptiveHarness(t *testing.T, delay time.Duration) (string, *geo.Classifier, *model.Node) {
	t.Helper()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","query":"203.0.113.7","countryCode":"DE","city":"Berlin","isp":"Test ISP","as":"AS64512","asname":"test","proxy":false,"hosting":false}`))
	}))
	t.Cleanup(slow.Close)

	in := geo.ClassifyInput{
		DataDir: t.TempDir(),
		Cfg: config.GeoConfig{
			Timeout:  config.Duration{Duration: time.Second}, // the per-node FLOOR
			HTTPSURL: "http://127.0.0.1:1/json",              // dead loopback — every hop stays hermetic
			DoHURL:   "http://127.0.0.1:1/resolve",           // dead loopback — the ladder must stay hermetic
		},
		UserAgent:       "adaptive-test/1",
		SelfURL:         slow.URL + "/json",
		UnlockEndpoints: deadUnlockEndpoints(),
		Sleep:           func(context.Context, time.Duration) error { return nil },
	}
	socks := newSocksServer(t)
	n := model.NewNode("adaptive", "vless", "u-adaptive", "adaptive.example.com", 443, map[string]string{"security": "tls", "type": "tcp"})
	return socks.Addr(), geo.NewClassifier(in), n
}

// classifyAdaptive runs the single-node wave (probe → hot-instance
// classification → flush) with the node's own measured probe RTT.
func classifyAdaptive(t *testing.T, socksAddr string, clf *geo.Classifier, n *model.Node, rttMs float64) geo.Summary {
	t.Helper()
	clf.ClassifyNode(context.Background(), n, socksAddr, "203.0.113.7", rttMs)
	probeByKey := map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.7")}
	recs, sum, err := clf.Flush(nil, []*model.Node{n}, probeByKey, 1, time.Now())
	require.NoError(t, err)
	require.Len(t, recs, 1)
	return sum
}

// TestAdaptiveTimeoutLetsSlowNodeClassify is the dynamic repro (repo
// acceptance discipline for seam/networking code): a slow node whose
// self-report answers in 1.5s — dead under today's fixed 1s floor —
// completes classification under the adaptive timeout (probe RTT 200ms →
// 10x = 2s above the floor). The 0-RTT twin below proves the delay really
// sits in the adaptive window: with the floor alone the same target times
// out.
func TestAdaptiveTimeoutLetsSlowNodeClassify(t *testing.T) {
	socksAddr, clf, n := adaptiveHarness(t, 1500*time.Millisecond)
	sum := classifyAdaptive(t, socksAddr, clf, n, 200)
	require.Equal(t, 1, sum.SelfReport, "the 1.5s-delayed self-report completes under the adaptive 2s timeout (floor alone would drop the node to unknown)")
	require.Equal(t, 0, sum.Unknown)
}

// TestZeroRTTNodeKeepsFloorTimeout pins byte-stability (T5) behaviorally:
// a 0-RTT node keeps EXACTLY today's behavior — the floor timeout — so the
// same 1.5s target exceeds it and the node lands unknown (the pre-adaptive
// outcome for this shape, loud and honest).
func TestZeroRTTNodeKeepsFloorTimeout(t *testing.T) {
	socksAddr, clf, n := adaptiveHarness(t, 1500*time.Millisecond)
	sum := classifyAdaptive(t, socksAddr, clf, n, 0)
	require.Equal(t, 1, sum.Unknown, "0-RTT keeps the floor timeout: the 1.5s target exceeds it — byte-stable with today's behavior")
	require.Equal(t, 0, sum.SelfReport)
	require.Positive(t, sum.TimedOutCount, "the floor-bound request fails as a timeout, not as another failure class")
}
