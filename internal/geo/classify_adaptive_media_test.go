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

// The media battery rides the SAME RTT-adaptive per-request timeout as the
// geo ladder (owner decision, option (а), 2026-11-09): the Phase-1 hard 3s
// per-request cap is retired, so a slow media endpoint answers within the
// node's derived window instead of dying at 3s while the ladder enjoys
// 10-30s. The behavioral pins live beside the ladder's own in
// classify_adaptive_test.go — the same through-tunnel harness, pointed at a
// media channel.

// adaptiveMediaHarness wires one node's full through-tunnel classification
// path: socksServer → instant-204 alive gate → one media endpoint (YouTube
// premium) whose answer carries an injected delay and a definite region
// verdict body; every other battery channel points at a refused loopback
// (hermetic; no real network — deadUnlockEndpoints, overridden).
func adaptiveMediaHarness(t *testing.T, delay time.Duration) (string, *geo.Classifier, *model.Node) {
	t.Helper()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"contentRegion":"DE"}`))
	}))
	t.Cleanup(slow.Close)
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(gate.Close)

	ep := *deadUnlockEndpoints() // every channel refused loopback
	ep.AlivePrimary = gate.URL + "/generate_204"
	ep.AliveFallback = gate.URL + "/generate_204"
	ep.YouTubePremium = slow.URL + "/premium"

	in := geo.ClassifyInput{
		DataDir: t.TempDir(),
		Cfg: config.GeoConfig{
			Timeout:  config.Duration{Duration: 10 * time.Second}, // the per-node FLOOR (the production 10s)
			HTTPSURL: "http://127.0.0.1:1/json",                   // dead loopback — the ladder stays hermetic
			DoHURL:   "http://127.0.0.1:1/resolve",                // dead loopback — the ladder stays hermetic
		},
		UserAgent:       "adaptive-media-test/1",
		SelfURL:         "http://127.0.0.1:1/json", // dead loopback — the ladder stays hermetic
		UnlockEndpoints: &ep,
		Sleep:           func(context.Context, time.Duration) error { return nil },
	}
	socks := newSocksServer(t)
	n := model.NewNode("adaptive-media", "vless", "u-adaptive-media", "adaptive-media.example.com", 443, map[string]string{"security": "tls", "type": "tcp"})
	return socks.Addr(), geo.NewClassifier(in), n
}

// TestAdaptiveTimeoutLetsSlowMediaProbeComplete is the dynamic repro (repo
// acceptance discipline for seam/networking code): a media endpoint
// answering in 4.5s — dead under the retired 3s per-request cap — completes
// under the floor window (rttMs=0 → the floor IS the effective per-request
// window, 10s), and the YouTube verdict LANDS as the region the body
// declares, never unknown-by-timeout.
func TestAdaptiveTimeoutLetsSlowMediaProbeComplete(t *testing.T) {
	const delay = 4500 * time.Millisecond
	socksAddr, clf, n := adaptiveMediaHarness(t, delay)
	start := time.Now()
	clf.ClassifyNode(context.Background(), n, socksAddr, "203.0.113.7", 0)
	elapsed := time.Since(start)

	probeByKey := map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.7")}
	recs, _, err := clf.Flush(nil, []*model.Node{n}, probeByKey, 1, time.Now())
	require.NoError(t, err)
	require.Len(t, recs, 1)
	require.Equal(t, "DE", recs[0].MediaUnlocks.YouTubeRegion,
		"the 4.5s-delayed media answer must complete under the 10s floor window and land its verdict")
	require.GreaterOrEqual(t, elapsed, delay,
		"the battery must have waited out the injected delay, not failed fast")
}
