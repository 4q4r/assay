package geo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPacerWaitsMinDelayBetweenStartsWithInjectedClock pins the politeness
// pacing with an injected clock: the first external request starts
// immediately, every later start is pushed to last-start + min-delay, and the
// computed wait is handed to the injected sleeper — never to the real clock.
func TestPacerWaitsMinDelayBetweenStartsWithInjectedClock(t *testing.T) {
	const minDelay = 100 * time.Millisecond
	now := time.Unix(1700000000, 0)
	p := &pacer{
		minDelay: minDelay,
		now:      func() time.Time { return now },
	}
	var waits []time.Duration
	p.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		now = now.Add(d) // the fake clock advances by exactly the slept amount
		return nil
	}

	require.NoError(t, p.wait(context.Background()), "first start: nothing behind us — no wait")
	require.NoError(t, p.wait(context.Background()))
	require.NoError(t, p.wait(context.Background()))

	// The first call produced NO sleep (it never waits); each subsequent
	// start waits out exactly the min-delay against the previous slot.
	require.Len(t, waits, 2)
	assert.Equal(t, minDelay, waits[0], "start 2 waits out the min-delay against the recorded last start")
	assert.Equal(t, minDelay, waits[1], "start 3 waits out the min-delay against start 2's slot")
}

// TestPacerZeroMinDelayNeverWaits pins the disabled-pacing path (MinDelay 0 =
// no politeness delay, every request immediate).
func TestPacerZeroMinDelayNeverWaits(t *testing.T) {
	p := &pacer{minDelay: 0, now: time.Now}
	slept := false
	p.sleep = func(context.Context, time.Duration) error {
		slept = true
		return nil
	}
	require.NoError(t, p.wait(context.Background()))
	require.NoError(t, p.wait(context.Background()))
	assert.False(t, slept, "zero min-delay disables pacing entirely")
}

// TestPacerRespectsCancellation pins that a canceled context aborts the wait
// instead of sleeping through it (the wave must stay shutdown-responsive).
func TestPacerRespectsCancellation(t *testing.T) {
	p := &pacer{minDelay: time.Hour, now: func() time.Time { return time.Unix(0, 0) }}
	p.sleep = func(ctx context.Context, _ time.Duration) error {
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	// The FIRST wait primes the schedule with a zero wait (nothing behind
	// it); the SECOND reserves a slot one hour out and must observe the
	// cancellation inside the sleep.
	require.NoError(t, p.wait(context.Background()))
	cancel()
	require.ErrorIs(t, p.wait(ctx), context.Canceled)
}

// TestMergeGeoRecordsSameIdentityWinnerIsOrderIndependent pins the M-b
// determinism contract with self-reports in the mix: two distinct nodes
// (different credentials → different keys) can share one cold-base identity
// (scheme|host|port). The probe+report outcome that survives the merge must
// not depend on the arrival order of the nodes — the same inputs must always
// yield the same winner (final-review finding M-b).
func TestMergeGeoRecordsSameIdentityWinnerIsOrderIndependent(t *testing.T) {
	na := model.NewNode("s", "vless", "uuid-a", "dupe.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	nb := model.NewNode("s", "vless", "uuid-b", "dupe.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	require.NotEqual(t, na.Key, nb.Key, "distinct credentials → distinct node keys")
	require.Equal(t, model.GeoIdentity(&model.GeoRecord{Scheme: na.Scheme, Host: na.Host, Port: na.Port}),
		model.GeoIdentity(&model.GeoRecord{Scheme: nb.Scheme, Host: nb.Host, Port: nb.Port}),
		"both nodes share one cold-base identity")
	now := time.Now().UTC()
	probeByKey := map[string]store.ProbeResult{
		na.Key: {Key: na.Key, Alive: true, RTTMs: 10, ExitIP: "203.0.113.77", CheckedAt: now},
		nb.Key: {Key: nb.Key, Alive: false, RTTMs: 99, CheckedAt: now},
	}
	reports := map[string]*NodeReport{
		na.Key: {
			Key: na.Key, Class: ClassSelfReport,
			Geo: &Response{
				Status: "success", CountryCode: "DE", City: "Frankfurt am Main",
				AS: "AS51167 Contabo GmbH", ASName: "CONTABO", ISP: "Contabo GmbH",
				Hosting: true, Query: "203.0.113.77",
			},
		},
	}

	winner := func(nodes []*model.Node) *model.GeoRecord {
		t.Helper()
		dir := t.TempDir()
		recs, err := mergeGeoRecords(dir, nodes, probeByKey, 0, reports)
		require.NoError(t, err)
		require.Len(t, recs, 2, "both same-identity nodes produce records")
		path := filepath.Join(dir, "geo-base.jsonl")
		require.NoError(t, store.UpsertGeo(path, recs))
		got, err := store.ReadGeo(path)
		require.NoError(t, err)
		require.Len(t, got, 1, "the store keeps exactly one record per identity")
		return got[0]
	}

	a := winner([]*model.Node{na, nb})
	b := winner([]*model.Node{nb, na})
	assert.Equal(t, a.Alive, b.Alive,
		"the surviving alive flag must not depend on node arrival order")
	assert.Equal(t, a.RTTMs, b.RTTMs, //nolint:testifylint // determinism pin: exact bit equality is the contract
		"the surviving rtt must not depend on node arrival order")
	assert.Equal(t, a.LastProbe, b.LastProbe,
		"the surviving last_probe must not depend on node arrival order")
	assert.Equal(t, a.Country, b.Country,
		"the surviving geo must not depend on node arrival order")
}

// TestResponseASNExtractsNumber pins the as-field token extraction on the
// documented composite shape ("AS15169 Google Inc.").
func TestResponseASNExtractsNumber(t *testing.T) {
	assert.Equal(t, "AS15169", Response{AS: "AS15169 Google Inc."}.ASN())
	assert.Equal(t, "AS51167", Response{AS: "AS51167 Contabo GmbH"}.ASN())
	assert.Empty(t, Response{AS: ""}.ASN(), "empty as field (BGP-unannounced blocks) yields no ASN")
}
