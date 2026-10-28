package geo

import (
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBatchIntervalClampsToFreeTier unit-tests the production clamp directly:
// the free tier allows 15 batch requests/min, so a generous configuration
// (per_minute = 900) must clamp to one batch per 4s — without paying 4s of
// wall time in a behavior test (review finding 3).
func TestBatchIntervalClampsToFreeTier(t *testing.T) {
	assert.Equal(t, 4*time.Second, batchInterval(900), "900/min clamps to the 15/min free-tier ceiling")
	assert.Equal(t, 4*time.Second, batchInterval(15), "the ceiling itself is exact")
	assert.Equal(t, 12*time.Second, batchInterval(5), "below the ceiling the config wins")
	assert.Equal(t, time.Minute, batchInterval(0), "floored at 1/min — never a zero interval")
	assert.Equal(t, time.Minute, batchInterval(-7), "negative config floors at 1/min")
}

// TestNewClientDelegatesToBatchInterval pins that the production constructor
// really builds a burst-1 limiter at the clamped interval: exactly one
// immediate token, then the spacing is real (no burst-y 429 drivers).
func TestNewClientDelegatesToBatchInterval(t *testing.T) {
	cl := NewClient(config.GeoConfig{PerMinute: 900}, "")
	require.NotNil(t, cl.limiter)
	assert.True(t, cl.limiter.Allow(), "burst is 1: the first batch goes immediately")
	assert.False(t, cl.limiter.Allow(), "burst is 1: the second batch must wait out the clamped 4s interval")
}

// TestMergeGeoRecordsSameIdentityWinnerIsOrderIndependent pins the M-b
// determinism contract: two distinct nodes (different credentials → different
// keys) can share one cold-base identity (scheme|host|port). The probe
// outcome that survives the merge must not depend on the arrival order of the
// nodes (upstream parse iterates the fetch manifest, whose Go map order is
// randomized) — the same inputs must always yield the same winner
// (final-review finding M-b).
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
		na.Key: {Key: na.Key, Alive: true, RTTMs: 10, CheckedAt: now},
		nb.Key: {Key: nb.Key, Alive: false, RTTMs: 99, CheckedAt: now},
	}

	winner := func(nodes []*model.Node) *model.GeoRecord {
		t.Helper()
		dir := t.TempDir()
		recs, err := mergeGeoRecords(Input{
			DataDir:    dir,
			Nodes:      nodes,
			ProbeByKey: probeByKey,
		}, map[string]Response{}, map[string]string{})
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
}
