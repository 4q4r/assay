package store_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodesJSONLRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a := model.NewNode("s1", "vless", "u1", "a.example.com", 443, map[string]string{"security": "tls", "type": "tcp"})
	b := model.NewNode("s2", "trojan", "pw", "b.example.com", 443, map[string]string{"type": "tcp"})

	path := filepath.Join(dir, "nodes.jsonl")
	require.NoError(t, store.WriteNodes(path, []*model.Node{a, b}))

	got, err := store.ReadNodes(path)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, a.Key, got[0].Key)
	assert.Equal(t, "trojan", got[1].Scheme)
	assert.WithinDuration(t, a.FirstSeen.UTC(), got[0].FirstSeen.UTC(), time.Second)
}

func TestGeoBaseUpsertPreservesFirstSeenAndTag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo-base.jsonl")

	first := &model.GeoRecord{
		Tag: "pool-nl-01", Source: "s", Scheme: "vless", Host: "h1", Port: 443,
		IP: "5.6.7.8", Country: "nl", City: "Amsterdam", FirstSeen: "2026-10-01T00:00:00Z",
		LastSeen: "2026-10-01T00:00:00Z",
	}
	require.NoError(t, store.UpsertGeo(path, []*model.GeoRecord{first}))

	// A later wave updates the same node (same scheme|host|port identity):
	// LastSeen/LastProbe/geo refresh, FirstSeen and the assigned tag survive.
	update := &model.GeoRecord{
		Source: "s", Scheme: "vless", Host: "h1", Port: 443,
		IP: "5.6.7.8", Country: "nl", City: "Rotterdam", FirstSeen: "2026-10-28T00:00:00Z",
		LastSeen: "2026-10-28T00:00:00Z", LastProbe: "2026-10-28T01:00:00Z",
		RTTMs: 88.5, Alive: true,
	}
	require.NoError(t, store.UpsertGeo(path, []*model.GeoRecord{update}))

	recs, err := store.ReadGeo(path)
	require.NoError(t, err)
	require.Len(t, recs, 1, "upsert must not duplicate identity")
	assert.Equal(t, "pool-nl-01", recs[0].Tag, "assigned tag survives waves")
	assert.Equal(t, "2026-10-01T00:00:00Z", recs[0].FirstSeen, "first_seen survives waves")
	assert.Equal(t, "Rotterdam", recs[0].City, "geo refresh wins")
	assert.True(t, recs[0].Alive)
}

func TestGeoIdentityIsSchemeHostPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo-base.jsonl")
	a := &model.GeoRecord{Scheme: "vless", Host: "h", Port: 443}
	b := &model.GeoRecord{Scheme: "trojan", Host: "h", Port: 443}
	c := &model.GeoRecord{Scheme: "vless", Host: "h", Port: 8443}
	require.NoError(t, store.UpsertGeo(path, []*model.GeoRecord{a, b, c}))
	recs, err := store.ReadGeo(path)
	require.NoError(t, err)
	assert.Len(t, recs, 3, "different scheme or port = different identity")
}

func TestSelectionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "selection.json")
	sel := &model.Selection{
		GeneratedAt: time.Now().UTC(),
		CapApplied:  25,
		CitiesAlive: 12,
		Nodes: []model.SelectedNode{
			{Tag: "pool-de-01", Key: "k1", Country: "de", City: "Berlin", RTTMs: 40},
			{Tag: "pool-nl-01", Key: "k2", Country: "nl", City: "Amsterdam", RTTMs: 60},
		},
	}
	require.NoError(t, store.WriteSelection(path, sel))
	got, err := store.ReadSelection(path)
	require.NoError(t, err)
	require.Len(t, got.Nodes, 2)
	assert.Equal(t, "pool-de-01", got.Nodes[0].Tag)
}

func TestReadMissingFileReturnsEmptyNotError(t *testing.T) {
	dir := t.TempDir()
	nodes, err := store.ReadNodes(filepath.Join(dir, "missing.jsonl"))
	require.NoError(t, err)
	assert.Empty(t, nodes)
	recs, err := store.ReadGeo(filepath.Join(dir, "missing-geo.jsonl"))
	require.NoError(t, err)
	assert.Empty(t, recs)
	sel, err := store.ReadSelection(filepath.Join(dir, "missing-sel.json"))
	require.NoError(t, err)
	assert.Nil(t, sel)
}

func TestAppendProbeResultAndReadLatestByKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe-results.jsonl")
	r1 := store.ProbeResult{Key: "k1", Alive: true, RTTMs: 100, CheckedAt: time.Now().UTC().Add(-time.Hour)}
	r2 := store.ProbeResult{Key: "k1", Alive: false, CheckedAt: time.Now().UTC()}
	r3 := store.ProbeResult{Key: "k2", Alive: true, RTTMs: 50, CheckedAt: time.Now().UTC()}
	require.NoError(t, store.AppendProbeResults(path, []store.ProbeResult{r1, r2, r3}))

	latest, err := store.LatestProbeByKey(path)
	require.NoError(t, err)
	require.Len(t, latest, 2)
	assert.False(t, latest["k1"].Alive, "latest wave wins")
	assert.True(t, latest["k2"].Alive)
	assert.InDelta(t, 50.0, latest["k2"].RTTMs, 0.001)
}

// TestUpsertGeoPreservesProbeFieldsWhenIncomingHasNoProbeData pins the merge
// contract for probe telemetry: when an incoming record carries no probe data
// (last_probe empty), the previous Alive/RTTMs/SpeedBPS/BytesUp/BytesDown must
// survive — an unprobed wave must never zero a probed record's outcomes while
// keeping its stale last_probe (fix-round-1 finding #1, store side).
func TestUpsertGeoPreservesProbeFieldsWhenIncomingHasNoProbeData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo-base.jsonl")

	prev := &model.GeoRecord{
		Source: "s", Scheme: "vless", Host: "h1", Port: 443,
		IP: "5.6.7.8", Country: "nl", City: "Amsterdam",
		FirstSeen: "2026-10-01T00:00:00Z", LastSeen: "2026-10-01T00:00:00Z",
		LastProbe: "2026-10-01T12:00:00Z", RTTMs: 88.5, SpeedBPS: 2048,
		Alive: true, BytesUp: 111, BytesDown: 222,
	}
	require.NoError(t, store.UpsertGeo(path, []*model.GeoRecord{prev}))

	incoming := &model.GeoRecord{
		Source: "s", Scheme: "vless", Host: "h1", Port: 443,
		FirstSeen: "2026-10-28T00:00:00Z", LastSeen: "2026-10-28T00:00:00Z",
		// no LastProbe: the wave carried no probe outcome for this node
	}
	require.NoError(t, store.UpsertGeo(path, []*model.GeoRecord{incoming}))

	recs, err := store.ReadGeo(path)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	assert.True(t, recs[0].Alive, "alive must survive a probe-less wave")
	assert.InDelta(t, 88.5, recs[0].RTTMs, 0.001, "rtt_ms must survive a probe-less wave")
	assert.Equal(t, int64(2048), recs[0].SpeedBPS, "speed_bps must survive a probe-less wave")
	assert.Equal(t, int64(111), recs[0].BytesUp, "bytes_up must survive a probe-less wave")
	assert.Equal(t, int64(222), recs[0].BytesDown, "bytes_down must survive a probe-less wave")
	assert.Equal(t, "2026-10-01T12:00:00Z", recs[0].LastProbe, "last_probe must stay stale-not-zero")
}

// TestJSONLArtifactsAreExplicitly0600 pins the store write mode: every JSONL
// artifact (nodes/filtered/geo-base) and the fetch manifest are written 0600
// by an explicit Chmod in writeFileAtomic — deliberate hardening, not a
// CreateTemp side effect (review finding 11).
func TestJSONLArtifactsAreExplicitly0600(t *testing.T) {
	dir := t.TempDir()
	n := model.NewNode("s", "vless", "u", "h.example.com", 443, map[string]string{"security": "tls"})
	path := filepath.Join(dir, "nodes.jsonl")
	require.NoError(t, store.WriteNodes(path, []*model.Node{n}))

	st, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), st.Mode().Perm(), "state artifacts must be 0600")

	manifest := filepath.Join(dir, "cache", "manifest.json")
	require.NoError(t, store.WriteManifest(manifest, []byte(`{"fetched_at":"2026-10-28T00:00:00Z","sources":{}}`)))
	ms, err := os.Stat(manifest)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), ms.Mode().Perm(), "fetch manifest must be 0600")
}
