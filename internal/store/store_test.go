package store_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// TestUpsertGeoBlankFoldsGeoSource pins the provenance fold rule: geo_source
// follows the fields it describes — a wave that sets geo fields carries its
// provenance in, and a wave that leaves the geo fields blank (no evidence)
// keeps the previous wave's provenance instead of erasing it.
func TestUpsertGeoBlankFoldsGeoSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo-base.jsonl")

	reported := &model.GeoRecord{
		Source: "s", Scheme: "vless", Host: "h1", Port: 443,
		Country: "de", City: "Frankfurt am Main", GeoSource: "self-report",
		FirstSeen: "2026-10-01T00:00:00Z", LastSeen: "2026-10-01T00:00:00Z",
	}
	require.NoError(t, store.UpsertGeo(path, []*model.GeoRecord{reported}))

	// A later wave with NO geo evidence (blank geo + blank provenance):
	// fields AND their provenance survive.
	unknown := &model.GeoRecord{
		Source: "s", Scheme: "vless", Host: "h1", Port: 443,
		FirstSeen: "2026-10-02T00:00:00Z", LastSeen: "2026-10-02T00:00:00Z",
		LastProbe: "2026-10-02T01:00:00Z", RTTMs: 90, Alive: true,
	}
	require.NoError(t, store.UpsertGeo(path, []*model.GeoRecord{unknown}))
	recs, err := store.ReadGeo(path)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	assert.Equal(t, "self-report", recs[0].GeoSource, "provenance survives a no-evidence wave with the fields it describes")
	assert.Equal(t, "de", recs[0].Country)

	// A wave with FRESH evidence overwrites both: the fields describe the
	// fallback's evidence, and the provenance says so.
	fallback := &model.GeoRecord{
		Source: "s", Scheme: "vless", Host: "h1", Port: 443,
		Country: "nl", City: "Amsterdam", GeoSource: "doh-fallback",
		FirstSeen: "2026-10-03T00:00:00Z", LastSeen: "2026-10-03T00:00:00Z",
		LastProbe: "2026-10-03T01:00:00Z", RTTMs: 91, Alive: true,
	}
	require.NoError(t, store.UpsertGeo(path, []*model.GeoRecord{fallback}))
	recs, err = store.ReadGeo(path)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	assert.Equal(t, "doh-fallback", recs[0].GeoSource, "fresh evidence overwrites fields and provenance together")
	assert.Equal(t, "nl", recs[0].Country)
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

// writeFakeBackup drops a <prefix>.bak-<stamp> file with distinct stamps.
func writeFakeBackup(t *testing.T, dir, prefix, stamp, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, prefix+".bak-"+stamp), []byte(body), 0o600))
}

// TestKeepNewestBackupsKeepsNewest pins the retention semantics: keep=N
// retains the N newest <prefix>.bak-* files and deletes the older ones;
// keep=0 is a no-op (unlimited).
func TestKeepNewestBackupsKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	stamps := []string{"20260101-000001", "20260101-000002", "20260101-000003", "20260101-000004", "20260101-000005"}
	for i, s := range stamps {
		writeFakeBackup(t, dir, "config.json", s, fmt.Sprintf("v%d", i))
	}

	require.NoError(t, store.KeepNewestBackups(dir, "config.json", 2))
	remaining, err := filepath.Glob(filepath.Join(dir, "config.json.bak-*"))
	require.NoError(t, err)
	assert.Len(t, remaining, 2)
	assert.Contains(t, remaining, filepath.Join(dir, "config.json.bak-20260101-000005"))
	assert.Contains(t, remaining, filepath.Join(dir, "config.json.bak-20260101-000004"))

	// keep=0 = unlimited: a fresh set survives untouched.
	require.NoError(t, store.KeepNewestBackups(dir, "config.json", 0))
	remaining, err = filepath.Glob(filepath.Join(dir, "config.json.bak-*"))
	require.NoError(t, err)
	assert.Len(t, remaining, 2, "keep=0 must never delete")
}

// TestKeepNewestBackupsIsPrefixScoped pins that the retention only touches
// backups of ITS prefix (activate backups and geo-base backups can share a
// directory shape without cross-deleting).
func TestKeepNewestBackupsIsPrefixScoped(t *testing.T) {
	dir := t.TempDir()
	writeFakeBackup(t, dir, "config.json", "20260101-000001", "a")
	writeFakeBackup(t, dir, "other.json", "20260101-000002", "b")
	require.NoError(t, store.KeepNewestBackups(dir, "config.json", 1))
	_, err := os.Stat(filepath.Join(dir, "other.json.bak-20260101-000002"))
	require.NoError(t, err, "another prefix's backup must never be touched")
}

// TestKeepNewestBackupsLoudOnDeletionFailure pins the safety rule: a backup
// that cannot be deleted fails the call loud — rollback depth is never
// silently reduced without an error.
func TestKeepNewestBackupsLoudOnDeletionFailure(t *testing.T) {
	dir := t.TempDir()
	writeFakeBackup(t, dir, "config.json", "20260101-000001", "old")
	// A non-empty DIRECTORY wearing a backup name cannot be removed as a
	// file — the deletion must surface as an error, not a silent skip. It
	// wears the OLDEST stamp so retention actually tries to delete it.
	stubDir := filepath.Join(dir, "config.json.bak-20200101-000000")
	require.NoError(t, os.Mkdir(stubDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(stubDir, "x"), []byte("stub"), 0o600))
	err := store.KeepNewestBackups(dir, "config.json", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "20200101-000000", "the undeletable backup must be named")
}

// TestRewriteGeoWithBackupStatErrorIsLoud pins F10: a stat error other than
// not-exist is NOT "nothing to back up" — it must fail loud instead of
// silently reducing the rollback depth. A store path under a REGULAR FILE
// fails stat with ENOTDIR (not IsNotExist).
func TestRewriteGeoWithBackupStatErrorIsLoud(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	storePath := filepath.Join(blocker, "geo-base.jsonl")

	records := []*model.GeoRecord{{Host: "new.example.com", Scheme: "vless", Port: 443}}
	_, err := store.RewriteGeoWithBackup(storePath, records, time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC), 0)
	require.Error(t, err, "a stat error other than not-exist must not skip the backup silently")
	assert.Contains(t, err.Error(), "stat pre-prune store", "the error names the refused operation")

	// The missing-store contract stays: no file → no backup, clean write.
	missing := filepath.Join(dir, "geo-base.jsonl")
	bp, err := store.RewriteGeoWithBackup(missing, records, time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC), 0)
	require.NoError(t, err)
	assert.Empty(t, bp, "a missing store has nothing to back up")
}

// captureStderr swaps os.Stderr for a pipe around fn — the loud-warning
// channel for library code without a writer seam.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 8192)
		n, _ := r.Read(buf)
		done <- string(buf[:n])
	}()
	fn()
	require.NoError(t, w.Close())
	os.Stderr = old
	return <-done
}

// TestReadWaveStateCorruptBacksUpAndWarns pins F9: a corrupt wave-state.json
// is backed up (wave-state.json.corrupt-<unix-ts>), the reset is announced
// loud, and availability is preserved (reset to 0 — never a wave-blocking
// error).
func TestReadWaveStateCorruptBacksUpAndWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wave-state.json")
	require.NoError(t, os.WriteFile(path, []byte("{corrupt"), 0o600))

	var st store.WaveState
	var err error
	warning := captureStderr(t, func() {
		st, err = store.ReadWaveState(path)
	})
	require.NoError(t, err, "availability is preserved: a corrupt state never fails the wave")
	assert.Equal(t, uint64(0), st.CurrentWaveSeq, "corrupt state resets to 0")
	assert.Contains(t, warning, "corrupt", "the reset is announced loud, not silent")

	// The corrupt bytes survive in the backup; the original path is gone.
	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	var backups []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "wave-state.json.corrupt-") {
			backups = append(backups, e.Name())
		}
	}
	require.Len(t, backups, 1, "exactly one corrupt backup lands")
	b, readErr := os.ReadFile(filepath.Join(dir, backups[0]))
	require.NoError(t, readErr)
	assert.Equal(t, "{corrupt", string(b), "the corrupt bytes are preserved for the operator")
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "the corrupt file is renamed away, not left in place")
}

// TestReadWaveStateHealthyFileUntouched pins that the F9 backup path only
// fires on corruption: a healthy state file is read in place, unrenamed.
func TestReadWaveStateHealthyFileUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wave-state.json")
	require.NoError(t, store.WriteWaveState(path, store.WaveState{CurrentWaveSeq: 42}))

	warning := captureStderr(t, func() {
		st, err := store.ReadWaveState(path)
		require.NoError(t, err)
		assert.Equal(t, uint64(42), st.CurrentWaveSeq)
	})
	assert.Empty(t, warning, "a healthy file never warns")
	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Len(t, entries, 1, "no corrupt backup appears")
	assert.Equal(t, "wave-state.json", entries[0].Name())
}

// TestRewriteGeoWithBackupAppliesRetention pins the prune-side wiring: the
// new backup is written first, then retention applies, then the store is
// rewritten — and a retention failure aborts BEFORE the store is touched.
func TestRewriteGeoWithBackupAppliesRetention(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "geo-base.jsonl")
	require.NoError(t, os.WriteFile(storePath, []byte(`{"host":"old"}`+"\n"), 0o600))
	// Two pre-existing backups; keep=1 → only the NEW backup survives.
	writeFakeBackup(t, dir, "geo-base.jsonl", "20260101-000001", "older")
	writeFakeBackup(t, dir, "geo-base.jsonl", "20260101-000002", "old")

	records := []*model.GeoRecord{{Host: "new.example.com", Scheme: "vless", Port: 443}}
	bp, err := store.RewriteGeoWithBackup(storePath, records, time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC), 1)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "geo-base.jsonl.bak-20261028-120000"), bp)

	remaining, err := filepath.Glob(filepath.Join(dir, "geo-base.jsonl.bak-*"))
	require.NoError(t, err)
	assert.Len(t, remaining, 1, "keep=1: only the fresh backup remains")

	// Retention failure must abort BEFORE the store rewrite (loud, atomic).
	// A non-empty DIRECTORY wearing a backup name cannot be removed as a file.
	stubDir := filepath.Join(dir, "geo-base.jsonl.bak-20200101-000000")
	require.NoError(t, os.Mkdir(stubDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(stubDir, "x"), []byte("stub"), 0o600))
	before, readErr := os.ReadFile(storePath)
	require.NoError(t, readErr)
	_, err = store.RewriteGeoWithBackup(storePath, records, time.Date(2026, 10, 28, 13, 0, 0, 0, time.UTC), 2)
	require.Error(t, err)
	after, readErr := os.ReadFile(storePath)
	require.NoError(t, readErr)
	assert.Equal(t, string(before), string(after), "the store must be untouched when retention fails")
}
