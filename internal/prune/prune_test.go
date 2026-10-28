package prune_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"public_vpn/internal/model"
	"public_vpn/internal/prune"
	"public_vpn/internal/rank"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

// rec builds one record; the scheme is fixed to vless and the port to 443 —
// identity tests do not depend on them and every rule under test keys on
// host/alive/last_probe. recBytes carries the knobs rec does not vary.
func rec(tag, host string, alive bool, lastProbe time.Time) *model.GeoRecord {
	return recBytes(tag, "vless", host, 443, alive, lastProbe, 0)
}

func recBytes(tag, scheme, host string, port int, alive bool, lastProbe time.Time, up int64) *model.GeoRecord {
	r := &model.GeoRecord{
		Tag:     tag,
		Scheme:  scheme,
		Host:    host,
		Port:    port,
		Alive:   alive,
		BytesUp: up,
	}
	if !lastProbe.IsZero() {
		r.LastProbe = lastProbe.UTC().Format(time.RFC3339)
	}
	return r
}

func identity(scheme, host string, port int) string {
	return fmt.Sprintf("%s|%s|%d", scheme, strings.ToLower(host), port)
}

// filteredIdentitiesOf mirrors what the maintain wave feeds prune: the keys of
// the just-filtered node set (the same identity scheme rank uses).
func filteredIdentitiesOf(recs ...*model.GeoRecord) map[string]bool {
	m := map[string]bool{}
	for _, r := range recs {
		m[identity(r.Scheme, r.Host, r.Port)] = true
	}
	return m
}

func opts() prune.Options {
	return prune.Options{
		DeadAfter: 48 * time.Hour,
		TTL:       24 * time.Hour,
		Now:       now,
	}
}

func TestPruneDeadAfterBoundary(t *testing.T) {
	// Rule A: alive=false AND last_probe strictly older than dead_after.
	dead := recBytes("pool-de-01", "vless", "de.example.com", 443, false, now.Add(-49*time.Hour), 7777)
	atBoundary := rec("pool-de-02", "de2.example.com", false, now.Add(-48*time.Hour))
	kept, removed, report := prune.Select(
		[]*model.GeoRecord{dead, atBoundary},
		filteredIdentitiesOf(dead, atBoundary), // both still referenced by sources
		opts(),
	)
	require.Len(t, kept, 1)
	require.Len(t, removed, 1)
	assert.Equal(t, "pool-de-01", removed[0].Tag)
	assert.Equal(t, 1, report.RemovedDead, "removed by the dead_after rule")
	assert.Equal(t, 0, report.RemovedStale)
	assert.Equal(t, "pool-de-02", kept[0].Tag)
}

func TestPruneAtExactBoundaryIsKept(t *testing.T) {
	// "older than dead_after" is strict: exactly 48h is not older.
	atBoundary := rec("", "de.example.com", false, now.Add(-48*time.Hour))
	kept, removed, _ := prune.Select(
		[]*model.GeoRecord{atBoundary},
		filteredIdentitiesOf(atBoundary),
		opts(),
	)
	require.Empty(t, removed)
	require.Len(t, kept, 1)
}

func TestPruneStaleOrphanRemovedOnlyWhenSourceDroppedIt(t *testing.T) {
	// Rule B (ttl-stale orphan): rank's freshness check fails AND the node is
	// absent from the current filtered set — the source dropped the link, and
	// rank would refuse the record anyway. Physical removal, nothing else.
	orphan := rec("", "gone.example.com", true, now.Add(-25*time.Hour)) // stale per ttl
	referenced := rec("", "here.example.com", true, now.Add(-25*time.Hour))

	kept, removed, report := prune.Select(
		[]*model.GeoRecord{orphan, referenced},
		filteredIdentitiesOf(referenced), // only "here" survives the filter wave
		opts(),
	)
	require.Len(t, removed, 1)
	assert.Equal(t, "vless|gone.example.com|443", model.GeoIdentity(removed[0]))
	assert.Equal(t, 1, report.RemovedStale)
	assert.Equal(t, 0, report.RemovedDead)
	require.Len(t, kept, 1)
	assert.Equal(t, "here.example.com", kept[0].Host,
		"a stale-but-referenced record stays: a future probe can refresh it")
}

func TestPruneNeverRemovesAliveReferencedOrUnprobedRecords(t *testing.T) {
	aliveStale := rec("pool-de-01", "de.example.com", true, now.Add(-72*time.Hour)) // stale but alive + referenced
	unprobed := rec("", "fresh.example.com", false, time.Time{})                    // never probed, referenced
	kept, removed, _ := prune.Select(
		[]*model.GeoRecord{aliveStale, unprobed},
		filteredIdentitiesOf(aliveStale, unprobed),
		opts(),
	)
	require.Empty(t, removed, "no recoverable state may be pruned")
	require.Len(t, kept, 2)
}

func TestPruneUnparseableLastProbeIsStaleForOrphans(t *testing.T) {
	// rank's freshness contract: unparseable/missing timestamps carry no fresh
	// evidence. An orphan with a garbage timestamp is removable; a referenced
	// one is not.
	orphan := rec("", "gone.example.com", true, time.Time{})
	orphan.LastProbe = "not-a-timestamp"

	kept, removed, _ := prune.Select([]*model.GeoRecord{orphan}, map[string]bool{}, opts())
	require.Len(t, removed, 1)
	require.Empty(t, kept)
	_ = rank.AliveDataFresh // exported from rank and reused here (see package doc)
}

func TestPruneEmptyInputYieldsEmpty(t *testing.T) {
	kept, removed, _ := prune.Select(nil, map[string]bool{}, opts())
	require.Empty(t, kept)
	require.Empty(t, removed)
}

// --- store integration: backup + atomic rewrite ---

func TestRewriteGeoWithBackupKeepsPrePruneCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo-base.jsonl")
	original := []*model.GeoRecord{
		rec("pool-de-01", "de.example.com", true, now),
		rec("", "old.example.com", false, now.Add(-72*time.Hour)),
	}
	require.NoError(t, store.WriteGeo(path, original))

	pruned := original[:1]
	clock := now.Add(30 * time.Minute) // deterministic backup stamp
	backupPath, err := store.RewriteGeoWithBackup(path, pruned, clock, 0)
	require.NoError(t, err)
	require.NotEmpty(t, backupPath)
	assert.Contains(t, filepath.Base(backupPath), ".bak-20261028-123000",
		"backup convention: <name>.bak-<ts> next to the store")

	// Backup holds the PRE-prune content (2 records).
	back, err := store.ReadGeo(backupPath)
	require.NoError(t, err)
	require.Len(t, back, 2)

	// Store now holds the pruned content (1 record).
	live, err := store.ReadGeo(path)
	require.NoError(t, err)
	require.Len(t, live, 1)
	assert.Equal(t, "pool-de-01", live[0].Tag)

	// No temp artifacts left behind (atomic temp+rename).
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), ".tmp-", "atomic rewrite leaves nothing behind")
	}
}

func TestRewriteGeoWithBackupOnMissingStoreSkipsBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geo-base.jsonl")
	backupPath, err := store.RewriteGeoWithBackup(path, []*model.GeoRecord{}, now, 0)
	require.NoError(t, err)
	assert.Empty(t, backupPath, "nothing to back up when the store does not exist yet")
}
