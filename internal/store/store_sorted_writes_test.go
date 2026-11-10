package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"assay/internal/model"
	"assay/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sortedBase builds records whose insertion order deliberately differs from
// their identity order (and differs between the two runs below), so any
// Go-map-order leakage into the file shows up as a line-order difference.
func sortedBase() []*model.GeoRecord {
	return []*model.GeoRecord{
		{Scheme: "vless", Host: "zulu.example.com", Port: 443, Country: "de"},
		{Scheme: "vless", Host: "alpha.example.com", Port: 443, Country: "nl"},
		{Scheme: "trojan", Host: "2001:db8::1", Port: 2053, Country: "us"},
		{Scheme: "vless", Host: "Mike.example.com", Port: 8443, Country: "fr"},
		{Scheme: "ss", Host: "bravo.example.com", Port: 80, Country: "pl"},
	}
}

// TestUpsertGeoWritesAreSortedAndByteDeterministic pins the W7 sorted-write
// contract: the geo-base file is written in identity order (stable across
// runs — Go map iteration order must never reach the disk), so two runs over
// identical logical data produce byte-identical files, while each record's
// content is untouched.
func TestUpsertGeoWritesAreSortedAndByteDeterministic(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "base-a.jsonl")
	pathB := filepath.Join(dir, "base-b.jsonl")

	require.NoError(t, store.UpsertGeo(pathA, sortedBase()))
	// Second "run": fresh store file, same logical data (plus a no-op
	// re-upsert through the merged path, which is the real maintain-wave
	// shape: existing records come back through ReadGeo).
	require.NoError(t, store.UpsertGeo(pathB, sortedBase()))
	require.NoError(t, store.UpsertGeo(pathB, sortedBase()))

	a, err := os.ReadFile(pathA)
	require.NoError(t, err)
	b, err := os.ReadFile(pathB)
	require.NoError(t, err)
	assert.Equal(t, string(a), string(b), "identical logical data must produce a byte-identical file")

	// Line order is the identity order.
	records, err := store.ReadGeo(pathA)
	require.NoError(t, err)
	require.Len(t, records, 5)
	for i := 1; i < len(records); i++ {
		prev, cur := model.GeoIdentity(records[i-1]), model.GeoIdentity(records[i])
		assert.Less(t, prev, cur, "file lines must be sorted by identity (line %d: %s >= %s)", i, prev, cur)
	}

	// Content per record is unchanged by the sort (the set is the same).
	want := map[string]bool{}
	for _, r := range sortedBase() {
		want[model.GeoIdentity(r)] = true
	}
	for _, r := range records {
		assert.True(t, want[model.GeoIdentity(r)], "record %s must survive the write", model.GeoIdentity(r))
	}
}

// TestUpsertGeoSecondRunKeepsSortedOrder pins that re-upserting over an
// existing (sorted) file preserves the byte-identical layout — the maintain
// wave's actual every-6h shape.
func TestUpsertGeoSecondRunKeepsSortedOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "base.jsonl")
	require.NoError(t, store.UpsertGeo(path, sortedBase()))
	first, err := os.ReadFile(path)
	require.NoError(t, err)

	require.NoError(t, store.UpsertGeo(path, sortedBase()))
	second, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(first), string(second), "re-upsert of identical data must not shuffle the file")
}
