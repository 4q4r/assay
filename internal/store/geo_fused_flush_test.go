package store_test

// Allocation-audit F2 tests: the classification flush's store contract.
// The old path read geo-base twice (geo.Flush's own read + UpsertGeo's
// internal re-read), re-ran the blank-fold matrix twice, and sorted with a
// comparator that computed model.GeoIdentity (fmt.Sprintf) TWICE per
// comparison. The fused path merges once against the already-read records
// and sorts with keys extracted once per record — this file pins that the
// fused output is byte-identical to the pre-change tree's output (golden
// generated at the base commit) and that the blank-fold contract is
// idempotent under the double application the old path performed.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"assay/internal/model"
	"assay/internal/store"

	"github.com/stretchr/testify/require"
)

func geoSortFixtureForTest() ([]*model.GeoRecord, []*model.GeoRecord) {
	g := func(scheme, host string, port int, cc string) *model.GeoRecord {
		return &model.GeoRecord{Scheme: scheme, Host: host, Port: port, Country: cc, Tag: "t-" + cc}
	}
	existing := []*model.GeoRecord{
		g("vless", "zulu.example.com", 443, "de"),
		g("vless", "alpha.example.com", 443, "nl"),
		g("trojan", "2001:db8::1", 2053, "us"),
		g("vless", "Mike.example.com", 8443, "fr"),
		g("ss", "bravo.example.com", 80, "pl"),
	}
	incoming := []*model.GeoRecord{
		g("vless", "charlie.example.com", 443, "it"),
		g("vless", "alpha.example.com", 443, "nl"),
		g("vless", "MIKE.example.com", 8443, "fr"),
		g("vmess", "echo.example.com", 80, "gb"),
		g("vless", "mike.example.com", 8443, "fr"),
	}
	return existing, incoming
}

// TestMergeGeoRecordsAndWriteGeoSortedMatchPreChangeGolden pins the F2
// fusion's observable: MergeGeoRecords + WriteGeoSorted produce the exact
// bytes the pre-change UpsertGeo produced (identity-string comparator,
// sorted once per write) on the shuffled, identity-tricky fixture.
func TestMergeGeoRecordsAndWriteGeoSortedMatchPreChangeGolden(t *testing.T) {
	existing, incoming := geoSortFixtureForTest()

	dir := t.TempDir()
	path := filepath.Join(dir, "base.jsonl")
	require.NoError(t, store.WriteGeoSorted(path, mustMerged(t, existing, incoming)))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	want, err := os.ReadFile(filepath.Join("testdata", "allocparity", "geo-sort-golden.jsonl"))
	require.NoError(t, err)
	// .gitattributes pins LF checkouts; the strip is the belt to that for
	// working trees materialized before the attribute (a windows checkout
	// converts LF→CRLF and the CRLF bytes are checkout noise, never content
	// the writers emit — os.WriteFile stores the \n bytes it is given).
	// On linux the strip is a no-op: the byte-exact contract is untouched.
	golden := strings.ReplaceAll(string(want), "\r\n", "\n")
	require.Equal(t, golden, string(raw),
		"the fused merge+sort+write must be byte-identical to the pre-change UpsertGeo output")

	// And UpsertGeo — recomposed on the same pieces — keeps matching the
	// golden too (the recomposition may not drift from either side).
	require.NoError(t, store.UpsertGeo(path, incoming))
	again, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, golden, string(again),
		"recomposed UpsertGeo must stay byte-identical to the pre-change output")
}

func mustMerged(t *testing.T, existing, incoming []*model.GeoRecord) []*model.GeoRecord {
	t.Helper()
	merged := store.MergeGeoRecords(existing, incoming)
	require.Len(t, merged, 7, "case-variant hosts fold to one identity; the triple mike arrival folds to one record")
	return merged
}
