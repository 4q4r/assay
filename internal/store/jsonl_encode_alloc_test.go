//go:build !race

package store

import (
	"path/filepath"
	"testing"

	"assay/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Alloc-count instruments live behind !race: the race detector's own
// instrumentation allocates deterministically per operation and would
// falsify every bound here. The byte-parity pins in
// jsonl_encode_internal_test.go stay race-clean.

// TestJSONLWritersEncodeSinglePass is the audit M3 RED instrument: the three
// writer loops must stop paying the per-record double copy (json.Marshal
// slice + append(b, '\n') copy) and encode in a single pass to the buffered
// writer. Bounds sit BETWEEN the measured pre-change and post-change values
// on this toolchain (pre: 3.15 / 8.47 / 3.16 allocs per record —
// WriteNodes / AppendProbeResults / WriteKnownAlive; post: 2.16 / 7.48 /
// 2.17), so each arm fails on the pre-change tree and holds on the
// single-pass encode. AppendProbeResults' residual includes its internal
// journal re-read (the compacted latest-per-key rewrite design — out of M3
// scope, see the alloc-wave F1 report's disclosed concern).
func TestJSONLWritersEncodeSinglePass(t *testing.T) {
	const n = 100
	nodes, results, ka := jsonlFixture(t)
	grown := make([]*model.Node, 0, n)
	for i := range n {
		cl := *nodes[i%len(nodes)]
		cl.Key = "k" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		grown = append(grown, &cl)
	}
	grownResults := make([]ProbeResult, 0, n)
	for i := range n {
		r := results[i%len(results)]
		r.Key = grown[i].Key
		grownResults = append(grownResults, r)
	}
	grownKA := make(map[string]KnownAliveRecord, n)
	for i := range n {
		rec := ka["k1"]
		rec.Key = grown[i].Key
		grownKA[grown[i].Key] = rec
	}

	dir := t.TempDir()
	t.Run("WriteNodes", func(t *testing.T) {
		allocs := testing.AllocsPerRun(30, func() {
			require.NoError(t, WriteNodes(filepath.Join(dir, "nodes.jsonl"), grown))
		})
		t.Logf("allocs/op: %.0f (%.2f/record)", allocs, allocs/n)
		assert.Less(t, allocs/n, 2.7,
			"WriteNodes must encode single-pass — no per-record Marshal-slice + newline-append copy pair (audit M3)")
	})
	t.Run("AppendProbeResults", func(t *testing.T) {
		allocs := testing.AllocsPerRun(30, func() {
			require.NoError(t, AppendProbeResults(filepath.Join(dir, "probe-results.jsonl"), grownResults))
		})
		t.Logf("allocs/op: %.0f (%.2f/record)", allocs, allocs/n)
		assert.Less(t, allocs/n, 8.0,
			"AppendProbeResults' write loop must encode single-pass (audit M3)")
	})
	t.Run("WriteKnownAlive", func(t *testing.T) {
		allocs := testing.AllocsPerRun(30, func() {
			require.NoError(t, WriteKnownAlive(filepath.Join(dir, "known-alive.jsonl"), grownKA))
		})
		t.Logf("allocs/op: %.0f (%.2f/record)", allocs, allocs/n)
		assert.Less(t, allocs/n, 2.7,
			"WriteKnownAlive must encode single-pass — no per-record Marshal-slice + newline-append copy pair (audit M3)")
	})
}
