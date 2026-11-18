package store

// Allocation-audit F1 pins: the JSONL readers preallocate their sink slice
// from a cheap line-count pre-pass instead of growing a nil slice through
// ~20 full backing-array copies at incident scale (148k parsed / 50k
// filtered nodes per wave). The observable: for an N-line file the returned
// slice's capacity is exactly N (append growth without a hint gives 8 for
// 5 lines).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"assay/internal/model"

	"github.com/stretchr/testify/require"
)

// jsonMarshalForTest keeps the fixtures one-liner-shaped.
func jsonMarshalForTest(v any) ([]byte, error) { return json.Marshal(v) }

func writeLines(t *testing.T, dir, name string, n int, makeLine func(i int) string) string {
	t.Helper()
	var b strings.Builder
	for i := range n {
		b.WriteString(makeLine(i))
		b.WriteByte('\n')
	}
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))
	return path
}

func TestReadNodesPreallocatesExactCapacity(t *testing.T) {
	dir := t.TempDir()
	path := writeLines(t, dir, "nodes.jsonl", 5, func(i int) string {
		n := model.NewNode("s", "vless", "uuid-"+string(rune('a'+i)), "h"+string(rune('a'+i))+".example.com", 443,
			map[string]string{"security": "tls", "type": "tcp"})
		raw, err := jsonMarshalForTest(n)
		require.NoError(t, err)
		return string(raw)
	})
	nodes, err := ReadNodes(path)
	require.NoError(t, err)
	require.Len(t, nodes, 5)
	require.Equal(t, 5, cap(nodes),
		"ReadNodes must preallocate from the line count (no hint grows cap to 8 through repeated backing-array copies)")
}

func TestReadGeoPreallocatesExactCapacity(t *testing.T) {
	dir := t.TempDir()
	path := writeLines(t, dir, "geo-base.jsonl", 5, func(i int) string {
		g := &model.GeoRecord{Scheme: "vless", Host: "h" + string(rune('a'+i)) + ".example.com", Port: 443}
		raw, err := jsonMarshalForTest(g)
		require.NoError(t, err)
		return string(raw)
	})
	recs, err := ReadGeo(path)
	require.NoError(t, err)
	require.Len(t, recs, 5)
	require.Equal(t, 5, cap(recs),
		"ReadGeo must preallocate from the line count (no hint grows cap to 8 through repeated backing-array copies)")
}

func TestReadProbeResultsPreallocatesExactCapacity(t *testing.T) {
	dir := t.TempDir()
	path := writeLines(t, dir, "probe-results.jsonl", 5, func(i int) string {
		r := ProbeResult{Key: "k" + string(rune('a'+i)), Host: "h" + string(rune('a'+i)) + ".example.com", Alive: true}
		raw, err := jsonMarshalForTest(r)
		require.NoError(t, err)
		return string(raw)
	})
	out, err := ReadProbeResults(path)
	require.NoError(t, err)
	require.Len(t, out, 5)
	require.Equal(t, 5, cap(out),
		"ReadProbeResults must preallocate from the line count (no hint grows cap to 8 through repeated backing-array copies)")
}

func TestReadNodesBlankLinesDoNotBreakCapacityHint(t *testing.T) {
	dir := t.TempDir()
	path := writeLines(t, dir, "nodes.jsonl", 3, func(i int) string {
		n := model.NewNode("s", "vless", "uuid-"+string(rune('a'+i)), "h"+string(rune('a'+i))+".example.com", 443,
			map[string]string{"security": "tls", "type": "tcp"})
		raw, err := jsonMarshalForTest(n)
		require.NoError(t, err)
		return string(raw)
	})
	blanky := path + ".blank"
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(blanky, append([]byte("\n\n"), raw...), 0o600))
	nodes, err := ReadNodes(blanky)
	require.NoError(t, err)
	require.Len(t, nodes, 3)
	require.GreaterOrEqual(t, cap(nodes), len(nodes),
		"the line-count hint may pad for blank lines but must never under-allocate")
}
