package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"assay/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jsonlFixture builds the writer inputs once: the escaping-heavy record set
// (HTML-sensitive characters, non-ASCII city, omitempty spread) so any
// encoder swap that alters bytes cannot hide.
func jsonlFixture(t *testing.T) ([]*model.Node, []ProbeResult, map[string]KnownAliveRecord) {
	t.Helper()
	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	nodes := []*model.Node{
		{
			Key: "k1", Source: "plug-a", Scheme: "vless", UUID: "u&s@er", Host: "de1.example.com", Port: 443,
			Params: map[string]string{"sni": "<svc>.example.com", "path": "/ws&x=1"}, FirstSeen: ts, LastSeen: ts,
		},
		{
			Key: "k2", Source: "plug-b", Scheme: "vmess", UUID: "юникод-user", Host: "jp1.example.jp", Port: 2053,
			Fragment: "узел-01", FirstSeen: ts, LastSeen: ts,
		},
	}
	results := []ProbeResult{
		{
			Key: "k1", Host: "de1.example.com", Alive: true, Status: "passed", ExitIP: "203.0.113.7",
			RTTMs: 12.5, SpeedBPS: 1_000_000, Checks: 2, TotalChecks: 2, CheckedAt: ts,
		},
		{
			Key: "k2", Host: "jp1.example.jp", Alive: false, Status: "failed", Reason: "http <403> & blocked",
			FailureKind: "http-status", CheckedAt: ts,
		},
	}
	ka := map[string]KnownAliveRecord{
		"k1": {Key: "k1", Host: "de1.example.com", Link: "vless://u%26s%40er@de1.example.com:443", LastSeen: ts, LastStatus: "passed", AliveStreak: 3, AliveWaveSeq: 9},
		"k2": {Key: "k2", Host: "jp1.example.jp", LastSeen: ts.Add(-time.Hour), LastStatus: "semi-passed", AliveStreak: 1, AliveWaveSeq: 8},
	}
	return nodes, results, ka
}

// goldenPath resolves the frozen byte-parity goldens under testdata.
func goldenPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", "jsonl-goldens", name)
}

// TestJSONLWritersByteParityAgainstGoldens pins the EXACT bytes of all three
// writer loops (writeJSONL via WriteNodes, AppendProbeResults, WriteKnownAlive)
// against goldens frozen on the pre-change tree (allocation audit M3/F6). The
// single-pass encode must not alter a byte: the store files are the W17
// crash-recovery truth and the allocparity pipeline goldens key off them.
func TestJSONLWritersByteParityAgainstGoldens(t *testing.T) {
	nodes, results, ka := jsonlFixture(t)
	dir := t.TempDir()

	nodesPath := filepath.Join(dir, "nodes.jsonl")
	require.NoError(t, WriteNodes(nodesPath, nodes))
	resultsPath := filepath.Join(dir, "probe-results.jsonl")
	require.NoError(t, AppendProbeResults(resultsPath, results))
	kaPath := filepath.Join(dir, "known-alive.jsonl")
	require.NoError(t, WriteKnownAlive(kaPath, ka))

	for _, tc := range []struct{ name, got string }{
		{"nodes.jsonl", nodesPath},
		{"probe-results.jsonl", resultsPath},
		{"known-alive.jsonl", kaPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile(goldenPath(t, tc.name))
			require.NoError(t, err, "golden must exist (frozen pre-change)")
			got, err := os.ReadFile(tc.got)
			require.NoError(t, err)
			assert.Equal(t, string(want), string(got), "writer bytes must stay byte-identical (M3 parity pin)")
		})
	}
}
