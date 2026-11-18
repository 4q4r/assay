package geo

// Allocation-audit F2: the classification flush must read geo-base from
// disk exactly ONCE. The pre-change path read it twice — once in
// mergeGeoRecords, then AGAIN inside store.UpsertGeo (which re-read the
// same 12–19MB file, rebuilt the byIdentity map, and re-ran the blank-fold
// matrix over every record). The fused flush merges against the records it
// already read and writes once.

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"assay/internal/model"
	"assay/internal/store"

	"github.com/stretchr/testify/require"
)

func TestFlushReadsGeoBaseOnce(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "geo-base.jsonl")
	prev := &model.GeoRecord{
		Scheme: "vless", Host: "flush1.example.com", Port: 443,
		Country: "de", City: "Berlin", GeoSource: "self-report",
		FirstSeen: "2026-01-01T00:00:00Z", LastSeen: "2026-01-01T00:00:00Z",
	}
	raw, err := jsonMarshalGeoForTest([]*model.GeoRecord{prev})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(base, raw, 0o600))

	n := model.NewNode("s", "vless", "uuid-flush", "flush1.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	now := time.Now().UTC()
	probeByKey := map[string]store.ProbeResult{
		n.Key: {Key: n.Key, Alive: true, RTTMs: 120, ExitIP: "203.0.113.5", CheckedAt: now},
	}

	clf := NewClassifier(ClassifyInput{DataDir: dir})
	reads := 0
	clf.readGeo = func(path string) ([]*model.GeoRecord, error) {
		reads++
		return store.ReadGeo(path)
	}
	writes := 0
	clf.writeGeo = func(path string, merged []*model.GeoRecord) error {
		writes++
		require.Len(t, merged, 1,
			"the flush must write the FULL merged set (existing folded with the wave's records), not the wave subset")
		return store.WriteGeoSorted(path, merged)
	}
	_, _, err = clf.Flush(io.Discard, []*model.Node{n}, probeByKey, 0, now)
	require.NoError(t, err)
	require.Equal(t, 1, reads,
		"the classification flush must read geo-base exactly once through the read seam")
	require.Equal(t, 1, writes,
		"the flush must write through the fused one-pass writer (store.WriteGeoSorted — no re-read, no re-merge), "+
			"not store.UpsertGeo (the double-read/double-merge writer)")

	// The written store keeps the folded record (prev survived via FirstSeen).
	got, err := store.ReadGeo(base)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "2026-01-01T00:00:00Z", got[0].FirstSeen,
		"first_seen must survive the flush fold")
	require.True(t, got[0].Alive, "the probe outcome must fold into the written record")
}

func jsonMarshalGeoForTest(recs []*model.GeoRecord) ([]byte, error) {
	var buf []byte
	for _, r := range recs {
		line, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	return buf, nil
}
