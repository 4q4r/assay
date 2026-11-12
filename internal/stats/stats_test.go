//go:build unix

package stats_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"assay/internal/model"
	"assay/internal/stats"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realShapedResponse is what `xray api statsquery -pattern "outbound>>>pool-"
// -reset=true` prints on this core (26.3.27): the reflection JSON marshaler
// drops zero-valued counters (protobuf omitempty), so an outbound that only
// has traffic in one direction carries exactly one entry; a value of 0 never
// appears at all. int64 values are JSON numbers.
const realShapedResponse = `{
    "stat": [
        {
            "name": "outbound>>>pool-de-01>>>traffic>>>uplink",
            "value": 5120
        },
        {
            "name": "outbound>>>pool-de-01>>>traffic>>>downlink",
            "value": 102400
        },
        {
            "name": "outbound>>>pool-nl-03>>>traffic>>>downlink",
            "value": 2048
        }
    ]
}`

// fakeXrayStats writes a script that prints the given stdout and exits with
// the given code — the stand-in for the xray api CLI.
func fakeXrayStats(t *testing.T, dir, stdout string, exitCode int) string {
	t.Helper()
	path := filepath.Join(dir, "fake-stats-xray.sh")
	body := fmt.Sprintf("#!/bin/sh\ncat <<'EOF'\n%s\nEOF\nexit %d\n", stdout, exitCode)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o755))
	return path
}

func TestStatsQueryParsesRealShapedResponse(t *testing.T) {
	dir := t.TempDir()
	res, err := stats.Run(context.Background(), stats.Options{
		BinPath: fakeXrayStats(t, dir, realShapedResponse, 0),
		Server:  "127.0.0.1:15490",
		Pattern: "outbound>>>pool-",
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	require.Len(t, res.Deltas, 2, "one delta per outbound with counters")

	byTag := map[string]stats.Delta{}
	for _, d := range res.Deltas {
		byTag[d.Tag] = d
	}
	assert.Equal(t, int64(5120), byTag["pool-de-01"].Up)
	assert.Equal(t, int64(102400), byTag["pool-de-01"].Down)
	assert.Equal(t, int64(0), byTag["pool-nl-03"].Up, "missing uplink counter is a tolerated zero (L7 shape)")
	assert.Equal(t, int64(2048), byTag["pool-nl-03"].Down)
}

func TestStatsQueryToleratesEmptyResponse(t *testing.T) {
	// xray omits the empty stat array entirely — the response is just `{}`.
	// No traffic yet / counters disabled: data-level emptiness, not an error.
	dir := t.TempDir()
	res, err := stats.Run(context.Background(), stats.Options{
		BinPath: fakeXrayStats(t, dir, "{}", 0),
		Server:  "127.0.0.1:15490",
		Pattern: "outbound>>>pool-",
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	assert.Empty(t, res.Deltas)
}

func TestStatsQueryIgnoresNonPoolOutbounds(t *testing.T) {
	// D6 namespace discipline: a pool- pattern substring match cannot return
	// foreign tags, but the fold must never credit one even if it appears.
	dir := t.TempDir()
	res, err := stats.Run(context.Background(), stats.Options{
		BinPath: fakeXrayStats(t, dir, `{"stat":[
			{"name":"outbound>>>pool-de-01>>>traffic>>>uplink","value":10},
			{"name":"outbound>>>proxy-0>>>traffic>>>uplink","value":99999},
			{"name":"outbound>>>direct>>>traffic>>>downlink","value":777}
		]}`, 0),
		Server:  "127.0.0.1:15490",
		Pattern: "outbound>>>pool-",
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	require.Len(t, res.Deltas, 1, "only pool- namespaced counters may fold")
	assert.Equal(t, "pool-de-01", res.Deltas[0].Tag)
}

func TestStatsQueryFailsLoudOnBadExitAndBadJSON(t *testing.T) {
	t.Run("non-zero exit", func(t *testing.T) {
		dir := t.TempDir()
		_, err := stats.Run(context.Background(), stats.Options{
			BinPath: fakeXrayStats(t, dir, "failed to dial 127.0.0.1:15490", 1),
			Server:  "127.0.0.1:15490",
			Pattern: "outbound>>>pool-",
			Timeout: 5 * time.Second,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "statsquery")
	})

	t.Run("malformed JSON body", func(t *testing.T) {
		dir := t.TempDir()
		_, err := stats.Run(context.Background(), stats.Options{
			BinPath: fakeXrayStats(t, dir, "not json at all", 0),
			Server:  "127.0.0.1:15490",
			Pattern: "outbound>>>pool-",
			Timeout: 5 * time.Second,
		})
		require.Error(t, err, "a corrupted response must fail loud, never fold as zeros")
	})

	t.Run("missing binary fails loud", func(t *testing.T) {
		_, err := stats.Run(context.Background(), stats.Options{
			BinPath: filepath.Join(t.TempDir(), "no-such-xray"),
			Server:  "127.0.0.1:15490",
			Pattern: "outbound>>>pool-",
			Timeout: 5 * time.Second,
		})
		require.Error(t, err)
	})
}

func geoWith(tag string, up, down int64) *model.GeoRecord {
	return &model.GeoRecord{Tag: tag, BytesUp: up, BytesDown: down}
}

func TestFoldIncrementsPoolRecords(t *testing.T) {
	// -reset=true makes every poll return the DELTA since the previous poll,
	// so folding is an increment, never an overwrite.
	recs := []*model.GeoRecord{
		geoWith("pool-de-01", 100, 200),
		geoWith("pool-nl-03", 0, 0),
		geoWith("", 500, 500), // cold record never selected: no tag, no counters
	}
	deltas := []stats.Delta{
		{Tag: "pool-de-01", Up: 5120, Down: 102400},
		{Tag: "pool-nl-03", Up: 0, Down: 2048},
	}
	updated, totalUp, totalDown := stats.Fold(recs, deltas)
	assert.Equal(t, 2, updated)
	assert.Equal(t, int64(5120), totalUp)
	assert.Equal(t, int64(104448), totalDown)
	assert.Equal(t, int64(100+5120), recs[0].BytesUp)
	assert.Equal(t, int64(200+102400), recs[0].BytesDown)
	assert.Equal(t, int64(0), recs[1].BytesUp, "missing uplink folds as zero")
	assert.Equal(t, int64(2048), recs[1].BytesDown)
	assert.Equal(t, int64(500), recs[2].BytesUp, "records without tags are untouched")
}

func TestFoldSkipsForeignTagsDefensively(t *testing.T) {
	recs := []*model.GeoRecord{geoWith("proxy-0", 1, 1)}
	updated, _, _ := stats.Fold(recs, []stats.Delta{{Tag: "proxy-0", Up: 99999, Down: 99999}})
	assert.Equal(t, 0, updated, "non-pool tags must never fold (D6 namespace wall)")
	assert.Equal(t, int64(1), recs[0].BytesUp)
}
