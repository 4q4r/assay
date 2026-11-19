package probe

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"assay/internal/model"
	"assay/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The journal-bounded skip reporting (allocation audit M4/F7, the S7
// journal-flood lesson): the per-class skip disclosure is ONE summary line
// with counts on the Progress writer; per-node lines move to
// Options.DebugProgress (nil = discard — the production daemon never wires
// it, so the journal stays bounded at any node count).

func summaryFixture(t *testing.T, n int) ([]*model.Node, map[string]store.ProbeResult) {
	t.Helper()
	now := time.Now().UTC()
	nodes := make([]*model.Node, 0, n)
	latest := make(map[string]store.ProbeResult, n)
	for i := range n {
		nd := node(t, "skip"+string(rune('a'+i)))
		nodes = append(nodes, nd)
		// The first two are stale (outside the window) — the rest skip.
		if i < 2 {
			latest[nd.Key] = store.ProbeResult{Key: nd.Key, Alive: true, Status: "passed", CheckedAt: now.Add(-2 * time.Hour)}
			continue
		}
		latest[nd.Key] = store.ProbeResult{Key: nd.Key, Alive: true, Status: "passed", CheckedAt: now.Add(-time.Minute)}
	}
	return nodes, latest
}

func skipSummaryRuns(t *testing.T, log string) int {
	t.Helper()
	return strings.Count(log, "skipping")
}

func TestSkipFreshSummaryLineIsBounded(t *testing.T) {
	nodes, latest := summaryFixture(t, 6)
	var progress, debug strings.Builder
	opts := Options{
		SkipFreshWithin: 30 * time.Minute,
		Latest:          latest,
		Progress:        &progress,
		DebugProgress:   &debug,
		TCPPrefilter:    prefilterOff(),
	}
	skipped := freshSkipSet(nodes, opts, time.Now().UTC())
	require.Len(t, skipped, 4, "four fresh passed nodes sit inside the window")

	assert.Equal(t, 1, skipSummaryRuns(t, progress.String()),
		"exactly ONE summary skip line may hit the journal, no per-node lines")
	assert.Contains(t, progress.String(), "4", "the summary must carry the skip count")
	assert.NotContains(t, progress.String(), "skipa.example.com",
		"per-node detail must not leak into the bounded journal stream")

	perNode := strings.Count(debug.String(), "skipping")
	assert.Equal(t, 4, perNode, "the debug sink carries the per-node skip lines")
	assert.Contains(t, debug.String(), nodes[2].Key, "per-node lines keep the key+age detail")
}

func TestKnownAliveSkipSummaryLineIsBounded(t *testing.T) {
	now := time.Now().UTC()
	nodes := make([]*model.Node, 0, 5)
	ka := make(map[string]store.KnownAliveRecord, 5)
	for i := range 5 {
		nd := node(t, "ka"+string(rune('a'+i)))
		nodes = append(nodes, nd)
		if i == 0 {
			// The first node's entry is outside the TTL — it stays probed.
			ka[nd.Key] = store.KnownAliveRecord{Key: nd.Key, LastSeen: now.Add(-3 * time.Hour), LastStatus: "passed"}
			continue
		}
		ka[nd.Key] = store.KnownAliveRecord{Key: nd.Key, LastSeen: now.Add(-time.Minute), LastStatus: "passed"}
	}
	var progress, debug strings.Builder
	opts := Options{
		KnownAliveTTL: time.Hour,
		KnownAlive:    ka,
		Progress:      &progress,
		DebugProgress: &debug,
		TCPPrefilter:  prefilterOff(),
	}
	skipped := knownAliveSkipSet(nodes, opts, now)
	require.Len(t, skipped, 4)

	assert.Equal(t, 1, skipSummaryRuns(t, progress.String()),
		"exactly ONE summary known-alive skip line, no per-node lines")
	assert.Contains(t, progress.String(), "4", "the summary must carry the skip count")
	assert.Contains(t, progress.String(), "known-alive", "the summary names the skip class")
	assert.Equal(t, 4, strings.Count(debug.String(), "skipping"),
		"the debug sink carries the per-node known-alive skip lines")
}

// TestDebugProgressNilKeepsJournalEmpty pins the production wiring contract:
// with no debug sink wired (the daemon's shape), the skip decision still
// works and the Progress stream carries only the one summary line.
func TestDebugProgressNilKeepsJournalEmpty(t *testing.T) {
	nodes, latest := summaryFixture(t, 6)
	var progress strings.Builder
	opts := Options{
		SkipFreshWithin: 30 * time.Minute,
		Latest:          latest,
		Progress:        &progress,
		TCPPrefilter:    prefilterOff(),
	}
	skipped := freshSkipSet(nodes, opts, time.Now().UTC())
	require.Len(t, skipped, 4)
	assert.Equal(t, 1, skipSummaryRuns(t, progress.String()))
	assert.NotContains(t, progress.String(), "skipc.example.com")
}

// TestRunContextSkipsStayOffOutcomeOrder guards the regression surface the
// summary rework touches: the probed set stays intact when the skip plumbing
// runs through the full Run path (the summary lines must not change WHO is
// probed — the two stale nodes pass, exactly as pre-change).
func TestRunContextSkipsStayOffOutcomeOrder(t *testing.T) {
	nodes, latest := summaryFixture(t, 6)
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	var probed atomic.Int32
	factory := Factory(func(_ context.Context, nd *model.Node) (SocksInstance, error) {
		probed.Add(1)
		return &staticInstance{addr: socks.Addr()}, nil
	})
	out, err := Run(context.Background(), nodes, factory,
		Options{SkipFreshWithin: 30 * time.Minute, Latest: latest, TCPPrefilter: prefilterOff()}, "")
	require.NoError(t, err)
	require.Len(t, out, 2, "only the two stale nodes are probed")
	assert.Equal(t, int32(2), probed.Load())
	probedKeys := map[string]bool{out[0].Key: true, out[1].Key: true}
	assert.True(t, probedKeys[nodes[0].Key] && probedKeys[nodes[1].Key],
		"the probed pair is the stale pair")
}
