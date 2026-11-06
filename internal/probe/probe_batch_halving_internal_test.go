package probe

// Adaptive batch halving (v2rayN pattern, big-batch wave): when a batch
// FAILS AS A BATCH (instance boot failure, address-count mismatch, whole-
// batch context death — never per-node handshake failures, which are normal
// outcomes), the UNPROBED nodes of that batch are retried at half the batch
// size, recursively, down to the halving floor of 20 (the pre-big-batch
// default); at the floor the batch is reported failed loudly. Per-node
// verdict logic is untouched — halving is a process-model recovery, not a
// verdict change. Every test here drives the production RunWithBatchFactory
// seam with fixture batch factories, exactly like the pre-filter tests.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"public_vpn/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// batchBootRecorder is the halving fixture BatchFactory: it records every
// boot's batch size and every node that reached the factory, fails the first
// failFirst boots (all boots when alwaysFail), and otherwise hands every
// batch node the loopback socks address (same fakeBatchInstance contract the
// pre-filter fixtures use — one address per batch node).
type batchBootRecorder struct {
	mu         sync.Mutex
	boots      []int
	arrivals   []string
	failFirst  int
	alwaysFail bool
	bootErr    error
	socksAddr  string
}

func (r *batchBootRecorder) factory() BatchFactory {
	return func(_ context.Context, batch []*model.Node) (BatchSocksInstance, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.boots = append(r.boots, len(batch))
		for _, n := range batch {
			r.arrivals = append(r.arrivals, n.Key)
		}
		if r.alwaysFail || len(r.boots) <= r.failFirst {
			return nil, r.bootErr
		}
		addrs := make([]string, len(batch))
		for i := range addrs {
			addrs[i] = r.socksAddr
		}
		return &fakeBatchInstance{addrs: addrs}, nil
	}
}

func (r *batchBootRecorder) bootSizes() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.boots...)
}

func (r *batchBootRecorder) arrivalKeys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.arrivals...)
}

// falsePtr is the explicit-off tri-state pointer (exit-IP echo off in the
// halving fixtures — the tests pin batch mechanics, not the D8 anchor).
func falsePtr() *bool {
	v := false
	return &v
}

// halvingNodes builds n unique-link nodes (unique uuid + host per name), so
// the wave dedup keeps every node as its own probe job.
func halvingNodes(t *testing.T, prefix string, n int) []*model.Node {
	t.Helper()
	nodes := make([]*model.Node, n)
	for i := range nodes {
		nodes[i] = node(t, fmt.Sprintf("%s-%d", prefix, i))
	}
	return nodes
}

// powerOfTwoLadder is the expected always-fail boot ladder for a wave of
// 1024 nodes at batch size 1024: 1024, then 512×2, 256×4, 128×8, 64×16,
// 32×32 — and stop (32/2 = 16 would cross the floor of 20).
func powerOfTwoLadder() []int {
	ladder := []int{1024}
	for size := 512; size >= 32; size /= 2 {
		for range 1024 / size {
			ladder = append(ladder, size)
		}
	}
	return ladder
}

// TestAdaptiveBatchHalvingRecoversBootFailure: the FIRST instance boot fails
// at batch size S → the unprobed nodes retry at S/2 and succeed → every node
// gets an alive outcome exactly once (no duplicates, no losses) and the boot
// ladder is exactly [S, S/2, S/2].
func TestAdaptiveBatchHalvingRecoversBootFailure(t *testing.T) {
	tests := []struct {
		name  string
		wave  int // node count (== batch size: one full batch)
		batch int
		want  []int // expected boot-size ladder
	}{
		{"floor-adjacent batch halves to 20 and recovers", 40, 40, []int{40, 20, 20}},
		{"brief example: 1000-node batch halves once and recovers", 1000, 1000, []int{1000, 500, 500}},
		{"power-of-two batch halves cleanly", 1024, 1024, []int{1024, 512, 512}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			site := healthySite(t)
			socks := newSocksServer(t, site.Listener.Addr().String())
			rec := &batchBootRecorder{
				failFirst: 1,
				bootErr:   errors.New("boom: temp xray instance failed to start"),
				socksAddr: socks.Addr(),
			}
			nodes := halvingNodes(t, "halve", tt.wave)

			opts := baseOpts(site.URL, exitIPEcho(t, "9.9.9.9"))
			opts.Threads = 1
			opts.BatchSize = tt.batch
			opts.BatchConcurrency = 50
			opts.ExitProbe = falsePtr()
			opts.Attempts = 1
			var log strings.Builder
			opts.Progress = &log

			results, err := RunWithBatchFactory(context.Background(), nodes, nil, rec.factory(), opts, "")
			require.NoError(t, err)

			assert.Equal(t, tt.want, rec.bootSizes(), "boot ladder: failed boot at S, retries at S/2")
			require.Len(t, results, tt.wave, "one outcome per node — no losses")
			counts := map[string]int{}
			for _, r := range results {
				counts[r.Key]++
				assert.True(t, r.Alive, "node %s re-probed successfully after the halving retry", r.Key)
				assert.NotEqual(t, "instance-boot", r.FailureKind,
					"the boot failure must not leak into per-node verdicts after recovery")
			}
			for _, n := range nodes {
				assert.Equal(t, 1, counts[n.Key], "node %s probed exactly once (no duplicates)", n.Key)
			}
			assert.Contains(t, log.String(), "adaptive halving", "the halving decision is loud in the wave log")
		})
	}
}

// TestAdaptiveBatchHalvingFloorFailsLoud: a factory that ALWAYS fails boots
// drives the recursion to the floor of 20; below it there is no retry — the
// batch is reported failed loudly with per-node instance-boot outcomes
// (exactly the pre-halving semantics), and every node still gets exactly one
// outcome.
func TestAdaptiveBatchHalvingFloorFailsLoud(t *testing.T) {
	tests := []struct {
		name      string
		wave      int
		batch     int
		want      []int // expected boot-size ladder until the floor
		wantBoots int
	}{
		{"batch at floor size 20 fails without retrying below the floor", 20, 20, []int{20}, 1},
		{"40-node batch descends to exactly 20", 40, 40, []int{40, 20, 20}, 3},
		{"1024-node ladder bottoms out at 32 (16 would cross the floor)", 1024, 1024, powerOfTwoLadder(), 63},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			site := healthySite(t)
			socks := newSocksServer(t, site.Listener.Addr().String()) // never reached
			rec := &batchBootRecorder{
				alwaysFail: true,
				bootErr:    errors.New("boom: temp xray instance failed to start"),
				socksAddr:  socks.Addr(),
			}
			nodes := halvingNodes(t, "floor", tt.wave)

			opts := baseOpts(site.URL, exitIPEcho(t, "9.9.9.9"))
			opts.Threads = 1
			opts.BatchSize = tt.batch
			opts.ExitProbe = falsePtr()
			opts.Attempts = 1
			var log strings.Builder
			opts.Progress = &log

			results, err := RunWithBatchFactory(context.Background(), nodes, nil, rec.factory(), opts, "")
			require.NoError(t, err, "batch boot failure is a loud per-node outcome, never a wave error")

			boots := rec.bootSizes()
			assert.Len(t, boots, tt.wantBoots, "total boot attempts follow the halving ladder")
			assert.ElementsMatch(t, tt.want, boots, "boot sizes follow the halving ladder down to the floor")
			for _, size := range boots {
				assert.GreaterOrEqual(t, size, 20, "no boot ever goes below the halving floor of 20")
			}
			require.Len(t, results, tt.wave, "every node still gets exactly one outcome")
			counts := map[string]int{}
			for _, r := range results {
				counts[r.Key]++
				assert.False(t, r.Alive, "nothing can be alive when every boot fails")
				assert.Equal(t, "instance-boot", r.FailureKind, "floor failure keeps the instance-boot class")
				assert.Contains(t, r.Reason, "boom", "the boot error reason is carried verbatim (one-lined)")
			}
			for _, n := range nodes {
				assert.Equal(t, 1, counts[n.Key], "node %s reported failed exactly once", n.Key)
			}
			assert.Contains(t, log.String(), "halving floor 20 reached",
				"the floor is reported loudly in the wave log")
		})
	}
}

// TestAdaptiveBatchHandshakeFailuresDoNotHalve: the batch instance boots and
// probes fine, but every per-node attempt fails (dead upstream behind the
// socks relay) — per-node handshake failures are NORMAL outcomes and must
// NEVER trigger halving: exactly one boot, no halving lines, outcomes carry
// their real failure class (not instance-boot).
func TestAdaptiveBatchHandshakeFailuresDoNotHalve(t *testing.T) {
	site := healthySite(t) // unused as upstream — the relay points at a refused endpoint
	deadHost, deadPort := refusedEndpoint(t)
	socks := newSocksServer(t, net.JoinHostPort(deadHost, strconv.Itoa(deadPort)))
	rec := &batchBootRecorder{socksAddr: socks.Addr()}
	nodes := halvingNodes(t, "handshake", 40)

	opts := Options{
		Timeout:          2 * time.Second,
		Attempts:         1,
		URL:              site.URL,
		Threads:          1,
		BatchSize:        40,
		BatchConcurrency: 40,
		ExitProbe:        falsePtr(),
		TCPPrefilter:     prefilterOff(),
	}
	var log strings.Builder
	opts.Progress = &log

	results, err := RunWithBatchFactory(context.Background(), nodes, nil, rec.factory(), opts, "")
	require.NoError(t, err)

	assert.Equal(t, []int{40}, rec.bootSizes(), "one boot — handshake failures never halve the batch")
	require.Len(t, results, 40)
	for _, r := range results {
		assert.False(t, r.Alive, "the upstream is dead — the node is honestly failed")
		assert.NotEqual(t, "instance-boot", r.FailureKind,
			"a per-node handshake failure keeps its own failure class")
	}
	assert.NotContains(t, log.String(), "adaptive halving", "no halving on per-node failures")
	assert.NotContains(t, log.String(), "halving floor", "no floor report on per-node failures")
}

// TestAdaptiveBatchHalvingSkipsPrefilteredNodes: the wave-1 TCP pre-filter
// runs BEFORE batching, so a TCP-dead endpoint never enters a batch and can
// never enter a halving retry — the fixture factory must never see its key,
// and it produces no wave record (its probe history stays untouched).
func TestAdaptiveBatchHalvingSkipsPrefilteredNodes(t *testing.T) {
	site := healthySite(t)
	aliveHost, alivePortStr, err := net.SplitHostPort(site.Listener.Addr().String())
	require.NoError(t, err)
	alivePort, err := strconv.Atoi(alivePortStr)
	require.NoError(t, err)
	deadHost, deadPort := refusedEndpoint(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	rec := &batchBootRecorder{
		failFirst: 1,
		bootErr:   errors.New("boom: temp xray instance failed to start"),
		socksAddr: socks.Addr(),
	}

	nodes := make([]*model.Node, 0, 41)
	for i := range 40 {
		nodes = append(nodes, tcpNode(fmt.Sprintf("pf-halve-%d", i), aliveHost, alivePort))
	}
	dead := tcpNode("pf-halve-dead", deadHost, deadPort)
	nodes = append(nodes, dead) // dead last: exclusion is by verdict, not order

	opts := Options{
		Timeout:      5 * time.Second,
		Attempts:     1,
		URL:          site.URL,
		Threads:      1,
		BatchSize:    40,
		ExitProbe:    falsePtr(),
		TCPPrefilter: nil, // default ON — the stage drops the dead endpoint before batching
	}
	var log strings.Builder
	opts.Progress = &log

	results, err := RunWithBatchFactory(context.Background(), nodes, nil, rec.factory(), opts, "")
	require.NoError(t, err)

	for _, key := range rec.arrivalKeys() {
		assert.NotEqual(t, dead.Key, key, "the pre-filtered node never enters a batch — nor a halving retry")
	}
	assert.Equal(t, []int{40, 20, 20}, rec.bootSizes(),
		"only the 40 pre-filter-surviving nodes batch (and halve on the boot failure)")
	require.Len(t, results, 40, "the pre-filtered node produces no wave record")
	for _, r := range results {
		assert.NotEqual(t, dead.Key, r.Key, "no probe-log write for the pre-filtered node")
		assert.True(t, r.Alive, "surviving nodes recovered through the halving retry")
	}
	assert.Contains(t, log.String(), "adaptive halving")
}

// TestBigBatchRunsAsSingleBatch (load shape): a 1000-node wave runs as ONE
// batch — exactly one factory invocation, exactly one "probing batch" line —
// both for an explicit batch_size 1000 and for an UNSET batch_size (the new
// config default of 1000; the old default of 20 would have produced 50
// batches).
func TestBigBatchRunsAsSingleBatch(t *testing.T) {
	tests := []struct {
		name      string
		batchSize int // 0 = unset → the config default
	}{
		{"explicit batch_size 1000", 1000},
		{"unset batch_size rides the new 1000 default", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			site := healthySite(t)
			socks := newSocksServer(t, site.Listener.Addr().String())
			rec := &batchBootRecorder{socksAddr: socks.Addr()}
			nodes := halvingNodes(t, "big", 1000)

			opts := baseOpts(site.URL, exitIPEcho(t, "9.9.9.9"))
			opts.Threads = 1
			opts.BatchSize = tt.batchSize
			opts.BatchConcurrency = 50
			opts.ExitProbe = falsePtr()
			opts.Attempts = 1
			var log strings.Builder
			opts.Progress = &log

			results, err := RunWithBatchFactory(context.Background(), nodes, nil, rec.factory(), opts, "")
			require.NoError(t, err)

			assert.Equal(t, []int{1000}, rec.bootSizes(), "one boot for the whole 1000-node wave")
			batchLines := strings.Count(log.String(), "probing batch of 1000 nodes")
			assert.Equal(t, 1, batchLines, "exactly one batch line for the wave")
			require.Len(t, results, 1000)
			counts := map[string]int{}
			for _, r := range results {
				counts[r.Key]++
				assert.True(t, r.Alive)
			}
			for _, n := range nodes {
				assert.Equal(t, 1, counts[n.Key], "node %s probed exactly once", n.Key)
			}
		})
	}
}
