package cli

import (
	"reflect"
	"sync"
	"testing"

	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The batch render cache (allocation audit M6/F9): the probe batch factory
// rendered every node's outbound fresh and re-rendered the WHOLE set on
// every adaptive-halving retry — the halving changes only the member set,
// so unchanged nodes' outbound definitions are reused render-once per wave.

func cacheFixtureNodes(t *testing.T, n int) []*model.Node {
	t.Helper()
	nodes := make([]*model.Node, 0, n)
	for i := range n {
		nodes = append(nodes, model.NewNode("plug-a", "vless", "uuid-"+string(rune('a'+i)),
			"de"+string(rune('a'+i))+".example.com", 443,
			map[string]string{"security": "tls", "type": "tcp", "sni": "svc.example.com"}))
	}
	return nodes
}

func cacheRenderConfig() render.Config {
	return render.Config{TCPMaxSeg: config.DefaultTCPMaxSeg, TLSFingerprint: config.DefaultTLSFingerprint}
}

// TestBatchOutboundCacheRendersOncePerKey is the M6 RED instrument: the
// halving recursion re-invokes the factory with chunk subsets; a node's
// outbound must be BUILT once and REUSED (same map instance) across those
// invocations. Pre-change every call rebuilt every map — the pointer
// identity assertion below fails on the rebuild path.
func TestBatchOutboundCacheRendersOncePerKey(t *testing.T) {
	nodes := cacheFixtureNodes(t, 4)
	cache := newBatchOutboundCache()

	first, err := buildBatchOutbounds(cacheRenderConfig(), cache, nodes)
	require.NoError(t, err)
	require.Len(t, first, len(nodes))

	// The halving-retry shape: a CHUNK subset (member set changed) of the
	// same nodes comes back through the factory.
	retry, err := buildBatchOutbounds(cacheRenderConfig(), cache, nodes[1:3])
	require.NoError(t, err)
	require.Len(t, retry, 2)

	for i := range retry {
		assertMapIdentical(t, first[i+1], retry[i],
			"an unchanged node's outbound map must be reused across factory invocations (audit M6)")
	}
}

// TestBatchOutboundCacheConcurrentWaves pins the concurrency contract: batch
// goroutines share one wave cache over DISJOINT node sets; the mutex must
// make concurrent build+lookup safe (exercised under -race).
func TestBatchOutboundCacheConcurrentWaves(t *testing.T) {
	nodes := cacheFixtureNodes(t, 16)
	cache := newBatchOutboundCache()
	var wg sync.WaitGroup
	errs := make([]error, len(nodes))
	for i, nd := range nodes {
		wg.Add(1)
		go func(i int, nd *model.Node) {
			defer wg.Done()
			got, err := buildBatchOutbounds(cacheRenderConfig(), cache, []*model.Node{nd})
			errs[i] = err
			if err == nil {
				// Second pass: the cache hit path, concurrently with misses.
				_, _ = buildBatchOutbounds(cacheRenderConfig(), cache, []*model.Node{nd})
				if got[0] == nil {
					t.Error("nil outbound")
				}
			}
		}(i, nd)
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
}

// TestBatchOutboundCacheIndependentWaves pins the cache SCOPE: a fresh
// cache (new wave) re-renders — no cross-wave carryover of knob-dependent
// outbounds.
func TestBatchOutboundCacheIndependentWaves(t *testing.T) {
	nodes := cacheFixtureNodes(t, 2)
	first, err := buildBatchOutbounds(cacheRenderConfig(), newBatchOutboundCache(), nodes)
	require.NoError(t, err)
	second, err := buildBatchOutbounds(cacheRenderConfig(), newBatchOutboundCache(), nodes)
	require.NoError(t, err)
	for i := range nodes {
		assertMapIdentical(t, first[i], first[i], "sanity: a map is identical to itself")
		assert.False(t, sameMapInstance(first[i], second[i]),
			"a new wave cache must not reuse the previous wave's maps")
	}
}

// sameMapInstance reports whether two map values are the SAME map object
// (maps are reference types; reflect exposes their identity via Pointer).
func sameMapInstance(a, b map[string]any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

func assertMapIdentical(t *testing.T, a, b map[string]any, msg string) {
	t.Helper()
	require.True(t, sameMapInstance(a, b), "%s (map instance identity)", msg)
}
