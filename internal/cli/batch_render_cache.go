package cli

import (
	"fmt"
	"sync"

	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/render"
)

// batchOutboundCache is the probe stage's render-once cache for batch
// outbound definitions (allocation audit M6/F9). The adaptive-halving loop
// re-invokes the batch factory per retry with a shrinking member set; the
// outbounds are pure functions of (node, wave-constant knobs), so each
// node's outbound is BUILT once per wave and REUSED across retries. One
// cache per factory instance — newProbeBatchFactory creates it per wave, so
// knob changes between waves never see stale definitions.
//
// Concurrency: separate batch goroutines share the cache over disjoint node
// sets (batches slice `ordered` disjointly; halving chunks are sequential
// within one batch), and StartTempXrayBatch clones each outbound map before
// stamping its position tag, so the cached maps are read-only after build.
// The mutex covers the build-or-lookup.
type batchOutboundCache struct {
	mu    sync.Mutex
	byKey map[string]map[string]any
}

func newBatchOutboundCache() *batchOutboundCache {
	return &batchOutboundCache{byKey: map[string]map[string]any{}}
}

// buildBatchOutbounds returns the batch's outbound definitions, rendering
// only the nodes the cache has not seen this wave. The hardening-knob
// defaults are materialized here (the same normalization the factory
// applied pre-cache), so a cached definition is byte-equal to a fresh one.
func buildBatchOutbounds(
	rcfg render.Config, cache *batchOutboundCache, nodes []*model.Node,
) ([]map[string]any, error) {
	if rcfg.TCPMaxSeg == 0 {
		rcfg.TCPMaxSeg = config.DefaultTCPMaxSeg
	}
	if rcfg.TLSFingerprint == "" {
		rcfg.TLSFingerprint = config.DefaultTLSFingerprint
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	outbounds := make([]map[string]any, len(nodes))
	for i, n := range nodes {
		ob, ok := cache.byKey[n.Key]
		if !ok {
			built, _, err := render.BuildOutbound(n, fmt.Sprintf("probe-out-%d", i), rcfg)
			if err != nil {
				return nil, fmt.Errorf("render outbound for batch node %d: %w", i, err)
			}
			cache.byKey[n.Key] = built
			ob = built
		}
		outbounds[i] = ob
	}
	return outbounds, nil
}
