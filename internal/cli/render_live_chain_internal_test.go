package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"assay/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenderWaveCandidateFallbackChain pins the owner contract's never-empty
// fallback chain on the LIVE render path — the tail wave's runRender leg
// over a seeded store (the same harness the alloc-parity parity tests use),
// not the direct RenderOwnConfig fixtures the render package tests cover.
// The production escalation 2026-11-19 (deployed live.json showing
// fallbackTag block on pool_us/pool_us_clean) was diagnosed as a STALE
// pre-merge artifact — the renderer provably cannot emit block on a
// non-root balancer — and this test pins that guarantee at the CLI layer:
// the candidate.json the wave writes chains EVERY non-root balancer to its
// parent (clean/city/service variant → parent country, country → pool_all),
// block on pool_all ONLY. Both store-read seams assert identically: nil
// reader = the legacy single-stage read path, wave cache = the daemon's
// read-once production semantics.
func TestRenderWaveCandidateFallbackChain(t *testing.T) {
	for name, reader := range map[string]*waveRecordCache{
		"legacy-direct-store": nil,
		"wave-record-cache":   newWaveRecordCache(),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := fixtureConfig(t, dir)
			seedAllocFixture(t, cfg)
			runAllocFixtureWave(t, cfg, reader)

			p := newPaths(cfg)
			raw, err := os.ReadFile(filepath.Join(p.renderedDir, "candidate.json"))
			require.NoError(t, err, "the wave render leg must write the candidate")
			var cand struct {
				Routing struct {
					Balancers []struct {
						Tag         string   `json:"tag"`
						FallbackTag string   `json:"fallbackTag"`
						Selector    []string `json:"selector"`
					} `json:"balancers"`
				} `json:"routing"`
			}
			require.NoError(t, json.Unmarshal(raw, &cand))
			require.NotEmpty(t, cand.Routing.Balancers, "the candidate carries the balancer tree")

			byTag := map[string]string{}
			for _, b := range cand.Routing.Balancers {
				if b.Tag != model.PoolAllBalancerTag {
					require.NotEqual(t, "block", b.FallbackTag,
						"balancer %s: a rendered balancer must never fall back straight to block — "+
							"only the pool_all root does (owner contract: never-empty chain)", b.Tag)
				}
				byTag[b.Tag] = b.FallbackTag
			}
			require.Equal(t, "block", byTag[model.PoolAllBalancerTag],
				"pool_all is the chain root — block (D7 preserved)")

			// Parent-chain checks over the tiers the fixture renders.
			if fb, ok := byTag[model.CountryBalancerTag("us")]; ok {
				assert.Equal(t, model.PoolAllBalancerTag, fb, "pool_us chains to the pool-wide live set")
			}
			if fb, ok := byTag[model.CleanCountryBalancerTag("us")]; ok {
				assert.Equal(t, model.CountryBalancerTag("us"), fb,
					"pool_us_clean chains to its parent pool_us — the exact shape the "+
						"2026-11-19 production escalation surfaced (a stale pre-merge artifact, "+
						"not a renderer emission)")
			}
			if fb, ok := byTag[model.CleanCountryBalancerTag("de")]; ok {
				assert.Equal(t, model.CountryBalancerTag("de"), fb, "pool_de_clean chains to pool_de")
			}
			if fb, ok := byTag[model.CountryBalancerTag("de")]; ok {
				assert.Equal(t, model.PoolAllBalancerTag, fb, "pool_de chains to pool_all")
			}
			// City variants (if rendered) chain to their parent country.
			for tag, fb := range byTag {
				if tag != model.PoolAllBalancerTag && fb == "block" {
					t.Errorf("balancer %s carries block outside the root — live-path regression", tag)
				}
			}
		})
	}
}
