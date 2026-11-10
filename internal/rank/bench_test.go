package rank_test

import (
	"fmt"
	"testing"

	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/rank"
	"assay/internal/store"
)

func buildRankCorpus(nodes, countries int) ([]*model.Node, []*model.GeoRecord, map[string]store.ProbeResult) {
	ns := make([]*model.Node, 0, nodes)
	recs := make([]*model.GeoRecord, 0, nodes)
	probe := map[string]store.ProbeResult{}
	for i := range nodes {
		cc := fmt.Sprintf("c%02d", i%countries)
		city := fmt.Sprintf("City%d", i%37)
		n := model.NewNode("s", "vless", fmt.Sprintf("u-%d", i), fmt.Sprintf("n%d.example.com", i), 443,
			map[string]string{"security": "tls", "type": "tcp"})
		ns = append(ns, n)
		recs = append(recs, &model.GeoRecord{
			Source: "s", Scheme: n.Scheme, Host: n.Host, Port: n.Port,
			Country: cc, City: city, Alive: i%10 != 0, // 10% dead
			RTTMs: float64(50 + i%400), SpeedBPS: int64(500_000 + i%9_000_000),
		})
		probe[n.Key] = store.ProbeResult{Key: n.Key, Alive: i%10 != 0, Checks: i % 4, TotalChecks: 3}
	}
	return ns, recs, probe
}

func BenchmarkSelect10kNodes100Countries(b *testing.B) {
	ns, recs, probe := buildRankCorpus(10_000, 100)
	cfg := config.SelectConfig{PerCountryCap: 3, SoftCap: 25, CityExpandThreshold: 25, Ceiling: 40}
	b.ResetTimer()
	for range b.N {
		sel := rank.Select(ns, recs, probe, cfg, 0)
		if len(sel.Nodes) == 0 {
			b.Fatal("empty selection")
		}
	}
}

func BenchmarkSelect50kNodesUnlimitedCities(b *testing.B) {
	ns, recs, probe := buildRankCorpus(50_000, 500)
	cfg := config.SelectConfig{PerCountryCap: 5, SoftCap: 25, CityExpandThreshold: 25, Ceiling: 40}
	b.ResetTimer()
	for range b.N {
		_ = rank.Select(ns, recs, probe, cfg, 0)
	}
}

// BenchmarkSelectUnboundedScaling is the W19 O(N²) regression guard for the
// unbounded DEFAULT (absent caps = all alive selected): the fast path is one
// sort + one pass, so ns/op must scale ~linearly with pool size (300 → 3000
// nodes ≈ 10-15×, not the ~100× of a quadratic rescan). Benchmark-report
// guard — no wall-clock assertions (CI-flake-proof); the structural
// guarantee is the greedy-loop bypass in greedySelect, pinned behaviorally by
// TestUnboundedFastPathPreservesRankOrder.
func BenchmarkSelectUnboundedScaling(b *testing.B) {
	for _, n := range []int{300, 3000} {
		b.Run(fmt.Sprintf("nodes_%d", n), func(b *testing.B) {
			ns, recs, probe := buildRankCorpus(n, 40)
			b.ResetTimer()
			for range b.N {
				sel := rank.Select(ns, recs, probe, config.SelectConfig{}, 0)
				if len(sel.Nodes) == 0 {
					b.Fatal("unbounded select produced an empty selection")
				}
			}
		})
	}
}
