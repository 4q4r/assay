package render_test

import (
	"fmt"
	"testing"

	"assay/internal/model"
	"assay/internal/render"
)

// benchSelection builds an own-render selection at scale: the emission work
// (outbounds + balancers) grows with the active count, so the benchmarks pin
// render cost against the shapes that matter for the daemon.
func benchSelection(nodes int) (*model.Selection, map[string]*model.Node) {
	sel := &model.Selection{}
	byKey := map[string]*model.Node{}
	for i := range nodes {
		city := fmt.Sprintf("City%d", i%37)
		cc := fmt.Sprintf("c%02d", i%100)
		n := model.NewNode("s", "vless", fmt.Sprintf("u-%d", i), fmt.Sprintf("n%d.example.com", i), 443,
			map[string]string{"type": "xhttp", "security": "reality", "sni": "donor.example", "pbk": "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M", "sid": "b1", "host": "cdn.example", "path": "/p", "mode": "packet-up"})
		byKey[n.Key] = n
		sel.Nodes = append(sel.Nodes, model.SelectedNode{
			Tag: model.PoolTag(cc, i/100+1), Key: n.Key, Country: cc, City: city,
		})
	}
	return sel, byKey
}

func benchRender(b *testing.B, n int) {
	b.Helper()
	sel, byKey := benchSelection(n)
	b.ResetTimer()
	for range b.N {
		if _, _, err := render.RenderOwnConfig(sel, ownCore(), nil, byKey, nil, render.Config{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRender25Pool(b *testing.B) {
	benchRender(b, 25)
}

func BenchmarkRender40PoolCeiling(b *testing.B) {
	benchRender(b, 40)
}

// BenchmarkRenderEmissionScaling is the W19 O(N²) regression guard for the
// render emission path under the UNBOUNDED selection default: 100 countries
// × 37 cities of balancers (harder than the owner's live 40 countries) plus
// the adaptive-observatory arithmetic. Emission must stay linear-ish —
// 300 → 3000 nodes ≈ 10-15× ns/op, not ~100×. Benchmark-report guard (no
// wall-clock assertions); the grouping itself is map-based single passes
// (addBalancers), verified by construction.
func BenchmarkRenderEmissionScaling(b *testing.B) {
	for _, n := range []int{300, 3000} {
		b.Run(fmt.Sprintf("nodes_%d", n), func(b *testing.B) {
			benchRender(b, n)
		})
	}
}
