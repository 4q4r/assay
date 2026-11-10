package filter_test

import (
	"fmt"
	"strings"
	"testing"

	"assay/internal/filter"
	"assay/internal/model"
)

// buildNodes makes n distinct nodes (plus n/4 exact duplicates for the dedupe
// path) across a handful of sources.
func buildNodes(n int) []*model.Node {
	nodes := make([]*model.Node, 0, n+n/4)
	for i := range n {
		nod := model.NewNode(fmt.Sprintf("src%d", i%5), "vless", fmt.Sprintf("uuid-%d", i),
			fmt.Sprintf("node%d.example.com", i), 443, map[string]string{
				"security": "tls", "type": "xhttp", "sni": "donor.example",
			})
		nodes = append(nodes, nod)
		if i%4 == 0 {
			dup := model.NewNode("other-src", "vless", fmt.Sprintf("uuid-%d", i),
				fmt.Sprintf("node%d.example.com", i), 443, map[string]string{
					"security": "tls", "type": "xhttp", "sni": "donor.example",
				})
			nodes = append(nodes, dup)
		}
	}
	return nodes
}

func BenchmarkFilterDedupe10k(b *testing.B) {
	nodes := buildNodes(10_000)
	b.ResetTimer()
	for range b.N {
		kept, dropped := filter.Run(nodes)
		if len(kept) < 9000 || len(dropped) < 2000 {
			b.Fatalf("unexpected counts: kept=%d dropped=%d", len(kept), len(dropped))
		}
	}
}

func BenchmarkFilterDedupe50k(b *testing.B) {
	nodes := buildNodes(50_000)
	b.ResetTimer()
	for range b.N {
		filter.Run(nodes)
	}
}

func BenchmarkFilterRejectClasses(b *testing.B) {
	// Heavy-rejection corpus: only every 10th node is acceptable.
	nodes := make([]*model.Node, 0, 10_000)
	for i := range 10_000 {
		var nod *model.Node
		if i%10 == 0 {
			nod = model.NewNode("s", "vless", fmt.Sprintf("u%d", i), fmt.Sprintf("ok%d.example.com", i), 443,
				map[string]string{"security": "tls", "type": "tcp"})
		} else {
			nod = model.NewNode("s", "vless", fmt.Sprintf("u%d", i), fmt.Sprintf("10.0.%d.%d", i/256, i%256), 443,
				map[string]string{"security": "tls", "type": "tcp"})
		}
		nodes = append(nodes, nod)
	}
	b.ResetTimer()
	for range b.N {
		kept, dropped := filter.Run(nodes)
		if len(kept) != 1000 || len(dropped) != 9000 {
			b.Fatalf("unexpected: kept=%d dropped=%d", len(kept), len(dropped))
		}
	}
}

// keep imports honest if the corpus builder changes shape.
var _ = strings.TrimSpace
