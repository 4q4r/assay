package render_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"assay/internal/model"
	"assay/internal/render"
)

// benchTemplate builds a template with the live-config structure at scale:
// the pool insertion work grows with outbounds/rules, so the benchmark pins
// render cost against a large host config too.
func benchTemplate(outbounds, rules int) []byte {
	m := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"dns": map[string]any{"queryStrategy": "UseIPv4"},
		"burstObservatory": map[string]any{
			"subjectSelector": []any{"proxy-"},
			"pingConfig":      map[string]any{"destination": "http://1.1.1.1/cdn-cgi/trace", "interval": "10s", "sampling": 5, "timeout": "3s"},
		},
		"inbounds": []any{
			map[string]any{"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}},
			map[string]any{"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": map[string]any{}},
		},
	}
	obs := make([]any, 0, outbounds+1)
	obs = append(obs, map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "AsIs"}})
	for i := range outbounds {
		obs = append(obs, map[string]any{
			"tag": fmt.Sprintf("proxy-%d", i), "protocol": "vless",
			"settings":       map[string]any{"vnext": []any{map[string]any{"address": fmt.Sprintf("198.51.100.%d", i%254+1), "port": 443, "users": []any{map[string]any{"id": "00000000-0000-0000-0000-000000000001", "encryption": "none"}}}}},
			"streamSettings": map[string]any{"network": "xhttp", "security": "reality", "sockopt": map[string]any{"tcpMaxSeg": 1440}, "realitySettings": map[string]any{"fingerprint": "firefox", "serverName": "donor.example", "publicKey": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "shortId": "AA"}},
		})
	}
	m["outbounds"] = obs
	rs := make([]any, 0, rules+1)
	for i := range rules {
		rs = append(rs, map[string]any{"type": "field", "inboundTag": []any{"socks-in", "http-in"}, "domain": []any{fmt.Sprintf("domain:bench%d.example", i)}, "outboundTag": "direct"})
	}
	rs = append(rs, map[string]any{"type": "field", "inboundTag": []any{"socks-in", "http-in"}, "network": "tcp,udp", "balancerTag": "best_rtt"})
	m["routing"] = map[string]any{
		"domainStrategy": "IPIfNonMatch",
		"rules":          rs,
		"balancers": []any{map[string]any{
			"tag": "best_rtt", "selector": []any{"proxy-"},
			"strategy": map[string]any{"type": "leastLoad", "settings": map[string]any{"expected": 1, "tolerance": 0.2}},
		}},
	}
	b, _ := json.Marshal(m)
	return b
}

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

func BenchmarkRender25PoolLargeTemplate(b *testing.B) {
	tpl := benchTemplate(50, 400)
	sel, byKey := benchSelection(25)
	cfg := render.Config{StatsPort: 15490}
	b.ResetTimer()
	for range b.N {
		if _, err := render.Render(render.Input{Template: tpl, Selection: sel, NodesByKey: byKey, Cfg: cfg}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRender40PoolCeiling(b *testing.B) {
	tpl := benchTemplate(10, 50)
	sel, byKey := benchSelection(40)
	cfg := render.Config{StatsPort: 15490}
	b.ResetTimer()
	for range b.N {
		if _, err := render.Render(render.Input{Template: tpl, Selection: sel, NodesByKey: byKey, Cfg: cfg}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRenderEmissionScaling is the W19 O(N²) regression guard for the
// render emission path under the UNBOUNDED selection default: 100 countries
// × 37 cities of balancers (harder than the owner's live 40 countries) plus
// the adaptive-observatory arithmetic. Emission must stay linear-ish —
// 300 → 3000 nodes ≈ 10-15× ns/op, not ~100×. Benchmark-report guard (no
// wall-clock assertions); the grouping itself is map-based single passes
// (addBalancers), verified by construction.
func BenchmarkRenderEmissionScaling(b *testing.B) {
	tpl := benchTemplate(5, 40)
	cfg := render.Config{StatsPort: 15490}
	for _, n := range []int{300, 3000} {
		b.Run(fmt.Sprintf("nodes_%d", n), func(b *testing.B) {
			sel, byKey := benchSelection(n)
			b.ResetTimer()
			for range b.N {
				if _, err := render.Render(render.Input{Template: tpl, Selection: sel, NodesByKey: byKey, Cfg: cfg}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
