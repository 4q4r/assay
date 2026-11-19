package parse_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"assay/internal/filter"
	"assay/internal/parse"
)

// buildMixed returns a deterministic mixed corpus of n lines: ~85% valid
// links (vless/trojan), rejected schemes, garbage, blanks (owner mandate:
// parse benchmarks at 10k+ synthetic lines).
func buildMixed(n int) string {
	var b strings.Builder
	b.Grow(n * 140)
	for i := range n {
		switch i % 8 {
		case 0, 1, 2, 3, 4, 5:
			fmt.Fprintf(&b, "vless://uuid-%d@node%d.example.com:443?type=xhttp&security=reality&sni=donor.example&pbk=PK%d&sid=%04x&fp=chrome&mode=packet-up#node-%d\n", i, i, i%7, i&0xffff, i)
		case 6:
			fmt.Fprintf(&b, "trojan://pass-%d@tj%d.example.com:443?type=tcp&security=tls#tj-%d\n", i, i, i)
		case 7:
			switch i % 24 {
			case 7:
				fmt.Fprintln(&b, "tuic://uuid@h.example.com:443?congestion_control=bbr")
			case 15:
				fmt.Fprintln(&b, "ss://YWVzLTI1Ni1nY206cHc@ss.example.com:443#ss")
			case 19:
				fmt.Fprintf(&b, "ss://%s@ssb%d.example.com:8388?sni=s.example.com&type=tcp&plugin=obfs-local%%3Bobfs%%3Dhttp#ss-%d\n",
					base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:benchpw")), i, i)
			case 23:
				fmt.Fprintln(&b, "this line is not a link at all")
			}
		}
	}
	return b.String()
}

func BenchmarkParseLines10k(b *testing.B) {
	corpus := buildMixed(10_000)
	b.SetBytes(int64(len(corpus)))
	b.ResetTimer()
	for range b.N {
		res := parse.Lines("bench", []byte(corpus), nil)
		if len(res.Nodes) < 8700 {
			b.Fatalf("expected >=8700 nodes, got %d", len(res.Nodes))
		}
	}
}

func BenchmarkParseLines50k(b *testing.B) {
	corpus := buildMixed(50_000)
	b.SetBytes(int64(len(corpus)))
	b.ResetTimer()
	for range b.N {
		res := parse.Lines("bench", []byte(corpus), nil)
		if len(res.Nodes) < 43_000 {
			b.Fatalf("expected >=43000 nodes, got %d", len(res.Nodes))
		}
	}
}

func BenchmarkParseLinkSingle(b *testing.B) {
	link := "vless://1918fb45-3312-4893-b3f9-77b7c3e647b6@109.122.197.79:443?type=xhttp&security=reality&sni=www.kit.edu&host=www.kit.edu&path=/&pbk=I-reZxJUuER7atFvxyYlI_OxoDdV0rQev16Hewhjcz4&sid=616f0ee48093b218&fp=chrome&mode=packet-up#Germans"
	b.ResetTimer()
	for range b.N {
		if _, err := parse.Link("bench", link); err != nil {
			b.Fatal(err)
		}
	}
}

// buildMixedWithDrops is the production-shaped corpus (the live funnel:
// ~2/3 of parsed lines drop at the filter): 60% reality keeps, 25%
// no-reality/tls lines, 10% exact duplicates of earlier lines, 5%
// allowInsecure lines.
func buildMixedWithDrops(n int) string {
	var b strings.Builder
	b.Grow(n * 140)
	keep := func(i int) {
		fmt.Fprintf(&b, "vless://uuid-%d@node%d.example.com:443?type=xhttp&security=reality&sni=donor.example&pbk=PK%d&sid=%04x&fp=chrome&mode=packet-up#node-%d\n", i, i, i%7, i&0xffff, i)
	}
	for i := range n {
		switch {
		case i%100 < 60:
			keep(i)
		case i%100 < 85:
			fmt.Fprintf(&b, "vless://uuid-%d@node%d.example.com:443?type=tcp&security=none&sni=donor.example#drop-%d\n", i, i, i)
		case i%100 < 95:
			keep(i - 1) // exact duplicate of the previous line
		default:
			fmt.Fprintf(&b, "vless://uuid-%d@ins.example.com:443?type=tcp&security=reality&insecure=1#ins-%d\n", i, i)
		}
	}
	return b.String()
}

// BenchmarkParseFilterPipeline50k measures the production-shaped parse+filter
// pass over the drop-heavy corpus. two-stage is the pre-F3 shape (unfiltered
// parse, then the filter stage over every parsed node); fused is the F3
// single pass with the filter package's line-level prefilter. Same tree, same
// corpus, same toolchain — the delta isolates the pre-reject effect.
func BenchmarkParseFilterPipeline50k(b *testing.B) {
	corpus := buildMixedWithDrops(50_000)
	b.SetBytes(int64(len(corpus)))
	b.Run("two-stage", func(b *testing.B) {
		for range b.N {
			res := parse.Lines("bench", []byte(corpus), nil)
			kept, _ := filter.Run(res.Nodes)
			if len(kept) < 30_000 {
				b.Fatalf("unexpected kept=%d", len(kept))
			}
		}
	})
	b.Run("fused", func(b *testing.B) {
		for range b.N {
			// A fresh prefilter per iteration is the production shape: its
			// dedup map is per-source, one-shot per wave.
			pre := filter.NewPrefilter(filter.WithProtocols(
				[]string{"vless", "vmess", "trojan", "ss", "hysteria2"}))
			res := parse.Lines("bench", []byte(corpus), pre)
			kept, _ := filter.Run(res.Nodes)
			if len(kept) < 30_000 {
				b.Fatalf("unexpected kept=%d", len(kept))
			}
		}
	})
}
