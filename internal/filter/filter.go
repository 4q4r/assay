// Package filter applies the ingest security filter (DESIGN.md §4 step 3):
// keep security=reality|tls only, drop allowInsecure/insecure variants, drop
// private/loopback hosts, dedupe by identity key, and cap per-source output.
package filter

import (
	"fmt"
	"strings"

	"public_vpn/internal/model"
	"public_vpn/internal/parse"
)

// Dropped records why a node was excluded, so the pipeline report can count
// rejection classes.
type Dropped struct {
	Key    string
	Host   string
	Reason string
}

// Options configures Run.
type Options struct {
	// SourceCap limits how many nodes a single source may contribute
	// (DESIGN.md §4 step 3 "per-source caps"). 0 = unlimited.
	SourceCap int
}

// Option mutates Options.
type Option func(*Options)

// WithSourceCap sets the per-source cap.
func WithSourceCap(n int) Option {
	return func(o *Options) { o.SourceCap = n }
}

// Run filters nodes in input order and returns (kept, dropped). The function
// is deterministic: identical input yields identical output order.
func Run(nodes []*model.Node, opts ...Option) ([]*model.Node, []Dropped) {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	var kept []*model.Node
	var dropped []Dropped
	seen := make(map[string]bool, len(nodes))
	perSource := make(map[string]int)
	for _, n := range nodes {
		if reason := reject(n); reason != "" {
			dropped = append(dropped, Dropped{Key: n.Key, Host: n.Host, Reason: reason})
			continue
		}
		if seen[n.Key] {
			dropped = append(dropped, Dropped{
				Key: n.Key, Host: n.Host,
				Reason: "duplicate of an earlier node (same host/port/credential/params)",
			})
			continue
		}
		if o.SourceCap > 0 && perSource[n.Source] >= o.SourceCap {
			dropped = append(dropped, Dropped{
				Key: n.Key, Host: n.Host,
				Reason: fmt.Sprintf("source %q cap %d reached", n.Source, o.SourceCap),
			})
			continue
		}
		seen[n.Key] = true
		perSource[n.Source]++
		kept = append(kept, n)
	}
	return kept, dropped
}

func reject(n *model.Node) string {
	if n.Host == "" {
		return "empty host"
	}
	if n.Port <= 0 || n.Port > 65535 {
		return fmt.Sprintf("invalid port %d", n.Port)
	}
	switch n.Security {
	case "reality", "tls":
	default:
		return fmt.Sprintf("no reality/tls security (security=%q)", n.Security)
	}
	if insecure(n.Params) {
		return "insecure TLS allowed (allowInsecure/insecure=1|true) — rejected by ingest hygiene"
	}
	if parse.IsPrivateHost(n.Host) {
		return fmt.Sprintf("private/loopback host %q", n.Host)
	}
	return ""
}

func insecure(params map[string]string) bool {
	for _, k := range []string{"allowinsecure", "insecure"} {
		switch strings.ToLower(params[k]) {
		case "1", "true":
			return true
		}
	}
	return false
}
