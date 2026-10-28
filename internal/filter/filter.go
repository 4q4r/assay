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
	// AllowedProtocols is the scheme acceptance allowlist (the [filter]
	// .protocols policy). A scheme outside it is dropped. nil/empty = built-in
	// default vless,vmess,trojan.
	AllowedProtocols map[string]bool
	// AllowInsecure admits links carrying allowInsecure/insecure=1|true
	// (the [filter].allow_insecure policy). Default false: denial in filter.
	AllowInsecure bool
}

// Option mutates Options.
type Option func(*Options)

// WithSourceCap sets the per-source cap.
func WithSourceCap(n int) Option {
	return func(o *Options) { o.SourceCap = n }
}

// WithProtocols sets the scheme allowlist (nil = default vless,vmess,trojan).
func WithProtocols(schemes []string) Option {
	return func(o *Options) {
		if len(schemes) == 0 {
			o.AllowedProtocols = nil
			return
		}
		o.AllowedProtocols = make(map[string]bool, len(schemes))
		for _, s := range schemes {
			o.AllowedProtocols[s] = true
		}
	}
}

// WithAllowInsecure admits allowInsecure links (default: dropped).
func WithAllowInsecure(v bool) Option {
	return func(o *Options) { o.AllowInsecure = v }
}

// defaultProtocols mirrors [filter].protocols' documented default.
var defaultProtocols = map[string]bool{"vless": true, "vmess": true, "trojan": true}

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
		if reason := reject(n, o); reason != "" {
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

func reject(n *model.Node, o Options) string {
	allowed := o.AllowedProtocols
	if allowed == nil {
		allowed = defaultProtocols
	}
	if !allowed[n.Scheme] {
		return fmt.Sprintf("scheme %q not in the [filter].protocols allowlist", n.Scheme)
	}
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
	if !o.AllowInsecure && insecure(n.Params) {
		return "insecure TLS allowed (allowInsecure/insecure=1|true) — " +
			"rejected by ingest hygiene ([filter].allow_insecure=false)"
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
