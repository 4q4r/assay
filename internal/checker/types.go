// Package checker implements the W8 site-to-location check: for a given set
// of URLs it ranks the node pool by how well each node serves those URLs,
// with per-node geo context from the cold base. Every probe runs OUT-OF-BAND
// through a temporary single-node xray instance (managed binary, SOCKS5
// inbound on 127.0.0.1) — the live client is never involved, the cold base is
// read-only, and nothing is rendered or activated (D2 safety surface).
package checker

import (
	"net"
	"net/url"
	"time"
)

// Verdict is the classification of one HTTP attempt (or of a node overall).
type Verdict string

// Attempt- and node-level verdicts. blocked-* verdicts are the honest
// "blocked-ish" classes: the request completed but the site (or its CDN)
// refused service — they are NEVER silently counted as success.
const (
	VerdictSuccess     Verdict = "success"      // 2xx/3xx (reachable)
	VerdictBlockedHTTP Verdict = "blocked-http" // 403/451/429/5xx
	VerdictBlockedPage Verdict = "blocked-page" // 2xx + blockpage signature in a tiny body
	VerdictDNSFail     Verdict = "dns-fail"     // the node could not resolve the target
	VerdictTLSFail     Verdict = "tls-fail"     // explicit TLS handshake/verification failed
	VerdictDialFail    Verdict = "dial-fail"    // the tunnel CONNECT itself failed (node egress never came up)
	VerdictReadTimeout Verdict = "read-timeout" // connected, but the response stalled (post-connect)
	VerdictCanceled    Verdict = "canceled"     // context canceled (operator abort) — never a timeout
	VerdictTimeout     Verdict = "timeout"      // the probe deadline cut the attempt off
	VerdictPartial     Verdict = "partial"      // node aggregate: some attempts succeeded
	VerdictBlocked     Verdict = "blocked"      // node aggregate: every attempt was blocked-ish
	VerdictFail        Verdict = "fail"         // node aggregate: no HTTP-level answer at all
	VerdictError       Verdict = "error"        // instance/engine failure (not the node's fault per se)
)

// Target is one normalized check target.
type Target struct {
	URL  string `json:"url"`
	Host string `json:"host"`
}

// isHTTPS reports whether the explicit TLS check applies to this target.
func (t Target) isHTTPS() bool { return len(t.URL) >= 8 && t.URL[:8] == "https://" }

// hostPort returns the dialable host:port of the target (explicit port kept,
// scheme default applied). Resolution of the HOST happens at the exit; this
// is the ADDRESS handed through the socks CONNECT.
func (t Target) hostPort() string {
	u, err := url.Parse(t.URL)
	if err != nil || u.Hostname() == "" {
		return net.JoinHostPort(t.Host, "443")
	}
	if u.Port() != "" {
		return u.Host
	}
	port := "443"
	if u.Scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// Attempt is one HTTP request driven through a node's temp instance.
type Attempt struct {
	N         int      `json:"n"`
	Status    int      `json:"status"`   // final HTTP status; 0 = no HTTP answer
	Statuses  []int    `json:"statuses"` // redirect chain + final
	Hops      []string `json:"hops"`     // every URL requested (redirect chain)
	FinalURL  string   `json:"final_url"`
	ConnectMS float64  `json:"connect_ms"` // socks/tunnel setup (includes node connect + remote accept)
	TLSMS     float64  `json:"tls_ms"`     // TLS handshake (https only)
	TTFBMS    float64  `json:"ttfb_ms"`    // request sent → first response byte
	TotalMS   float64  `json:"total_ms"`
	Bytes     int64    `json:"bytes"`
	SpeedBPS  float64  `json:"speed_bps"`
	Verdict   Verdict  `json:"verdict"`
	Signature string   `json:"signature,omitempty"` // blockpage signature that matched
	Err       string   `json:"err,omitempty"`
}

// NodeResult is the per-node outcome for ONE target URL: raw attempts plus
// aggregates computed by Aggregate().
type NodeResult struct {
	Tag     string `json:"tag"`
	Key     string `json:"key"`
	Host    string `json:"host"`
	Country string `json:"country"`
	City    string `json:"city"`
	ASN     string `json:"asn"`
	ISP     string `json:"isp"`

	InstanceFailed bool   `json:"instance_failed,omitempty"`
	InstanceErr    string `json:"instance_err,omitempty"`

	Attempts []Attempt `json:"attempts"`

	// Aggregates (filled by Aggregate).
	OK            int      `json:"ok"`
	Total         int      `json:"total"`
	Statuses      []int    `json:"statuses"`    // unique HTTP statuses seen, ascending
	TLSVersion    string   `json:"tls_version"` // explicit TLS probe result ("1.3" style) or ""
	TLSOK         bool     `json:"tls_ok"`
	TLSErr        string   `json:"tls_err,omitempty"` // explicit TLS probe failure (distinct class)
	ConnectMS     float64  `json:"connect_ms"`        // mean over successful attempts
	AvgTTFBMS     float64  `json:"avg_ttfb_ms"`
	AvgMS         float64  `json:"avg_ms"`
	MedianTotalMS float64  `json:"median_ms"`
	AvgSpeedBPS   float64  `json:"avg_speed_bps"`
	ResolvedIPs   []string `json:"resolved_ips,omitempty"` // as observed at the exit
	DNSMethod     string   `json:"dns_method,omitempty"`   // how ResolvedIPs were observed
	Verdict       Verdict  `json:"verdict"`
	Signature     string   `json:"signature,omitempty"` // blockpage signature that matched
}

// GroupStat is one country or city bucket of the geo summary.
type GroupStat struct {
	Country     string  `json:"country"`
	City        string  `json:"city,omitempty"` // empty on country-level rows
	Nodes       int     `json:"nodes"`
	OK          int     `json:"ok"`
	Total       int     `json:"total"`
	SuccessRate float64 `json:"success_rate"`
	MedianMS    float64 `json:"median_ms"`
	AvgMS       float64 `json:"avg_ms"`
	AvgSpeedBPS float64 `json:"avg_speed_bps"`
}

// TargetResult is one URL's full outcome: per-node rows + geo summary.
type TargetResult struct {
	URL            string        `json:"url"`
	Rows           []*NodeResult `json:"rows"`
	Countries      []GroupStat   `json:"countries"`
	Cities         []GroupStat   `json:"cities"`
	Recommendation []GroupStat   `json:"recommendation"`
}

// Report is the whole check run: what was asked, what answered.
type Report struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Targets     []*TargetResult `json:"targets"`
	Stale       bool            `json:"stale"`
	StaleAge    string          `json:"stale_age,omitempty"`
	GeoTTL      string          `json:"geo_ttl,omitempty"`
	Checked     int             `json:"checked_nodes"`
	Skipped     int             `json:"skipped_dead"`
	Attempts    int             `json:"attempts"`
	Timeout     string          `json:"timeout"`
}
