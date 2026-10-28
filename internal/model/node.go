// Package model defines the pipeline's core records: the normalized node
// identity produced by parse/filter, the DESIGN.md §5 cold-base geo record,
// and the tag/balancer naming contract (D5/D6).
package model

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Node is the normalized representation of one accepted proxy link.
// Params carries every link parameter verbatim (L9): sni/host/path/pbk/sid/
// mode/uuid are auth or transport material and are never rewritten.
type Node struct {
	Key       string            `json:"key"`
	Source    string            `json:"source"`
	Scheme    string            `json:"scheme"`
	UUID      string            `json:"uuid"`
	Host      string            `json:"host"`
	Port      int               `json:"port"`
	Network   string            `json:"network"`
	Security  string            `json:"security"`
	Params    map[string]string `json:"params"`
	Fragment  string            `json:"fragment,omitempty"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

// NewNode builds a node and computes its identity key: a hash of
// (scheme, host, port, credential, transport params) per DESIGN.md §4 step 2.
func NewNode(source, scheme, cred, host string, port int, params map[string]string) *Node {
	n := &Node{
		Source:  source,
		Scheme:  strings.ToLower(scheme),
		UUID:    cred,
		Host:    strings.ToLower(host),
		Port:    port,
		Params:  params,
		Network: params["type"],
		Security: func() string {
			if s := params["security"]; s != "" {
				return s
			}
			// trojan is TLS by definition; vmess carries it in the tls field.
			if n2 := strings.ToLower(scheme); n2 == "trojan" {
				return "tls"
			}
			return params["tls"]
		}(),
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}
	n.Key = identityKey(n.Scheme, n.Host, n.Port, n.UUID, n.Params)
	return n
}

func identityKey(scheme, host string, port int, cred string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("\x00")
	b.WriteString(host)
	b.WriteString("\x00")
	b.WriteString(strconv.Itoa(port))
	b.WriteString("\x00")
	b.WriteString(cred)
	for _, k := range keys {
		b.WriteString("\x00")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(params[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])[:16]
}

// Link reconstructs a share-link URI for the node (used to hand links to the
// out-of-band prober). Params are re-encoded verbatim; the fragment carries
// the remark so prober logs stay attributable.
func (n *Node) Link() string {
	q := url.Values{}
	keys := make([]string, 0, len(n.Params))
	for k := range n.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		q.Set(k, n.Params[k])
	}
	cred := n.UUID
	if n.Scheme == "vmess" {
		return n.vmessLink()
	}
	if n.Scheme == "ss" {
		return n.ssLink()
	}
	frag := ""
	if n.Fragment != "" {
		frag = "#" + url.PathEscape(n.Fragment)
	}
	return fmt.Sprintf("%s://%s@%s:%d?%s%s", n.Scheme, url.PathEscape(cred), n.Host, n.Port, q.Encode(), frag)
}

func (n *Node) vmessLink() string {
	payload := map[string]any{
		"v":    "2",
		"ps":   n.Fragment,
		"add":  n.Host,
		"port": strconv.Itoa(n.Port),
		"id":   n.UUID,
	}
	for k, v := range n.Params {
		payload[k] = v
	}
	raw, _ := json.Marshal(payload)
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

// ssLink rebuilds a SIP002 link: ss://base64url(method:password)@host:port.
// method/password are excluded from the query (they are the userinfo); every
// other param re-encodes verbatim.
func (n *Node) ssLink() string {
	q := url.Values{}
	keys := make([]string, 0, len(n.Params))
	for k := range n.Params {
		if k == "method" || k == "password" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		q.Set(k, n.Params[k])
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(n.UUID))
	frag := ""
	if n.Fragment != "" {
		frag = "#" + url.PathEscape(n.Fragment)
	}
	return "ss://" + userinfo + "@" + net.JoinHostPort(n.Host, strconv.Itoa(n.Port)) + "?" + q.Encode() + frag
}

// GeoRecord is the DESIGN.md §5 cold-base record. The JSON field set is a
// regression contract with geo-base.jsonl on disk.
type GeoRecord struct {
	Tag         string `json:"tag"`
	Source      string `json:"source"`
	Scheme      string `json:"scheme"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	IP          string `json:"ip"`
	Country     string `json:"country"`
	City        string `json:"city"`
	ASN         string `json:"asn"`
	ASName      string `json:"asname"`
	ISP         string `json:"isp"`
	ProxyFlag   bool   `json:"proxy_flag"`
	HostingFlag bool   `json:"hosting_flag"`
	// GeoSource marks the provenance of the geo fields: "self-report" (the
	// node answered ip-api through its own tunnel — the strongest exit-geo
	// evidence), "doh-fallback" (the through-tunnel DoH view, indirect), or
	// "" (no geo evidence in the wave that last set the fields). Old
	// batch-era records read as "".
	GeoSource string  `json:"geo_source"`
	FirstSeen string  `json:"first_seen"`
	LastSeen  string  `json:"last_seen"`
	LastProbe string  `json:"last_probe"`
	RTTMs     float64 `json:"rtt_ms"`
	SpeedBPS  int64   `json:"speed_bps"`
	Alive     bool    `json:"alive"`
	BytesUp   int64   `json:"bytes_up"`
	BytesDown int64   `json:"bytes_down"`
}

// ApplyProbe merges a probe wave outcome into the cold record.
func (g *GeoRecord) ApplyProbe(alive bool, rttMs float64, speedBPS int64, probedAt time.Time) {
	g.Alive = alive
	g.RTTMs = rttMs
	g.SpeedBPS = speedBPS
	g.LastProbe = probedAt.UTC().Format(time.RFC3339)
}

// Selection is the outcome of the select stage: the active node set with
// assigned pool tags, grouped so the renderer can build balancers.
type Selection struct {
	GeneratedAt time.Time      `json:"generated_at"`
	CapApplied  int            `json:"cap_applied"`
	CitiesAlive int            `json:"cities_alive"`
	Nodes       []SelectedNode `json:"nodes"`
}

// SelectedNode is one node admitted into the active pool with its tag.
type SelectedNode struct {
	Tag     string  `json:"tag"`
	Key     string  `json:"key"`
	Country string  `json:"country"`
	City    string  `json:"city"`
	RTTMs   float64 `json:"rtt_ms"`
	Speed   int64   `json:"speed"`
	Checks  int     `json:"checks"`
	Total   int     `json:"total_checks"`
}

// PoolTag renders the flat outbound tag per D5: pool-<cc>-NN with cc lowered.
func PoolTag(cc string, seq int) string {
	return fmt.Sprintf("pool-%s-%02d", strings.ToLower(cc), seq)
}

// GeoIdentity is the canonical cold-base record identity:
// scheme (verbatim) | lowercased host | port. Every consumer — the store
// upsert join, the rank select join, the prune orphan rules — must key
// records through THIS function (W7 M2: hoisted from triplicated inline
// copies in store/rank/prune; the equivalence pin lives in
// internal/store/geo_identity_equivalence_test.go). The scheme is
// deliberately not case-normalized: that is the historical on-disk key
// semantics, and changing it would silently re-key the cold base.
func GeoIdentity(g *GeoRecord) string {
	return fmt.Sprintf("%s|%s|%d", g.Scheme, strings.ToLower(g.Host), g.Port)
}

// CountryBalancerTag renders the per-country balancer tag: pool_<cc>.
func CountryBalancerTag(cc string) string {
	return "pool_" + strings.ToLower(cc)
}

// CityBalancerTag renders the per-city balancer tag: pool_<cc>_<city-slug>.
func CityBalancerTag(cc, city string) string {
	return fmt.Sprintf("pool_%s_%s", strings.ToLower(cc), CitySlug(city))
}

// CitySlug lowercases a city name and maps spaces to underscores so it is safe
// inside a xray tag.
func CitySlug(city string) string {
	s := strings.ToLower(strings.TrimSpace(city))
	s = strings.Join(strings.Fields(s), "_")
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
