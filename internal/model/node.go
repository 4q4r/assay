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
	Tag           string `json:"tag"`
	Source        string `json:"source"`
	Scheme        string `json:"scheme"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	IP            string `json:"ip"`
	Country       string `json:"country"`
	City          string `json:"city"`
	ASN           string `json:"asn"`
	ASName        string `json:"asname"`
	ISP           string `json:"isp"`
	ProxyFlag     bool   `json:"proxy_flag"`
	HostingFlag   bool   `json:"hosting_flag"`
	FlagsVerified bool   `json:"flags_verified"`
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
	// Run-count liveness (W8): wave sequence in which this node was last
	// confirmed alive, and the consecutive-alive streak. Time-based TTL is
	// superseded by these for liveness decisions.
	AliveWaveSeq int    `json:"alive_wave_seq"`
	AliveStreak  int    `json:"alive_streak"`
	LastAliveAt  string `json:"last_alive_at"`
	// Phase-1 IP quality & media unlock (populated by the geo unlock stage;
	// -1/""/false = unchecked — a record that never ran the stage carries
	// these zero/unset values, and the store's blank-fold keeps a later
	// evidence-less wave from clobbering a checked value).
	RiskScore        int               `json:"risk_score"`        // 0..100 composite; -1 = unchecked
	IsResidential    bool              `json:"is_residential"`    // !hosting && !proxy && (isp || mobile)
	IsHosting        bool              `json:"is_hosting"`        // hosting evidence (ip-api hosting | widget privacy/asn)
	IsProxy          bool              `json:"is_proxy"`          // proxy/vpn/tor evidence
	IsMobile         bool              `json:"is_mobile"`         // mobile-network evidence
	ScamalyticsScore int               `json:"scamalytics_score"` // 0..100; -1 = unchecked (Phase 1 probes no such source)
	AbuseScore       int               `json:"abuse_score"`       // 0..100; -1 = unchecked (Phase 1 probes no such source)
	IPType           string            `json:"ip_type"`           // IPType* constants; "" = unchecked
	MediaUnlocks     MediaUnlockStatus `json:"media_unlocks"`
}

// MediaUnlockStatus is the Phase-1 per-exit-IP media/AI unlock probe result.
// CheckedAt (RFC3339 UTC) is the cache-TTL stamp: "" = never probed. Every
// other field is one of the vocabulary constants below; UnlockUnknown means
// the probe ran but could not produce a definite answer (non-fatal failure).
type MediaUnlockStatus struct {
	ChatGPT       string `json:"chatgpt"`        // UnlockYes|UnlockWebOnly|UnlockAppOnly|UnlockBlocked|UnlockUnknown
	Netflix       string `json:"netflix"`        // UnlockNetflixFull|UnlockNetflixOriginals|UnlockBlocked|UnlockUnknown
	YouTubeRegion string `json:"youtube_region"` // ISO-3166-1 alpha-2 | UnlockBlocked | UnlockUnknown
	Disney        string `json:"disney"`         // UnlockYes|UnlockBlocked|UnlockUnknown
	TikTok        string `json:"tiktok"`         // UnlockYes|UnlockTikTokIDC|UnlockBlocked|UnlockUnknown
	CheckedAt     string `json:"checked_at"`
}

// Unlock/IP-type vocabulary (the stored contract for MediaUnlockStatus and
// GeoRecord.IPType — defined once so producer and consumer never drift).
const (
	UnlockUnknown          = "unknown"
	UnlockYes              = "yes"
	UnlockBlocked          = "blocked"
	UnlockWebOnly          = "webonly"
	UnlockAppOnly          = "apponly"
	UnlockNetflixFull      = "full"
	UnlockNetflixOriginals = "originals"
	UnlockTikTokIDC        = "idc"
	IPTypeResidential      = "Residential"
	IPTypeDataCenter       = "DataCenter"
	IPTypeBusiness         = "Business"
	IPTypeMobile           = "Mobile"
	IPTypeUnknown          = "Unknown"
)

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
	GeneratedAt time.Time `json:"generated_at"`
	// CapApplied is the selection bound actually applied. W19 semantics:
	// every [select] cap defaults to UNBOUNDED, so when no cap is configured
	// CapApplied equals len(Nodes) (every alive node went active); an
	// explicit cap knob reports the bound it enforced.
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
	IsClean bool    `json:"is_clean"` // true when hosting_flag=false && proxy_flag=false
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

// Naming contract for the W16 pseudo-location surface (owner item 14):
//   - UnknownCountryCode is the D5 tag-grammar pseudo-code (cc=xx) carried by
//     unknown-geo nodes: their outbounds stay pool-xx-NN, so the flat tag
//     grammar and every geo-base join stay intact. NOT an ISO code — never
//     confusable with a real country.
//   - UnknownBalancerTag is the pseudo-location balancer tag over those
//     nodes (pool_unknown) — a first-class pool_routes target.
//   - PoolAllBalancerTag is the pool-wide balancer (the «общий балансир»):
//     leastLoad over the ENTIRE pool- namespace, rendered whenever ≥1 pool
//     node exists.
const (
	UnknownCountryCode = "xx"
	UnknownBalancerTag = "pool_unknown"
	PoolAllBalancerTag = "pool_all"
)

// CityBalancerTag renders the per-city balancer tag: pool_<cc>_<city-slug>.
func CityBalancerTag(cc, city string) string {
	return fmt.Sprintf("pool_%s_%s", strings.ToLower(cc), CitySlug(city))
}

// KnownAliveRecord is the durable liveness record persisted in
// known-alive.jsonl. It tracks nodes that have been confirmed alive across
// waves so that (a) probing can skip them within the TTL window and
// (b) nodes removed from source lists are retained ("orphaned but known
// alive") for N waves instead of being dropped immediately.
type KnownAliveRecord struct {
	Key          string    `json:"key"`
	Host         string    `json:"host"`
	Link         string    `json:"link"`
	LastSeen     time.Time `json:"last_seen"`
	LastStatus   string    `json:"last_status"`
	AliveStreak  int       `json:"alive_streak"`
	AliveWaveSeq int       `json:"alive_wave_seq"`
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

// CityKey is the case-folded GROUPING key for city names: geo sources emit
// case variants of the same city ("Frankfurt am Main" / "Frankfurt Am
// Main") that are ONE city on every grouping surface (check geo summary,
// list --cities table + --json, render city-balancer grouping, rank D7
// caps + city-diversity tie-break). Grouping folds through this key;
// DISPLAY never does — the shown spelling is the group's deterministic
// lowest-string variant (CityDisplay), so output is stable across runs no
// matter which variant a geo source hands out. This is a display/grouping
// concern only: stored records (geo-base) keep their original spelling.
// The render city-balancer TAG is still composed through CitySlug — fed
// with the group's CityDisplay spelling, so the slug (CitySlug lowercases
// again, idempotent on the folded display) is variant-independent.
func CityKey(city string) string {
	return strings.ToLower(strings.TrimSpace(city))
}

// CityDisplay picks the deterministic display spelling of a city group:
// the lexicographically lowest (byte-wise) of the two trimmed variants.
// Applied pairwise while folding rows into a group, it converges on the
// group's lowest original casing — the same determinism convention the
// render goldens pin (identical data in, byte-identical output out).
func CityDisplay(a, b string) string {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if b < a {
		return b
	}
	return a
}
