// Package geo implements the exit-geo classification pass (W11 self-report
// design; W16 adds the HTTPS rung; owner order 2026-11-07 merges the pass
// into the probe batch lifecycle — «сразу на чеке»): EVERY node the probe
// just proved alive is classified THROUGH ITS OWN HOT TUNNEL — the same
// temp instance's socks endpoint, before that instance is torn down. The
// per-node failure ladder, every rung riding the SAME hot instance:
//
//  1. HTTP ip-api self-report — GET http://ip-api.com/json/ with no ip
//     parameter, so ip-api answers "who is asking" and the response IS that
//     node's exit geo (the strongest possible D8 exit-truth evidence).
//  2. HTTPS self-geo — GET [geo].https_url (default https://ipinfo.io/json),
//     keyless and TLS-only: an exit that blocks plain HTTP wholesale (the
//     class W11 could only offer the resolver-network DoH view) is rescued
//     here. Provenance "self-report-https"; the field mapping is honest
//     about the free tier (see applyReport).
//  3. DoH fallback — o-o.myaddr.l.google.com TXT via [geo].doh_url reveals
//     the exit network's own resolver IP; the ip-api single-IP lookup of
//     THAT IP rides the same tunnel (indirect — the resolver network).
//  4. Unknown — no geo evidence; geo fields stay untouched.
//
// On top of the ladder, the SAME hot instance carries the unlock battery v2
// (unlock.go): cftrace echo, 3-source consensus, DNS-over-TCP, media probes,
// hijack detection, OK_FLAKY retry, STUN for hysteria2. One pass, one
// tunnel, per wave per alive node — no freshness gates, no exit-IP cache,
// no eligibility layer (all removed with the separate geo/unlock stages).
// A tunnel that dies mid-battery records honest unknowns for this wave; the
// next wave re-classifies.
//
// Why the old aggregate limit disappears in principle: the batch era POSTed
// groups of exit IPs from THIS box's single source IP against a 15 req/min
// clamp (landmine L6). The self-report's requests originate from thousands
// of DISTINCT node exit IPs — each carries its own per-source budget (45
// req/min per source on the ip-api single endpoint; ipinfo's free tier is
// likewise limited per source IP), so the budget never pools. A small
// politeness pacing (DefaultSelfReportPacing between external request
// starts per node) remains: hourly waves have no reason to burst nodes or
// DoH.
//
// Failure classes fall back, never drop: each rung's transport reset,
// timeout, non-200, or API-level failure advances the ladder. A node whose
// evidence fails entirely stays in the cold base with geo fields untouched —
// missing geo never drops a usable node; the class is reported loud in the
// wave log.
//
// The ip-api free tier is HTTP-only and non-commercial — still satisfied:
// personal use, public geo data, plain HTTP. The ipinfo free tier is
// keyless and personal-use (ToS) — same personal-use footing.
package geo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"assay/internal/model"
	"assay/internal/store"

	"golang.org/x/net/proxy"
)

// SelfReportURL is the ip-api single-IP endpoint WITHOUT an ip parameter:
// the service answers for the caller's own address — the self-report
// semantics. Automatic (no config knob): the whole point of the redesign is
// that nothing about it needs tuning.
const SelfReportURL = "http://ip-api.com/json/"

// Geo field provenance markers (model.GeoRecord.GeoSource).
const (
	GeoSourceSelfReport      = "self-report"
	GeoSourceSelfReportHTTPS = "self-report-https"
	GeoSourceDoHFallback     = "doh-fallback"
)

// Node report classes (the wave log groups by these).
const (
	ClassSelfReport      = GeoSourceSelfReport
	ClassSelfReportHTTPS = GeoSourceSelfReportHTTPS
	ClassDoHFallback     = GeoSourceDoHFallback
	ClassUnknown         = "unknown"
)

// DefaultSelfReportPacing spaces a node's external request starts (ladder
// rungs + battery probes alike — politeness toward nodes and the DoH
// endpoint, NOT a rate-limit honor: each node's requests carry their own
// per-source budget). Deliberately not a config knob.
const DefaultSelfReportPacing = 100 * time.Millisecond

// dohProbeName is the special domain whose TXT answer (queried THROUGH the
// tunnel) carries the IP of the resolver that asked Google — the exit
// network's own resolver in the typical case.
const dohProbeName = "o-o.myaddr.l.google.com"

// Response is the ip-api single-IP answer (ONE JSON object — the batch era
// answered with an ARRAY). Field set pinned from
// http://ip-api.com/docs/api:json (testdata fixtures carry the full
// documented default set; we consume the subset below).
type Response struct {
	Query       string `json:"query"`
	Status      string `json:"status"`
	Message     string `json:"message"` // present only when status=fail
	CountryCode string `json:"countryCode"`
	Country     string `json:"country"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	AS          string `json:"as"`
	ASName      string `json:"asname"`
	Reverse     string `json:"reverse"`
	Proxy       bool   `json:"proxy"`
	Hosting     bool   `json:"hosting"`
	Mobile      bool   `json:"mobile"`
}

// ASN extracts the AS-number token ("AS60781") from the composite as field.
func (r Response) ASN() string {
	f := strings.Fields(r.AS)
	if len(f) > 0 {
		return f[0]
	}
	return ""
}

// InfoResponse is the ipinfo.io /json answer (the hop-2 HTTPS self-geo).
// Field surface verified LIVE 2026-10-29 against the keyless free endpoint:
// ip / hostname / city / region / country (ISO alpha-2) / loc / org /
// postal / timezone / readme. The free tier carries NO proxy/hosting flags
// (ipinfo privacy detection is a paid product) and NO separate ISP field;
// we consume only the fields the cold base stores.
type InfoResponse struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Country string `json:"country"`
	// Org is the composite network field ("AS24940 Hetzner Online GmbH").
	Org string `json:"org"`
}

// ASNPair splits the composite org field into (as, asname) HONESTLY: ipinfo
// has no separate asname field, so the org remainder IS the closest evidence
// for both — the record comment in applyReport documents that class
// difference wherever these values land.
func (r InfoResponse) ASNPair() (string, string) {
	f := strings.Fields(r.Org)
	if len(f) == 0 {
		return "", ""
	}
	return f[0], strings.Join(f[1:], " ")
}

// NodeReport is one node's classification outcome (geo ladder + battery
// fold), keyed by the node and persisted through Flush.
type NodeReport struct {
	Key string
	// ProbeExitIP is the probe wave's observed exit (the D8 anchor the
	// churn check compares against).
	ProbeExitIP string
	Geo         *Response // nil = no ip-api geo evidence this wave
	// HTTPS carries the hop-2 ipinfo answer when that rung succeeded
	// (Class SelfReportHTTPS); nil otherwise.
	HTTPS *InfoResponse
	Class string // ClassSelfReport | ClassSelfReportHTTPS | ClassDoHFallback | ClassUnknown
	// Detail carries the failure chain for the loud wave log ("self-report:
	// …; https: …; doh-fallback: …").
	Detail string
	// Churn marks a self-report (either rung) whose reported IP differs from
	// the probe wave's exit IP (exit churn between the waves — logged loud).
	Churn bool
	// Phase-1 unlock stage (nil = the stage did not run for this exit or it
	// produced no evidence — the cold record keeps whatever it carried).
	Unlocks *model.MediaUnlockStatus
	Quality *IPQuality
	// RateLimited marks a node whose ip-api self-report returned HTTP 429.
	// Such nodes skip further tunnel retries against ip-api; their exit IPs
	// are collected and resolved via the local-machine batch fallback.
	RateLimited bool
	// RateLimitTTL is the retry delay advertised by ip-api via the X-Ttl
	// header on a 429 (zero when absent).
	RateLimitTTL time.Duration
	// EchoIP is the exit IP recovered via the HTTPS echo fallback when
	// self-report fully failed (empty when not recovered).
	EchoIP string
	// RequestRTTMs are the per-request RTTs observed for this node (ms).
	RequestRTTMs []float64
	// TimedOut counts timed-out requests for this node.
	TimedOut int
}

// Summary aggregates the wave's classes for the wave log.
type Summary struct {
	Eligible        int
	SelfReport      int
	SelfReportHTTPS int
	DoHFallback     int
	Unknown         int
	Churn           int
	RequestRTTMs    []float64
	TimedOutCount   int
}

func summarize(reports []NodeReport, eligible int) Summary {
	s := Summary{Eligible: eligible, RequestRTTMs: []float64{}}
	for _, r := range reports {
		switch r.Class {
		case ClassSelfReport:
			s.SelfReport++
		case ClassSelfReportHTTPS:
			s.SelfReportHTTPS++
		case ClassDoHFallback:
			s.DoHFallback++
		case ClassUnknown:
			s.Unknown++
		}
		if r.Churn {
			s.Churn++
		}
		s.RequestRTTMs = append(s.RequestRTTMs, r.RequestRTTMs...)
		s.TimedOutCount += r.TimedOut
	}
	return s
}

func mergeGeoRecords(
	dataDir string, nodes []*model.Node, probeByKey map[string]store.ProbeResult, waveSeq uint64,
	reports map[string]*NodeReport,
) ([]*model.GeoRecord, error) {
	existing, err := store.ReadGeo(filepath.Join(dataDir, "geo-base.jsonl"))
	if err != nil {
		return nil, err
	}
	prevByKey := map[string]*model.GeoRecord{}
	for _, e := range existing {
		prevByKey[model.GeoIdentity(e)] = e
	}
	now := time.Now().UTC()
	// Same-identity records (scheme|host|port) can arrive from distinct node
	// keys (the same server advertised with different credentials/params).
	// Apply their probes in stable (identity, node key) order so the outcome
	// that survives the store's last-write merge never depends on the
	// caller's arrival order — identical inputs always yield the same winner
	// (M-b).
	sorted := make([]*model.Node, len(nodes))
	copy(sorted, nodes)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Scheme != b.Scheme {
			return a.Scheme < b.Scheme
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Key < b.Key
	})
	records := make([]*model.GeoRecord, 0, len(probeByKey))
	for _, n := range sorted {
		pr, ok := probeByKey[n.Key]
		if !ok {
			// Partial probe wave: the node has no probe outcome in the map,
			// so this wave carries no new liveness truth for it. Emit nothing
			// — re-emitting the previous record would either resurrect stale
			// values or (via the store merge) zero Alive/RTT/Speed under a
			// stale last_probe. Unprobed records stay byte-identical on disk.
			continue
		}
		rec := &model.GeoRecord{
			Source: n.Source, Scheme: n.Scheme, Host: n.Host, Port: n.Port,
			FirstSeen: now.Format(time.RFC3339), LastSeen: now.Format(time.RFC3339),
			// Phase-1 scores start unchecked; carried prev records keep theirs.
			RiskScore: -1, ScamalyticsScore: -1, AbuseScore: -1,
		}
		if prev, ok := prevByKey[model.GeoIdentity(rec)]; ok {
			rec = prev
			rec.LastSeen = now.Format(time.RFC3339)
		}
		rec.ApplyProbe(pr.Alive, pr.RTTMs, pr.SpeedBPS, pr.CheckedAt)
		applyReport(rec, reports[n.Key], pr.ExitIP)
		// Run-count liveness (W8).
		if pr.Alive {
			rec.AliveStreak++
			if waveSeq > 0 {
				rec.AliveWaveSeq = int(waveSeq) //nolint:gosec // wave seq fits in int
			} else {
				rec.AliveWaveSeq++
			}
			rec.LastAliveAt = now.Format(time.RFC3339)
		} else {
			rec.AliveStreak = 0
		}
		records = append(records, rec)
	}
	return records, nil
}

// applyReport folds one node's ladder outcome into its cold record.
//   - self-report success (hop 1): geo fields from the node's own ip-api
//     answer; rec.IP takes the response's query IP (the freshest
//     through-tunnel exit truth — it may have churned since the probe wave);
//     provenance "self-report".
//   - self-report-https success (hop 2): geo fields from the node's own
//     ipinfo answer — see the field-mapping honesty note below; provenance
//     "self-report-https".
//   - doh-fallback success (hop 3): geo fields from the exit network's
//     resolver network (indirect — the provenance marker says so); rec.IP
//     keeps the probe's exit IP (the resolver IP is evidence, not the exit).
//   - unknown (hop 4): nothing is written — previous-wave geo survives via
//     the store's blank-fold (missing geo never drops a usable node).
func applyReport(rec *model.GeoRecord, report *NodeReport, probeExitIP string) {
	if report == nil {
		return // not eligible this wave: nothing new to say
	}
	// The D8 anchor: the probe wave's through-tunnel exit IP lands on the
	// record regardless of the geo outcome (the freshest truth below may
	// override it).
	if probeExitIP != "" {
		rec.IP = probeExitIP
	}
	if report != nil && report.EchoIP != "" {
		rec.IP = report.EchoIP
	}
	// Phase-1 fold: attach the unlock stage's verdict BEFORE the class
	// branches below (the HTTPS/unknown branches return early and must not
	// skip it). Both nil = the stage did not run (or produced no evidence)
	// → the record keeps whatever it carried; mergeGeoRecords starts rec
	// from prev, so old values survive an evidence-less wave.
	if report.Quality != nil {
		q := report.Quality
		rec.RiskScore = q.RiskScore
		rec.IsResidential = q.IsResidential
		rec.IsHosting = q.IsHosting
		rec.IsProxy = q.IsProxy
		rec.IsMobile = q.IsMobile
		rec.ScamalyticsScore = q.ScamalyticsScore
		rec.AbuseScore = q.AbuseScore
		rec.IPType = q.IPType
	}
	if report.Unlocks != nil {
		rec.MediaUnlocks = *report.Unlocks
	}
	if report.Class == ClassSelfReportHTTPS {
		if report.HTTPS == nil {
			return // defensive: the class always carries the answer
		}
		g := report.HTTPS
		rec.Country = strings.ToLower(g.Country)
		rec.City = g.City
		rec.ASN, rec.ASName = g.ASNPair()
		// Field-mapping honesty (ipinfo vs ip-api): the free /json tier has
		// no separate ISP field and NO proxy/hosting flags (ipinfo privacy
		// detection is a paid product) — they are written EMPTY here: the
		// freshest evidence wins wholesale, and the self-report-https
		// provenance marker names exactly which class produced the fields,
		// so a consumer never mistakes an empty flag for a measured
		// "not a proxy". Unlike ip-api, ipinfo folds the network name into
		// org: ASName is the org remainder, not a separate upstream field.
		rec.ISP = ""
		rec.ProxyFlag = false
		rec.HostingFlag = false
		rec.FlagsVerified = false
		rec.GeoSource = report.Class
		if g.IP != "" {
			// The https self-report's ip is the freshest through-tunnel exit
			// truth — it wins over the probe-wave anchor (churn logged loud).
			rec.IP = g.IP
		}
		return
	}
	if report.Geo == nil || report.Geo.Status != "success" {
		return // unknown: leave every geo field untouched
	}
	g := report.Geo
	rec.Country = strings.ToLower(g.CountryCode)
	rec.City = g.City
	rec.ASN = g.ASN()
	rec.ASName = g.ASName
	rec.ISP = g.ISP
	rec.ProxyFlag = g.Proxy
	rec.HostingFlag = g.Hosting
	rec.FlagsVerified = true
	rec.GeoSource = report.Class
	if report.Class == ClassSelfReport && g.Query != "" {
		// The self-report's query IP is the freshest through-tunnel exit
		// truth — it wins over the probe-wave anchor (churn is logged loud).
		rec.IP = g.Query
	}
}

// fetchExitIPEcho performs ONE GET against an HTTPS echo endpoint through the
// tunnel and returns the trimmed exit IP string. Used for exit-IP recovery
// when self-report fails entirely.
func fetchExitIPEcho(ctx context.Context, cl *http.Client, endpoint, userAgent string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("exit-ip echo: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("exit-ip echo: not an IP: %q", ip)
	}
	return ip, nil
}

// RateLimitError signals an HTTP 429 from ip-api, carrying the retry delay
// advertised via the X-Ttl header (if any).
type RateLimitError struct {
	StatusCode int
	TTL        time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("ip-api: 429 (retry after %s)", e.TTL)
}

// fetchIPAPI performs ONE GET against an ip-api single-IP endpoint through
// the tunnel and decodes the documented single-object answer. A transport
// error, a non-200 status, and a status=fail body are three distinct failure
// classes for the wave log; all route to the fallback (the returned Response
// is non-nil ONLY on success). HTTP 429 is surfaced as *RateLimitError so
// callers can detect rate limiting and switch to the batch fallback instead
// of retrying through the same tunnel.
func fetchIPAPI(ctx context.Context, cl *http.Client, endpoint, userAgent string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusTooManyRequests {
		ttl := parseTTL(resp.Header.Get("X-Ttl"))
		// also try X-Retry-After? spec says X-Ttl
		return nil, &RateLimitError{StatusCode: resp.StatusCode, TTL: ttl}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip-api: %s", resp.Status)
	}
	var out Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode ip-api response: %w", err)
	}
	if out.Status != "success" {
		msg := out.Message
		if msg == "" {
			msg = "unspecified"
		}
		return nil, fmt.Errorf("ip-api status=%s (%s)", out.Status, msg)
	}
	return &out, nil
}

// fetchHTTPSInfo performs ONE GET against the [geo].https_url endpoint
// (rung 2) through the tunnel and decodes the ipinfo.io /json shape. A
// transport error and a non-200 status are the rung's failure classes for
// the wave log; the returned InfoResponse is non-nil ONLY on success. The
// response carries no API-level status field (unlike ip-api): HTTP 200 with
// a decodable body IS the success contract, verified live 2026-10-29.
func fetchHTTPSInfo(ctx context.Context, cl *http.Client, endpoint, userAgent string) (*InfoResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("https self-geo: %s", resp.Status)
	}
	var out InfoResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode https self-geo response: %w", err)
	}
	if out.IP == "" && out.Country == "" {
		return nil, errors.New("https self-geo response carries neither ip nor country")
	}
	return &out, nil
}

// parseTTL parses an ip-api X-Ttl header value (seconds) into a duration.
func parseTTL(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	// ip-api X-Ttl is seconds.
	if n, err := time.ParseDuration(v + "s"); err == nil {
		return n
	}
	// fallback: integer seconds
	var secs int
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0
		}
		secs = secs*10 + int(c-'0')
	}
	return time.Duration(secs) * time.Second
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded")
}

// NewTunnelClient builds the production through-tunnel HTTP client for one
// temp instance's socks endpoint (exported for the L5 pin test; the Classifier
// is the production caller). The x/net socks dialer forwards HOSTNAMES to the
// proxy (ATYP=domain) — resolution happens at the EXIT (socks5h semantics).
// User-Agent is a per-request concern (the pipeline UA rides each request).
// Keep-alives stay OFF: a node carries 1–2 requests per wave, so connection
// reuse buys nothing while fresh connections keep every request trace clean.
func NewTunnelClient(socksAddr string, timeout time.Duration) (*http.Client, error) {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks dialer: %w", err)
	}
	dialer, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks dialer: no context support")
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			Proxy:               nil, // L5: NEVER http.ProxyFromEnvironment here
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   true, // 1–2 requests per instance: reuse buys nothing
		},
		Timeout: timeout,
	}, nil
}

// pacer spaces external request starts: every caller reserves the next free
// slot (last start + min-delay) and sleeps out the difference. The first
// request never waits; the clock and sleeper are injectable (tests pin the
// spacing without wall time).
type pacer struct {
	minDelay time.Duration
	mu       sync.Mutex
	next     time.Time
	now      func() time.Time
	sleep    func(ctx context.Context, d time.Duration) error
}

func (p *pacer) wait(ctx context.Context) error {
	p.mu.Lock()
	now := p.now()
	start := now
	if p.next.After(now) {
		start = p.next
	}
	p.next = start.Add(p.minDelay)
	p.mu.Unlock()
	d := start.Sub(now)
	if d <= 0 {
		return nil
	}
	return p.sleep(ctx, d)
}
