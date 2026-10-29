// Package geo implements the exit-geo enrichment stage (W11 self-report
// design; W16 adds the HTTPS rung): EVERY alive node asks geo endpoints
// THROUGH ITS OWN TUNNEL. The per-node failure ladder, every rung riding the
// SAME temp socks instance:
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
// Why the old aggregate limit disappears in principle: the batch era POSTed
// groups of exit IPs from THIS box's single source IP against a 15 req/min
// clamp (landmine L6). The self-report's requests originate from thousands
// of DISTINCT node exit IPs — each carries its own per-source budget (45
// req/min per source on the ip-api single endpoint; ipinfo's free tier is
// likewise limited per source IP), so the budget never pools. A small
// politeness pacing (DefaultSelfReportPacing between external request
// starts) remains: hourly waves have no reason to burst nodes or DoH.
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
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/store"

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

// DefaultSelfReportPacing spaces external request starts across the wave
// (politeness toward nodes and the DoH endpoint — NOT a rate-limit honor:
// each node's requests carry their own per-source budget). Roughly the old
// batch era's per-IP throughput; deliberately not a config knob.
const DefaultSelfReportPacing = 100 * time.Millisecond

// selfReportConcurrency bounds how many temp instances exist at once (each
// is a full xray process — parity with the checker's default).
const selfReportConcurrency = 4

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
	City        string `json:"city"`
	ISP         string `json:"isp"`
	AS          string `json:"as"`
	ASName      string `json:"asname"`
	Proxy       bool   `json:"proxy"`
	Hosting     bool   `json:"hosting"`
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

// SocksInstance is one live temp SOCKS5 endpoint (structural mirror of the
// checker's type: the production instance is a temp single-node xray).
type SocksInstance interface {
	Addr() string
	Close() error
}

// Factory spawns one instance per node — the piggyback infrastructure. The
// CLI wires checker.NewXrayFactory here (same render.BuildOutbound outbound,
// same hardening, same bootMu port handout as the check stage).
type Factory func(ctx context.Context, n *model.Node) (SocksInstance, error)

// NodeReport is one node's geo outcome.
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
}

// Summary aggregates the wave's classes for the wave log.
type Summary struct {
	Eligible        int
	SelfReport      int
	SelfReportHTTPS int
	DoHFallback     int
	Unknown         int
	Churn           int
}

// Input bundles the geo stage dependencies.
type Input struct {
	DataDir    string
	Nodes      []*model.Node
	ProbeByKey map[string]store.ProbeResult
	Cfg        config.GeoConfig
	// UserAgent is [http].user_agent — the ONE pipeline UA knob; empty falls
	// back to config.DefaultUserAgent inside the tunnel client.
	UserAgent string
	// Factory is the temp-instance infrastructure the self-report piggybacks
	// on (production: checker.NewXrayFactory). REQUIRED — nil fails loud.
	Factory Factory
	// Progress receives the loud per-node class lines. nil = discard.
	Progress io.Writer
	// SelfURL overrides the self-report endpoint (test seam; empty = the
	// production SelfReportURL constant).
	SelfURL string
	// Now is the clock seam for pacing (tests inject; nil = time.Now).
	Now func() time.Time
	// Sleep is the sleeper seam for pacing (tests inject; nil = timer wait).
	Sleep func(ctx context.Context, d time.Duration) error
}

// Run enriches alive nodes' exit geo via per-node self-report, merges probe
// outcomes, and upserts the geo-base.jsonl cold store. Records are returned
// for reporting, together with the wave's class summary.
func Run(ctx context.Context, in Input) ([]*model.GeoRecord, Summary, error) {
	if in.Factory == nil {
		return nil, Summary{}, errors.New(
			"geo: no temp-instance factory wired — the self-report piggybacks on the checker infrastructure")
	}
	reporter := &Reporter{
		Factory:   in.Factory,
		SelfURL:   in.SelfURL,
		HTTPSURL:  in.Cfg.HTTPSURL,
		DoHURL:    in.Cfg.DoHURL,
		Timeout:   in.Cfg.Timeout.Duration,
		UserAgent: in.UserAgent,
		MinDelay:  DefaultSelfReportPacing,
		Now:       in.Now,
		Sleep:     in.Sleep,
		Progress:  in.Progress,
	}
	exitIPs := collectExitIPs(in.Nodes, in.ProbeByKey)
	reports := reporter.reportAll(ctx, in.Nodes, exitIPs.byNode)
	byKey := make(map[string]*NodeReport, len(reports))
	for i := range reports {
		byKey[reports[i].Key] = &reports[i]
	}
	records, err := mergeGeoRecords(in, byKey)
	if err != nil {
		return nil, Summary{}, err
	}
	if err := store.UpsertGeo(filepath.Join(in.DataDir, "geo-base.jsonl"), records); err != nil {
		return nil, Summary{}, err
	}
	// Eligible = nodes with a live probe exit IP — exactly the jobs the
	// reporter ran (NOT the distinct-IP count: several nodes may share one
	// exit).
	return records, summarize(reports, len(exitIPs.byNode)), nil
}

func summarize(reports []NodeReport, eligible int) Summary {
	s := Summary{Eligible: eligible}
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
	}
	return s
}

type exitIPIndex struct {
	distinct []string
	byNode   map[string]string // node key -> exit ip
}

// collectExitIPs indexes the tunnel exit IPs of alive probes (D8): only nodes
// with a live probe carrying an exit IP enter geo self-report.
func collectExitIPs(nodes []*model.Node, probeByKey map[string]store.ProbeResult) exitIPIndex {
	idx := exitIPIndex{byNode: map[string]string{}}
	seen := map[string]bool{}
	for _, n := range nodes {
		pr, ok := probeByKey[n.Key]
		if !ok || !pr.Alive || pr.ExitIP == "" {
			continue
		}
		idx.byNode[n.Key] = pr.ExitIP
		if !seen[pr.ExitIP] {
			seen[pr.ExitIP] = true
			idx.distinct = append(idx.distinct, pr.ExitIP)
		}
	}
	return idx
}

func mergeGeoRecords(in Input, reports map[string]*NodeReport) ([]*model.GeoRecord, error) {
	existing, err := store.ReadGeo(filepath.Join(in.DataDir, "geo-base.jsonl"))
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
	nodes := make([]*model.Node, len(in.Nodes))
	copy(nodes, in.Nodes)
	sort.Slice(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
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
	records := make([]*model.GeoRecord, 0, len(in.ProbeByKey))
	for _, n := range nodes {
		pr, ok := in.ProbeByKey[n.Key]
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
		}
		if prev, ok := prevByKey[model.GeoIdentity(rec)]; ok {
			rec = prev
			rec.LastSeen = now.Format(time.RFC3339)
		}
		rec.ApplyProbe(pr.Alive, pr.RTTMs, pr.SpeedBPS, pr.CheckedAt)
		applyReport(rec, reports[n.Key], pr.ExitIP)
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
	rec.GeoSource = report.Class
	if report.Class == ClassSelfReport && g.Query != "" {
		// The self-report's query IP is the freshest through-tunnel exit
		// truth — it wins over the probe-wave anchor (churn is logged loud).
		rec.IP = g.Query
	}
}

// Reporter drives the per-node self-report wave: one temp instance per node
// (the piggyback — every ladder rung rides the SAME socks endpoint),
// politeness pacing between external request starts, loud per-node class
// lines on Progress.
type Reporter struct {
	Factory   Factory
	SelfURL   string // test seam; empty = SelfReportURL
	HTTPSURL  string // the [geo].https_url knob; empty = config.DefaultGeoHTTPSURL
	DoHURL    string
	Timeout   time.Duration // per through-tunnel request
	UserAgent string
	MinDelay  time.Duration // pacing between external request starts
	Now       func() time.Time
	Sleep     func(ctx context.Context, d time.Duration) error
	Progress  io.Writer
}

// reportAll runs the wave over the eligible nodes (bounded concurrency, one
// instance per node, results in stable node order).
func (r *Reporter) reportAll(ctx context.Context, nodes []*model.Node, exitIPs map[string]string) []NodeReport {
	type job struct {
		node   *model.Node
		exitIP string
	}
	jobs := make([]job, 0, len(exitIPs))
	for _, n := range nodes { // input order — deterministic progress lines
		if ip, ok := exitIPs[n.Key]; ok {
			jobs = append(jobs, job{node: n, exitIP: ip})
		}
	}
	out := make([]NodeReport, len(jobs))
	workers := min(selfReportConcurrency, len(jobs))
	if workers < 1 {
		return out
	}
	p := &pacer{minDelay: r.MinDelay, now: r.nowFn(), sleep: r.sleepFn()}
	var next atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(jobs) {
					return
				}
				if err := ctx.Err(); err != nil {
					return
				}
				out[i] = r.reportNode(ctx, p, jobs[i].node, jobs[i].exitIP)
			}
		}()
	}
	wg.Wait()
	return out
}

func (r *Reporter) nowFn() func() time.Time {
	if r.Now != nil {
		return r.Now
	}
	return time.Now
}

func (r *Reporter) sleepFn() func(context.Context, time.Duration) error {
	if r.Sleep != nil {
		return r.Sleep
	}
	return func(ctx context.Context, d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
}

func (r *Reporter) selfEndpoint() string {
	if r.SelfURL != "" {
		return r.SelfURL
	}
	return SelfReportURL
}

func (r *Reporter) httpsEndpoint() string {
	if r.HTTPSURL != "" {
		return r.HTTPSURL
	}
	return config.DefaultGeoHTTPSURL
}

// reportNode drives one node: ONE temp instance (the piggyback) → the paced
// four-rung ladder: plain-HTTP ip-api self-report → HTTPS self-geo → DoH
// fallback → unknown. Every rung rides the SAME instance.
func (r *Reporter) reportNode(ctx context.Context, p *pacer, n *model.Node, probeExitIP string) NodeReport {
	rep := NodeReport{Key: n.Key}
	inst, err := r.Factory(ctx, n)
	if err != nil {
		rep.Class = ClassUnknown
		rep.Detail = fmt.Sprintf("temp instance: %v", err)
		r.logNode(n, rep)
		return rep
	}
	defer func() { _ = inst.Close() }()

	cl, err := NewTunnelClient(inst.Addr(), r.Timeout)
	if err != nil {
		rep.Class = ClassUnknown
		rep.Detail = fmt.Sprintf("tunnel client: %v", err)
		r.logNode(n, rep)
		return rep
	}

	// Rung 1 — the self-report: the node asks ip-api who is asking.
	if err := p.wait(ctx); err != nil {
		rep.Class = ClassUnknown
		rep.Detail = fmt.Sprintf("canceled: %v", err)
		r.logNode(n, rep)
		return rep
	}
	rep.ProbeExitIP = probeExitIP
	var selfErr error
	rep.Geo, selfErr = fetchIPAPI(ctx, cl, r.selfEndpoint(), r.userAgent())
	if selfErr == nil && rep.Geo != nil {
		rep.Class = ClassSelfReport
		rep.Churn = probeExitIP != "" && rep.Geo.Query != probeExitIP
		r.logNode(n, rep)
		return rep
	}

	// Rung 2 — the HTTPS self-geo through the SAME instance: [geo].https_url
	// (default ipinfo.io/json) answers "who is asking" over TLS — no
	// plain-HTTP dependency, keyless, per-node source (ipinfo's free tier is
	// rate-limited per source IP and every node is its own). The request
	// start takes a pacer slot like every external request of the wave.
	if err := p.wait(ctx); err != nil {
		rep.Class = ClassUnknown
		rep.Detail = "canceled during fallback"
		r.logNode(n, rep)
		return rep
	}
	info, infoErr := fetchHTTPSInfo(ctx, cl, r.httpsEndpoint(), r.userAgent())
	if infoErr == nil && info != nil {
		rep.HTTPS = info
		rep.Class = ClassSelfReportHTTPS
		rep.Churn = probeExitIP != "" && info.IP != probeExitIP
		rep.Detail = fmt.Sprintf("self-report failed (%v); https self-geo ok", selfErr)
		r.logNode(n, rep)
		return rep
	}

	// Rung 3 — the DoH fallback through the SAME instance: discover the exit
	// network's resolver IP, then look IT up via ip-api through the tunnel
	// (still a per-node source — the aggregate limit stays gone). EVERY
	// external request start takes a politeness slot: the DoH probe AND the
	// fallback lookup each wait before they fire — a start that skipped the
	// pacer would let the bounded workers bypass the pacing exactly here.
	rep.Class = ClassUnknown
	if err := p.wait(ctx); err != nil {
		rep.Detail = fmt.Sprintf("canceled during fallback (self-report: %v; https: %v)", selfErr, infoErr)
		r.logNode(n, rep)
		return rep
	}
	resolver, dohErr := r.resolveExitResolver(ctx, cl)
	if dohErr != nil {
		rep.Detail = fmt.Sprintf("self-report: %v; https: %v; doh-fallback: %v", selfErr, infoErr, dohErr)
		r.logNode(n, rep)
		return rep
	}
	if err := p.wait(ctx); err != nil {
		rep.Detail = fmt.Sprintf("canceled during fallback (self-report: %v; https: %v)", selfErr, infoErr)
		r.logNode(n, rep)
		return rep
	}
	lookupURL := strings.TrimSuffix(r.selfEndpoint(), "/") + "/" + url.PathEscape(resolver)
	fb, lookupErr := fetchIPAPI(ctx, cl, lookupURL, r.userAgent())
	if lookupErr != nil {
		rep.Detail = fmt.Sprintf("self-report: %v; https: %v; doh-fallback (resolver %s): %v",
			selfErr, infoErr, resolver, lookupErr)
	} else {
		rep.Geo = fb
		rep.Class = ClassDoHFallback
		rep.Detail = fmt.Sprintf("self-report failed (%v); https failed (%v); doh fallback via resolver %s",
			selfErr, infoErr, resolver)
	}
	r.logNode(n, rep)
	return rep
}

// resolveExitResolver queries the DoH endpoint THROUGH the tunnel for the
// probe domain's TXT answer and extracts the resolver IP (the quoted string
// in the dns.google/resolve JSON answer).
func (r *Reporter) resolveExitResolver(ctx context.Context, cl *http.Client) (string, error) {
	endpoint := r.DoHURL + "?name=" + url.QueryEscape(dohProbeName) + "&type=TXT"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", r.userAgent())
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("doh: %s", resp.Status)
	}
	var dr struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&dr); err != nil {
		return "", fmt.Errorf("decode doh answer: %w", err)
	}
	for _, a := range dr.Answer {
		// Type 16 = TXT; the data is the RFC1035 quoted string ("203.0.113.7").
		candidate := strings.Trim(a.Data, `"`)
		if a.Type == 16 && net.ParseIP(candidate) != nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("doh answer carries no resolver IP for %s", dohProbeName)
}

// fetchIPAPI performs ONE GET against an ip-api single-IP endpoint through
// the tunnel and decodes the documented single-object answer. A transport
// error, a non-200 status, and a status=fail body are three distinct failure
// classes for the wave log; all route to the fallback (the returned Response
// is non-nil ONLY on success).
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

func (r *Reporter) userAgent() string {
	if r.UserAgent == "" {
		return config.DefaultUserAgent
	}
	return r.UserAgent
}

func (r *Reporter) logNode(n *model.Node, rep NodeReport) {
	if r.Progress == nil {
		return
	}
	switch rep.Class {
	case ClassSelfReport:
		if rep.Churn && rep.Geo != nil {
			_, _ = fmt.Fprintf(r.Progress,
				"geo: %s (%s): self-report ok — exit-ip churn (probe saw %s, node now reports %s)\n",
				n.Key, n.Host, rep.ProbeExitIP, rep.Geo.Query)
		}
	case ClassSelfReportHTTPS:
		// A rung-2 success means rung 1 failed — the degraded evidence class
		// is loud, same as the DoH fallback's line.
		_, _ = fmt.Fprintf(r.Progress, "geo: %s (%s): %s\n", n.Key, n.Host, rep.Detail)
		if rep.Churn && rep.HTTPS != nil {
			_, _ = fmt.Fprintf(r.Progress,
				"geo: %s (%s): https self-geo — exit-ip churn (probe saw %s, node now reports %s)\n",
				n.Key, n.Host, rep.ProbeExitIP, rep.HTTPS.IP)
		}
	case ClassDoHFallback:
		_, _ = fmt.Fprintf(r.Progress, "geo: %s (%s): %s\n", n.Key, n.Host, rep.Detail)
	case ClassUnknown:
		_, _ = fmt.Fprintf(r.Progress, "geo: %s (%s): UNKNOWN geo — %s (node stays usable; geo fields preserved)\n",
			n.Key, n.Host, rep.Detail)
	}
}

// NewTunnelClient builds the production through-tunnel HTTP client for one
// temp instance's socks endpoint (exported for the L5 pin test; the Reporter
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
