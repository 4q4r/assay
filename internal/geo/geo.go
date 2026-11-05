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
	"bytes"
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

// DefaultSelfReportConcurrency bounds how many temp instances exist at once
// (each is a full xray process — parity with the checker's default) when
// [geo].self_report_concurrency is unset (0).
const DefaultSelfReportConcurrency = 8

// DynamicGeoConcurrency returns the dynamic concurrency for geo given a budget.
// A non-positive budget falls back to DefaultSelfReportConcurrency.
func DynamicGeoConcurrency(budget int) int {
	if budget <= 0 {
		return DefaultSelfReportConcurrency
	}
	return budget
}

// ComputeGeoConcurrency is an alias for DynamicGeoConcurrency.
func ComputeGeoConcurrency(budget int) int {
	return DynamicGeoConcurrency(budget)
}

// DynamicConcurrency is an alias for DynamicGeoConcurrency.
func DynamicConcurrency(budget int) int {
	return DynamicGeoConcurrency(budget)
}

// DefaultMaxTTL caps the rate-limit retry sleep when [geo].max_ttl is unset.
const DefaultMaxTTL = 30 * time.Second

// DefaultGeoMaxTTL is an alias for DefaultMaxTTL.
const DefaultGeoMaxTTL = DefaultMaxTTL

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
	// Concurrency overrides [geo].self_report_concurrency when > 0 (dynamic,
	// CPU/RAM-aware budget). 0 = fall back to the config value.
	Concurrency int
	// DynamicConcurrency is an alias for Concurrency.
	DynamicConcurrency int
	// Progress receives the loud per-node class lines. nil = discard.
	Progress io.Writer
	// SelfURL overrides the self-report endpoint (test seam; empty = the
	// production SelfReportURL constant).
	SelfURL string
	// UnlockEndpoints overrides the Phase-1 unlock probe URLs (test seam;
	// nil = the production defaultUnlockEndpoints set).
	UnlockEndpoints *UnlockEndpoints
	// Now is the clock seam for pacing (tests inject; nil = time.Now).
	Now func() time.Time
	// Sleep is the sleeper seam for pacing (tests inject; nil = timer wait).
	Sleep func(ctx context.Context, d time.Duration) error
	// ExitCache is the hot in-memory exit-IP cache (may be nil = disabled).
	ExitCache *ExitGeoCache
	// WaveSeq is the current wave sequence number for run-count liveness.
	WaveSeq uint64
}

// Run enriches alive nodes' exit geo via per-node self-report, merges probe
// outcomes, and upserts the geo-base.jsonl cold store. Records are returned
// for reporting, together with the wave's class summary.
func Run(ctx context.Context, in Input) ([]*model.GeoRecord, Summary, error) {
	if in.Factory == nil {
		return nil, Summary{}, errors.New(
			"geo: no temp-instance factory wired — the self-report piggybacks on the checker infrastructure")
	}
	concurrency := in.Cfg.SelfReportConcurrency
	if in.Concurrency > 0 {
		concurrency = in.Concurrency
	}
	if in.DynamicConcurrency > 0 {
		concurrency = in.DynamicConcurrency
	}
	reporter := &Reporter{
		Factory:               in.Factory,
		SelfURL:               in.SelfURL,
		HTTPSURL:              in.Cfg.HTTPSURL,
		ExitIPEchoURL:         in.Cfg.ExitIPEchoURL,
		DoHURL:                in.Cfg.DoHURL,
		Timeout:               in.Cfg.Timeout.Duration,
		UserAgent:             in.UserAgent,
		MinDelay:              DefaultSelfReportPacing,
		SelfReportConcurrency: concurrency,
		MaxTTL:                in.Cfg.MaxTTL.Duration,
		Now:                   in.Now,
		Sleep:                 in.Sleep,
		Progress:              in.Progress,
		Cache:                 in.ExitCache,
		UnlockEndpoints:       in.UnlockEndpoints,
	}
	exitIPs := collectExitIPs(in.Nodes, in.ProbeByKey)
	reports := reporter.reportAll(ctx, in.Nodes, exitIPs.byNode)
	byKey := make(map[string]*NodeReport, len(reports))
	for i := range reports {
		byKey[reports[i].Key] = &reports[i]
	}
	// Phase-1 unlock stage: quality + media probes once per distinct exit IP
	// whose cached state is older than UnlockTTL (gated by [geo].unlock_probes;
	// no-op when off — zero production behavior change).
	runUnlockWave(ctx, in, reporter, reports, exitIPs)
	records, err := mergeGeoRecords(in, byKey)
	if err != nil {
		return nil, Summary{}, err
	}
	// Batch fallback: resolve exit IPs of rate-limited nodes from the local
	// machine (a different source IP, not rate-limited). Honor ip-api's X-Ttl
	// by sleeping the max advertised delay before the batch (best-effort),
	// capped at Cfg.MaxTTL.
	applyRateLimitedFallback(ctx, in, reporter, reports, records)

	if err := store.UpsertGeo(filepath.Join(in.DataDir, "geo-base.jsonl"), records); err != nil {
		return nil, Summary{}, err
	}
	// Eligible = nodes with a live probe exit IP — exactly the jobs the
	// reporter ran (NOT the distinct-IP count: several nodes may share one
	// exit).
	return records, summarize(reports, len(exitIPs.byNode)), nil
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
			if in.WaveSeq > 0 {
				rec.AliveWaveSeq = int(in.WaveSeq) //nolint:gosec // wave seq fits in int
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

// applyBatchRecords overlays ip-api batch results (resolved from the local
// machine) onto records whose exit IP was rate-limited through the tunnel.
// Flags are verified (ip-api is the source) — FlagsVerified = true.
func applyBatchRecords(records []*model.GeoRecord, batch map[string]*Response) {
	for _, rec := range records {
		g, ok := batch[rec.IP]
		if !ok || g == nil || g.Status != "success" {
			continue
		}
		rec.Country = strings.ToLower(g.CountryCode)
		rec.City = g.City
		rec.ASN = g.ASN()
		rec.ASName = g.ASName
		rec.ISP = g.ISP
		rec.ProxyFlag = g.Proxy
		rec.HostingFlag = g.Hosting
		rec.GeoSource = "batch-fallback"
		rec.FlagsVerified = true
		if g.Query != "" {
			rec.IP = g.Query
		}
	}
}

// applyRateLimitedFallback resolves exit IPs of rate-limited nodes from the
// local machine (a different source IP, not rate-limited). Honor ip-api's
// X-Ttl by sleeping the max advertised delay before the batch (best-effort),
// capped at Cfg.MaxTTL.
//
//nolint:cyclop // batch fallback branches are inherent
func applyRateLimitedFallback(
	ctx context.Context, in Input, reporter *Reporter, reports []NodeReport, records []*model.GeoRecord,
) {
	rateLimitedIPs := map[string]bool{}
	for i := range reports {
		if !reports[i].RateLimited {
			continue
		}
		if ip := reports[i].ProbeExitIP; ip != "" {
			rateLimitedIPs[ip] = true
		}
		if reports[i].EchoIP != "" {
			rateLimitedIPs[reports[i].EchoIP] = true
		}
	}
	if len(rateLimitedIPs) == 0 {
		return
	}
	maxTTL := time.Duration(0)
	for i := range reports {
		if reports[i].RateLimited && reports[i].RateLimitTTL > maxTTL {
			maxTTL = reports[i].RateLimitTTL
		}
	}
	capTTL := reporter.MaxTTL
	if capTTL <= 0 {
		capTTL = in.Cfg.MaxTTL.Duration
	}
	if capTTL > 0 && maxTTL > capTTL {
		maxTTL = capTTL
	}
	if maxTTL > 0 {
		// best-effort honor of X-Ttl; ignore cancellation errors here
		_ = reporter.sleepFn()(ctx, maxTTL)
	}
	ips := make([]string, 0, len(rateLimitedIPs))
	for ip := range rateLimitedIPs {
		ips = append(ips, ip)
	}
	batch, berr := BatchLookup(ctx, ips, in.UserAgent)
	if berr != nil {
		if reporter.Progress != nil {
			_, _ = fmt.Fprintf(reporter.Progress, "geo batch fallback: %v\n", berr)
		}
	} else {
		applyBatchRecords(records, batch)
	}
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

// Reporter drives the per-node self-report wave: one temp instance per node
// (the piggyback — every ladder rung rides the SAME socks endpoint),
// politeness pacing between external request starts, loud per-node class
// lines on Progress.
type Reporter struct {
	Factory               Factory
	SelfURL               string // test seam; empty = SelfReportURL
	HTTPSURL              string // the [geo].https_url knob; empty = config.DefaultGeoHTTPSURL
	ExitIPEchoURL         string // the [geo].exit_ip_echo_url knob; empty = config.DefaultGeoExitIPEchoURL
	DoHURL                string
	Timeout               time.Duration // per through-tunnel request
	UserAgent             string
	MinDelay              time.Duration // pacing between external request starts
	SelfReportConcurrency int           // max concurrent temp instances (0 = default)
	MaxTTL                time.Duration // cap for the rate-limit retry sleep (0 = no cap)
	Now                   func() time.Time
	Sleep                 func(ctx context.Context, d time.Duration) error
	Progress              io.Writer
	// in-wave cache by exit IP (unexported, lazily init) — legacy fallback
	// used only when Cache (ExitGeoCache) is nil.
	cacheMu sync.Mutex
	cache   map[string]NodeReport
	// Hot cross-wave exit-IP cache (may be nil = disabled).
	Cache *ExitGeoCache
	// UnlockEndpoints carries the Phase-1 probe URL seam (nil = defaults).
	UnlockEndpoints *UnlockEndpoints
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
	concurrency := r.SelfReportConcurrency
	if concurrency <= 0 {
		concurrency = DefaultSelfReportConcurrency
	}
	workers := min(concurrency, len(jobs))
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

func (r *Reporter) exitIPEchoEndpoint() string {
	return r.ExitIPEchoURL
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

// reportNode drives one node: ONE temp instance (the piggyback) → the paced
// four-rung ladder: plain-HTTP ip-api self-report → HTTPS self-geo → DoH
// fallback → unknown. Every rung rides the SAME instance.
//
//nolint:cyclop,gocognit // per-node ladder is inherently branchy
func (r *Reporter) reportNode(ctx context.Context, p *pacer, n *model.Node, probeExitIP string) NodeReport {
	// In-wave cache by exit IP: reuse a previous result for the same exit IP.
	if probeExitIP != "" {
		if r.Cache != nil {
			if cached, ok := r.Cache.Get(probeExitIP); ok && cached != nil {
				clone := cached.Report
				clone.Key = n.Key
				clone.ProbeExitIP = probeExitIP
				clone.RequestRTTMs = append([]float64(nil), cached.Report.RequestRTTMs...)
				clone.TimedOut = cached.Report.TimedOut
				r.logNode(n, clone)
				return clone
			}
		} else {
			r.cacheMu.Lock()
			if cached, ok := r.cache[probeExitIP]; ok {
				clone := cached
				clone.Key = n.Key
				clone.ProbeExitIP = probeExitIP
				clone.RequestRTTMs = append([]float64(nil), cached.RequestRTTMs...)
				clone.TimedOut = cached.TimedOut
				r.cacheMu.Unlock()
				r.logNode(n, clone)
				return clone
			}
			r.cacheMu.Unlock()
		}
	}

	rep := NodeReport{Key: n.Key, RequestRTTMs: []float64{}}
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
	selfStart := time.Now()
	rep.Geo, selfErr = fetchIPAPI(ctx, cl, r.selfEndpoint(), r.userAgent())
	selfElapsed := time.Since(selfStart).Milliseconds()
	if selfErr != nil {
		if isTimeoutErr(selfErr) {
			rep.TimedOut++
		}
	} else {
		rep.RequestRTTMs = append(rep.RequestRTTMs, float64(selfElapsed))
	}
	rateLimited := false
	var rateLimitTTL time.Duration
	if rle, ok := errors.AsType[*RateLimitError](selfErr); ok {
		rateLimited = true
		rateLimitTTL = rle.TTL
		rep.RateLimited = true
		rep.RateLimitTTL = rateLimitTTL
	}
	if selfErr == nil && rep.Geo != nil {
		rep.Class = ClassSelfReport
		rep.Churn = probeExitIP != "" && rep.Geo.Query != probeExitIP
		cacheResult(r, probeExitIP, rep)
		r.logNode(n, rep)
		return rep
	}

	// Rung 2 — the HTTPS self-geo through the SAME instance. Skipped when
	// the failure was a 429? No — a different service (ipinfo) may still
	// answer; only ip-api retries are suppressed.
	if err := p.wait(ctx); err != nil {
		rep.Class = ClassUnknown
		rep.Detail = "canceled during fallback"
		r.logNode(n, rep)
		return rep
	}
	httpsStart := time.Now()
	info, infoErr := fetchHTTPSInfo(ctx, cl, r.httpsEndpoint(), r.userAgent())
	httpsElapsed := time.Since(httpsStart).Milliseconds()
	if infoErr != nil {
		if isTimeoutErr(infoErr) {
			rep.TimedOut++
		}
	} else {
		rep.RequestRTTMs = append(rep.RequestRTTMs, float64(httpsElapsed))
	}
	if infoErr == nil && info != nil {
		rep.HTTPS = info
		rep.Class = ClassSelfReportHTTPS
		rep.Churn = probeExitIP != "" && info.IP != probeExitIP
		rep.Detail = fmt.Sprintf("self-report failed (%v); https self-geo ok", selfErr)
		cacheResult(r, probeExitIP, rep)
		r.logNode(n, rep)
		return rep
	}

	// Rung 3 — DoH fallback (skipped when rate-limited: it would issue
	// another ip-api request through the same exit, still rate-limited).
	rep.Class = ClassUnknown
	if rateLimited {
		rep.Detail = fmt.Sprintf("self-report: %v (rate-limited, X-Ttl=%s); https: %v",
			selfErr, rateLimitTTL, infoErr)
	} else {
		done := r.doHFallback(ctx, p, cl, selfErr, infoErr, &rep)
		if strings.Contains(rep.Detail, "canceled during fallback") {
			r.logNode(n, rep)
			return rep
		}
		if rep.Class == ClassDoHFallback {
			cacheResult(r, probeExitIP, rep)
			r.logNode(n, rep)
			return rep
		}
		if done {
			r.logNode(n, rep)
			return rep
		}
	}

	// Exit IP echo fallback: recover the exit IP over HTTPS when self-report
	// fully failed. Does not provide geo flags.
	if ep := r.exitIPEchoEndpoint(); ep != "" {
		if echoIP, echoErr := fetchExitIPEcho(ctx, cl, ep, r.userAgent()); echoErr == nil {
			rep.EchoIP = echoIP
			if rep.Detail != "" {
				rep.Detail += "; exit-ip echo ok"
			}
		}
	}

	cacheResult(r, probeExitIP, rep)
	r.logNode(n, rep)
	return rep
}

// doHFallback attempts the DoH rung. It returns true when the caller should
// return immediately (cancellation or success); false when it should continue
// to the exit-IP echo fallback.
func (r *Reporter) doHFallback(
	ctx context.Context, p *pacer, cl *http.Client, selfErr, infoErr error, rep *NodeReport,
) bool {
	if err := p.wait(ctx); err != nil {
		rep.Detail = fmt.Sprintf("canceled during fallback (self-report: %v; https: %v)", selfErr, infoErr)
		return true
	}
	dohStart := time.Now()
	resolver, dohErr := r.resolveExitResolver(ctx, cl)
	dohElapsed := time.Since(dohStart).Milliseconds()
	if dohErr != nil {
		if isTimeoutErr(dohErr) {
			rep.TimedOut++
		}
	} else {
		rep.RequestRTTMs = append(rep.RequestRTTMs, float64(dohElapsed))
	}
	if dohErr != nil {
		rep.Detail = fmt.Sprintf("self-report: %v; https: %v; doh-fallback: %v", selfErr, infoErr, dohErr)
		return false
	}
	if err := p.wait(ctx); err != nil {
		rep.Detail = fmt.Sprintf("canceled during fallback (self-report: %v; https: %v)", selfErr, infoErr)
		return true
	}
	lookupURL := strings.TrimSuffix(r.selfEndpoint(), "/") + "/" + url.PathEscape(resolver)
	lookupStart := time.Now()
	fb, lookupErr := fetchIPAPI(ctx, cl, lookupURL, r.userAgent())
	lookupElapsed := time.Since(lookupStart).Milliseconds()
	if lookupErr != nil {
		if isTimeoutErr(lookupErr) {
			rep.TimedOut++
		}
	} else {
		rep.RequestRTTMs = append(rep.RequestRTTMs, float64(lookupElapsed))
	}
	if lookupErr == nil {
		rep.Geo = fb
		rep.Class = ClassDoHFallback
		rep.Detail = fmt.Sprintf("self-report failed (%v); https failed (%v); doh fallback via resolver %s",
			selfErr, infoErr, resolver)
		// unreachable on success path
		return true
	}
	rep.Detail = fmt.Sprintf("self-report: %v; https: %v; doh-fallback (resolver %s): %v",
		selfErr, infoErr, resolver, lookupErr)
	if rle, ok := errors.AsType[*RateLimitError](lookupErr); ok {
		rep.RateLimited = true
		rep.RateLimitTTL = rle.TTL
	}
	return false
}

func cacheResult(r *Reporter, exitIP string, rep NodeReport) {
	if exitIP == "" {
		return
	}
	if r.Cache != nil {
		entry := nodeReportToEntry(exitIP, rep)
		_ = r.Cache.Set(exitIP, entry)
		return
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if r.cache == nil {
		r.cache = map[string]NodeReport{}
	}
	// store a copy without Key (Key is per-node)
	stored := rep
	stored.Key = ""
	r.cache[exitIP] = stored
}

func nodeReportToEntry(exitIP string, rep NodeReport) *ExitGeoEntry {
	entry := &ExitGeoEntry{
		ExitIP:    exitIP,
		GeoSource: rep.Class,
		Report:    rep,
	}
	// store a copy without Key (Key is per-node)
	stored := rep
	stored.Key = ""
	entry.Report = stored
	if rep.Geo != nil {
		entry.Country = strings.ToLower(rep.Geo.CountryCode)
		entry.City = rep.Geo.City
		entry.ASN = rep.Geo.ASN()
		entry.ASName = rep.Geo.ASName
		entry.ISP = rep.Geo.ISP
		entry.ProxyFlag = rep.Geo.Proxy
		entry.HostingFlag = rep.Geo.Hosting
		entry.GeoSource = rep.Class
		entry.FlagsVerified = rep.Geo != nil // refined below
	}
	if rep.Class == ClassSelfReport {
		entry.FlagsVerified = true
	} else {
		entry.FlagsVerified = false
	}
	if rep.ProbeExitIP != "" {
		if net.ParseIP(rep.ProbeExitIP) != nil {
			entry.ExitIP = rep.ProbeExitIP
		}
	}
	if entry.ExitIP == "" {
		entry.ExitIP = exitIP
	}
	return entry
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

// RateLimitError signals an HTTP 429 from ip-api, carrying the retry delay
// advertised via the X-Ttl header (if any).
type RateLimitError struct {
	StatusCode int
	TTL        time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("ip-api: 429 (retry after %s)", e.TTL)
}

// IsRateLimit reports whether err is a *RateLimitError.
func IsRateLimit(err error) bool {
	var rle *RateLimitError
	return errors.As(err, &rle)
}

// RateLimitTTL extracts the retry delay from a *RateLimitError.
func RateLimitTTL(err error) time.Duration {
	var rle *RateLimitError
	if errors.As(err, &rle) && rle != nil {
		return rle.TTL
	}
	return 0
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

func (r *Reporter) userAgent() string {
	if r.UserAgent == "" {
		return config.DefaultUserAgent
	}
	return r.UserAgent
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

// BatchLookup queries ip-api's batch endpoint from the LOCAL machine (no
// tunnel) for the given exit IPs. Returns a map IP -> *Response. Up to 100
// IPs per request (ip-api batch limit).
func BatchLookup(ctx context.Context, ips []string, userAgent string) (map[string]*Response, error) {
	out := map[string]*Response{}
	uniq := dedupeIPs(ips)
	const batchSize = 100
	for i := 0; i < len(uniq); i += batchSize {
		end := min(i+batchSize, len(uniq))
		chunk := uniq[i:end]
		if err := batchLookupChunk(ctx, chunk, userAgent, out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func dedupeIPs(ips []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, ip := range ips {
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}

func batchLookupChunk(ctx context.Context, chunk []string, userAgent string, out map[string]*Response) error {
	body, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://ip-api.com/batch", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if rerr != nil {
		return rerr
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ip-api batch: %s", resp.Status)
	}
	var arr []Response
	if err := json.Unmarshal(respBody, &arr); err != nil {
		return err
	}
	for j := range arr {
		r := arr[j]
		key := r.Query
		if key == "" && j < len(chunk) {
			key = chunk[j]
		}
		cp := r
		out[key] = &cp
	}
	return nil
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
