package geo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"assay/internal/checker"
	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/store"
)

// DefaultClassifyTimeout is the per-node FLOOR (minimum effective timeout)
// of one through-tunnel classification request when the config materialized
// no [geo].timeout (hand-built configs in tests; production configs pass
// applyGeoDefaults' 8s). The effective per-request timeout is
// RTT-adaptive (owner order 2026-11-08): classifyTimeout clamps
// 10x the node's measured probe RTT into [floor, adaptiveTimeoutCeiling] —
// a request with no deadline would hang the hot instance.
const DefaultClassifyTimeout = 8 * time.Second

// adaptiveRTTMultiplier is the endpoint-speed headroom over the node's own
// measured probe RTT: ladder and media endpoints are observed up to ~5-8x
// slower per-request than the CF-trace probe anchor through the same
// tunnel, so 10x covers the observed ratio with margin.
const adaptiveRTTMultiplier = 10

// adaptiveTimeoutCeiling bounds one adaptive-derived per-request timeout:
// it caps the battery worst-case arithmetic at the 30s slot cost (the
// battery stays bounded by classifyNodeBudget regardless).
const adaptiveTimeoutCeiling = 30 * time.Second

// classifyNodeBudget bounds ONE node's full classification battery (the
// self-report ladder plus the unlock battery v2, pacing included). The
// production wave context is deadline-less (context.Background), and the
// battery's raw-TCP channels carry no read deadline of their own — a target
// that accepts the tunnel dial and silently answers nothing would hold a
// battery goroutine forever, and in the merged flow the batch lifecycle
// waits on every battery (one wedge = one stalled batch). The budget is a
// code-level constant (no new config surface): with the RTT-adaptive
// per-request timeout (owner order 2026-11-08), the worst-case battery
// arithmetic at the 30s per-request ceiling is ~38 HTTP request slots
// (ladder 5 single-attempt — four rungs plus the exit-IP echo that fires
// when the rungs all fail — + gate 2x2 retry slots + consensus echoes 3x2 +
// ip-api body-contract echo 1x2 + media probes 9 retried endpoints x2
// (TikTok contributes three: home, explore, and the header-variant re-shot)
// plus 3 single-shot Disney POSTs) x 30s ≈ 1140s, + ~10s pacing/retry
// stagger ≈ 1150s — twenty minutes is ≈ 1.04x that arithmetic. The margin
// is thin and deliberate: every HTTP channel already bounds itself with its
// per-request deadline, so the budget's real job is the deadline-less
// raw-TCP channels (DNS-over-TCP, STUN), where a wedged framed read has no
// other bound. One fragility note: a future media probe adds +60s at the
// ceiling — more than the ~50s of headroom this recount leaves. A
// budget-burning battery records NOTHING for the node this wave — the
// honesty contract's skip (the next wave re-classifies).
var classifyNodeBudget = 20 * time.Minute

// classifyTimeout derives ONE node's per-request classification timeout
// from that node's own measured probe RTT (owner order 2026-11-08 — no
// blanket value for all nodes). rttMs <= 0 or NaN (no usable probe
// measurement) fails safe to the floor: byte-stable with the pre-adaptive
// behavior. Otherwise raw = rttMs x adaptiveRTTMultiplier, clamped into
// [floor, adaptiveTimeoutCeiling] — the ceiling wins when a config floor
// sits above it, keeping the battery worst-case arithmetic bounded. The
// [geo].timeout knob is the FLOOR (minimum effective timeout).
func classifyTimeout(rttMs float64, floor time.Duration) time.Duration {
	if rttMs <= 0 || math.IsNaN(rttMs) {
		return floor
	}
	raw := time.Duration(rttMs*adaptiveRTTMultiplier) * time.Millisecond
	return min(max(raw, floor), adaptiveTimeoutCeiling)
}

// ClassifyInput bundles the classification pass's shared dependencies. The
// pass rides the probe batch lifecycle (owner order 2026-11-07 «сразу на
// чеке»): every alive node is classified through its own hot instance
// address while the probe wave's batch process is still open.
type ClassifyInput struct {
	// DataDir is the wave data dir (geo-base.jsonl lives here; Flush upserts).
	DataDir string
	// Cfg is the materialized [geo] config (timeout, endpoints, the
	// unlock_probes escape hatch is consulted by the WIRER, not here).
	Cfg config.GeoConfig
	// UserAgent is [http].user_agent — the ONE pipeline UA knob; empty falls
	// back to config.DefaultUserAgent.
	UserAgent string
	// UnlockEndpoints overrides the battery probe URLs (test seam; nil = the
	// production defaultUnlockEndpoints set).
	UnlockEndpoints *UnlockEndpoints
	// SelfURL overrides the self-report endpoint (test seam; empty = the
	// production SelfReportURL constant).
	SelfURL string
	// Now is the clock seam (tests inject; nil = time.Now).
	Now func() time.Time
	// Sleep is the sleeper seam for pacing (tests inject; nil = timer wait).
	Sleep func(ctx context.Context, d time.Duration) error
	// Progress receives the loud per-node classification lines. nil = discard.
	Progress io.Writer
}

// Classifier accumulates one wave's per-node classification outcomes and
// flushes them into geo-base.jsonl. It is the merged flow's classification
// pass: the probe engine calls ClassifyNode per alive node through the hot
// instance (the tunnel is proven working at that instant), and the CLI
// flushes once after the probe wave persists its outcomes — the same
// merge-and-upsert contract the old separate geo stage had, minus the
// freshness gates and the exit-IP cache (classification refreshes every
// wave; battery-version staleness stays a data contract via freshUnlock).
//
// Safe for concurrent use: batches classify in parallel through the probe
// engine's per-batch instances.
type Classifier struct {
	in      ClassifyInput
	mu      sync.Mutex
	reports map[string]NodeReport
	nodes   map[string]*model.Node
}

// NewClassifier builds an empty wave accumulator.
func NewClassifier(in ClassifyInput) *Classifier {
	return &Classifier{
		in:      in,
		reports: map[string]NodeReport{},
		nodes:   map[string]*model.Node{},
	}
}

// ClassifyNode runs the FULL classification battery for ONE alive node
// through the given hot instance address (the SAME socks endpoint the node's
// probe just passed): the self-report ladder (ip-api → HTTPS self-geo → DoH
// fallback → exit-ip echo) plus the unlock battery v2 (cftrace echo,
// 3-source consensus, DNS-over-TCP, media probes, hijack detection,
// OK_FLAKY retry, STUN for hysteria2). No freshness gate, no cache, no
// eligibility layer: per-wave per-alive-node by owner order. A tunnel that
// dies mid-battery records honest unknowns for this wave (bounded — the
// next wave re-classifies); a canceled wave records nothing (partial
// verdicts must never masquerade as checked).
//
// rttMs is the node's OWN measured probe RTT (median TTFB in ms, as the
// probe engine measured it) — the input of the RTT-adaptive per-request
// timeout every battery client is built with; <=0 fails safe to the floor
// ([geo].timeout, default 8s). The signature matches probe.ClassifyFunc
// 1:1 — probe never imports geo; the CLI bridges the seam.
func (c *Classifier) ClassifyNode(ctx context.Context, n *model.Node, addr string, exitIP string, rttMs float64) {
	done := make(chan struct{})
	go func() {
		c.classifyNode(ctx, n, addr, exitIP, rttMs)
		close(done)
	}()
	timer := time.NewTimer(classifyNodeBudget)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		// The battery blew the node budget: a channel is wedged — the raw
		// TCP reads (DNS-over-TCP, STUN) carry no read deadline of their
		// own, and a target that accepts the tunnel dial and then answers
		// nothing would hold a battery goroutine forever. In the merged
		// flow the batch lifecycle WAITS on every battery, so one wedge
		// would stall the whole batch. Return anyway: the node stays an
		// honest unknown this wave, the batch teardown severs the wedged
		// read, and a late completion still records (concurrency-safe).
		if c.in.Progress != nil {
			_, _ = fmt.Fprintf(c.in.Progress,
				"classify: %s (%s): battery exceeded the %s node budget —"+
					" skipping (wedged channel; node stays unknown this wave)\n",
				n.Key, n.Host, classifyNodeBudget)
		}
	}
}

// classifyNode is ClassifyNode's battery body (see ClassifyNode for the
// budget contract that wraps it).
func (c *Classifier) classifyNode(ctx context.Context, n *model.Node, addr string, exitIP string, rttMs float64) {
	floor := c.in.Cfg.Timeout.Duration
	if floor <= 0 {
		floor = DefaultClassifyTimeout
	}
	timeout := classifyTimeout(rttMs, floor)
	p := &pacer{minDelay: DefaultSelfReportPacing, now: c.nowFn(), sleep: c.sleepFn()}
	rep := NodeReport{Key: n.Key, ProbeExitIP: exitIP, RequestRTTMs: []float64{}}
	cl, err := NewTunnelClient(addr, timeout)
	if err != nil {
		rep.Class = ClassUnknown
		rep.Detail = fmt.Sprintf("tunnel client: %v", err)
		c.record(n, rep)
		c.logNode(n, rep)
		return
	}
	c.runLadder(ctx, p, cl, exitIP, &rep)

	// The battery rides the same hot instance: certificate validation ALWAYS
	// on (tlsRoots nil = the system pool — the hijack detector's production
	// contract), plus the checker tunnel client for the DNS-over-TCP and
	// STUN channels.
	ucl, uerr := buildUnlockClient(addr, timeout, nil)
	if uerr != nil {
		rep.Detail = joinDetails(rep.Detail, fmt.Sprintf("unlock client: %v", uerr))
	} else {
		tc := checker.NewTunnelClient(addr, timeout)
		probed, widget, ev := probeUnlockSet(ctx, &unlockProbe{
			cl: ucl, tc: tc, ua: c.userAgent(), ep: c.unlockEndpoints(), pac: p,
			sleep: c.sleepFn(), now: c.nowFn(), exitIP: exitIP,
			scheme: n.Scheme, requestTimeout: timeout,
		})
		if probed != nil {
			rep.Unlocks = probed
			rep.Quality = ComputeIPQuality(rep.Geo, widget)
			logUnlock(c.in.Progress, exitIP, probed, rep.Quality, ev, timeout)
		}
	}
	if ctx.Err() != nil {
		// Canceled mid-classification: attach and persist NOTHING — a
		// partial pass must not overwrite the record's checked verdicts.
		return
	}
	c.record(n, rep)
	c.logNode(n, rep)
}

// Flush merges the wave's classification outcomes with the probe store into
// geo-base.jsonl (the same merge contract the old geo stage had: probe
// outcomes land on every probed record, classification evidence folds where
// it ran, previous geo/unlock fields survive where this wave has none) and
// prints the wave-level classification summary. started timestamps the
// pass for the wave-duration visibility.
func (c *Classifier) Flush(
	w io.Writer, nodes []*model.Node, probeByKey map[string]store.ProbeResult, waveSeq uint64, started time.Time,
) ([]*model.GeoRecord, Summary, error) {
	c.mu.Lock()
	reports := make([]NodeReport, 0, len(c.reports))
	byKey := make(map[string]*NodeReport, len(c.reports))
	for _, rep := range c.reports {
		reports = append(reports, rep)
		rp := rep
		byKey[rep.Key] = &rp
	}
	c.mu.Unlock()

	records, err := mergeGeoRecords(c.in.DataDir, nodes, probeByKey, waveSeq, byKey)
	if err != nil {
		return nil, Summary{}, err
	}
	if err := store.UpsertGeo(filepath.Join(c.in.DataDir, "geo-base.jsonl"), records); err != nil {
		return nil, Summary{}, err
	}
	summary := summarize(reports, len(reports))
	if w != nil {
		outf(w, "classify complete: %d alive classified in %s — geo: %d self-report, %d self-report-https, "+
			"%d doh-fallback, %d unknown (nodes stay usable; geo preserved)\n",
			len(reports), time.Since(started).Round(time.Second),
			summary.SelfReport, summary.SelfReportHTTPS, summary.DoHFallback, summary.Unknown)
		if summary.Churn > 0 {
			outf(w, "WARNING: %d node(s) reported an exit IP different from the probe wave "+
				"(exit churn — geo reflects the freshest tunnel truth)\n", summary.Churn)
		}
		withGeo, alive := 0, 0
		for _, r := range records {
			if r.Country != "" {
				withGeo++
			}
			if r.Alive {
				alive++
			}
		}
		outf(w, "geo store: %d records (%d alive, %d geo-enriched) → %s\n",
			len(records), alive, withGeo, filepath.Join(c.in.DataDir, "geo-base.jsonl"))
	}
	return records, summary, nil
}

// record stores one node's outcome (concurrency-safe: batches classify in
// parallel).
func (c *Classifier) record(n *model.Node, rep NodeReport) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports[n.Key] = rep
	c.nodes[n.Key] = n
}

// runLadder drives one node's self-report ladder through the GIVEN tunnel
// client (the hot probe instance's socks endpoint — no instance spawn, no
// freshness gate): rung 1 plain-HTTP ip-api self-report → rung 2 HTTPS
// self-geo → rung 3 DoH fallback → exit-ip echo recovery → unknown.
//
//nolint:cyclop // the ladder is inherently branchy (unchanged logic, moved seam)
func (c *Classifier) runLadder(ctx context.Context, p *pacer, cl *http.Client, probeExitIP string, rep *NodeReport) {
	if err := p.wait(ctx); err != nil {
		rep.Class = ClassUnknown
		rep.Detail = fmt.Sprintf("canceled: %v", err)
		return
	}
	var selfErr error
	selfStart := time.Now()
	rep.Geo, selfErr = fetchIPAPI(ctx, cl, c.selfEndpoint(), c.userAgent())
	selfElapsed := time.Since(selfStart).Milliseconds()
	if selfErr != nil {
		if isTimeoutErr(selfErr) {
			rep.TimedOut++
		}
	} else {
		rep.RequestRTTMs = append(rep.RequestRTTMs, float64(selfElapsed))
	}
	rateLimited := false
	if rle, ok := errors.AsType[*RateLimitError](selfErr); ok {
		rateLimited = true
		rep.RateLimited = true
		rep.RateLimitTTL = rle.TTL
	}
	if selfErr == nil && rep.Geo != nil {
		rep.Class = ClassSelfReport
		rep.Churn = probeExitIP != "" && rep.Geo.Query != probeExitIP
		return
	}

	// Rung 2 — the HTTPS self-geo through the SAME instance. A different
	// service (ipinfo) may still answer; only ip-api retries are suppressed.
	if err := p.wait(ctx); err != nil {
		rep.Class = ClassUnknown
		rep.Detail = "canceled during fallback"
		return
	}
	httpsStart := time.Now()
	info, infoErr := fetchHTTPSInfo(ctx, cl, c.httpsEndpoint(), c.userAgent())
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
		return
	}

	// Rung 3 — DoH fallback (skipped when rate-limited: it would issue
	// another ip-api request through the same exit, still rate-limited).
	rep.Class = ClassUnknown
	if rateLimited {
		rep.Detail = fmt.Sprintf("self-report: %v (rate-limited, X-Ttl=%s); https: %v",
			selfErr, rep.RateLimitTTL, infoErr)
	} else {
		if done := c.doHFallback(ctx, p, cl, selfErr, infoErr, rep); done {
			return
		}
	}

	// Exit IP echo fallback: recover the exit IP over HTTPS when self-report
	// fully failed. Does not provide geo flags.
	if ep := c.in.Cfg.ExitIPEchoURL; ep != "" {
		if echoIP, echoErr := fetchExitIPEcho(ctx, cl, ep, c.userAgent()); echoErr == nil {
			rep.EchoIP = echoIP
			if rep.Detail != "" {
				rep.Detail += "; exit-ip echo ok"
			}
		}
	}
}

// doHFallback attempts the DoH rung. It returns true when the caller should
// return immediately (cancellation or success); false when it should
// continue to the exit-IP echo fallback.
func (c *Classifier) doHFallback(
	ctx context.Context, p *pacer, cl *http.Client, selfErr, infoErr error, rep *NodeReport,
) bool {
	if err := p.wait(ctx); err != nil {
		rep.Detail = fmt.Sprintf("canceled during fallback (self-report: %v; https: %v)", selfErr, infoErr)
		return true
	}
	dohStart := time.Now()
	resolver, dohErr := resolveExitResolver(ctx, cl, c.in.Cfg.DoHURL, c.userAgent())
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
	lookupURL := strings.TrimSuffix(c.selfEndpoint(), "/") + "/" + url.PathEscape(resolver)
	lookupStart := time.Now()
	fb, lookupErr := fetchIPAPI(ctx, cl, lookupURL, c.userAgent())
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

// endpoint helpers: production defaults apply when the config seam is empty
// (the same contract the old Reporter endpoints had).
func (c *Classifier) selfEndpoint() string {
	if c.in.SelfURL != "" {
		return c.in.SelfURL
	}
	return SelfReportURL
}

func (c *Classifier) httpsEndpoint() string {
	if c.in.Cfg.HTTPSURL != "" {
		return c.in.Cfg.HTTPSURL
	}
	return config.DefaultGeoHTTPSURL
}

func (c *Classifier) unlockEndpoints() UnlockEndpoints {
	if c.in.UnlockEndpoints != nil {
		return *c.in.UnlockEndpoints
	}
	return defaultUnlockEndpoints()
}

func (c *Classifier) nowFn() func() time.Time {
	if c.in.Now != nil {
		return c.in.Now
	}
	return time.Now
}

func (c *Classifier) sleepFn() func(context.Context, time.Duration) error {
	if c.in.Sleep != nil {
		return c.in.Sleep
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

func (c *Classifier) userAgent() string {
	if c.in.UserAgent == "" {
		return config.DefaultUserAgent
	}
	return c.in.UserAgent
}

// logNode emits the loud per-node geo class line (the merged flow keeps the
// old line grammar — journal continuity).
func (c *Classifier) logNode(n *model.Node, rep NodeReport) {
	if c.in.Progress == nil {
		return
	}
	switch rep.Class {
	case ClassSelfReport:
		if rep.Churn && rep.Geo != nil {
			_, _ = fmt.Fprintf(c.in.Progress,
				"geo: %s (%s): self-report ok — exit-ip churn (probe saw %s, node now reports %s)\n",
				n.Key, n.Host, rep.ProbeExitIP, rep.Geo.Query)
		}
	case ClassSelfReportHTTPS:
		// A rung-2 success means rung 1 failed — the degraded evidence class
		// is loud, same as the DoH fallback's line.
		_, _ = fmt.Fprintf(c.in.Progress, "geo: %s (%s): %s\n", n.Key, n.Host, rep.Detail)
		if rep.Churn && rep.HTTPS != nil {
			_, _ = fmt.Fprintf(c.in.Progress,
				"geo: %s (%s): https self-geo — exit-ip churn (probe saw %s, node now reports %s)\n",
				n.Key, n.Host, rep.ProbeExitIP, rep.HTTPS.IP)
		}
	case ClassDoHFallback:
		_, _ = fmt.Fprintf(c.in.Progress, "geo: %s (%s): %s\n", n.Key, n.Host, rep.Detail)
	case ClassUnknown:
		_, _ = fmt.Fprintf(c.in.Progress, "geo: %s (%s): UNKNOWN geo — %s (node stays usable; geo fields preserved)\n",
			n.Key, n.Host, rep.Detail)
	}
}

// joinDetails appends one detail fragment with the "; " separator.
func joinDetails(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// outf prints one formatted summary line to w (nil-safe).
func outf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	_, _ = fmt.Fprintf(w, format+"\n", args...)
}

// resolveExitResolver queries the DoH endpoint THROUGH the tunnel for the
// probe domain's TXT answer and extracts the resolver IP (the quoted string
// in the dns.google/resolve JSON answer).
func resolveExitResolver(ctx context.Context, cl *http.Client, dohURL, userAgent string) (string, error) {
	endpoint := dohURL + "?name=" + url.QueryEscape(dohProbeName) + "&type=TXT"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", userAgent)
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
