// Package probe implements the out-of-band liveness wave (W2, W14 engine):
// every probed node gets a temporary single-node xray instance — the SAME
// infrastructure the check/geo stages use (one factory, no drift) — so
// real-tunnel HTTP probes deliver latency, the tunnel EXIT IP (D8 — never
// the advertised host) and an optional through-tunnel speedtest uniformly
// across EVERY rendered protocol, hysteria2 included. The live client is
// never involved.
package probe

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"public_vpn/internal/checker"
	"public_vpn/internal/model"
	"public_vpn/internal/store"
)

// DefaultConcurrency bounds how many temp instances exist at once (each is
// a full xray process). W19: 32 — enough workers to saturate the factory's
// boot-serialization ceiling (~10 boots/sec; the HTTP phase is parallel), so
// wave wall time stays bounded-minutes per 1000 nodes while the semaphore
// still bounds instantaneous load. The engine boots REAL cores: the boot
// mutex remains the true bottleneck, and 32 workers keep every core busy
// behind it. An explicit [probe].threads (the owner's live 20) is
// untouched by this default.
const DefaultConcurrency = 32

// exitIPURL is the through-tunnel endpoint the engine reads the D8 exit IP
// from (the SAME ip-api self-report call the geo stage makes — one mental
// model, one rate-limit surface; the free tier's budget is per requesting
// IP, and our requests originate from thousands of distinct exits). Test
// seam: ExitIPURL (zero in production).
const exitIPURL = "http://ip-api.com/json/"

// Options configures one probe wave.
type Options struct {
	Timeout time.Duration // per-attempt HTTP timeout
	// Threads is the parallel temp-instance worker count (0 = default 32).
	// Boot windows serialize inside the factory; the HTTP phase is parallel.
	Threads   int
	URL       string // probe target URL
	Attempts  int    // HTTP GET attempts per node (>= 1)
	Speedtest bool   // measure download speed through the node's instance
	// SpeedtestURL is the sample the speedtest downloads.
	SpeedtestURL     string
	SpeedtestTimeout time.Duration // download sample window
	// SkipFreshWithin is [probe].skip_fresh_within: nodes whose LATEST probe
	// result is exactly `passed` and newer than this window are skipped in
	// the wave — no link, no probe-log entry (their passed history stays
	// intact for rank's geo.ttl gate). 0 = probe everything (the default).
	SkipFreshWithin time.Duration
	// Latest carries the newest outcome per node key (store.LatestProbeByKey)
	// the skip decision reads. nil/empty = nothing to skip on.
	Latest map[string]store.ProbeResult
	// Now is the clock seam (tests inject; nil = time.Now().UTC()).
	Now func() time.Time
	// Progress receives per-node progress lines ("probing …"). nil = discard.
	Progress io.Writer
	// ExitProbe controls the D8 exit-IP echo. nil = ON (the production
	// default: every alive record carries its tunnel exit IP — the W10
	// *bool precedent). Tests pass an explicit false to run without the
	// echo double.
	ExitProbe *bool
	// ExitIPURL overrides the exit-IP echo endpoint (test seam; empty =
	// exitIPURL).
	ExitIPURL string
}

// SocksInstance is one live temp SOCKS5 endpoint (production: a temp xray;
// tests: an in-process server). Structural twin of the checker/geo seams —
// the CLI adapter hands a checker.NewXrayFactory product over 1:1.
type SocksInstance interface {
	Addr() string
	Close() error
}

// Factory spawns one instance per node (production: checker.NewXrayFactory
// — one temp single-node xray per probed node, the SAME render.BuildOutbound
// product the live renderer uses, hardening knobs included).
type Factory func(ctx context.Context, n *model.Node) (SocksInstance, error)

// probeJob is one unique-link unit of work: every node carrying the link
// takes the outcome.
type probeJob struct {
	link  string
	keys  []string
	host  string
	node  *model.Node
	order int
}

// Run probes every node and appends outcomes to the probe log. Nodes without
// an outcome are recorded as not-alive-this-wave. Nodes skipped by
// [probe].skip_fresh_within (latest result exactly `passed`, newer than the
// window) produce NEITHER a link NOR a log entry — their probe history is
// preserved untouched. Input node order is preserved in the output.
func Run(
	ctx context.Context, nodes []*model.Node, f Factory, opts Options, resultsPath string,
) ([]store.ProbeResult, error) {
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	skipped := freshSkipSet(nodes, opts, now)
	byLink := make(map[string]*probeJob, len(nodes))
	ordered := make([]*probeJob, 0, len(nodes))
	for _, n := range nodes {
		if skipped[n.Key] {
			continue
		}
		link := n.Link()
		job, dup := byLink[link]
		if dup {
			job.keys = append(job.keys, n.Key) // identical links probe once; both nodes take the outcome
			continue
		}
		job = &probeJob{link: link, keys: []string{n.Key}, host: n.Host, node: n, order: len(ordered)}
		byLink[link] = job
		ordered = append(ordered, job)
	}
	outcomes := runJobs(ctx, f, ordered, opts)

	out := make([]store.ProbeResult, 0, len(nodes))
	for _, job := range ordered {
		for _, key := range job.keys {
			out = append(out, outcomeFor(key, outcomes[job.order], now))
		}
	}
	if resultsPath != "" {
		if err := store.AppendProbeResults(resultsPath, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// outcomeFor translates one link outcome into the per-node store record
// (schema unchanged — select/geo-base consumers keep reading the same
// fields).
func outcomeFor(key string, o *outcome, now time.Time) store.ProbeResult {
	if o == nil {
		return store.ProbeResult{Key: key, Alive: false, CheckedAt: now}
	}
	return store.ProbeResult{
		Key:         key,
		Host:        o.host,
		Alive:       o.alive,
		Status:      o.status,
		Reason:      o.reason,
		ExitIP:      o.exitIP,
		RTTMs:       o.rttMS,
		SpeedBPS:    o.speedBPS,
		Checks:      o.checks,
		TotalChecks: o.total,
		FailureKind: o.failureKind,
		CheckedAt:   now,
	}
}

// outcome is one link's aggregated probe result.
type outcome struct {
	host        string
	alive       bool
	status      string // passed | semi-passed | failed
	reason      string
	exitIP      string
	rttMS       float64
	speedBPS    int64
	checks      int
	total       int
	failureKind string
}

// runJobs executes every job under the concurrency throttle, preserving the
// input order in the returned slice.
func runJobs(ctx context.Context, f Factory, jobs []*probeJob, opts Options) []*outcome {
	concurrency := opts.Threads
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	out := make([]*outcome, len(jobs))
	if len(jobs) == 0 {
		return out
	}
	sem := make(chan struct{}, concurrency)
	done := make([]chan struct{}, len(jobs))
	for i := range done {
		done[i] = make(chan struct{})
	}
	for i := range jobs {
		go func(i int) {
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = runJob(ctx, f, jobs[i], opts)
			close(done[i])
		}(i)
	}
	for i := range done {
		<-done[i]
	}
	return out
}

// runJob drives one unique link: temp instance → attempts → exit IP →
// speedtest → aggregation. An instance that fails to boot is a loud per-node
// outcome (failureKind instance-boot), never a wave error.
func runJob(ctx context.Context, f Factory, job *probeJob, opts Options) *outcome {
	progressf(opts.Progress, "probing %s (%s)…", job.keys[0], job.host)
	inst, err := f(ctx, job.node)
	if err != nil {
		return &outcome{
			host: job.host, alive: false, status: "failed",
			reason: oneLine(err.Error()), failureKind: "instance-boot",
			total: opts.Attempts,
		}
	}
	defer func() { _ = inst.Close() }()

	o := &outcome{host: job.host} // total counts up in the attempt loop below
	var ttfbs, totals []float64
	tc := checker.NewTunnelClient(inst.Addr(), opts.Timeout)
	for range opts.Attempts {
		attempt, aerr := tc.Get(ctx, opts.URL)
		if aerr != nil && attempt.Verdict == "" {
			// Fallback (Get normally classifies itself): a measured connect
			// means the tunnel came up, so a timeout here is a stalled read.
			attempt.Verdict = checker.VerdictFor(aerr, attempt.ConnectMS > 0)
		}
		o.total++
		if attempt.Verdict == checker.VerdictSuccess {
			o.checks++
			ttfbs = append(ttfbs, attempt.TTFBMS)
			totals = append(totals, attempt.TotalMS)
		} else {
			o.noteFailure(attempt)
		}
	}

	// kept simple: an if-else chain here would trip gocritic's ifElseChain
	switch {
	case o.checks == o.total && o.total > 0:
		o.status, o.alive = "passed", true
	case o.checks > 0:
		o.status, o.alive = "semi-passed", true
	default:
		o.status, o.alive = "failed", false
	}

	if o.alive {
		o.rttMS = median(ttfbs)
		if o.rttMS <= 0 {
			o.rttMS = median(totals)
		}
		measureAliveExtras(ctx, tc, o, opts)
	}
	return o
}

// measureAliveExtras fills the alive-only anchors: the D8 exit-IP echo and
// the optional through-tunnel speedtest. The echo defaults ON (nil means
// on — production waves build Options without touching the field);
// best-effort — an unreachable echo leaves the anchor empty and never
// fails the probe.
func measureAliveExtras(ctx context.Context, tc *checker.TunnelClient, o *outcome, opts Options) {
	if opts.ExitProbe == nil || *opts.ExitProbe {
		o.exitIP = exitIPOf(ctx, tc, opts.ExitIPURL)
	}
	if opts.Speedtest && opts.SpeedtestURL != "" {
		o.speedBPS = speedSample(ctx, tc, opts.SpeedtestURL, opts.SpeedtestTimeout)
	}
}

// noteFailure records one failed attempt's verdict class and reason. The
// failure kind keeps the FIRST failure class seen (deterministic tie-break —
// mixed failure classes on one node are rare and any honest class beats a
// misleading aggregate).
func (o *outcome) noteFailure(a checker.Attempt) {
	if o.failureKind == "" && a.Verdict != "" && a.Verdict != checker.VerdictSuccess {
		o.failureKind = string(a.Verdict)
	}
	if o.reason == "" {
		switch {
		case a.Signature != "":
			o.reason = "blockpage: " + a.Signature
		case a.Err != "":
			o.reason = oneLine(a.Err)
		case a.Status != 0:
			o.reason = fmt.Sprintf("http %d", a.Status)
		}
	}
}

// exitIPOf reads the tunnel exit IP (D8) through the node's own instance —
// the same self-report call the geo stage makes. Best-effort: a failed echo
// leaves the anchor empty (geo falls back gracefully); it must never fail
// the probe of an alive node.
func exitIPOf(ctx context.Context, tc *checker.TunnelClient, endpoint string) string {
	if endpoint == "" {
		endpoint = exitIPURL
	}
	var payload struct {
		Query string `json:"query"`
	}
	if _, err := tc.GetJSON(ctx, endpoint, &payload); err != nil {
		return ""
	}
	return strings.TrimSpace(payload.Query)
}

// speedSample downloads ONE sample through the node's instance and returns
// bytes/second (0 on any failure — a missing measurement is honest, an
// invented one is not).
func speedSample(ctx context.Context, tc *checker.TunnelClient, url string, window time.Duration) int64 {
	bytes, elapsed, err := tc.DownloadWindow(ctx, url, window)
	if err != nil || bytes == 0 || elapsed <= 0 {
		return 0
	}
	return int64(float64(bytes) / elapsed.Seconds())
}

// median returns the median of a float sample (0 on empty — never invented).
func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	if len(sorted)%2 == 1 {
		return sorted[len(sorted)/2]
	}
	return (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
}

// freshSkipSet resolves the [probe].skip_fresh_within skip list: a node is
// skipped when its latest outcome is exactly `passed` (strict — semi-passed
// is re-probed) and its age is inside the window. Every skip is logged.
func freshSkipSet(nodes []*model.Node, opts Options, now time.Time) map[string]bool {
	if opts.SkipFreshWithin <= 0 || len(opts.Latest) == 0 {
		return nil
	}
	var skipped map[string]bool
	for _, n := range nodes {
		pr, ok := opts.Latest[n.Key]
		if !ok || pr.Status != "passed" {
			continue
		}
		if age := now.Sub(pr.CheckedAt); age < opts.SkipFreshWithin {
			if skipped == nil {
				skipped = map[string]bool{}
			}
			skipped[n.Key] = true
			progressf(opts.Progress,
				"skipping %s (%s): latest passed %s ago, within skip_fresh_within %s",
				n.Key, n.Host, age.Round(time.Second), opts.SkipFreshWithin)
		}
	}
	return skipped
}

func progressf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	_, _ = fmt.Fprintf(w, format+"\n", args...)
}

func oneLine(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
