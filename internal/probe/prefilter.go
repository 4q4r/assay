package probe

// Wave-1 TCP pre-filter (owner-approved probe-optimization program): a plain
// TCP dial per unique node endpoint kills closed-port endpoints in
// milliseconds, BEFORE any temp-xray boot spends CPU on them. The pipeline's
// pool is ~95% dead (2,893 alive of 65,865 keys) and every batch boot is a
// full xray process, so skipping dead endpoints before batching is the single
// largest CPU win available.
//
// Honest-by-construction: a failed TCP dial means no TCP listener — an xray
// TCP transport cannot connect either — so the exclusion is strictly safe and
// false-negative-free. A successful dial proves nothing beyond reachability,
// so those nodes still run the full probe. Reference mechanics (xray-knife
// pkg/http/prescan.go, verified against the tagged source 2026-11-06):
// dial each unique host:port once and fan the verdict out to every config
// sharing it; UDP-based protocols bypass; links without a dialable endpoint
// pass through so the full probe reports them exactly as it would without the
// stage; a canceled dial is NOT a verdict.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"public_vpn/internal/model"
)

// dialFunc is one TCP dial (production: net.Dialer.DialContext; tests: the
// Options.dialer seam).
type dialFunc = func(ctx context.Context, network, address string) (net.Conn, error)

// Prefilter tuning defaults (config knobs: [probe].tcp_prefilter_workers,
// [probe].tcp_prefilter_timeout). The knife runs 512 workers / 2s; 256
// workers keep fd pressure modest while still saturating any realistic
// endpoint count (a plain SYN handshake is cheap — no core instance), and a
// 1s bound is generous for a connect() that would take ~RTT to refuse.
const (
	DefaultPrefilterWorkers = 256
	DefaultPrefilterTimeout = time.Second
)

// prefilterEnabled resolves the tri-state stage knob on Options: nil
// (absent) = ON — the owner default (the pre-filter ships on, like every
// probe wave); an explicit false keeps the stage off with zero dials.
func (o Options) prefilterEnabled() bool {
	return o.TCPPrefilter == nil || *o.TCPPrefilter
}

// isUDPTransport reports whether the node runs over a UDP transport, so a
// TCP dial would produce a false negative (xray-knife isUDPBased parity,
// restricted to the schemes this pipeline can carry: tuic/wireguard/hysteria
// v1 never pass parse; hysteria2 and the kcp/mkcp/quic transport types do).
func isUDPTransport(n *model.Node) bool {
	if n == nil {
		return false
	}
	switch strings.ToLower(n.Scheme) {
	case "hysteria2", "hy2":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(n.Network)) {
	case "kcp", "mkcp", "quic":
		return true
	}
	return false
}

// endpointForNode returns the host:port to TCP-dial for the node, or "" when
// the dial is meaningless (empty host, invalid port): those nodes pass
// through untouched so the full probe reports them exactly as it would
// without the stage. The host is lowercased for the dedup key (DNS is
// case-insensitive — variant spellings of one endpoint must dial once), and
// surrounding brackets are stripped from bracketed IPv6 literals so
// net.JoinHostPort does not double-wrap (xray-knife endpointForProto parity).
func endpointForNode(n *model.Node) string {
	if n == nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(n.Host))
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "" || n.Port <= 0 || n.Port > 65535 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(n.Port))
}

// prefilterStats is the stage's per-wave accounting (LINK counts: a link is
// one unique probeJob; every node carrying the link takes its verdict).
type prefilterStats struct {
	linksTotal      int            // links entering the stage
	uniqueEndpoints int            // distinct host:port pairs actually dialed
	linksDead       int            // links excluded (TCP verdict: dead)
	linksBypassed   int            // links kept without dialing (UDP transport / no endpoint)
	linksPassed     int            // links reaching batching with an alive verdict
	linksUnchecked  int            // links passing through unchecked (wave torn down mid-dial — no verdict)
	drops           map[string]int // drop-reason class → link count (the filter-style drop report)
}

// logLine renders the one-line stage report in the pipeline's stage style
// ("filter complete: … kept, … dropped %v"): the dedup saving is visible as
// links vs unique-endpoints, the verdict split as filtered-dead /
// bypassed-udp / passed-through, dials interrupted by wave teardown rendered
// separately (a canceled dial is not a passed-through verdict), and the
// drop-reason breakdown last.
func (s *prefilterStats) logLine() string {
	return fmt.Sprintf(
		"probe pre-filter: links %d → unique-endpoints %d — "+
			"filtered-dead %d, bypassed-udp %d, passed-through %d, unchecked %d; drops %v",
		s.linksTotal, s.uniqueEndpoints, s.linksDead, s.linksBypassed, s.linksPassed, s.linksUnchecked, s.drops,
	)
}

// prefilterOrdered applies the wave-1 TCP pre-filter to the engine's ordered
// job list and prints the stage line — a no-op when the stage is disabled or
// there is nothing to filter (RunWithBatchFactory calls exactly this).
func prefilterOrdered(ctx context.Context, ordered []*probeJob, opts Options) []*probeJob {
	if !opts.prefilterEnabled() || len(ordered) == 0 {
		return ordered
	}
	survivors, stats := runTCPPrefilter(ctx, ordered, opts)
	progressf(opts.Progress, "%s", stats.logLine())
	return survivors
}

// dialOutcome is one endpoint's pre-filter result: reason is the drop-reason
// class ("" = alive); checked=false means the wave was torn down mid-dial and
// the result carries no verdict at all.
type dialOutcome struct {
	reason  string
	checked bool
}

// dialVerdicts dials each unique endpoint once across a worker pool (capped
// at the endpoint count, floor 1) and returns endpoint → outcome. The map is
// filled under a mutex; the pool is bounded by a semaphore — the same shape
// the engine's job loops use.
func dialVerdicts(
	ctx context.Context, dial dialFunc, eps []string, timeout time.Duration, workers int,
) map[string]dialOutcome {
	if workers > len(eps) {
		workers = len(eps)
	}
	if workers < 1 {
		workers = 1
	}
	verdicts := make(map[string]dialOutcome, len(eps))
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ep := range eps {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			reason, checked := dialEndpoint(ctx, dial, endpoint, timeout)
			mu.Lock()
			verdicts[endpoint] = dialOutcome{reason: reason, checked: checked}
			mu.Unlock()
		}(ep)
	}
	wg.Wait()
	return verdicts
}

// runTCPPrefilter dials each unique endpoint once (worker pool capped at the
// endpoint count) and returns the jobs that survive, preserving input order.
// A dial failure classifies the endpoint dead and every job sharing it is
// excluded from the wave with a per-reason drop count. Dials interrupted by
// wave teardown (parent context canceled) produce NO verdict — those jobs
// pass through unchecked (xray-knife FailCanceled parity: an unchecked node
// is not a dead node, and writing it as one would be a fake verdict).
func runTCPPrefilter(ctx context.Context, jobs []*probeJob, opts Options) ([]*probeJob, prefilterStats) {
	timeout := opts.TCPPrefilterTimeout
	if timeout <= 0 {
		timeout = DefaultPrefilterTimeout
	}
	workers := opts.TCPPrefilterWorkers
	if workers <= 0 {
		workers = DefaultPrefilterWorkers
	}

	stats := prefilterStats{linksTotal: len(jobs), drops: map[string]int{}}
	jobEndpoint := make([]string, len(jobs)) // per-job dedup key ("" = bypassed, no dial)
	unique := make(map[string]struct{})
	for i, job := range jobs {
		ep := ""
		if !isUDPTransport(job.node) {
			ep = endpointForNode(job.node)
		}
		jobEndpoint[i] = ep
		if ep != "" {
			unique[ep] = struct{}{}
		}
	}
	stats.uniqueEndpoints = len(unique)

	dial := opts.dialer
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}

	eps := make([]string, 0, len(unique))
	for ep := range unique {
		eps = append(eps, ep)
	}
	verdicts := dialVerdicts(ctx, dial, eps, timeout, workers)

	// Fan the verdicts out in input order: bypassed jobs (no dialable
	// endpoint), survivors, and dead links assemble into the passing slice
	// in exactly the engine's input order.
	passing := make([]*probeJob, 0, len(jobs))
	for i, job := range jobs {
		ep := jobEndpoint[i]
		switch {
		case ep == "":
			stats.linksBypassed++
			passing = append(passing, job)
		case !verdicts[ep].checked:
			// Teardown mid-dial: no verdict — the job passes through
			// unchecked and is counted separately so the stage report
			// never overstates passed-through after a canceled wave
			// (xray-knife FailCanceled parity).
			stats.linksUnchecked++
			passing = append(passing, job)
		case verdicts[ep].reason == "":
			stats.linksPassed++
			passing = append(passing, job)
		default:
			stats.linksDead++
			stats.drops[verdicts[ep].reason]++
		}
	}
	// Re-normalize the order indices: the surviving slice feeds batching
	// directly, and both engine paths (runJobs/runBatchJobs) address their
	// outcome slices by these indices — stale pre-filter indices would index
	// the outcome slice out of range.
	for i, job := range passing {
		job.order = i
	}
	return passing, stats
}

// dialEndpoint performs ONE TCP dial bounded by the per-dial timeout (DNS
// resolution included — a DNS failure means xray cannot resolve the endpoint
// either). Returns (reason, checked): checked=false means the wave was torn
// down mid-dial and the result carries no verdict.
func dialEndpoint(ctx context.Context, dial dialFunc, endpoint string, timeout time.Duration) (string, bool) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(dialCtx, "tcp", endpoint)
	if err == nil {
		_ = conn.Close()
		return "", true
	}
	if ctx.Err() != nil {
		return "", false // wave teardown: not a verdict
	}
	return classifyDialFailure(err), true
}

// classifyDialFailure buckets a dial error into the drop-reason classes the
// stage report counts (the filter-policy drop-report pattern: classes, not
// raw error strings).
func classifyDialFailure(err error) string {
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return "dns"
	}
	if opErr, ok := errors.AsType[*net.OpError](err); ok && errors.Is(opErr.Err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "DNS"):
		return "dns"
	case strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "unreachable"):
		return "unreachable"
	case strings.Contains(msg, "connection reset"):
		return "reset"
	default:
		return "other"
	}
}
