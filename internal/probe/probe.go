// Package probe implements the out-of-band liveness wave (W2, W14 engine):
// every probed node gets a temporary single-node xray instance — the SAME
// infrastructure the check stage uses (one factory, no drift) — so
// real-tunnel HTTP probes deliver latency, the tunnel EXIT IP (D8 — never
// the advertised host) and an optional through-tunnel speedtest uniformly
// across EVERY rendered protocol, hysteria2 included. The live client is
// never involved.
package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"assay/internal/checker"
	"assay/internal/model"
	"assay/internal/store"
)

// DefaultConcurrency bounds how many temp instances exist at once (each is
// a full xray process). W19: 32 — enough workers to saturate the factory's
// boot-serialization ceiling (~10 boots/sec; the HTTP phase is parallel), so
// wave wall time stays bounded-minutes per 1000 nodes while the semaphore
// still bounds instantaneous load. The engine boots REAL cores: the boot
// mutex remains the true bottleneck, and 32 workers keep every core busy
// behind it. An explicit [probe].threads (the owner's live 20) is
// untouched by this default.
const DefaultConcurrency = 12

// exitIPURL is the through-tunnel endpoint the engine reads the D8 exit IP
// from (the SAME ip-api self-report the classification pass makes — one mental
// model, one rate-limit surface; the free tier's budget is per requesting
// IP, and our requests originate from thousands of distinct exits). Test
// seam: ExitIPURL (zero in production).
const exitIPURL = "http://ip-api.com/json/"

// Options configures one probe wave.
type Options struct {
	Timeout          time.Duration                     // per-attempt HTTP timeout
	Threads          int                               // parallel temp-instance workers (0 = default 32)
	BatchSize        int                               // nodes per xray process (0 = unset → 1000)
	BatchConcurrency int                               // nodes probed concurrently inside one batch (0 = default 10)
	URL              string                            // probe target URL
	Attempts         int                               // HTTP GET attempts per node (>= 1)
	Speedtest        bool                              // measure download speed through the node's instance
	SpeedtestURL     string                            // the sample the speedtest downloads
	SpeedtestTimeout time.Duration                     // download sample window
	SkipFreshWithin  time.Duration                     // skip fresh passed nodes within this window (0 = probe all)
	Latest           map[string]store.ProbeResult      // latest outcome per node key
	KnownAlive       map[string]store.KnownAliveRecord // known-alive set (skip within TTL)
	KnownAliveTTL    time.Duration                     // TTL for known-alive entries (0 = disabled)
	KnownAliveMu     *sync.RWMutex                     // optional guard for KnownAlive (nil = unlocked)
	Now              func() time.Time                  // clock seam (nil = time.Now().UTC())
	Progress         io.Writer                         // progress output (nil = discard)
	ExitProbe        *bool                             // D8 exit-IP echo (nil = ON)
	ExitIPURL        string                            // exit-IP echo endpoint override
	Limiter          *AdaptiveLimiter                  // optional dynamic concurrency limiter
	// TCPPrefilter gates the wave-1 TCP pre-filter stage (prefilter.go):
	// plain TCP-dial each unique endpoint before batching; closed endpoints
	// never reach an xray boot. Tri-state like ExitProbe: nil (absent) = ON
	// (the owner default — the stage ships on); an explicit false disables
	// the stage with zero dials.
	TCPPrefilter *bool
	// TCPPrefilterWorkers bounds concurrent pre-filter dials (0 = default
	// 256, capped at the unique endpoint count).
	TCPPrefilterWorkers int
	// TCPPrefilterTimeout bounds ONE TCP dial, DNS resolution included
	// (0 = default 1s).
	TCPPrefilterTimeout time.Duration
	// dialer is the test seam for the pre-filter's TCP dials (nil =
	// net.Dialer; production leaves it nil).
	dialer dialFunc

	// Classifier runs the FULL classification battery (ip-api self-report +
	// unlock battery v2) for ONE alive node THROUGH the SAME hot instance
	// address the node's probe just passed (addr) — the tunnel is proven
	// working RIGHT NOW, so the verdicts describe a verified-hot tunnel
	// instead of a stale cross-wave respawn (owner order 2026-11-07:
	// «сразу на чеке чекать медиа, блоки, страны»). The hook runs BEFORE the
	// batch instance is torn down; a nil Classifier = probe-only wave (the
	// [geo].unlock_probes explicit-off escape hatch). The hook owns its
	// honesty: it never fails the probe, and a battery that dies mid-flight
	// records honest unknowns for this wave (the next wave re-classifies).
	Classifier ClassifyFunc
}

// ClassifyFunc is the classification hook the probe engine invokes per alive
// node while the batch instance is still open. exitIP carries the probe
// wave's observed D8 anchor (may be empty when the echo failed — the battery
// does not need it; the ladder's churn check degrades gracefully). rttMs
// carries the node's own measured probe RTT (median TTFB in ms; the input
// the RTT-adaptive per-request timeout derives from).
type ClassifyFunc func(ctx context.Context, node *model.Node, addr string, exitIP string, rttMs float64)

// SocksInstance is one live temp SOCKS5 endpoint (production: a temp xray;
// tests: an in-process server). Structural twin of the checker/geo seams —
// the CLI adapter hands a checker.NewXrayFactory product over 1:1.
type SocksInstance = checker.SocksInstance

// BatchSocksInstance extends SocksInstance for multi-node batches.
// A batch instance exposes multiple addresses (one per node in the batch).
type BatchSocksInstance = checker.BatchSocksInstance

// Factory spawns one instance per node (production: checker.NewXrayFactory
// — one temp single-node xray per probed node, the SAME render.BuildOutbound
// product the live renderer uses, hardening knobs included).
type Factory = checker.InstanceFactory

// BatchFactory spawns ONE instance for a batch of nodes (production:
// checker.NewXrayBatchFactory — one temp xray with N outbounds for N nodes).
// Returns a BatchSocksInstance with N addresses matching the input node order.
type BatchFactory = checker.BatchInstanceFactory

// probeJob is one unique-link unit of work: every node carrying the link
// takes the outcome.
type probeJob struct {
	link  string
	keys  []string
	host  string
	node  *model.Node
	order int
}

// batchJob is a group of probeJobs processed by one batch instance.
type batchJob struct {
	jobs  []*probeJob
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
	return RunWithBatchFactory(ctx, nodes, f, nil, opts, resultsPath)
}

// RunWithBatchFactory is like Run but accepts an optional BatchFactory for
// multi-node batching. When batchFactory is non-nil, nodes are grouped into
// batches of size opts.BatchSize (0 = unset → the big-batch default 1000,
// config.DefaultProbeBatchSize) and processed with fewer xray process
// spawns. A batch that fails AS A BATCH (instance boot failure, address
// mismatch, whole-batch context death — never per-node handshake failures)
// retries its unprobed nodes at half the batch size, recursively, down to
// the halvingFloorBatchSize floor of 20 (adaptive halving). The single-node
// factory `f` is used as a fallback for any nodes not handled by the batch
// factory (e.g., remainder nodes).
// Before any batching, the wave-1 TCP pre-filter (prefilter.go) excludes
// TCP-dead endpoints from the wave when enabled (default ON).
func RunWithBatchFactory(
	ctx context.Context, nodes []*model.Node, f Factory, batchFactory BatchFactory, opts Options, resultsPath string,
) ([]store.ProbeResult, error) {
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	skipped := freshSkipSet(nodes, opts, now)
	if ks := knownAliveSkipSet(nodes, opts, now); ks != nil {
		if skipped == nil {
			skipped = map[string]bool{}
		}
		for k := range ks {
			skipped[k] = true
		}
	}
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

	// Wave-1 TCP pre-filter: decide WHO reaches batching before any temp
	// xray boot. Closed endpoints are excluded from this wave entirely (no
	// outcome, no log entry — their previous probe results stay untouched);
	// UDP transports bypass; the stage reports one summary line with the
	// drop-reason breakdown. An explicit [probe].tcp_prefilter=false skips
	// the stage (byte-identical to the pre-wave-1 behavior).
	ordered = prefilterOrdered(ctx, ordered, opts)

	var outcomes []*outcome
	if batchFactory != nil && len(ordered) > 0 {
		batchSize := opts.BatchSize
		if batchSize <= 0 {
			batchSize = 1000 // default batch size (config.DefaultProbeBatchSize, big-batch model)
		}
		outcomes = runBatchJobs(ctx, batchFactory, ordered, opts, batchSize)
	} else {
		outcomes = runJobs(ctx, f, ordered, opts)
	}

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
	limiter := opts.Limiter
	sem := make(chan struct{}, concurrency)
	done := make([]chan struct{}, len(jobs))
	for i := range done {
		done[i] = make(chan struct{})
	}
	for i := range jobs {
		go func(i int) {
			if limiter != nil {
				if err := limiter.Acquire(ctx); err != nil {
					close(done[i])
					return
				}
				defer limiter.Release()
			} else {
				sem <- struct{}{}
				defer func() { <-sem }()
			}
			res := runJob(ctx, f, jobs[i], opts)
			out[i] = res
			if limiter != nil && res != nil {
				rtt := time.Duration(res.rttMS * float64(time.Millisecond))
				limiter.RecordOutcome(rtt, !res.alive)
			}
			close(done[i])
		}(i)
	}
	for i := range done {
		<-done[i]
	}
	return out
}

// halvingFloorBatchSize is the adaptive batch-halving floor (the
// pre-big-batch default): a batch that failed AS A BATCH retries its
// unprobed nodes at half the batch size only while the retry size stays at
// or above this floor; below it the batch is reported failed loudly. The
// floor is deliberately a code-level constant, not a knob (owner-approved
// big-batch wave design — halving is automatic, no new config surface).
const halvingFloorBatchSize = 20

// runBatchJobs executes jobs in batches using a BatchFactory. Each batch
// shares one xray process. The concurrency limit applies to BATCHES, not
// individual nodes.
func runBatchJobs(ctx context.Context, bf BatchFactory, jobs []*probeJob, opts Options, batchSize int) []*outcome {
	concurrency := opts.Threads
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}

	// Group jobs into batches
	batches := make([]*batchJob, 0, (len(jobs)+batchSize-1)/batchSize)
	for i := 0; i < len(jobs); i += batchSize {
		end := min(i+batchSize, len(jobs))
		batches = append(batches, &batchJob{jobs: jobs[i:end], order: i})
	}

	out := make([]*outcome, len(jobs))
	if len(batches) == 0 {
		return out
	}

	limiter := opts.Limiter
	sem := make(chan struct{}, concurrency)
	done := make([]chan struct{}, len(batches))
	for i := range done {
		done[i] = make(chan struct{})
	}

	for i := range batches {
		go func(i int) {
			if limiter != nil {
				if err := limiter.Acquire(ctx); err != nil {
					close(done[i])
					return
				}
				defer limiter.Release()
			} else {
				sem <- struct{}{}
				defer func() { <-sem }()
			}
			batchOutcomes := runBatchJobAdaptive(ctx, bf, batches[i].jobs, opts, batchSize)
			// Write outcomes back to the correct positions
			for j, o := range batchOutcomes {
				out[batches[i].order+j] = o
				if limiter != nil && o != nil {
					rtt := time.Duration(o.rttMS * float64(time.Millisecond))
					limiter.RecordOutcome(rtt, !o.alive)
				}
			}
			close(done[i])
		}(i)
	}

	for i := range done {
		<-done[i]
	}
	return out
}

// runBatchJobAdaptive drives one batch with adaptive halving (the v2rayN
// pattern): a batch that fails AS A BATCH — instance boot failure, address
// mismatch, whole-batch context death, but NEVER per-node handshake
// failures, which are normal outcomes — retries its UNPROBED nodes at half
// the batch size, recursively, down to the halvingFloorBatchSize floor of
// 20; at the floor the remaining nodes are reported failed loudly (per-node
// instance-boot outcomes, exactly the pre-halving semantics). A successful
// batch never halves anything, and per-node verdict logic is untouched:
// halving is a process-model recovery, not a verdict change. The returned
// slice stays aligned 1:1 with jobs.
func runBatchJobAdaptive(
	ctx context.Context, bf BatchFactory, jobs []*probeJob, opts Options, batchSize int,
) []*outcome {
	outcomes, failure := runBatchJobOnce(ctx, bf, jobs, opts)
	if failure == nil {
		return outcomes
	}
	out := make([]*outcome, len(jobs))
	copy(out, outcomes) // outcomes is nil after a boot failure — out stays all-unprobed
	unprobed := unprobedIdxs(ctx, out)
	if len(unprobed) == 0 {
		return out // every node holds a standing outcome despite the batch-level event
	}
	half := batchSize / 2
	if ctx.Err() != nil {
		// The whole-batch context ended: retries would boot-fail against the
		// same dead context. Report loudly instead of spinning the ladder.
		progressf(opts.Progress,
			"probing batch of %d nodes failed as a batch (%v) — wave context ended, reporting %d unprobed nodes failed",
			batchSize, failure, len(unprobed))
		fillUnprobedFailures(out, unprobed, jobs, opts, failure)
		return out
	}
	if half < halvingFloorBatchSize {
		progressf(opts.Progress,
			"probing batch halving floor %d reached — reporting %d unprobed nodes failed (%v)",
			halvingFloorBatchSize, len(unprobed), failure)
		fillUnprobedFailures(out, unprobed, jobs, opts, failure)
		return out
	}
	progressf(opts.Progress,
		"probing batch of %d nodes failed as a batch (%v) — adaptive halving: %d unprobed nodes retry at batch size %d",
		batchSize, failure, len(unprobed), half)
	for start := 0; start < len(unprobed); start += half {
		end := min(start+half, len(unprobed))
		chunk := unprobed[start:end]
		chunkJobs := make([]*probeJob, len(chunk))
		for i, idx := range chunk {
			chunkJobs[i] = jobs[idx]
		}
		chunkOut := runBatchJobAdaptive(ctx, bf, chunkJobs, opts, half)
		for i, idx := range chunk {
			out[idx] = chunkOut[i]
		}
	}
	return out
}

// runBatchJobOnce makes ONE batch attempt: single temp instance → per-node
// attempts → exit IP → speedtest → aggregation. It returns the per-node
// outcomes aligned with jobs (nil for never-probed nodes) plus the batch-
// level failure, if any: a boot error, an address-count mismatch, or the
// whole-batch context dying mid-probe (failed outcomes from a dead context
// are artifacts, and the adaptive layer re-decides their fate). Per-node
// handshake failures are normal outcomes and never set the batch failure.
func runBatchJobOnce(ctx context.Context, bf BatchFactory, jobs []*probeJob, opts Options) ([]*outcome, error) {
	// Collect nodes for the batch factory
	nodes := make([]*model.Node, len(jobs))
	for i, job := range jobs {
		nodes[i] = job.node
	}

	progressf(opts.Progress, "probing batch of %d nodes (%s)…", len(nodes), jobs[0].host)

	inst, err := bf(ctx, nodes)
	if err != nil {
		return nil, err
	}
	defer func() { _ = inst.Close() }()

	addrs := inst.Addrs()
	if len(addrs) != len(jobs) {
		return nil, errors.New("batch instance address count mismatch")
	}

	// Probe nodes within the batch CONCURRENTLY.
	// BatchConcurrency limits simultaneous probes per batch (0 = no limit, probe all at once).
	// This avoids the sequential bottleneck: batchSize=10 * 3 attempts * 10s = 300s serial.
	batchConcurrency := opts.BatchConcurrency
	if batchConcurrency <= 0 {
		batchConcurrency = 10 // default batch concurrency
	}
	if batchConcurrency > len(jobs) {
		batchConcurrency = len(jobs)
	}

	results := make([]*outcome, len(jobs))
	sem := make(chan struct{}, batchConcurrency)
	done := make([]chan struct{}, len(jobs))
	for i := range done {
		done[i] = make(chan struct{})
	}

	for i, job := range jobs {
		go func(i int, job *probeJob, addr string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = probeNode(ctx, addr, job, opts)
			close(done[i])
		}(i, job, addrs[i])
	}

	for i := range done {
		<-done[i]
	}

	if cerr := ctx.Err(); cerr != nil {
		return results, fmt.Errorf("batch context ended mid-probe: %w", cerr)
	}
	// Classification rides the hot instance: every ALIVE outcome gets the
	// full battery through its own per-node socks port BEFORE the deferred
	// instance teardown. A dead wave context skips the pass (the adaptive
	// layer re-decides this batch; the next wave re-classifies).
	classifyAliveNodes(ctx, opts, jobs, addrs, results)
	return results, nil
}

// classifyAliveNodes runs the Options.Classifier hook for every alive
// outcome of a batch, concurrently within the batch's own probe concurrency,
// while the batch instance is still open. The hook is best-effort by
// contract: it never changes the probe outcomes, and a nil hook is the
// probe-only wave.
func classifyAliveNodes(ctx context.Context, opts Options, jobs []*probeJob, addrs []string, results []*outcome) {
	if opts.Classifier == nil || ctx.Err() != nil {
		return
	}
	sem := make(chan struct{}, max(opts.BatchConcurrency, 1))
	done := make([]chan struct{}, len(jobs))
	for i := range done {
		done[i] = make(chan struct{})
	}
	for i, job := range jobs {
		if results[i] == nil || !results[i].alive {
			close(done[i])
			continue
		}
		go func(i int, job *probeJob, addr string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			opts.Classifier(ctx, job.node, addr, results[i].exitIP, results[i].rttMS)
			close(done[i])
		}(i, job, addrs[i])
	}
	for i := range done {
		<-done[i]
	}
}

// unprobedIdxs returns the positions lacking a trustworthy outcome: never-
// probed (nil) always; additionally, once the batch context has ended, a
// failed outcome is a context artifact and counts as unprobed (alive
// outcomes completed before the cancellation and stand).
func unprobedIdxs(ctx context.Context, out []*outcome) []int {
	ctxDead := ctx.Err() != nil
	var idxs []int
	for i, o := range out {
		if o == nil || (ctxDead && !o.alive) {
			idxs = append(idxs, i)
		}
	}
	return idxs
}

// fillUnprobedFailures records the loud batch-level failure for every
// unprobed node — the exact per-node shape the pre-halving batchBootFailure
// produced (failed / instance-boot / one-lined reason).
func fillUnprobedFailures(out []*outcome, idxs []int, jobs []*probeJob, opts Options, err error) {
	for _, idx := range idxs {
		out[idx] = &outcome{
			host: jobs[idx].host, alive: false, status: "failed",
			reason: oneLine(err.Error()), failureKind: "instance-boot",
			total: opts.Attempts,
		}
	}
}

// probeNode probes a single node through the given address.
func probeNode(ctx context.Context, addr string, job *probeJob, opts Options) *outcome {
	o := &outcome{host: job.host}
	var ttfbs, totals []float64
	tc := checker.NewTunnelClient(addr, opts.Timeout)
	for range opts.Attempts {
		attempt, aerr := tc.Get(ctx, opts.URL)
		if aerr != nil && attempt.Verdict == "" {
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
		if opts.Classifier != nil && ctx.Err() == nil {
			// Classification rides the hot single-node instance (same
			// contract as the batch path): the battery runs BEFORE the
			// deferred teardown.
			opts.Classifier(ctx, job.node, inst.Addr(), o.exitIP, o.rttMS)
		}
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
// the same self-report the classification pass makes. Best-effort: a failed
// echo leaves the anchor empty (the classification ladder falls back
// gracefully); it must never fail the probe of an alive node.
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

// knownAliveSkipSet resolves the KnownAlive skip list: a node present in the
// KnownAlive set is skipped when its entry is still within KnownAliveTTL.
// Both `passed` and `semi-passed` (and any non-failed known-alive) entries
// are skipped — the whole point of the redesign. Every skip is logged.
func knownAliveSkipSet(nodes []*model.Node, opts Options, now time.Time) map[string]bool {
	if opts.KnownAliveTTL <= 0 || len(opts.KnownAlive) == 0 {
		return nil
	}
	if opts.KnownAliveMu != nil {
		opts.KnownAliveMu.RLock()
		defer opts.KnownAliveMu.RUnlock()
	}
	var skipped map[string]bool
	for _, n := range nodes {
		rec, ok := opts.KnownAlive[n.Key]
		if !ok {
			continue
		}
		if age := now.Sub(rec.LastSeen); age < opts.KnownAliveTTL {
			status := rec.LastStatus
			if status == "failed" {
				continue
			}
			if skipped == nil {
				skipped = map[string]bool{}
			}
			skipped[n.Key] = true
			progressf(opts.Progress,
				"skipping known-alive node %s (%s): last seen %s ago",
				n.Key, n.Host, age.Round(time.Second))
		}
	}
	return skipped
}

// KnownAliveSkipSet is the exported form of knownAliveSkipSet (tests in
// external packages).
func KnownAliveSkipSet(nodes []*model.Node, opts Options, now time.Time) map[string]bool {
	return knownAliveSkipSet(nodes, opts, now)
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
