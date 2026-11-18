package cli

import (
	"io"
	"math"
	"time"

	"assay/internal/config"
	"assay/internal/platform"
)

// The memory gate (the 2026-11-18 swap-thrash incident): during a maintain
// wave the host's available memory can dip under what the heavy-alloc
// stages (fetch/parse/filter — parse alone handled 148,084 nodes in the
// incident, with daemon RSS 686M-1.6G and swap peaks 284-686M on a 15G
// host) can safely churn through, and the resulting host-wide swap thrash
// killed every TLS handshake on the box until the wave's heavy phases
// passed. Before each heavy stage the gate samples host MemAvailable
// (the per-OS platform reader); below the configured floor it WAITS in a
// bounded loop — one loud line per wait — and, when the wait budget
// expires, the wave SKIPS its remaining heavy stages for this cycle: the
// schedule re-arms normally and the last-good config keeps serving (D7).
// The gate never sits half-wave forever and never applies at the probe
// entry (probe is dial-bound and already adaptive).
//
// Knobs: [maintain].memory_gate_min_avail (floor, default 1.5Gi) and
// [maintain].memory_gate_max_wait (budget, default 30m; "0s" disables the
// gate entirely — the owner's escape hatch).

// memoryGateCheckInterval is the bounded wait loop's sample cadence.
// Code-owned, not a knob (only the two incident knobs are operator-facing
// — the supervision-politeness ruling).
const memoryGateCheckInterval = 30 * time.Second

// memoryReader samples host memory availability in bytes. The seam is
// defined at the CONSUMER (the gate) per the interface discipline; the
// concrete per-OS readers live in internal/platform, and tests inject
// scripts through this interface.
type memoryReader interface {
	MemAvailable() (uint64, error)
}

// platformMemoryReader adapts the platform package's per-OS reader to the
// gate's consumer-side seam.
type platformMemoryReader struct{}

func (platformMemoryReader) MemAvailable() (uint64, error) { return platform.MemAvailable() }

// gateVerdict is one memory-gate decision at a heavy stage entry.
type gateVerdict int

const (
	// gateProceed: MemAvailable is above the floor (or the gate fail-opens
	// on a read error) — the stage runs.
	gateProceed gateVerdict = iota
	// gateSkip: the wait budget expired below the floor — the wave skips its
	// remaining heavy stages for this cycle.
	gateSkip
	// gateStop: the daemon's stop channel closed during the wait — the wave
	// pauses through the existing between-stage checkpoint semantics (W17).
	gateStop
)

// memoryGate holds the wave gate's resolved knobs and seams.
type memoryGate struct {
	reader     memoryReader
	floor      uint64 // bytes of MemAvailable below which a heavy stage holds
	maxWait    time.Duration
	checkEvery time.Duration
	out        io.Writer
	now        func() time.Time
	// after arms a wait and returns the timer channel plus a stop func —
	// the same seam discipline as the scheduler's deps.after (a superseded
	// timer must not linger armed until it fires).
	after func(time.Duration) (<-chan time.Time, func())
	// stop is the daemon's lifetime channel: a stop during a gate wait
	// finishes PROMPTLY (the wait loop selects on it — never a full budget
	// of lag). Nil (the one-shot maintain path) = the loop never wakes
	// early, exactly the pre-gate signal behavior for a CLI process.
	stop <-chan struct{}
	// beat feeds the self-watchdog transport (darwin; nil-safe). One call
	// per hold-loop iteration keeps the widest legitimate heartbeat gap at
	// one check interval even across a full-budget hold.
	beat func()
}

// newMemoryGate resolves the gate from the config (post-defaults: the
// fields are always non-nil after applyMaintainDefaults, and the nil checks
// below keep hand-built test configs honest). An explicit max_wait of 0
// ("0s") constructs NO gate — nil, the disabled state, the owner's escape
// hatch.
func newMemoryGate(cfg *config.Config, out io.Writer, stop <-chan struct{}) *memoryGate {
	if cfg == nil {
		return nil
	}
	m := cfg.Maintain
	var maxWait time.Duration
	if m.MemoryGateMaxWait != nil {
		maxWait = m.MemoryGateMaxWait.Duration
	} else {
		maxWait = config.DefaultMemoryGateMaxWait
	}
	if maxWait == 0 {
		return nil
	}
	floor := config.DefaultMemoryGateMinAvail
	if m.MemoryGateMinAvail != nil && m.MemoryGateMinAvail.Bytes > 0 {
		floor = m.MemoryGateMinAvail.Bytes
	}
	return &memoryGate{
		reader:     platformMemoryReader{},
		floor:      floor,
		maxWait:    maxWait,
		checkEvery: memoryGateCheckInterval,
		out:        out,
		now:        time.Now,
		after: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTimer(d)
			return t.C, func() { t.Stop() }
		},
		stop: stop,
	}
}

// allow runs the gate at one heavy stage entry: proceed immediately when
// MemAvailable is above the floor (silent — loud lines are for holds),
// otherwise hold in a bounded loop (one loud line per wait), until the
// floor is met (proceed, with a recovery line), the budget expires (skip),
// or the daemon stops (prompt stop).
func (g *memoryGate) allow(stage string) gateVerdict {
	avail, err := g.reader.MemAvailable()
	if err != nil {
		// Fail-open BY CONTRACT: the gate is a thrash guard, not a hard
		// dependency — a platform that cannot answer the read degrades to
		// the pre-gate behavior, loudly, never by holding waves on a signal
		// it cannot see.
		outf(g.out, "memory gate: MemAvailable read failed (%v) — proceeding without gating\n", err)
		return gateProceed
	}
	if avail >= g.floor {
		return gateProceed
	}
	total := g.waitsBudgeted()
	start := g.now()
	for wait := 1; ; wait++ {
		if g.beat != nil {
			g.beat() // coordination-loop progress while holding
		}
		outf(g.out, "memory gate: MemAvailable %s below floor %s — holding before %s (wait %d/%d)\n",
			config.FormatByteSize(avail), config.FormatByteSize(g.floor), stage, wait, total)
		sleep := g.checkEvery
		if remaining := g.maxWait - g.now().Sub(start); remaining < sleep {
			sleep = remaining // never sleep past the budget
		}
		if sleep < 0 {
			sleep = 0
		}
		timerC, stopTimer := g.after(sleep)
		select {
		case <-g.stop:
			stopTimer()
			return gateStop
		case <-timerC:
		}
		avail, err = g.reader.MemAvailable()
		if err != nil {
			outf(g.out, "memory gate: MemAvailable read failed (%v) — proceeding without gating\n", err)
			return gateProceed
		}
		if avail >= g.floor {
			if g.beat != nil {
				g.beat() // the gate released — coordination-loop progress
			}
			outf(g.out, "memory gate: MemAvailable %s recovered — proceeding before %s (waited %d/%d)\n",
				config.FormatByteSize(avail), stage, wait, total)
			return gateProceed
		}
		if g.now().Sub(start) >= g.maxWait {
			// The budget expired with the host still under the floor: the
			// wave-level skip line is the orchestrator's job (it names the
			// wave consequence); the gate returns the verdict.
			return gateSkip
		}
	}
}

// waitsBudgeted is the loud line's wait denominator: how many holds the
// budget allows at the check cadence (30m / 30s = 60), rounded up, at
// least one.
func (g *memoryGate) waitsBudgeted() int {
	if g.checkEvery <= 0 {
		return 1
	}
	n := int(math.Ceil(float64(g.maxWait) / float64(g.checkEvery)))
	return max(n, 1)
}
