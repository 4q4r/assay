package cli

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"assay/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMemoryReader is the memoryReader seam: a scripted sequence of byte
// counts (the last value repeats once the script runs out) or a sticky
// error. Reads are counted so tests can assert exactly how many samples a
// verdict consumed.
type fakeMemoryReader struct {
	mu     sync.Mutex
	values []uint64
	err    error
	reads  int
}

func (f *fakeMemoryReader) MemAvailable() (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.err != nil {
		return 0, f.err
	}
	if len(f.values) == 0 {
		return 0, nil
	}
	v := f.values[0]
	if len(f.values) > 1 {
		f.values = f.values[1:]
	}
	return v, nil
}

func (f *fakeMemoryReader) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// gateClock is the gate's test clock: after(d) advances the fake instant by
// d and returns an already-ready timer channel, so allow() runs fully
// synchronously in the test goroutine — every sleep is a clock tick, no
// goroutines, no flakes.
type gateClock struct {
	nowNano atomic.Int64
}

func (c *gateClock) now() time.Time { return time.Unix(0, c.nowNano.Load()) }

func (c *gateClock) after(d time.Duration) (<-chan time.Time, func()) {
	c.nowNano.Add(int64(d))
	ch := make(chan time.Time, 1)
	ch <- c.now()
	return ch, func() {}
}

// neverAfter is the after seam for stop-path tests: the timer never fires,
// so a select that wakes must have woken on the stop channel.
func neverAfter(time.Duration) (<-chan time.Time, func()) {
	ch := make(chan time.Time)
	return ch, func() {}
}

// testGate builds a gate over the seam pair (reader, clock/seams).
func testGate(reader memoryReader, clock *gateClock, maxWait time.Duration, out *bytes.Buffer) *memoryGate {
	return &memoryGate{
		reader:     reader,
		floor:      1500 << 20, // 1.5Gi
		maxWait:    maxWait,
		checkEvery: time.Second,
		out:        out,
		now:        clock.now,
		after:      clock.after,
	}
}

func newTestGateConfig(t *testing.T, floor uint64, maxWait time.Duration) *config.Config {
	t.Helper()
	cfg := maintainCfg(t)
	cfg.Maintain.MemoryGateMinAvail = &config.ByteSize{Bytes: floor}
	cfg.Maintain.MemoryGateMaxWait = &config.Duration{Duration: maxWait}
	return cfg
}

func TestMemoryGateProceedsAboveFloorSilently(t *testing.T) {
	var buf bytes.Buffer
	g := testGate(&fakeMemoryReader{values: []uint64{3 << 30}}, &gateClock{}, 30*time.Second, &buf)
	require.Equal(t, gateProceed, g.allow("parse"))
	require.Empty(t, buf.String(), "the healthy path is silent — loud lines are for holds only")
}

// TestMemoryGateTable pins the verdict table: hold lines per wait, recovery
// mid-wait proceeds, budget expiry skips, stop wakes prompt, disabled gate
// is a nil constructor, read failure fail-opens.
func TestMemoryGateTable(t *testing.T) {
	tests := []struct {
		name        string
		reader      *fakeMemoryReader
		maxWait     time.Duration
		stage       string
		stop        func() <-chan struct{}
		after       func(time.Duration) (<-chan time.Time, func())
		want        gateVerdict
		wantHolds   int
		wantInLog   []string
		wantNotLog  []string
		wantMaxRead int
	}{
		{
			name:       "below floor whole budget → skip, one hold line per wait",
			reader:     &fakeMemoryReader{values: []uint64{1 << 30}},
			maxWait:    5 * time.Second,
			want:       gateSkip,
			wantHolds:  5,
			wantInLog:  []string{"holding before parse (wait 1/5)", "holding before parse (wait 5/5)"},
			wantNotLog: []string{"recovered"},
		},
		{
			name:       "dips below floor then recovers mid-wait → proceeds",
			reader:     &fakeMemoryReader{values: []uint64{1 << 30, 1 << 30, 2 << 30}},
			maxWait:    5 * time.Second,
			want:       gateProceed,
			wantHolds:  2,
			wantInLog:  []string{"holding before parse (wait 1/5)", "holding before parse (wait 2/5)", "recovered — proceeding before parse"},
			wantNotLog: []string{"SKIPPING"},
		},
		{
			name:   "stop during wait → prompt gateStop, timer never fired",
			reader: &fakeMemoryReader{values: []uint64{1 << 30}},
			stage:  "parse",
			stop: func() <-chan struct{} {
				stopC := make(chan struct{})
				close(stopC)
				return stopC
			},
			after:     neverAfter,
			want:      gateStop,
			wantHolds: 1,
			wantNotLog: []string{
				"recovered",
				"SKIPPING",
			},
			wantMaxRead: 1, // one sample (the hold line), then the stop woke the wait
		},
		{
			name:        "read failure → fail-open proceed with a loud line",
			reader:      &fakeMemoryReader{err: assert.AnError},
			maxWait:     5 * time.Second,
			want:        gateProceed,
			wantHolds:   0,
			wantInLog:   []string{"read failed"},
			wantMaxRead: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			clock := &gateClock{}
			g := testGate(tt.reader, clock, tt.maxWait, &buf)
			if tt.after != nil {
				g.after = tt.after
			}
			if tt.stop != nil {
				g.stop = tt.stop()
			}
			got := g.allow("parse")
			require.Equal(t, tt.want, got)
			out := buf.String()
			for _, want := range tt.wantInLog {
				assert.Contains(t, out, want)
			}
			for _, forbidden := range tt.wantNotLog {
				assert.NotContains(t, out, forbidden)
			}
			assert.Equal(t, tt.wantHolds, bytes.Count(buf.Bytes(), []byte("holding before "+tt.stage)),
				"one loud line per hold:\n%s", out)
			if tt.wantMaxRead > 0 {
				assert.LessOrEqual(t, tt.reader.count(), tt.wantMaxRead, "sample budget exceeded")
			}
		})
	}
}

// TestMemoryGateBudgetBelowCheckInterval pins the degenerate budget: a
// maxWait smaller than one check interval holds once and skips (the sleep
// never overshoots the budget — the wait sleeps min(interval, remaining)).
func TestMemoryGateBudgetBelowCheckInterval(t *testing.T) {
	var buf bytes.Buffer
	clock := &gateClock{}
	g := testGate(&fakeMemoryReader{values: []uint64{1 << 30}}, clock, 500*time.Millisecond, &buf)
	g.checkEvery = 2 * time.Second
	require.Equal(t, gateSkip, g.allow("filter"))
	assert.Contains(t, buf.String(), "holding before filter (wait 1/1)")
	assert.NotContains(t, buf.String(), "wait 2/", "a 500ms budget produces exactly one hold")
	// The clock advanced by min(checkEvery, remaining) — 500ms, not 2s.
	assert.LessOrEqual(t, clock.nowNano.Load(), int64(600*time.Millisecond))
}

// TestNewMemoryGateDisabledOnZeroMaxWait pins the escape hatch: an explicit
// "0s" memory_gate_max_wait constructs NO gate; a normal config constructs
// one carrying the resolved knobs.
func TestNewMemoryGateDisabledOnZeroMaxWait(t *testing.T) {
	disabled := newTestGateConfig(t, 1<<30, 0)
	require.Nil(t, newMemoryGate(disabled, &bytes.Buffer{}, nil),
		`memory_gate_max_wait = "0s" disables the gate entirely`)
	normal := newTestGateConfig(t, 2<<30, 45*time.Minute)
	g := newMemoryGate(normal, &bytes.Buffer{}, nil)
	require.NotNil(t, g)
	require.Equal(t, uint64(2<<30), g.floor)
	require.Equal(t, 45*time.Minute, g.maxWait)
	require.Equal(t, memoryGateCheckInterval, g.checkEvery)
}

// TestFormatGateBytes pins the loud-line byte rendering (the knob spelling).
func TestFormatGateBytes(t *testing.T) {
	require.Equal(t, "1.5Gi", config.FormatByteSize(3<<29))
	require.Equal(t, "1.0Gi", config.FormatByteSize(1<<30))
	require.Equal(t, "512.0Mi", config.FormatByteSize(512<<20))
	require.Equal(t, "64Ki", config.FormatByteSize(64<<10))
	require.Equal(t, "100B", config.FormatByteSize(100))
}

// --- wave integration: the gate rides the stage entries (fetch/parse/filter) ---

// TestWaveMemoryGateSkipAbortsCleanly pins the budget-expiry semantics: the
// wave stops BEFORE the gated stage, returns nil (clean — the scheduler
// re-arms and the next wave runs on schedule), and the loud skip line names
// the consequence.
func TestWaveMemoryGateSkipAbortsCleanly(t *testing.T) {
	rec := &stageRecorder{}
	buf := &bytes.Buffer{}
	cfg := newTestGateConfig(t, 1<<30, time.Millisecond) // floor 1Gi, budget 1ms
	g := newMemoryGate(cfg, buf, nil)
	g.reader = &fakeMemoryReader{values: []uint64{512 << 20}} // always below floor
	g.checkEvery = time.Millisecond
	clock := &gateClock{}
	g.now, g.after = clock.now, clock.after
	err := runMaintainGraceful(buf, cfg, maintainOptions{}, rec.stages(), nil, g)
	require.NoError(t, err, "a gate skip is a CLEAN abort — the wave returns nil, the schedule re-arms")
	assert.Empty(t, rec.order, "no stage runs past the expired gate")
	out := buf.String()
	assert.Contains(t, out, "SKIPPING the wave before fetch")
	assert.Contains(t, out, "last-good config keeps serving")
}

// TestWaveMemoryGateStopPausesBeforeStage pins the stop-channel contract: a
// stop during a gate wait finishes PROMPTLY through the existing pause
// semantics (W17 checkpoint discipline) — no budget-sized lag.
func TestWaveMemoryGateStopPausesBeforeStage(t *testing.T) {
	rec := &stageRecorder{}
	buf := &bytes.Buffer{}
	cfg := newTestGateConfig(t, 1<<30, time.Hour)
	g := newMemoryGate(cfg, buf, nil)
	g.reader = &fakeMemoryReader{values: []uint64{512 << 20}} // holds forever
	stop := make(chan struct{})
	g.stop = stop
	done := make(chan error, 1)
	go func() {
		done <- runMaintainGraceful(buf, cfg, maintainOptions{}, rec.stages(), nil, g)
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	select {
	case err := <-done:
		require.NoError(t, err, "a stop during a gate wait is the clean pause")
	case <-time.After(5 * time.Second):
		t.Fatal("the gate wait did not finish promptly on stop — the wait loop must select on it")
	}
	assert.Empty(t, rec.order)
	assert.Contains(t, buf.String(), "shutdown requested while holding at the memory gate before fetch")
}

// TestWaveGateAppliesOnlyAtHeavyStageEntries pins the scope: the gate checks
// ride fetch/parse/filter entries ONLY — probe (dial-bound, already adaptive)
// and every tail stage run ungated.
func TestWaveGateAppliesOnlyAtHeavyStageEntries(t *testing.T) {
	rec := &stageRecorder{}
	buf := &bytes.Buffer{}
	cfg := newTestGateConfig(t, 1<<30, time.Hour)
	g := newMemoryGate(cfg, buf, nil)
	// Alternating low/high: every gated entry holds once (low), then recovers
	// (high). Three gated entries = exactly three hold blocks; the wave then
	// runs every remaining stage — probe included — with no gate lines.
	g.reader = &fakeMemoryReader{values: []uint64{
		512 << 20, 2 << 30,
		512 << 20, 2 << 30,
		512 << 20, 2 << 30,
		2 << 30, // probe entry: above floor, and no gate call exists to consume it
	}}
	clock := &gateClock{}
	g.now, g.after = clock.now, clock.after
	g.checkEvery = time.Millisecond
	require.NoError(t, runMaintainGraceful(buf, cfg, maintainOptions{}, rec.stages(), nil, g))
	assert.Equal(t,
		[]string{"fetch", "parse", "filter", "probe", "stats", "prune", "select", "render", "activate"},
		rec.order, "a recovering gate holds, then the whole wave runs")
	out := buf.String()
	assert.Contains(t, out, "holding before fetch")
	assert.Contains(t, out, "holding before parse")
	assert.Contains(t, out, "holding before filter")
	assert.NotContains(t, out, "holding before probe",
		"the gate does NOT apply at the probe entry (probe is dial-bound and already adaptive)")
	assert.Equal(t, 3, bytes.Count(buf.Bytes(), []byte("recovered — proceeding")),
		"exactly one recovery per gated stage entry")
}

// TestWaveNilGateIsNoOp pins the one-shot/test path: a nil gate (disabled or
// absent) never touches the wave — byte-identical to the pre-gate behavior.
func TestWaveNilGateIsNoOp(t *testing.T) {
	rec := &stageRecorder{}
	buf := &bytes.Buffer{}
	cfg := newTestGateConfig(t, 1<<30, 0) // "0s" → newMemoryGate returns nil
	require.Nil(t, newMemoryGate(cfg, buf, nil))
	require.NoError(t, runMaintainGraceful(buf, cfg, maintainOptions{}, rec.stages(), nil, nil))
	assert.Equal(t,
		[]string{"fetch", "parse", "filter", "probe", "stats", "prune", "select", "render", "activate"},
		rec.order)
	assert.NotContains(t, buf.String(), "memory gate")
}
