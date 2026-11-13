package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/plugins"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is the injected scheduler clock: the test advances time and
// fires the timer channel the scheduler armed. All access is mutex-guarded —
// the scheduler goroutine reads now/arms while the test mutates them.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	armed   []time.Duration
	stopped int
	tick    chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{
		now:  time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
		tick: make(chan time.Time, 8),
	}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After matches the P3-10 seam: (timer channel, stop func). Every stop is
// counted so tests can pin that the scheduler stops its superseded timers.
func (c *fakeClock) After(d time.Duration) (<-chan time.Time, func()) {
	c.mu.Lock()
	c.armed = append(c.armed, d)
	c.mu.Unlock()
	return c.tick, func() {
		c.mu.Lock()
		c.stopped++
		c.mu.Unlock()
	}
}

// stoppedCount reports how many armed timers the scheduler has stopped.
func (c *fakeClock) stoppedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopped
}

// armedCount reports how many timers the scheduler has armed so far.
func (c *fakeClock) armedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.armed)
}

// armedAt returns the n-th (0-based) armed duration.
func (c *fakeClock) armedAt(n int) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.armed[n]
}

// advance moves time and fires one armed timer.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	c.tick <- c.Now()
}

// advanceSilent moves time WITHOUT firing the armed timer — it models time
// passing DURING a wave (the wave closure calls it), which is exactly the
// case the start-anchored re-arm semantics must get right.
func (c *fakeClock) advanceSilent(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// waveRecorder collects the waves the scheduler ran (the scheduler
// goroutine appends while the test reads — mutex-guarded).
type waveRecorder struct {
	mu    sync.Mutex
	waves []maintainOptions
}

func (r *waveRecorder) record(opts maintainOptions) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waves = append(r.waves, opts)
}

func (r *waveRecorder) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.waves)
}

func (r *waveRecorder) all() []maintainOptions {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]maintainOptions(nil), r.waves...)
}

func newTestScheduler(clock *fakeClock, rec *waveRecorder, failFirst bool) *waveScheduler {
	calls := 0
	return &waveScheduler{
		cfg:               &config.Config{},
		refreshInterval:   time.Hour,
		speedtestInterval: 24 * time.Hour,
		deps:              watchDeps{now: clock.Now, after: clock.After},
		out:               io.Discard,
		runWave: func(_ *config.Config, opts maintainOptions, _ func() bool) error {
			calls++
			rec.record(opts) // failed waves record too (the kind ran)
			// Waves 1 and 4 take 10 real minutes (fake clock moves inside
			// the wave) — the discriminator for START-anchored re-arms.
			if calls == 1 || calls == 4 {
				clock.advanceSilent(10 * time.Minute)
			}
			if failFirst && calls == 1 {
				return errors.New("boom")
			}
			return nil
		},
	}
}

func TestSchedulerTickOrder(t *testing.T) {
	clock := newFakeClock()
	waves := &waveRecorder{}
	sched := newTestScheduler(clock, waves, false)
	stop := make(chan struct{})
	done := make(chan struct{})
	var ran []waveKind
	go func() {
		ran = sched.run(stop, nil)
		close(done)
	}()

	// Deterministic cadence: one tick at a time, each awaited on the TIMER
	// ARM (not the wave record — the post-wave re-arm happens between
	// them, so arming is the quiescent point). Waves 1 and 4 consume 10
	// minutes of clock each; every re-arm anchors at the wave's START, so
	// periods stay exact regardless of wave duration: the initial refresh
	// re-arms 1h after START (arm = 50m after the 10m wave), and the
	// speedtest fires exactly 24h after daemon start despite 20m of wave
	// time.
	waitForWaves(t, waves, 1) // initial plain refresh (10m long)
	waitArmed(t, clock, 1)
	clock.advance(50 * time.Minute) // t=13:00 — refresh due (start-anchored)
	waitForWaves(t, waves, 2)
	waitArmed(t, clock, 2)
	clock.advance(time.Hour) // refresh due again (t=14:00)
	waitForWaves(t, waves, 3)
	waitArmed(t, clock, 3)
	clock.advance(21 * time.Hour) // t=day+1 11:00 — 23h elapsed: plain refresh (10m long)
	waitForWaves(t, waves, 4)
	waitArmed(t, clock, 4)
	clock.advance(50 * time.Minute) // t=day+1 12:00 — exactly 24h: speedtest covers the refresh
	waitForWaves(t, waves, 5)
	waitArmed(t, clock, 5)

	close(stop)
	<-done

	want := []waveKind{waveRefresh, waveRefresh, waveRefresh, waveRefresh, waveSpeedtest}
	if fmt.Sprint(ran) != fmt.Sprint(want) {
		t.Fatalf("tick order mismatch: got %v want %v", ran, want)
	}
	recorded := waves.all()
	require.Len(t, recorded, 5, "wave options must mirror the ran kinds")
	require.False(t, recorded[0].speedtest, "initial wave is a plain refresh")
	require.False(t, recorded[3].speedtest, "the 23h tick is a plain refresh (speedtest anchors 24h from start)")
	require.True(t, recorded[4].speedtest, "the 24h tick runs the speedtest wave (start-anchored, wave time irrelevant)")
	require.Equal(t, 5, clock.armedCount(), "one arm per tick including the initial arm")
	require.Equal(t, 50*time.Minute, clock.armedAt(0),
		"initial re-arm anchors at wave START: interval minus the 10m the wave took")
	require.Equal(t, time.Hour, clock.armedAt(1), "instant waves arm the full interval")
	require.Equal(t, 50*time.Minute, clock.armedAt(3),
		"the 23h re-arm anchors at wave START too (1h interval − 10m wave)")
}

// waitArmed waits until the scheduler has (re)armed its timer n times — the
// quiescent point between waves where the clock may be advanced safely.
func waitArmed(t *testing.T, clock *fakeClock, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if clock.armedCount() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for arm %d", n)
}

// TestSchedulerSpeedtestDisabled pins the round-8 disable semantics:
// speedtestInterval = 0 ([maintain].speedtest_interval = "0s") means NO
// speedtest wave at all — the scheduler never schedules one, ticks past a
// would-be speedtest instant run plain refreshes, and the armed line says
// so. This is the owner's «выключи» made real at the schedule level.
func TestSchedulerSpeedtestDisabled(t *testing.T) {
	clock := newFakeClock()
	waves := &waveRecorder{}
	out := &syncWriter{}
	sched := &waveScheduler{
		cfg:               &config.Config{},
		refreshInterval:   time.Hour,
		speedtestInterval: 0, // disabled
		deps:              watchDeps{now: clock.Now, after: clock.After},
		out:               out,
		runWave: func(_ *config.Config, opts maintainOptions, _ func() bool) error {
			waves.record(opts)
			return nil
		},
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	var ran []waveKind
	go func() {
		ran = sched.run(stop, nil)
		close(done)
	}()

	waitForWaves(t, waves, 1) // initial refresh
	waitArmed(t, clock, 1)
	// Push the clock far past any would-be speedtest instant: with the wave
	// disabled, every due tick is a plain refresh, forever.
	clock.advance(1000 * time.Hour)
	waitForWaves(t, waves, 2)
	waitArmed(t, clock, 2)
	clock.advance(time.Hour)
	waitForWaves(t, waves, 3)
	waitArmed(t, clock, 3)

	close(stop)
	<-done

	for _, k := range ran {
		if k == waveSpeedtest {
			t.Fatalf("speedtest wave scheduled despite interval 0: %v", ran)
		}
	}
	for i, opts := range waves.all() {
		assert.False(t, opts.speedtest, "wave %d must be a probe-only refresh (speedtest disabled)", i)
	}
	text := out.String()
	assert.Contains(t, text, "speedtest disabled",
		"the armed line must name the disable explicitly:\n%s", text)
	assert.Contains(t, text, "speedtest_interval",
		"the armed line must name the knob that disables the wave:\n%s", text)
}

func TestSchedulerSurvivesWaveFailure(t *testing.T) {
	clock := newFakeClock()
	waves := &waveRecorder{}
	sched := newTestScheduler(clock, waves, true)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = sched.run(stop, nil)
		close(done)
	}()
	waitForWaves(t, waves, 1) // the initial wave failed — logged, not fatal
	clock.advance(time.Hour)
	waitForWaves(t, waves, 2)
	close(stop)
	<-done
}

func waitForWaves(t *testing.T, waves *waveRecorder, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if waves.len() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d waves", n)
}

func TestRunWatchGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	sigs := make(chan os.Signal, 1)
	watchdogStarted := make(chan struct{})
	sdStarted, sdStopped := make(chan struct{}), make(chan struct{})
	dep := watchDeps{
		startWatchdog: func(string, io.Writer) (*plugins.Registry, io.Closer, error) {
			close(watchdogStarted)
			return plugins.NewRegistry(), fakeCloser{}, nil
		},
		signals: sigs,
		now:     time.Now,
		after: func(time.Duration) (<-chan time.Time, func()) {
			return make(chan time.Time), func() {} // never fires — only the signal ends it
		},
		sdNotify: func(io.Writer) func() {
			close(sdStarted)
			return func() { close(sdStopped) }
		},
	}
	out := &syncWriter{}
	// The daemon owns a core manager (T4/S2): the fake core binary and a
	// test-band port so the bootstrap spawn succeeds hermetically, and the
	// SIGTERM shutdown's explicit core stop (C4) has something to stop.
	corePort := nextCoreTestPort()
	cfg := &config.Config{
		DataDir: dir,
		Plugins: config.PluginsConfig{Dir: filepath.Join(dir, "plugins")},
		Core: config.CoreConfig{
			XrayBin:   cliFakeBinary(t),
			SocksPort: corePort,
			HTTPPort:  corePort + 1,
			Loglevel:  "warning",
		},
	}
	done := make(chan error, 1)
	go func() { done <- runWatch(out, cfg, dep) }()
	<-watchdogStarted
	// The sd_notify handshake starts after the core manager's bootstrap
	// spawn (T4/S2 ordering) — bounded so a wedged spawn fails the test
	// instead of hanging it.
	select {
	case <-sdStarted:
	case <-time.After(15 * time.Second):
		t.Fatalf("daemon never reached READY: %s", out.String())
	}
	sigs <- os.Interrupt
	select {
	case err := <-done:
		require.NoError(t, err, "graceful shutdown exits nil")
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not shut down on signal")
	}
	require.Contains(t, out.String(), "watch: clean shutdown")
	select {
	case <-sdStopped:
	default:
		t.Fatal("shutdown must stop the sd_notify pinger")
	}
}

// syncWriter is a goroutine-safe output sink: the scheduler goroutine and
// the signal handler both write (production writes to os.Stdout — one Write
// syscall per line; a bytes.Buffer would race).
type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fakeCloser struct{}

func (fakeCloser) Close() error { return nil }

func TestWatchFetchContinuesWithBrokenPlugin(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf("data_dir = %q\n", dir)), 0o600))

	reg := plugins.NewRegistry()
	reg.Set(&plugins.Plugin{ID: "healthy", Path: "healthy.lua", Code: []byte(`
		return function()
			return { assay.node{ raw = "vless://a@h:1?s=1" }, assay.node{ raw = "vless://b@h:2?s=1" } }
		end`)})
	reg.Set(&plugins.Plugin{ID: "broken", Path: "broken.lua", Code: []byte(`
		return function() error("discovery exploded") end`)})

	res, err := resolveCommand(cfgPath)
	require.NoError(t, err)
	cfg := res.Config
	out := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	_, err = runFetchWith(cmd, cfg, reg, nil)
	require.NoError(t, err, "wave with one broken plugin must continue")

	text := out.String()
	require.Contains(t, text, `plugin broken     FAILED`, "broken plugin fails loud:\n"+text)
	require.Contains(t, text, "plugin healthy    ok: 2 nodes", "healthy plugin runs:\n"+text)

	// The manifest carries only the healthy source; parse consumes it.
	require.NoError(t, runParse(func() *cobra.Command {
		c := &cobra.Command{}
		c.SetOut(&bytes.Buffer{})
		return c
	}(), cfg))
	nodes, err := os.ReadFile(filepath.Join(dir, "nodes.jsonl"))
	require.NoError(t, err)
	require.Equal(t, 2, strings.Count(string(nodes), `"source":"healthy`),
		"healthy nodes must reach the pipeline: %s", nodes)
	require.NotContains(t, string(nodes), "broken", "broken plugin output must not leak")
}

// TestSchedulerStopsArmedTimersOnReArm (termination-audit P3-10): the
// re-arm path stops the superseded timer — a heartbeat-tick continue used
// to leave the previous timer armed until it fired (a lingering timer is
// GC-immune until it fires; with a 1h refresh and 60s idle ticks the old
// code accumulated up to ~60 live timers).
func TestSchedulerStopsArmedTimersOnReArm(t *testing.T) {
	clock := newFakeClock()
	waves := &waveRecorder{}
	sched := newTestScheduler(clock, waves, false)
	heartbeat := make(chan time.Time, 1)
	sched.heartbeatTick = heartbeat
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = sched.run(stop, nil)
		close(done)
	}()

	waitArmed(t, clock, 1) // the initial wave ran, the schedule re-armed
	require.Zero(t, clock.stoppedCount(), "nothing to stop yet — one live timer")

	// Two idle heartbeat ticks: each re-arm must stop the timer it
	// supersedes.
	heartbeat <- time.Now()
	waitArmed(t, clock, 2)
	heartbeat <- time.Now()
	waitArmed(t, clock, 3)
	require.Equal(t, 2, clock.stoppedCount(),
		"every re-arm must stop the superseded timer (P3-10)")

	// The stop branch stops the live timer too, then the loop exits.
	close(stop)
	<-done
	require.Equal(t, 3, clock.stoppedCount(),
		"the stop path must not leave an armed timer behind")
}
