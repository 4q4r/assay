package cli

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/plugins"
	"assay/internal/selfwatchdog"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selfWatchProbe is the recorded self-watchdog transport double (the
// ADDENDUM §1 test seam at the daemon level): it captures the threshold and
// the miss action the daemon wires, records beats, and reports active.
// SINGLE-USE: one probe instance serves one daemon (started/stopped close
// exactly once).
type selfWatchProbe struct {
	mu        sync.Mutex
	threshold time.Duration
	miss      func()
	beats     int
	started   chan struct{}
	stopped   chan struct{}
}

func newSelfWatchProbe() *selfWatchProbe {
	return &selfWatchProbe{started: make(chan struct{})}
}

func (p *selfWatchProbe) start(_ io.Writer, threshold time.Duration, onMiss func()) (func(), func(), bool) {
	p.mu.Lock()
	p.threshold = threshold
	p.miss = onMiss
	p.mu.Unlock()
	p.stopped = make(chan struct{})
	close(p.started)
	return func() {
		p.mu.Lock()
		p.beats++
		p.mu.Unlock()
	}, func() { close(p.stopped) }, true
}

// awaitStart blocks until the daemon wired the transport (bounded — a miss
// here means runWatch never reached the wiring).
func (p *selfWatchProbe) awaitStart(t *testing.T) {
	t.Helper()
	select {
	case <-p.started:
	case <-time.After(15 * time.Second):
		t.Fatal("the daemon never wired the self-watchdog transport")
	}
}

func (p *selfWatchProbe) beatCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.beats
}

func (p *selfWatchProbe) got() (time.Duration, func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.threshold, p.miss
}

// selfWatchRecord records the sd_notify start and the self-exit transport's
// exit code (os.Exit must never actually run under test).
type selfWatchRecord struct {
	mu       sync.Mutex
	exitCode int
	exited   chan struct{}
	sdOn     chan struct{}
}

func (r *selfWatchRecord) code() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exitCode
}

// selfWatchTestDeps builds daemon deps with the recorded transports: the
// bootstrap uses the fake core binary + a test-band port (same shape as
// TestRunWatchGracefulShutdown), sd_notify is a recorded no-op, selfWatch
// reports active, and selfExit records instead of exiting.
func selfWatchTestDeps(rec *selfWatchRecord, probe *selfWatchProbe) (watchDeps, chan os.Signal) {
	rec.exited = make(chan struct{})
	rec.sdOn = make(chan struct{})
	probe.stopped = make(chan struct{})
	sigs := make(chan os.Signal, 1)
	return watchDeps{
		startWatchdog: func(string, io.Writer) (*plugins.Registry, io.Closer, error) {
			return plugins.NewRegistry(), fakeCloser{}, nil
		},
		signals: sigs,
		now:     time.Now,
		after: func(time.Duration) <-chan time.Time {
			return make(chan time.Time) // never fires — only stop/miss end it
		},
		sdNotify: func(io.Writer) func() {
			close(rec.sdOn)
			return func() {}
		},
		selfWatch: probe.start,
		selfExit: func(code int) {
			rec.mu.Lock()
			rec.exitCode = code
			rec.mu.Unlock()
			close(rec.exited)
		},
	}, sigs
}

func selfWatchTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	corePort := nextCoreTestPort()
	return &config.Config{
		DataDir: dir,
		Plugins: config.PluginsConfig{Dir: filepath.Join(dir, "plugins")},
		Core: config.CoreConfig{
			XrayBin:   cliFakeBinary(t),
			SocksPort: corePort,
			HTTPPort:  corePort + 1,
			Loglevel:  "warning",
		},
	}
}

// TestSelfWatchDarwinTransportWiring pins the ADDENDUM §1 daemon wiring
// end-to-end at the daemon level: runWatch starts the transport with the
// code-owned threshold, feeds it beats from the coordination loop, triggers
// the SAME graceful-stop seam as SIGTERM on a missed threshold, stops the
// transport, and exits CLEAN (code 0 — launchd KeepAlive restarts the
// agent) with the mechanism named loudly in the output.
func TestSelfWatchDarwinTransportWiring(t *testing.T) {
	probe := newSelfWatchProbe()
	rec := &selfWatchRecord{}
	out := &syncWriter{}
	cfg := selfWatchTestConfig(t)

	done := make(chan error, 1)
	// deps are built BEFORE the goroutine: the test's sdOn select would
	// otherwise race the deps construction (a nil channel receive blocks
	// forever).
	dep, sigs := selfWatchTestDeps(rec, probe)
	// Hygiene: if an assertion fails before the miss fires, the daemon
	// goroutine still holds the fake core child — SIGTERM it so the run
	// never leaks an orphaned serve child holding the test-band port.
	t.Cleanup(func() {
		select {
		case sigs <- os.Interrupt:
		default:
		}
	})
	go func() { done <- runWatch(out, cfg, dep) }()

	select {
	case <-rec.sdOn:
	case <-time.After(15 * time.Second):
		t.Fatalf("daemon never reached READY: %s", out.String())
	}
	probe.awaitStart(t)

	threshold, miss := probe.got()
	assert.Equal(t, selfwatchdog.Threshold, threshold, "the transport gets the code-owned threshold")
	require.NotNil(t, miss, "the daemon wires a miss action (the clean self-exit)")

	// Beats flow from the coordination loop: the initial wave completes
	// (loud failures are fine — the completion itself beats).
	deadline := time.Now().Add(20 * time.Second)
	for probe.beatCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	assert.Positive(t, probe.beatCount(), "the daemon's coordination loop feeds the heartbeat")

	// Fire the miss the way the supervisor's pacing loop would (no beats
	// for the whole threshold).
	miss()

	select {
	case <-rec.exited:
	case <-time.After(45 * time.Second):
		t.Fatalf("the miss action never reached the clean self-exit: %s", out.String())
	}
	assert.Equal(t, 0, rec.code(), "the self-exit is CLEAN (code 0 — not a crash)")

	// The daemon itself unwound through the graceful-stop seam.
	select {
	case err := <-done:
		require.NoError(t, err, "the graceful seam leaves the daemon on a clean return path")
	case <-time.After(45 * time.Second):
		t.Fatal("the daemon did not unwind after the miss")
	}
	// The transport is stopped (leak-free shutdown).
	select {
	case <-probe.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown must stop the self-watchdog transport")
	}

	s := out.String()
	assert.Contains(t, s, "self-watchdog", "the mechanism is named loudly")
	assert.Contains(t, s, "clean self-exit", "the exit path is named loudly")
	assert.Contains(t, s, "KeepAlive", "the restart mechanism is named loudly")
}

// TestSelfWatchTransportIsDarwinOnly pins the transport selection: the
// production transport is active ONLY on darwin. On every other GOOS the
// sd_notify transport stays the ONLY watchdog (byte-identical linux
// behavior) — active=false, the beat a safe no-op, Stop safe.
func TestSelfWatchTransportIsDarwinOnly(t *testing.T) {
	beat, stop, active := productionSelfWatch(io.Discard, selfwatchdog.Threshold, func() {})
	defer stop()
	require.NotNil(t, beat)
	require.NotNil(t, stop)
	if runtime.GOOS == "darwin" {
		assert.True(t, active, "darwin runs the self-exit transport")
		return
	}
	assert.False(t, active, "on "+runtime.GOOS+" the sd_notify transport stays the only watchdog")
	assert.NotPanics(t, beat, "the inactive transport's beat is a safe no-op")
}

// TestSelfWatchConstantsAreCodeOwned pins the code-owned pacing constants
// (the supervision-politeness ruling: not operator-facing knobs).
func TestSelfWatchConstantsAreCodeOwned(t *testing.T) {
	assert.Equal(t, time.Hour, selfwatchdog.Threshold, "the miss threshold is the code-owned hour")
	assert.Equal(t, 60*time.Second, selfWatchTickInterval, "the idle tick is 60s — far under threshold/2 pacing")
	assert.Equal(t, 30*time.Second, selfExitGrace, "the graceful-unwind grace is the code-owned 30s")
}
