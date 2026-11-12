package selfwatchdog

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeClock is the injected heartbeat clock (the ADDENDUM §1 test seam):
// the test advances time and fires the pacing timers the supervisor armed.
// All access is mutex-guarded — the supervisor goroutine reads now/arms
// while the test mutates them.
type fakeClock struct {
	mu    sync.Mutex
	t     time.Time
	tick  chan time.Time
	armed []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{
		t:    time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC),
		tick: make(chan time.Time),
	}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.armed = append(c.armed, d)
	c.mu.Unlock()
	return c.tick
}

// armedAt returns the n-th (0-based) armed duration.
func (c *fakeClock) armedAt(n int) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.armed[n]
}

func (c *fakeClock) armedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.armed)
}

// waitForArms blocks until the supervisor has armed n timers (the loop runs
// in its own goroutine — arms are asynchronous relative to the test thread).
func (c *fakeClock) waitForArms(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if c.armedCount() >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("supervisor never armed %d pacing timers (armed %d)", n, c.armedCount())
		}
		time.Sleep(time.Millisecond)
	}
}

// fire advances the fake clock by d and delivers the pacing tick.
func (c *fakeClock) fire(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	t := c.t
	c.mu.Unlock()
	c.tick <- t
}

// TestPacesAtHalfThreshold pins the pacing shape: the supervisor checks at
// threshold/2 — the same WatchdogSec/2 cadence the sd_notify pinger uses
// (ADDENDUM §1: "the same WatchdogSec/2 pacing loop").
func TestPacesAtHalfThreshold(t *testing.T) {
	clk := newFakeClock()
	s := Start(time.Hour, func() {}, clk.Now, clk.After)
	defer s.Stop()
	clk.waitForArms(t, 1)
	assert.Equal(t, 30*time.Minute, clk.armedAt(0), "pacing = threshold/2")
}

// TestNoMissWhileBeatsKeepComing pins the healthy path: beats land at every
// pacing check (the daemon's coordination loop is alive) → onMiss never
// fires, the loop keeps pacing.
func TestNoMissWhileBeatsKeepComing(t *testing.T) {
	clk := newFakeClock()
	fired := 0
	s := Start(time.Hour, func() { fired++ }, clk.Now, clk.After)
	defer s.Stop()
	clk.waitForArms(t, 1)
	// 10 rounds of: advance 40 minutes (age would exceed nothing — a beat
	// just landed), pacing fires (threshold/2 = 30m), beat again.
	for i := range 10 {
		clk.fire(40 * time.Minute)
		s.Beat()
		clk.waitForArms(t, i+2)
	}
	assert.Zero(t, fired, "continuous beats must never trip the supervisor")
}

// TestMissFiresExactlyOnce pins the miss path: no beats for the whole
// threshold → the next pacing check fires onMiss EXACTLY once (a self-exit
// must never double-fire), and the loop stays pacable until Stop (the
// daemon's exit path owns what happens next).
func TestMissFiresExactlyOnce(t *testing.T) {
	clk := newFakeClock()
	fired := 0
	s := Start(time.Hour, func() { fired++ }, clk.Now, clk.After)
	defer s.Stop()
	clk.waitForArms(t, 1)

	// Advance just under the threshold: no miss yet (age < threshold).
	clk.fire(59 * time.Minute)
	clk.waitForArms(t, 2)
	assert.Zero(t, fired, "age just under the threshold must not fire")

	// Cross the threshold with no beat: the pacing check fires ONCE.
	clk.fire(30 * time.Minute) // age = 89m ≥ 60m
	clk.waitForArms(t, 3)
	assert.Equal(t, 1, fired, "the missed threshold fires exactly once")

	// Later pacing checks (clock still advancing, still no beats) never
	// re-fire — the miss is terminal for this supervisor.
	clk.fire(30 * time.Minute)
	clk.waitForArms(t, 4)
	clk.fire(30 * time.Minute)
	clk.waitForArms(t, 5)
	assert.Equal(t, 1, fired, "no double-fire, ever")
}

// TestBeatInsideWindowResets pins the boundary: a beat landing exactly at
// the threshold-minus-ε resets the age, so the next pacing check (age
// threshold/2 later) does NOT fire.
func TestBeatInsideWindowResets(t *testing.T) {
	clk := newFakeClock()
	fired := 0
	s := Start(time.Hour, func() { fired++ }, clk.Now, clk.After)
	defer s.Stop()
	clk.waitForArms(t, 1)

	clk.fire(55 * time.Minute) // age 55m
	s.Beat()                   // age reset to 0
	clk.waitForArms(t, 2)
	clk.fire(30 * time.Minute) // age 30m < threshold
	clk.waitForArms(t, 3)
	assert.Zero(t, fired, "a beat inside the window resets the age")
}

// TestStopIsCleanAndIdempotent pins the shutdown: Stop() returns (waits for
// the loop to exit), a second Stop() is a no-op, and a clock advance after
// Stop fires nothing (the pacing loop is gone).
func TestStopIsCleanAndIdempotent(t *testing.T) {
	clk := newFakeClock()
	fired := 0
	s := Start(time.Hour, func() { fired++ }, clk.Now, clk.After)
	clk.waitForArms(t, 1)

	s.Stop()
	s.Stop() // idempotent

	// Post-Stop the arming channel is no longer consumed: deliver one tick
	// via a buffered send (non-blocking proof the receiver is gone is
	// impossible in general; instead assert the loop is done by checking
	// Stop returned AND a fresh advance produces no additional arms).
	n := clk.armedCount()
	select {
	case clk.tick <- clk.Now():
	default:
	}
	assert.Equal(t, n, clk.armedCount(), "no new pacing arms after Stop")
	assert.Zero(t, fired)
}
