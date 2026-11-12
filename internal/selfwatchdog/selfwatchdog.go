// Package selfwatchdog is the transport-agnostic hang watchdog (plan
// ADDENDUM §1, owner ruling "per-OS excellence"): ONE internal heartbeat,
// per-OS native transports.
//
//   - linux/systemd: the transport is sd_notify(3) — the daemon pings
//     WATCHDOG=1 (internal/sdnotify) and SYSTEMD owns the kill+restart on
//     missed pings. This supervisor does NOT run there (byte-identical
//     linux behavior is a binding constraint).
//   - darwin/launchd: launchd has no external hang timer — the idiomatic
//     native contract is "a wedged job EXITS ITSELF and KeepAlive restarts
//     it". This supervisor paces at threshold/2, and when no Beat() arrived
//     within the threshold it fires the miss action once: the daemon's
//     CLEAN self-exit through the same graceful-stop seam SIGTERM uses
//     (never a crash), after which launchd KeepAlive=true restarts the
//     agent.
//
// What the heartbeat measures — honest bounds. Beats are emitted by the
// daemon's coordination loop: every wait-loop wake (a dedicated idle tick
// proves the loop reached its select), every wave boundary and stage
// boundary, every plugin completion in the fetch stage, every probe batch.
// With those feeds the widest legitimate beat gap is a single slow stage —
// far below the code-owned 1h threshold. The detection window is therefore
// inherently longer than systemd's WatchdogSec=300 (an in-process watchdog
// cannot observe its own total runtime wedge — nothing in-process can, and
// launchd offers no external timer; the sd_notify pinger on linux has the
// mirror-shape advantage of systemd's external kill). Extreme configs
// (e.g. [plugins].run_timeout = "0s" — an unbounded plugin run) can
// legitimately outlast the threshold; a false self-exit there costs one
// interrupted wave and a KeepAlive restart (last-good semantics, no data
// loss) — the honest trade for unattended hang recovery on darwin.
package selfwatchdog

import (
	"sync"
	"time"
)

// Threshold is the darwin miss threshold (code-owned, not a knob — the
// supervision-politeness ruling): comfortably above the widest legitimate
// beat gap (single slow stage; observed ~28 min probe stage) while keeping
// unattended recovery inside a wave cadence.
const Threshold = time.Hour

// Start runs the supervisor: it paces at threshold/2 and fires onMiss once
// when no Beat() arrived within the threshold. now and after are the clock
// seam (tests inject a controllable fake; production wires time.Now and
// time.After). The returned supervisor is non-nil; Stop is always safe.
func Start(
	threshold time.Duration, onMiss func(), now func() time.Time,
	after func(time.Duration) <-chan time.Time,
) *Supervisor {
	s := &Supervisor{
		threshold: threshold,
		now:       now,
		after:     after,
		onMiss:    onMiss,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	s.mu.Lock()
	s.last = now()
	s.mu.Unlock()
	go s.loop()
	return s
}

// Supervisor paces the heartbeat checks (see Start).
type Supervisor struct {
	threshold time.Duration
	now       func() time.Time
	after     func(time.Duration) <-chan time.Time
	onMiss    func()

	mu      sync.Mutex
	last    time.Time
	fired   bool
	stop    chan struct{}
	done    chan struct{}
	stopOne sync.Once
}

// Beat records one heartbeat (the daemon's coordination loop calls this at
// every progress point).
func (s *Supervisor) Beat() {
	s.mu.Lock()
	s.last = s.now()
	s.mu.Unlock()
}

// Stop ends the supervisor. Idempotent, waits for the loop to exit — the
// daemon's shutdown path must not leak the pacing goroutine.
func (s *Supervisor) Stop() {
	s.stopOne.Do(func() {
		close(s.stop)
		<-s.done
	})
}

// loop is the pacing loop: arm threshold/2, on fire check the heartbeat
// age, fire onMiss once on a miss.
func (s *Supervisor) loop() {
	defer close(s.done)
	pace := s.threshold / 2
	for {
		timer := s.after(pace)
		select {
		case <-s.stop:
			return
		case <-timer:
		}
		s.mu.Lock()
		age := s.now().Sub(s.last)
		missed := age >= s.threshold && !s.fired
		if missed {
			s.fired = true
		}
		onMiss := s.onMiss
		s.mu.Unlock()
		if missed {
			onMiss()
		}
	}
}
