//go:build windows

package main

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/svc"
)

// The svc.Handler state-machine pins (plan §2.2.2): StartPending first;
// Running with AcceptStop|AcceptShutdown reported PROMPTLY after the daemon
// finishes wiring (never gated on the first wave); Interrogate echoes the
// current status; Stop|Shutdown → StopPending → the SAME graceful-stop seam
// SIGTERM uses (close the stop-request transport) → (false, 0); a wiring
// failure never reports Running and fails the service (SCM recovery
// actions apply); malformed service args fail loud at start. These tests
// drive the handler over the real svc channel types with an injected
// daemon double — no SCM is involved (the real SCM lifecycle is the
// windows-scm CI leg).

// svcTestHandler builds a handler whose daemon is the given double. The
// double receives (wired, stopRequest) exactly as the production seam
// (cli.RunWatchService) does: closing wired reports readiness (§2.2.2); the
// handler closes stopRequest on svc.Stop|svc.Shutdown (§2.2.3) — the double
// unblocks on that close and returns, completing the graceful stop.
func svcTestHandler(run func(wired chan<- struct{}, stopRequest <-chan struct{}) error) *watchHandler {
	return &watchHandler{
		runDaemon: func(_ io.Writer, _ string, wired chan<- struct{}, stopRequest <-chan struct{}) error {
			return run(wired, stopRequest)
		},
		out: io.Discard,
	}
}

// driveExecute runs Execute on a goroutine and returns a channel carrying
// the (svcSpecificEC, exitCode) pair.
func driveExecute(h *watchHandler, r <-chan svc.ChangeRequest, s chan<- svc.Status) <-chan [2]uint32 {
	result := make(chan [2]uint32, 1)
	go func() {
		ss, code := h.Execute([]string{"assay", "watch", "-c", `C:\x\config.toml`}, r, s)
		result <- [2]uint32{boolToUint32(ss), code}
	}()
	return result
}

func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// expectStatus reads the next reported status (bounded — a wedged handler
// fails the test instead of hanging it).
func expectStatus(t *testing.T, s <-chan svc.Status) svc.Status {
	t.Helper()
	select {
	case st := <-s:
		return st
	case <-time.After(5 * time.Second):
		t.Fatal("handler never reported a status")
		return svc.Status{}
	}
}

// TestHandlerStateMachineHappyPath walks the full §2.2.2 sequence:
// StartPending → (wired) → Running{AcceptStop|AcceptShutdown} → Stop →
// StopPending → (false, 0).
func TestHandlerStateMachineHappyPath(t *testing.T) {
	s := make(chan svc.Status, 32)
	r := make(chan svc.ChangeRequest)
	h := svcTestHandler(func(wired chan<- struct{}, stopRequest <-chan struct{}) error {
		close(wired)  // the wiring signal — Closing wired reports readiness
		<-stopRequest // the graceful stop — this seam IS the SIGTERM seam
		return nil
	})
	result := driveExecute(h, r, s)

	st := expectStatus(t, s)
	require.Equal(t, svc.StartPending, st.State, "StartPending is the first report")

	st = expectStatus(t, s)
	require.Equal(t, svc.Running, st.State, "Running reported right after wiring")
	require.Equal(t, svc.AcceptStop|svc.AcceptShutdown, st.Accepts, "Running accepts stop and shutdown")

	r <- svc.ChangeRequest{Cmd: svc.Stop}
	st = expectStatus(t, s)
	require.Equal(t, svc.StopPending, st.State, "StopPending reported when the stop arrives")

	res := <-result
	require.Equal(t, uint32(0), res[0], "svcSpecificEC=false on a clean stop")
	require.Equal(t, uint32(0), res[1], "exit code 0 on a clean stop")
}

// TestHandlerRunningNotGatedOnWave pins "promptly after wiring, never
// after the first wave" (§2.2.2): the daemon double signals readiness and
// keeps working for a long time afterwards — Running is still reported
// immediately.
func TestHandlerRunningNotGatedOnWave(t *testing.T) {
	s := make(chan svc.Status, 32)
	r := make(chan svc.ChangeRequest)
	release := make(chan struct{})
	h := svcTestHandler(func(wired chan<- struct{}, _ <-chan struct{}) error {
		close(wired)
		<-release // the first wave keeps running…
		return nil
	})
	result := driveExecute(h, r, s)
	st := expectStatus(t, s)
	require.Equal(t, svc.StartPending, st.State)

	st = expectStatus(t, s)
	require.Equal(t, svc.Running, st.State, "Running must not wait for the wave to finish")

	// Wind down without tripping the (never-fired) wave gate: the handler
	// exits when the daemon returns, so release the wave and let the
	// daemon's natural nil return end the service.
	close(release)
	select {
	case res := <-result:
		require.Equal(t, uint32(0), res[1], "a daemon nil return is a clean stop")
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit after the daemon returned")
	}
}

// TestHandlerInterrogateEchoes pins the interrogate contract: c.CurrentStatus
// is echoed verbatim onto the status channel — and the handler still serves
// a stop AFTER an interrogate. The echo alone never ends the service: the
// handler's select loop waits for the next SCM command and the daemon double
// waits on stopRequest, so without a Stop the exit wait below can only time
// out (run 43339290411: the interrogate echo passed, then
// "handler did not exit after the stop completed" — no stop had been sent).
func TestHandlerInterrogateEchoes(t *testing.T) {
	s := make(chan svc.Status, 32)
	r := make(chan svc.ChangeRequest)
	h := svcTestHandler(func(wired chan<- struct{}, stopRequest <-chan struct{}) error {
		close(wired)
		<-stopRequest
		return nil
	})
	result := driveExecute(h, r, s)
	_ = expectStatus(t, s) // StartPending
	_ = expectStatus(t, s) // Running

	echo := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	r <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: echo}
	require.Equal(t, echo, expectStatus(t, s), "Interrogate echoes c.CurrentStatus verbatim")

	// The stop that the exit wait below promises: Interrogate does not stop
	// the service — Stop does, through the same seam as the happy path.
	r <- svc.ChangeRequest{Cmd: svc.Stop}
	require.Equal(t, svc.StopPending, expectStatus(t, s).State,
		"Stop after Interrogate reports StopPending")

	select {
	case res := <-result:
		require.Equal(t, uint32(0), res[1])
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit after the stop completed")
	}
}

// TestHandlerShutdownRidesStopSeam pins that svc.Shutdown feeds the SAME
// graceful-stop transport as svc.Stop.
func TestHandlerShutdownRidesStopSeam(t *testing.T) {
	s := make(chan svc.Status, 32)
	r := make(chan svc.ChangeRequest)
	h := svcTestHandler(func(wired chan<- struct{}, stopRequest <-chan struct{}) error {
		close(wired)
		<-stopRequest
		return nil
	})
	result := driveExecute(h, r, s)
	_ = expectStatus(t, s)
	_ = expectStatus(t, s)

	r <- svc.ChangeRequest{Cmd: svc.Shutdown}
	st := expectStatus(t, s)
	require.Equal(t, svc.StopPending, st.State, "Shutdown reports StopPending too")

	select {
	case res := <-result:
		require.Equal(t, uint32(0), res[0])
		require.Equal(t, uint32(0), res[1])
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit after shutdown")
	}
}

// TestHandlerWiringFailureFailsService pins the failure path: a daemon
// erroring during wiring never reports Running and exits with a
// service-specific failure code (SCM recovery actions apply — ADDENDUM §1).
func TestHandlerWiringFailureFailsService(t *testing.T) {
	s := make(chan svc.Status, 32)
	r := make(chan svc.ChangeRequest)
	h := svcTestHandler(func(chan<- struct{}, <-chan struct{}) error {
		return errors.New("wiring failed loudly")
	})
	result := driveExecute(h, r, s)

	st := expectStatus(t, s)
	require.Equal(t, svc.StartPending, st.State, "StartPending is still the first report")
	// And NOTHING else: the failure must not flip through Running.
	select {
	case st := <-s:
		assert.NotEqual(t, svc.Running, st.State, "a wiring failure never reports Running")
	case <-time.After(200 * time.Millisecond):
	}

	res := <-result
	require.Equal(t, uint32(1), res[0], "the exit code is service-specific")
	require.NotZero(t, res[1], "a wiring failure is a service failure")
}

// TestHandlerMalformedArgsFailLoud pins the arg-contract refusal: service
// arguments outside `watch [-c <path>]` fail the service at start; the
// daemon never runs on mis-read args.
func TestHandlerMalformedArgsFailLoud(t *testing.T) {
	s := make(chan svc.Status, 32)
	r := make(chan svc.ChangeRequest)
	daemonRan := false
	h := &watchHandler{
		runDaemon: func(_ io.Writer, _ string, _ chan<- struct{}, _ <-chan struct{}) error {
			daemonRan = true
			return nil
		},
		out: io.Discard,
	}
	ss, code := h.Execute([]string{"assay", "maintain"}, r, s)
	require.True(t, ss)
	require.NotZero(t, code)
	assert.False(t, daemonRan, "the daemon never runs on malformed service args")

	st := expectStatus(t, s)
	require.Equal(t, svc.StartPending, st.State, "only StartPending was ever reported")
}

// TestHandlerStartPendingHeartbeatPins pins the SCM SERVICE_STATUS
// checkpoint contract (the cycle-5 / 43414096837 fix): while the daemon is
// wiring, the handler re-asserts StartPending with an INCREMENTED
// CheckPoint on every heartbeat — a silent window lets the SCM assume an
// error (dwWaitHint contract) and kill the start of a slow-but-healthy
// wiring. Running is the LAST status the handler sends (the heartbeat is
// drained first — a heartbeat landing after Running would walk the SCM's
// state machine backwards), and Running carries CheckPoint 0 (no pending
// operation).
func TestHandlerStartPendingHeartbeatPins(t *testing.T) {
	orig := startPendingHeartbeat
	startPendingHeartbeat = 10 * time.Millisecond
	t.Cleanup(func() { startPendingHeartbeat = orig })

	s := make(chan svc.Status, 64)
	r := make(chan svc.ChangeRequest)
	release := make(chan struct{})
	h := svcTestHandler(func(wired chan<- struct{}, _ <-chan struct{}) error {
		time.Sleep(60 * time.Millisecond) // the wiring ladder — several heartbeats long
		close(wired)
		<-release
		return nil
	})
	result := driveExecute(h, r, s)

	first := expectStatus(t, s)
	require.Equal(t, svc.StartPending, first.State)
	require.Equal(t, uint32(0), first.CheckPoint, "the initial StartPending carries CheckPoint 0")

	// The heartbeats: StartPending updates with strictly advancing
	// checkpoints for as long as the wiring runs.
	var lastCP uint32
	for seen := 0; seen < 2; {
		st := expectStatus(t, s)
		require.Equal(t, svc.StartPending, st.State)
		require.Greater(t, st.CheckPoint, lastCP, "each heartbeat increments the CheckPoint")
		lastCP = st.CheckPoint
		seen++
	}

	st := expectStatus(t, s)
	require.Equal(t, svc.Running, st.State, "Running reported right after the wiring")
	require.Equal(t, uint32(0), st.CheckPoint, "Running carries CheckPoint 0 — no pending operation")

	// And nothing walks back: the next status can only be the StopPending
	// the stop produces — never a late StartPending heartbeat.
	r <- svc.ChangeRequest{Cmd: svc.Stop}
	next := expectStatus(t, s)
	require.Equal(t, svc.StopPending, next.State, "no heartbeat may land after Running")
	close(release) // the daemon unwinds; the handler exits through the stop path
	select {
	case res := <-result:
		require.Equal(t, uint32(0), res[0])
		require.Equal(t, uint32(0), res[1])
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit after the stop completed")
	}
}
