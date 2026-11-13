//go:build windows

// The windows service entrypoint and handler (plan §2.2.1/§2.2.2 + ADDENDUM
// §1): the same assay.exe runs as CLI and as a Windows service, gated by
// svc.IsWindowsService()'s process-token check. The handler implements the
// SCM contract — StartPending on entry, Running (AcceptStop|AcceptShutdown)
// reported PROMPTLY after the daemon finishes wiring (never gated on the
// first wave), Interrogate echoes, and Stop|Shutdown feeding the SAME
// graceful-stop seam the unix signals use (§2.2.3) before returning
// (false, 0). A clean stop is exit code 0; any daemon failure is a
// service-specific failure code, which the SCM recovery actions
// (ServiceRestart after 5s, §2.2.4) answer with a restart — the ADDENDUM §1
// transport: internal heartbeat → clean self-exit → recovery restart.
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"assay/internal/cli"
	"assay/internal/install"

	"golang.org/x/sys/windows/svc"
)

// serviceExitFailure is the service-specific exit code for every daemon
// failure (arg-contract refusals, config refusals, wiring errors): the SCM
// counts it as a failure and the recovery actions restart the service.
const serviceExitFailure uint32 = 1

// StartPending/StopPending wait hints (ms). StartPending is ONE definition
// with the installer (install.WinSvcStartPendingWaitHint): the handler
// declares the window to the SCM and awaitRunning waits exactly it — the
// two sides can never drift. StopPending mirrors the systemd
// TimeoutStopSec=1800 parity — the SCM's own pending-expected windows, not
// timeouts of ours.
const (
	startPendingWaitHintMs = uint32(install.WinSvcStartPendingWaitHint / time.Millisecond)
	stopPendingWaitHintMs  = 1800000
)

// startPendingHeartbeat is the interval between StartPending checkpoint
// updates while the daemon is still wiring. The SCM's SERVICE_STATUS
// contract (dwWaitHint/dwCheckPoint): when a declared window elapses with
// NO CheckPoint increment and NO state change, the SCM may assume an error
// occurred and stop the service — a single silent StartPending turns the
// declared 30s window into a hard ceiling that a slow-but-healthy wiring
// (cold runner: SCM process creation, Defender first-run scan of a fresh
// image) cannot survive, and gives the installer nothing to observe but a
// stall (cycle 5, 43414096837: the full 30s elapsed with the service never
// Running and no progress signal anywhere). The handler therefore
// re-asserts StartPending with an incremented CheckPoint every sixth of
// the window (5s at the production 30s hint) for as long as the wiring
// runs — the exact "increment this value as it completes each step of its
// initialization" pattern the SCM documentation prescribes. Package var:
// tests shrink it.
var startPendingHeartbeat = install.WinSvcStartPendingWaitHint / 6

// serviceEntrypoint is the windows service gate (§2.2.1): a service-context
// process (the SCM started it through the service dispatcher) runs
// svc.Run("assay", ...) and reports handled; every other invocation reports
// not-handled and falls through to the plain CLI.
func serviceEntrypoint() (bool, int) {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		// The token query failing is not a CLI condition — fail loud, never
		// guess into the CLI (a wrong guess in a service context would hang
		// the SCM's start).
		fmt.Fprintf(os.Stderr, "assay: windows service detection failed: %v\n", err)
		return true, 1
	}
	if !isSvc {
		return false, 0
	}
	if err := svc.Run("assay", &watchHandler{out: os.Stderr}); err != nil {
		fmt.Fprintf(os.Stderr, "assay: windows service run failed: %v\n", err)
		return true, 1
	}
	return true, 0
}

// watchHandler implements svc.Handler (§2.2.2). runDaemon is the daemon
// seam: production wires cli.RunWatchService; tests inject a double. out is
// the pre-sink diagnostics writer (os.Stderr in production — a service's
// stderr goes nowhere, so everything load-bearing is re-reported through
// the file log sink inside the daemon and the service exit code here).
type watchHandler struct {
	runDaemon func(out io.Writer, explicitCfg string, wired chan<- struct{}, stopRequest <-chan struct{}) error
	out       io.Writer
}

// Execute drives the §2.2.2 state machine.
func (h *watchHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending, WaitHint: startPendingWaitHintMs}
	// The wiring heartbeat (§2.2.2 + the SCM SERVICE_STATUS contract): the
	// StartPending CheckPoint advances while the daemon wires, so the SCM
	// never reads the start as stalled and the running-verify has a live
	// progress signal. stopHeartbeat drains the goroutine BEFORE the next
	// status send — a heartbeat landing after the Running report would walk
	// the SCM's state machine backwards.
	heartbeatStop := make(chan struct{})
	heartbeatDone := make(chan struct{})
	checkpoint := uint32(0)
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(startPendingHeartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatStop:
				return
			case <-ticker.C:
				checkpoint++
				s <- svc.Status{State: svc.StartPending, CheckPoint: checkpoint, WaitHint: startPendingWaitHintMs}
			}
		}
	}()
	stopHeartbeat := func() {
		close(heartbeatStop)
		<-heartbeatDone
	}

	cfgPath, err := cli.ParseServiceArgs(args)
	if err != nil {
		stopHeartbeat()
		h.failf("service argument contract refused: %v", err)
		return true, serviceExitFailure
	}
	run := h.runDaemon
	if run == nil {
		run = cli.RunWatchService
	}
	out := h.out
	if out == nil {
		out = os.Stderr
	}
	wired := make(chan struct{})
	stopRequest := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- run(out, cfgPath, wired, stopRequest) }()
	// Wire → Running (§2.2.2: Running happens RIGHT AFTER the daemon
	// finishes wiring — a daemon that exits during wiring fails the
	// service instead).
	select {
	case <-wired:
	case err := <-done:
		stopHeartbeat()
		if err == nil {
			h.failf("daemon exited during wiring without reporting readiness")
		} else {
			h.failf("daemon failed during wiring: %v", err)
		}
		return true, serviceExitFailure
	}
	stopHeartbeat()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				h.failf("daemon failed: %v", err)
				return true, serviceExitFailure
			}
			// The daemon exited cleanly on its own — the self-watchdog's
			// clean self-exit lands here in spirit (the transport exits the
			// PROCESS before this channel fires; a benign scheduler return
			// reads as a normal stop) and the SCM recovery contract stays
			// as configured (§2.2.4).
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending, WaitHint: stopPendingWaitHintMs}
				close(stopRequest) // the SAME graceful-stop seam SIGTERM uses (§2.2.3)
				if err := <-done; err != nil {
					h.failf("daemon failed during graceful stop: %v", err)
					return true, serviceExitFailure
				}
				return false, 0
			default:
				// Commands we never Accepted (Pause/Continue/…) — the SCM
				// contract says we only act on what we accept; everything
				// else is ignored without a state change.
			}
		}
	}
}

// failf writes a service-level failure to the diagnostics writer (the
// daemon's file log sink owns the real logging once wiring succeeded; this
// covers the pre-sink failure window).
func (h *watchHandler) failf(format string, a ...any) {
	out := h.out
	if out == nil {
		out = os.Stderr
	}
	fmt.Fprintf(out, "assay service: "+format+"\n", a...)
}
