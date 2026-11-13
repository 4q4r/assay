// The child-stop ladder driver (plan ADDENDUM §2, owner ruling "per-OS
// excellence"): stopping the managed xray child on windows is a GRACEFUL
// ladder — console ctrl event to the child's own process group → BOUNDED
// wait for the reap → os.Process.Kill() ONLY as the last-resort escalation
// (the unix SIGKILL-after-graceful-timeout ladder's windows mirror). The
// driver is GOOS-neutral: the per-OS primitives arrive as closures, so the
// ORDER is pinned by the locally-runnable suite while the windows
// primitives (GenerateConsoleCtrlEvent, CREATE_NEW_PROCESS_GROUP, Job
// Object) are pinned by the windows-tagged suite (CI leg). Unix passes no
// graceful primitive at all — the ladder degenerates to the exact pre-S2
// kill+reap behavior (byte-identical unix).

package core

import (
	"fmt"
	"time"
)

// childStopPrimitives carry the per-OS stop primitives. graceful is nil on
// unix (no console ctrl events — the plain kill path); on windows it is
// GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, <child pid>) — the child sits
// in its own process group since spawn (configureChildSpawn). reaped is
// the manager's waitDone channel (closed by the reaper when Wait returns);
// kill is the hard kill (TerminateProcess / SIGKILL-equivalent). pid is
// the child's pid — the bounded-reap error names it (audit P1).
type childStopPrimitives struct {
	pid      int
	graceful func() error
	reaped   func() <-chan struct{}
	kill     func() error
}

// reapWaitBounded bounds the post-kill reap wait (termination-audit P1).
// exec.WaitDelay bounds only the pipe-drain and post-cancel legs of
// exec.Wait — it cannot bound the wait for process DEATH itself: a child
// stuck in uninterruptible sleep (D-state — hung FUSE/NFS I/O, a stuck
// driver) accepts SIGKILL / TerminateProcess but is not reaped until it
// leaves D-state (kill(2)/proc(5) semantics; the adopted-path poll in
// manager.go documents exactly this class). The reaper goroutine stays
// alive until the child finally dies — correct by design; this bound's
// job is that the CALLER stops waiting forever and reports the exact
// state with the exact manual escalation, never a clean stop.
func reapWaitBounded(reaped func() <-chan struct{}, pid int, bound time.Duration) error {
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-reaped():
		return nil
	case <-timer.C:
		return fmt.Errorf("core: child pid %d not reaped within %s after the kill "+
			"(unreapable — likely D-state/zombie): it was NOT confirmed stopped; "+
			"escalate manually: kill -KILL %d (unix) / taskkill /F /PID %d (windows)",
			pid, bound, pid, pid)
	}
}

// stopChildWithLadder runs the ladder (ADDENDUM §2): graceful → bounded
// wait → kill → bounded reap. A failing graceful primitive is LOUD
// (logged) and escalates immediately — the containment never depends on
// the graceful mechanism succeeding (a service context may have no
// console at all). A kill error surfaces verbatim; the kill path reaps
// before returning, and that reap is bounded too (audit P1): reapBound is
// the post-kill deadline (windows passes killWaitDelay — the WaitDelay
// contract value; there is no external stop deadline to lean on).
func stopChildWithLadder(
	p childStopPrimitives, bound, reapBound time.Duration, logf func(string, ...any),
) error {
	if p.graceful != nil {
		if err := p.graceful(); err != nil {
			logf("graceful child stop failed (%v) — escalating to kill", err)
		} else {
			timer := time.NewTimer(bound)
			select {
			case <-p.reaped():
				timer.Stop()
				return nil // the graceful stop completed and was reaped
			case <-timer.C:
				logf("child did not exit within the graceful bound %s — escalating to kill", bound)
			}
		}
	}
	if err := p.kill(); err != nil {
		return err
	}
	// The kill path reaps too (exec.WaitDelay bounds Wait from hanging on
	// lingering inherited pipes — the M-3 landmine contract), and the reap
	// itself is bounded (audit P1 — the D-state class must not hang the
	// caller past the deadline).
	return reapWaitBounded(p.reaped, p.pid, reapBound)
}
