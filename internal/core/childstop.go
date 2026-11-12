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

import "time"

// childStopPrimitives carry the per-OS stop primitives. graceful is nil on
// unix (no console ctrl events — the plain kill path); on windows it is
// GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, <child pid>) — the child sits
// in its own process group since spawn (configureChildSpawn). reaped is
// the manager's waitDone channel (closed by the reaper when Wait returns);
// kill is the hard kill (TerminateProcess / SIGKILL-equivalent).
type childStopPrimitives struct {
	graceful func() error
	reaped   func() <-chan struct{}
	kill     func() error
}

// stopChildWithLadder runs the ladder (ADDENDUM §2): graceful → bounded
// wait → kill. A failing graceful primitive is LOUD (logged) and
// escalates immediately — the containment never depends on the graceful
// mechanism succeeding (a service context may have no console at all).
// A kill error surfaces verbatim; the kill path reaps before returning.
func stopChildWithLadder(p childStopPrimitives, bound time.Duration, logf func(string, ...any)) error {
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
	// lingering inherited pipes — the M-3 landmine contract).
	<-p.reaped()
	return nil
}
