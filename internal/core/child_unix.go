//go:build !windows

// The unix child lifecycle primitives: the byte-identical pre-S2 behavior.
// There are no console ctrl events and no Job Objects on unix — spawn is
// unconfigured (the child inherits the daemon's process group exactly as
// before), containment is the unix process-group/reaper contract, and the
// session-child stop is the plain kill+reap two-liner.

package core

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// configureChildSpawn is a no-op on unix — the child inherits the daemon's
// process group byte-identically with the pre-S2 spawn. The parameter must
// stay typed (the GOOS-split signature contract with child_windows.go).
func configureChildSpawn(_ *exec.Cmd) {}

// childJob is the windows-only containment type; unix has none.
type childJob struct{}

// attachChildJob is a no-op on unix (containment is the process-group
// contract; the daemon's SIGKILL ladder and the reaper own the child).
func attachChildJob(*os.Process) (*childJob, error) { return nil, nil }

// release is a no-op on unix.
func (j *childJob) release() {}

// stopSessionChildLocked is the pre-S2 session-child stop: hard kill
// (os.ErrProcessDone tolerated) then the reap. The kill shape is the EXACT
// pre-S2 behavior (S2 binding); the formerly-unguarded reap receive is the
// one bounded addition (termination-audit P1): WaitDelay bounds the
// pipe-drain legs of Wait, never the death wait itself, and a D-state
// child left Stop() hanging forever — taking the daemon's finishGraceful
// with it. The bound mirrors the manager's own adopted-path poll
// (manager.go: adoptedStopPoll + the post-poll truth vocabulary).
func (m *Manager) stopSessionChildLocked() error {
	pid := m.cmd.Process.Pid
	if err := m.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("core: kill child pid %d: %w", pid, err)
	}
	return reapWaitBounded(m.waitDone, pid, adoptedStopPoll)
}
