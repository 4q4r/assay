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

// stopSessionChildLocked is the EXACT pre-S2 session-child stop: hard kill
// (os.ErrProcessDone tolerated) then the WaitDelay-bounded reap. Any
// change here would be a linux behavior change — forbidden by the S2
// binding.
func (m *Manager) stopSessionChildLocked() error {
	if err := m.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("core: kill child pid %d: %w", m.cmd.Process.Pid, err)
	}
	<-m.waitDone()
	return nil
}
