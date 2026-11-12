//go:build windows

// The windows child lifecycle primitives (plan ADDENDUM §2):
//   - spawn: the xray child runs in its OWN process group
//     (CREATE_NEW_PROCESS_GROUP) so GenerateConsoleCtrlEvent can address it
//     alone — xray registers a console ctrl handler as its graceful
//     shutdown;
//   - containment: the child is assigned to a Job Object with
//     JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE at spawn — daemon death closes the
//     handle and the kernel kills every job process (no orphans), the
//     windows analog of the unix process-group cleanup;
//   - stop: the ladder (childstop.go) — CTRL_BREAK_EVENT to the process
//     group → bounded wait → TerminateProcess last resort.

package core

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// childGracefulStopBound bounds the CTRL_BREAK wait (ADDENDUM §2: "the
// ladder must still be bounded — don't wait forever on a child that
// ignores the event"). Code-owned, not a knob (the supervision-politeness
// ruling). Comfortably above a graceful xray shutdown (sub-second) while
// keeping service stops snappy.
const childGracefulStopBound = 10 * time.Second

// configureChildSpawn puts the child into its own process group at spawn
// (ADDENDUM §2). CREATE_NEW_PROCESS_GROUP also breaks the child's
// inheritance of ctrl-events aimed at OUR console — the event below goes
// to the child's group alone.
func configureChildSpawn(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

// childJob wraps the containment Job Object handle.
type childJob struct{ handle windows.Handle }

// attachChildJob creates the kill-on-close job and assigns the child
// process to it. A failure is fatal for the spawn (the caller kills the
// child): a core running OUTSIDE the containment could outlive the daemon.
// The child's handle is opened fresh by pid (os.Process keeps its handle
// unexported): AssignProcessToJobObject needs
// PROCESS_SET_QUOTA|PROCESS_TERMINATE — both ours, we are the parent.
func attachChildJob(p *os.Process) (*childJob, error) {
	//nolint:gosec // G115: a fresh child pid is positive by construction.
	hProc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		return nil, fmt.Errorf("open pid %d for the job assignment: %w", p.Pid, err)
	}
	defer func() { _ = windows.CloseHandle(hProc) }()
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job object: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("set job object kill-on-close limit: %w", err)
	}
	if err := windows.AssignProcessToJobObject(h, hProc); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("assign pid %d to the job object: %w", p.Pid, err)
	}
	return &childJob{handle: h}, nil
}

// release closes the job handle. KILL_ON_JOB_CLOSE makes this the final
// containment act: any process still in the job dies with the handle.
func (j *childJob) release() {
	if j == nil || j.handle == 0 {
		return
	}
	_ = windows.CloseHandle(j.handle)
	j.handle = 0
}

// stopSessionChildLocked is the windows ladder (ADDENDUM §2) over the
// neutral driver: CTRL_BREAK to the child's process group (xray's
// registered console ctrl handler shuts it down gracefully) → bounded
// wait → TerminateProcess last resort. A failing ctrl-event (e.g. the
// service context has no console attached) is logged loud by the driver
// and escalates immediately — the containment never depends on it.
func (m *Manager) stopSessionChildLocked() error {
	pid := m.cmd.Process.Pid
	err := stopChildWithLadder(childStopPrimitives{
		graceful: func() error {
			return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(pid))
		},
		reaped: m.waitDone,
		kill: func() error {
			if kerr := m.cmd.Process.Kill(); kerr != nil && !errors.Is(kerr, os.ErrProcessDone) {
				return fmt.Errorf("core: kill child pid %d: %w", pid, kerr)
			}
			return nil
		},
	}, childGracefulStopBound, func(f string, a ...any) {
		_, _ = fmt.Fprintf(m.log, "core: "+f+"\n", a...)
	})
	m.releaseJobLocked()
	return err
}
