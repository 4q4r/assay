//go:build windows

package core

import (
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// The windows child-lifecycle pins (plan ADDENDUM §2): the spawn puts the
// xray child into its own process group (CREATE_NEW_PROCESS_GROUP — the
// prerequisite for the CTRL_BREAK ladder), and the Job Object containment
// (KILL_ON_JOB_CLOSE) is assigned at spawn. The real CTRL_BREAK delivery
// and the kill-on-close kernel behavior are windows-CI proven (the
// windows-scm leg); here the ATTRIBUTES and the containment assignment are
// pinned.

// TestConfigureChildSpawnPins pins the ADDENDUM §2 spawn attribute: the
// child runs in its OWN process group — GenerateConsoleCtrlEvent can then
// address it alone (CTRL_BREAK_EVENT, <pid>).
func TestConfigureChildSpawnPins(t *testing.T) {
	cmd := &exec.Cmd{}
	configureChildSpawn(cmd)
	require.NotNil(t, cmd.SysProcAttr, "the spawn must carry windows SysProcAttr")
	assert.Equal(t, windows.CREATE_NEW_PROCESS_GROUP, cmd.SysProcAttr.CreationFlags,
		"the child must sit in its own process group (ADDENDUM §2)")
}

// TestAttachChildJobAssignsKillOnClose pins the containment: a real child
// (a sleeping cmd.exe) is assigned to a job whose limit flags carry
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; release closes the handle.
func TestAttachChildJobAssignsKillOnClose(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "timeout", "/t", "30")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	job, err := attachChildJob(cmd.Process)
	require.NoError(t, err, "the child must be assignable to the containment job")
	require.NotNil(t, job)
	require.NotZero(t, job.handle)

	// The job's limits carry KILL_ON_JOB_CLOSE (the ADDENDUM §2 flag).
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	require.NoError(t, windows.QueryInformationJobObject(job.handle, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil))
	assert.NotZero(t, info.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		"the job must kill its processes when the daemon's handle closes")

	job.release()
	assert.Zero(t, job.handle, "release closes the job handle")
}

// TestStopLadderChildBoundPins pins the bounded-wait constant: the CTRL_BREAK
// wait is bounded (ADDENDUM §2) — never a forever-wait on a child that
// ignores the event.
func TestStopLadderChildBoundPins(t *testing.T) {
	assert.Greater(t, childGracefulStopBound, time.Duration(0))
	assert.LessOrEqual(t, childGracefulStopBound, 30*time.Second, "the bound stays supervision-snappy")
}
