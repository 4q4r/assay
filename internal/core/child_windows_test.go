//go:build windows

package core

import (
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"

	"assay/internal/config"

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
	// testify's Equal is type-strict: the flag literal must carry the
	// uint32 type of CreationFlags (an untyped 512 compared against the
	// windows.Errno-typed constant read as uint32(0x200) vs int(512) and
	// failed the first real windows run, 43330792666).
	assert.Equal(t, uint32(windows.CREATE_NEW_PROCESS_GROUP), cmd.SysProcAttr.CreationFlags,
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

// TestStopLadderReapBoundPins pins the termination-audit P1 wiring on
// windows: the ladder's post-kill reap bound is killWaitDelay — the same
// WaitDelay contract value — so a child whose reap cannot complete
// (D-state class) fails the stop loud inside a bounded deadline instead of
// hanging the caller (the SCM WaitHint bounds the whole stop externally;
// the caller's deadline is smaller still).
func TestStopLadderReapBoundPins(t *testing.T) {
	assert.Greater(t, killWaitDelay, time.Duration(0), "the reap bound exists")
	assert.LessOrEqual(t, killWaitDelay, 30*time.Second, "the reap bound stays supervision-snappy")
}

// TestTransientManagerHasNoJobHandle pins the audit P2-1 constructor split
// on windows (the behavioral seam-record twin lives GOOS-neutral in
// containment_internal_test.go and runs on this CI leg too): the daemon
// constructor keeps containment, the transient one-shot constructor
// carries none — a one-shot activate's spawned core must survive the
// CLI's process exit (closing a KILL_ON_JOB_CLOSE handle would kill it).
func TestTransientManagerHasNoJobHandle(t *testing.T) {
	log := &strings.Builder{}
	cfg := config.CoreConfig{RollbackStrikes: 3}
	m, err := NewManager(cfg, t.TempDir(), log)
	require.NoError(t, err)
	t.Cleanup(func() { m.release() })
	assert.True(t, m.containment, "the daemon manager assigns spawned children to the job")

	tm, err := NewTransientManager(cfg, t.TempDir(), log)
	require.NoError(t, err)
	t.Cleanup(func() { tm.release() })
	assert.False(t, tm.containment, "the transient manager skips the job attach (audit P2-1)")
	assert.Nil(t, tm.job, "no containment job handle exists before any spawn")
}
