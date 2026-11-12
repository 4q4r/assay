//go:build windows

package platform

import (
	"syscall"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/stretchr/testify/require"
)

// TestKillProcessForceTranslatesDeadPid (review P2-1): an already-dead pid
// makes OpenProcess fail with ERROR_INVALID_PARAMETER (87 — windows has no
// kill-ESRCH), and KillProcessForce must surface that benign race as the
// ErrProcessGone sentinel the caller ignores alongside unix ESRCH
// (manager stopLocked). A live-but-inaccessible pid (ERROR_ACCESS_DENIED)
// is NOT gone: its original error stays wrapped and loud.
func TestKillProcessForceTranslatesDeadPid(t *testing.T) {
	gone := translateTerminateOpenErr(4242, windows.ERROR_INVALID_PARAMETER)
	require.ErrorIs(t, gone, ErrProcessGone,
		"the dead-pid OpenProcess failure must travel as the ErrProcessGone sentinel")
	require.NotErrorIs(t, gone, syscall.ESRCH,
		"the windows sentinel is a distinct ignore arm — syscall.ESRCH on windows GOOS is an "+
			"APPLICATION_ERROR that can never match a Windows API error")

	other := translateTerminateOpenErr(4242, windows.ERROR_ACCESS_DENIED)
	require.NotErrorIs(t, other, ErrProcessGone,
		"a live-but-inaccessible pid is not a gone pid — it must fail loudly, never be ignored")
	require.ErrorIs(t, other, windows.ERROR_ACCESS_DENIED,
		"the original transport error must stay in the chain for diagnosis")
	require.ErrorContains(t, other, "open pid 4242 for terminate",
		"the loud-error contract carries the pid and the failing call")
}
