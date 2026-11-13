//go:build windows

package testproc

import (
	"golang.org/x/sys/windows"
)

// parentAlive reports whether the entry parent is still alive on windows.
// Windows does NOT reparent orphans — the ppid stays stale after the
// parent dies — so the check opens a synchronization handle on the pid:
// an unopenable pid is gone, and a signaled handle is a terminated
// process. Compile-pinned by GOOS=windows vet; the runtime behavior is
// windows-CI-pending (disclosed in the fix report).
func parentAlive(pid int) bool {
	//nolint:gosec // G115: the entry parent pid is a real process id — positive by construction.
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false // the pid cannot be opened — the parent is gone
	}
	defer func() { _ = windows.CloseHandle(h) }()
	// WAIT_TIMEOUT = still running after the zero wait; WAIT_OBJECT_0 = the
	// handle signaled = the process terminated. A wait error reads as
	// gone (the handle cannot be waited on — the parent is unrechable).
	event, werr := windows.WaitForSingleObject(h, 0)
	return werr == nil && event == uint32(windows.WAIT_TIMEOUT)
}
