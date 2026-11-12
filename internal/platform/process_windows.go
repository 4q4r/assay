//go:build windows

package platform

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// stillActive is the Win32 STILL_ACTIVE exit code (259): the value
// GetExitCodeProcess reports for a live process (x/sys/windows does not
// export the constant; the value is a stable Win32 API fact).
const stillActive = 259

// ProcessAlive reports whether pid names a live process — the windows
// transport: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) plus the
// still-active exit-code probe. An unopenable pid (gone, reaped, or
// inaccessible) reads as dead; the unix EPERM-counts-alive nuance has no
// windows equivalent.
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	//nolint:gosec // G115: pid is bounds-checked above (positive).
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	return exitCode == stillActive
}

// KillProcessForce terminates pid unconditionally (TerminateProcess — the
// hard kill; windows has no SIGKILL, and the graceful-core-restart path
// becomes hard-kill there by the plan's documented degradation, §2.2.12).
func KillProcessForce(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("platform: terminate pid %d: invalid pid", pid)
	}
	//nolint:gosec // G115: pid is bounds-checked above (positive).
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("platform: open pid %d for terminate: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("platform: terminate pid %d: %w", pid, err)
	}
	return nil
}
