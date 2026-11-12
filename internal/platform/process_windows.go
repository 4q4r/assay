//go:build windows

package platform

import (
	"errors"
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
// windows equivalent. A process that exits with code 259
// (STILL_ACTIVE/STATUS_PENDING) reads as alive — the known
// GetExitCodeProcess ambiguity; KillProcessForce terminates with exit
// code 1, so assay's own kills never hit it.
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
// An already-dead pid returns ErrProcessGone — the benign adopted-stop
// race the caller ignores alongside unix ESRCH (review P2-1).
func KillProcessForce(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("platform: terminate pid %d: invalid pid", pid)
	}
	//nolint:gosec // G115: pid is bounds-checked above (positive).
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return translateTerminateOpenErr(pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("platform: terminate pid %d: %w", pid, err)
	}
	return nil
}

// translateTerminateOpenErr classifies an OpenProcess failure from the
// terminate path. An already-dead (reaped) pid fails with
// ERROR_INVALID_PARAMETER (87 — windows has no process-not-found code for
// OpenProcess), translated to the ErrProcessGone sentinel; every other
// failure stays a wrapped, loud error with the original cause in the chain.
func translateTerminateOpenErr(pid int, err error) error {
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return ErrProcessGone
	}
	return fmt.Errorf("platform: open pid %d for terminate: %w", pid, err)
}
