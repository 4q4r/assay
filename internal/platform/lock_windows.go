//go:build windows

package platform

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// LockFile takes an EXCLUSIVE non-blocking hold on f — the windows
// transport: LockFileEx with LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY
// over a one-byte range at offset 0 (the byte-range analog of the unix
// whole-file advisory flock — plan §5.5, the one-shot-refusal parity). A
// held lock returns ErrLockHeld; any other error is returned wrapped.
func LockFile(f *os.File) error {
	var ol windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &ol)
	if err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return ErrLockHeld
		}
		return fmt.Errorf("platform: LockFileEx: %w", err)
	}
	return nil
}

// UnlockFile releases the hold LockFile took (UnlockFileEx over the same
// one-byte range).
func UnlockFile(f *os.File) error {
	var ol windows.Overlapped
	if err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol); err != nil {
		return fmt.Errorf("platform: UnlockFileEx: %w", err)
	}
	return nil
}
