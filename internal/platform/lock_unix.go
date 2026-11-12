//go:build unix

package platform

import (
	"errors"
	"os"
	"syscall"
)

// LockFile takes an EXCLUSIVE non-blocking whole-file hold on f — the unix
// transport: flock(2) with LOCK_EX|LOCK_NB, the pre-S0 core-singleton
// mechanics, byte-identical. A held lock returns ErrLockHeld; any other
// error is returned RAW (callers add their own path context, exactly like
// the pre-S0 call sites did).
func LockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return ErrLockHeld
		}
		return err
	}
	return nil
}

// UnlockFile releases the hold LockFile took (flock LOCK_UN).
func UnlockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		return err
	}
	return nil
}
