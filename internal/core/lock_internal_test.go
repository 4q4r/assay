package core

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"assay/internal/platform"
)

// TestAcquireCoreLockDelegatesToPlatformSeam is the S0 recorded-actions
// double contract: acquireCoreLock must delegate the exclusive non-blocking
// hold to the platform lock seam (exactly one LockFile call on the opened
// file) and translate the seam's ErrLockHeld into the ErrDaemonHoldsCore
// singleton refusal — the S3 contract now rides the portable seam (plan
// §5.5: TestOneShotActivateRefusesUnderFlock parity must port to whatever
// transport the GOOS provides).
func TestAcquireCoreLockDelegatesToPlatformSeam(t *testing.T) {
	origLock, origUnlock := lockCoreFile, unlockCoreFile
	t.Cleanup(func() { lockCoreFile, unlockCoreFile = origLock, origUnlock })

	var lockCalls int
	var lockedFile *os.File
	lockCoreFile = func(f *os.File) error {
		lockCalls++
		lockedFile = f
		return nil
	}
	unlockCoreFile = func(_ *os.File) error {
		t.Errorf("acquireCoreLock must not unlock the lock it just took")
		return nil
	}

	dataDir := t.TempDir()
	f, err := acquireCoreLock(dataDir)
	require.NoError(t, err)
	require.NotNil(t, f)
	t.Cleanup(func() { _ = f.Close() })

	assert.Equal(t, 1, lockCalls, "exactly one platform LockFile call")
	assert.Equal(t, filepath.Join(dataDir, coreLockName), f.Name(),
		"the lock file is <data>/core.lock")
	require.NoError(t, lockedFile.Close(), "the locked file is the one acquireCoreLock opened")
}

// TestAcquireCoreLockTranslatesLockHeld pins the refusal translation: the
// platform sentinel ErrLockHeld becomes the daemon-owns-the-core refusal
// wrapped with the loud lock context, keeping errors.Is programmability and
// the TestOneShotActivateRefusesUnderFlock message intact.
func TestAcquireCoreLockTranslatesLockHeld(t *testing.T) {
	origLock := lockCoreFile
	t.Cleanup(func() { lockCoreFile = origLock })

	lockCoreFile = func(f *os.File) error {
		_ = f.Close()
		return platform.ErrLockHeld
	}

	dataDir := t.TempDir()
	f, err := acquireCoreLock(dataDir)
	require.Nil(t, f, "a refused acquisition returns no file")
	require.ErrorIs(t, err, ErrDaemonHoldsCore,
		"the sentinel must translate into the singleton refusal (errors.Is contract)")
	assert.Contains(t, err.Error(), "(flock on ",
		"the refusal carries the loud lock-path context")

	// A non-sentinel platform error is NOT a daemon-holds refusal — it
	// stays a wrapped plain error (loud, exact).
	lockCoreFile = func(f *os.File) error {
		_ = f.Close()
		return os.ErrPermission
	}
	f2, err2 := acquireCoreLock(dataDir)
	require.Nil(t, f2)
	require.NotErrorIs(t, err2, ErrDaemonHoldsCore,
		"a plain open/lock failure must not read as the daemon-holds refusal")
	require.ErrorIs(t, err2, os.ErrPermission)
}

// TestManagerReleaseDelegatesUnlock pins the manager-side seam: Release and
// release must surrender the hold through the platform UnlockFile seam —
// never a direct syscall.Flock (which is the windows compile blocker the
// seam exists to remove).
func TestManagerReleaseDelegatesUnlock(t *testing.T) {
	origLock, origUnlock := lockCoreFile, unlockCoreFile
	t.Cleanup(func() { lockCoreFile, unlockCoreFile = origLock, origUnlock })

	lockCoreFile = func(_ *os.File) error { return nil }
	var unlockCalls int
	unlockCoreFile = func(_ *os.File) error {
		unlockCalls++
		return errors.New("recorded")
	}

	path := filepath.Join(t.TempDir(), coreLockName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)

	m := &Manager{log: io.Discard, lockFile: f}
	m.Release()
	assert.Equal(t, 1, unlockCalls, "Release surrenders via the platform seam")
	assert.Nil(t, m.lockFile, "Release clears the lock file")
	require.ErrorIs(t, f.Close(), os.ErrClosed, "Release closed the file")
	assert.Equal(t, 1, unlockCalls, "a second Release is a no-op")
}
