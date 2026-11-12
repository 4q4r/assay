package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLockFileExclusiveNonBlocking pins the lock seam's cross-OS contract
// (plan §5.5): LockFile takes an exclusive, non-blocking hold (a second
// holder gets ErrLockHeld — the one-shot-refusal parity with
// flock LOCK_EX|LOCK_NB), and UnlockFile releases it so the next holder
// succeeds. On linux this exercises the real flock; on windows CI the same
// contract exercises LockFileEx — one contract, two transports.
func TestLockFileExclusiveNonBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	defer func() { _ = first.Close() }()

	require.NoError(t, LockFile(first), "the first holder takes the lock")

	second, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	defer func() { _ = second.Close() }()

	err = LockFile(second)
	require.ErrorIs(t, err, ErrLockHeld,
		"a second holder must be refused non-blocking with the sentinel")

	require.NoError(t, UnlockFile(first), "releasing must succeed")
	require.NoError(t, LockFile(second), "the lock must be free after UnlockFile")
	require.NoError(t, UnlockFile(second))
}

// TestErrLockHeldIsSentinel pins that ErrLockHeld is a package-level
// sentinel value: callers translate it with errors.Is through wrapping —
// never string comparison.
func TestErrLockHeldIsSentinel(t *testing.T) {
	require.Error(t, ErrLockHeld)
	wrapped := fmt.Errorf("core: flock %s: %w", "/data/core.lock", ErrLockHeld)
	require.ErrorIs(t, wrapped, ErrLockHeld,
		"errors.Is must work through wrapping (the refusal-translation contract)")
}
