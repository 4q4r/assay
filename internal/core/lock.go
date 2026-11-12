package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"assay/internal/platform"
)

// coreLockName is the singleton lock file's name inside the data dir (S3:
// the core manager takes a singleton file lock on the data dir).
const coreLockName = "core.lock"

// ErrDaemonHoldsCore marks the S3 singleton refusal: another assay process
// (the watch daemon) already owns the core for this data dir. The one-shot
// CLI surfaces it wrapped in the loud test-pinned refusal "the daemon owns
// the core — restart the unit or use watch" (pipeline's
// daemonOwnsCoreMessage, TestOneShotActivateRefusesUnderFlock); errors.Is
// is the programmatic contract.
var ErrDaemonHoldsCore = errors.New("core: the singleton core lock is already held — " +
	"the daemon owns the core (use the unit or `assay watch`)")

// lockCoreFile/unlockCoreFile are the portable lock seam (S0): the per-GOOS
// transport (flock on unix, LockFileEx on windows) lives in
// internal/platform. Package vars so tests can record calls against the
// seam (the recorded-actions double contract, lock_internal_test.go).
var (
	lockCoreFile   = platform.LockFile
	unlockCoreFile = platform.UnlockFile
)

// acquireCoreLock takes the EXCLUSIVE non-blocking hold on
// <data>/core.lock (S3: exactly one manager per data dir — a second one
// fails with ErrDaemonHoldsCore instead of double-spawning the core). The
// hold lives as long as the returned file stays open — the manager's
// lifetime; a dead holder releases it by the kernel, so there is no
// stale-lock state to recover from.
func acquireCoreLock(dataDir string) (*os.File, error) {
	path := filepath.Join(dataDir, coreLockName)
	//nolint:gosec // G703: the path is <dataDir>/core.lock, assembled from the
	// owner-configured data dir (the trust root) and a code-owned constant
	// file name — the variable component is the deployment's deliberate
	// location, and the lock file carries no secrets (the pid). No fixed
	// path alternative exists for a configurable data dir.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("core: open %s: %w", path, err)
	}
	if err := lockCoreFile(f); err != nil {
		_ = f.Close()
		if errors.Is(err, platform.ErrLockHeld) {
			return nil, fmt.Errorf("%w (flock on %s)", ErrDaemonHoldsCore, path)
		}
		return nil, fmt.Errorf("core: flock %s: %w", path, err)
	}
	return f, nil
}
