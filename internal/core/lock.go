package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
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

// acquireCoreLock takes the EXCLUSIVE non-blocking flock on
// <data>/core.lock (S3: exactly one manager per data dir — a second one
// fails with ErrDaemonHoldsCore instead of double-spawning the core). The
// lock lives as long as the returned file stays open — the manager's
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
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (flock on %s)", ErrDaemonHoldsCore, path)
		}
		return nil, fmt.Errorf("core: flock %s: %w", path, err)
	}
	return f, nil
}
