package platform

import "errors"

// ErrLockHeld is the sentinel LockFile returns when another holder owns
// the lock (the exclusive non-blocking refusal). Callers translate it with
// errors.Is — never string comparison — so the per-GOOS transport (flock on
// unix, LockFileEx on windows) stays inside the platform layer.
var ErrLockHeld = errors.New("platform: the file lock is already held")
