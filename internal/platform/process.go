package platform

import "errors"

// ErrProcessGone is the sentinel KillProcessForce returns when the target
// pid is already gone — the windows transport's OpenProcess failure for a
// dead (reaped) pid, the analog of the unix kill-ESRCH the caller ignores.
// Callers translate with errors.Is — never string comparison — so the
// per-GOOS transport stays inside the platform layer (the ErrLockHeld
// pattern). On unix KillProcessForce returns ESRCH raw and this sentinel
// never travels; the two are distinct ignore arms at every call site.
var ErrProcessGone = errors.New("platform: the process is already gone")
