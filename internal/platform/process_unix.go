//go:build unix

package platform

import (
	"errors"
	"syscall"
)

// ProcessAlive reports whether pid names a live process — the unix
// transport, byte-identical to the pre-S0 signal-0 probe: ESRCH = dead,
// EPERM = alive but not ours (counted alive — the status contract).
func ProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// KillProcessForce terminates pid unconditionally (SIGKILL). The error is
// returned raw: ESRCH (already dead) is the CALLER's documented ignore,
// preserving the pre-S0 adopted-stop contract.
func KillProcessForce(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
