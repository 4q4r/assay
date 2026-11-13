//go:build unix

package platform

import (
	"errors"
	"fmt"
	"os/exec"
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

// SetExecProcessGroup puts cmd in its own process group (Setpgid) so a
// later KillExecProcessGroup can reap the command's WHOLE subtree: the
// wrapper binaries openrc-run forks (openrc-run.sh, the supervise-daemon
// --stop leg) inherit the group, while daemons that setsid themselves away
// (supervise-daemon's supervised child) are deliberately outside it. Without
// the group, killing the direct child at a context bound orphans the
// helpers — and any of them holding the inherited output pipe keeps the
// caller's Wait blocked forever (the run 43358084471 hang class).
func SetExecProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// KillExecProcessGroup SIGKILLs cmd's whole process group (SetExecProcessGroup
// required). An already-dead group is not an error — the bound may fire after
// the tree exited on its own. Direct-child-only alternative would leave
// forked helpers alive as orphans.
func KillExecProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("platform: kill process group -%d: %w", cmd.Process.Pid, err)
	}
	return nil
}
