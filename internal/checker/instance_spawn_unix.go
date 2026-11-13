//go:build unix && !linux

package checker

import "os/exec"

// configureTempSpawn is a no-op on non-linux unix: the PDEATHSIG field
// does not exist in darwin's syscall.SysProcAttr (the containment belt is
// a linux mechanism — instance_spawn_linux.go). Temp instances on darwin
// keep the exact-PID Close contract and the ctx kill; no per-OS
// degradation of the linux belt is introduced here (per-OS excellence
// ruling).
func configureTempSpawn(_ *exec.Cmd) {}

// startTempChild is the plain start where no belt exists.
func startTempChild(cmd *exec.Cmd) error {
	return cmd.Start()
}
