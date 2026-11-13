//go:build windows

package checker

import "os/exec"

// configureTempSpawn is a no-op on windows: there is no PDEATHSIG analog,
// and the Job Object containment of internal/core is deliberately NOT
// copied here (a temp instance must die with its parent process — under a
// daemon that would require per-instance jobs with handles the checker
// does not own). The windows containment for temp instances remains the
// exact-PID Close contract plus the ctx kill; the parent-death belt is the
// unix PDEATHSIG (instance_spawn_linux.go). Compile-pinned by GOOS=windows vet;
// runtime behavior windows-CI-pending (disclosed in the fix report).
func configureTempSpawn(_ *exec.Cmd) {}

// startTempChild is the plain start on windows.
func startTempChild(cmd *exec.Cmd) error {
	return cmd.Start()
}
