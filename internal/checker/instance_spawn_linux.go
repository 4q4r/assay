//go:build linux

package checker

import (
	"os/exec"
	"runtime"
	"syscall"
)

// configureTempSpawn arms the parent-death containment belt (termination-
// audit P2-2, layer 2) for temp-instance children: PDEATHSIG=SIGKILL. A
// temp xray is an ephemeral probe — if the parent PROCESS dies (daemon
// crash, hard-killed test binary, CI timeout), the kernel kills the temp
// instance instead of leaving it holding its port band.
//
// KNOWN CAVEAT (documented, the standard pattern): Linux arms PDEATHSIG
// against the parent THREAD — the goroutine calling startTempChild locks
// its OS thread across the fork (startTempChild) so the attribute is set
// against a thread that PARKS (never dies) after Start returns.
//
// A2 NOTE: this belt is TEMP-INSTANCE ONLY by design. The daemon's managed
// core child must SURVIVE daemon death (the A2 adoption contract,
// internal/core) and therefore carries NO Pdeathsig — do not copy this
// into the core spawn.
func configureTempSpawn(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// startTempChild starts the temp-instance child with the containment belt
// armed (see configureTempSpawn for the thread-locking rationale).
func startTempChild(cmd *exec.Cmd) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return cmd.Start()
}
