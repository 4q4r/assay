//go:build unix

package checker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// envGrandchildPIDFile names the file the helper writes the booted temp
// instance's pid into (white-box: this test is package checker, so the
// helper reads the exact child pid off the instance).
const envGrandchildPIDFile = "CHECKER_CONTAINMENT_PIDFILE"

// TestTempInstanceDiesWithParent (termination-audit P2-2, layer 2): a temp
// instance whose parent process dies is contained — never left serving on
// its port band. The proof is cross-process: a helper (this same test
// binary, re-exec'd) boots a fake serve temp instance, records its pid,
// and EXITS WITHOUT Close; the grandchild must be dead or a dead-but-
// unreaped zombie shortly after. Without the belt (pre-fix), the
// grandchild served forever — the stray-checker.test class this fix
// eliminates. The belt is the unix PDEATHSIG (instance_spawn_linux.go); the fake
// serve child additionally carries the testproc parent watch — both layers
// must keep this test green (the leak-detection is the subject, not one
// mechanism).
func TestTempInstanceDiesWithParent(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc — the dead-or-zombie containment probe is Linux-specific")
	}
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")

	t.Setenv(envGrandchildPIDFile, pidFile)
	// Deliberately NOT setting CHECKFAKE_MODE here: the helper's own
	// TestMain must run tests (not the serve mode); the helper arms the
	// serve mode for its grandchild itself.
	helper := exec.CommandContext(context.Background(), os.Args[0], "-test.run=TestTempInstanceDiesWithParentHelper$", "-test.v")
	var out strings.Builder
	helper.Stdout = &out
	helper.Stderr = &out
	require.NoError(t, helper.Run(), "helper must boot the instance and exit: %s", out.String())

	raw, err := os.ReadFile(pidFile)
	require.NoError(t, err, "the helper must record the grandchild pid: %s", out.String())
	pid := strings.TrimSpace(string(raw))

	// The grandchild is not OUR child — containment = the pid is gone or a
	// dead-but-unreaped zombie (init reaps it; in containers the zombie may
	// linger). A live serve state (S/R/D) is the leak this pin forbids.
	require.Eventually(t, func() bool {
		state, serr := procState(pid)
		return serr != nil || state == 'Z' || state == 'X'
	}, 5*time.Second, 100*time.Millisecond,
		"the temp instance must die with its parent (containment belt) — %s", out.String())
}

// TestTempInstanceDiesWithParentHelper is the re-exec'd boot-and-die
// helper of TestTempInstanceDiesWithParent (never selected by the suite
// run — the parent selects it with -test.run=...$).
func TestTempInstanceDiesWithParentHelper(t *testing.T) {
	pidFile := os.Getenv(envGrandchildPIDFile)
	if pidFile == "" {
		t.Skip("helper mode only — selected via -test.run by the parent test")
	}
	t.Setenv(checkFakeModeEnv, checkFakeModeServe)
	inst, err := StartTempXray(context.Background(), os.Args[0], t.TempDir(), freedomOutbound())
	require.NoError(t, err)
	x, ok := inst.(*xrayInstance)
	require.True(t, ok, "the production factory returns the exact-pid instance")
	require.NoError(t, os.WriteFile(pidFile, []byte(strconv.Itoa(x.cmd.Process.Pid)), 0o600))
	// NO Close — the deliberate leak the containment belt must answer for.
}

// procState reads /proc/<pid>/stat's state letter (after the comm's
// closing paren — the same parse shape the manager suite's zombie fixture
// uses).
func procState(pid string) (byte, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%s/stat", pid))
	if err != nil {
		return 0, err
	}
	idx := strings.LastIndex(string(raw), ")")
	if idx < 0 || idx+2 >= len(raw) {
		return 0, fmt.Errorf("malformed stat for pid %s", pid)
	}
	return raw[idx+2], nil
}
