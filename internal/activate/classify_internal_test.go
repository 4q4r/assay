package activate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGateNonExitStartFailureAtDeadlineIsStartFailed pins the round-7 M-2
// closure: a spawn attempt that fails with an error OUTSIDE the recognized
// evidence classes (binary exists and is executable, no exec.Error, no
// ErrNotExist/ErrPermission — e.g. fork/exec EAGAIN under process pressure)
// must read as "start failed", even when the deadline has already elapsed.
// The old classifier fell through exactly this shape to the timeout branch,
// telling the operator the config was hanging when in fact no process ever
// existed to time out. Deterministic via the runGate seam: no process is
// spawned at all, the injected deadline is genuinely expired.
func TestGateNonExitStartFailureAtDeadlineIsStartFailed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	require.NoError(t, os.WriteFile(target, []byte(`{"v":1}`), 0o600))
	require.NoError(t, os.WriteFile(rendered, []byte(`{"v":1}`), 0o600))

	// A binary that exists and is executable: the classifier gets no help
	// from path evidence — the error class alone must decide.
	bin := filepath.Join(dir, "fake-xray.sh")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	restore := runGate
	runGate = func(*exec.Cmd) error {
		return errors.New("fork/exec " + bin + ": resource temporarily unavailable")
	}
	t.Cleanup(func() { runGate = restore })

	_, err := Run(Input{
		RenderedPath: rendered, TargetPath: target,
		XrayBin:     bin,
		TestTimeout: 1 * time.Nanosecond, // pre-expires: the failure lands under an elapsed clock
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start failed",
		"a child that never started must be reported as a start failure even at the deadline")
	assert.Contains(t, err.Error(), "resource temporarily unavailable",
		"the underlying start error must reach the operator")
	assert.NotContains(t, err.Error(), "timed out",
		"a start failure must never be mislabeled as a timeout")
}
