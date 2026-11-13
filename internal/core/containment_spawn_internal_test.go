//go:build unix

package core

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"assay/internal/config"

	"github.com/stretchr/testify/require"
)

// The BEHAVIORAL containment seam-record (termination-audit P2-1): the
// attach primitive is forced to fail — the containment manager refuses the
// spawn loud, the transient manager spawns and never consults the
// primitive. Unix-tagged: the COREFAKE TestMain harness (fakeBin,
// writeLiveFixture, waitPortAccepted) lives in the //go:build unix test
// files; the GOOS-neutral posture pins live in containment_internal_test.go
// and the windows primitives are pinned by child_windows_test.go.
func TestTransientManagerSkipsJobAttach(t *testing.T) {
	log := &containmentLog{}

	daemonDir := t.TempDir()
	m := newTestManager(t, config.CoreConfig{RollbackStrikes: 3}, daemonDir, log)
	require.True(t, m.containment, "the daemon-style manager keeps the kill-on-close job containment")

	cfg := config.CoreConfig{RollbackStrikes: 3}
	cfg.XrayBin = fakeBin(t)
	transientDir := t.TempDir()
	tm, err := NewTransientManager(cfg, transientDir, log)
	require.NoError(t, err)
	t.Cleanup(func() { tm.release() })
	require.False(t, tm.containment,
		"the transient one-shot manager must NOT carry the job containment (audit P2-1)")

	// Force the containment outcome through the seam and record
	// consultations.
	origAttach := attachChildJobFn
	t.Cleanup(func() { attachChildJobFn = origAttach })
	attaches := 0
	attachChildJobFn = func(*os.Process) (*childJob, error) {
		attaches++
		return nil, errors.New("forced containment failure")
	}

	// The daemon-shaped manager: the containment failure fails the spawn
	// loud — a child outside the job could outlive the daemon, so the
	// spawn refuses (the loud posture is pinned, not just the skip).
	const daemonPort = 22984
	writeLiveFixture(t, daemonDir, daemonPort, "")
	err = m.EnsureRunning(context.Background())
	require.Error(t, err, "the containment manager must refuse the spawn when the job attach fails")
	require.Contains(t, err.Error(), "containment job object", "the refusal names the containment leg")
	require.Equal(t, 1, attaches, "the daemon-shaped spawn consulted the attach primitive exactly once")
	require.NotContains(t, log.String(), "spawned pid", "nothing runs uncontained")

	// The transient manager: the same forced failure must be invisible —
	// the attach primitive is never consulted, the spawn succeeds and the
	// fake core serves (the A2 shape: the child survives this process).
	const transientPort = 22986
	writeLiveFixture(t, transientDir, transientPort, "")
	require.NoError(t, tm.EnsureRunning(context.Background()))
	require.Equal(t, 1, attaches,
		"the transient spawn must NEVER consult the job attach primitive (audit P2-1)")
	require.Contains(t, log.String(), "spawned pid", "the transient core spawned")
	require.NoError(t, waitPortAccepted(transientPort),
		"the transient core's socks inbound must serve — the A2 contract on windows too")
	require.Eventually(t, func() bool { return tm.childAliveLocked() },
		5*time.Second, 50*time.Millisecond,
		"the spawned child stays owned by the transient manager (no job-kill divergence)")
}
