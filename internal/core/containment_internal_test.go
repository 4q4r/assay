package core

import (
	"bytes"
	"sync"
	"testing"

	"assay/internal/config"

	"github.com/stretchr/testify/require"
)

// containmentLog is a mutex-guarded sink for the managers' child-stdio
// forwarding goroutines (the syncBuffer twin of manager_internal_test.go —
// that helper lives in a //go:build unix file, and this test must compile
// and run on every GOOS CI leg).
type containmentLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *containmentLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *containmentLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// The containment-constructor pins (termination-audit P2-1): the daemon's
// manager assigns its spawned child to the windows kill-on-close Job
// Object; a transient (one-shot wave) manager MUST NOT — under
// KILL_ON_JOB_CLOSE the one-shot CLI's process exit closes the job handle
// and the kernel kills every job process, so a one-shot activate killed
// the freshly activated core the wave must leave running (the A2
// divergence). The seam-record assertion mirrors lock_internal_test.go's
// recorded-actions pattern: the attach primitive is forced to fail — the
// containment manager refuses the spawn loud, the transient manager spawns
// and never consults the primitive. This file is GOOS-neutral: it runs on
// linux CI AND the windows CI leg (the windows-tagged primitives remain
// pinned by child_windows_test.go).

// The constructor-posture pins run on EVERY GOOS CI leg: the daemon
// manager keeps the containment flag, the transient one-shot manager
// carries none. The BEHAVIORAL seam-record (a spawn that consults — or
// must not consult — the attach primitive) lives in
// containment_spawn_internal_test.go: it drives real fake-core spawns,
// and the COREFAKE TestMain harness is a //go:build unix file — the
// windows leg keeps this posture pin plus the windows-tagged primitive
// pins (child_windows_test.go).
func TestTransientManagerPosturesDisagree(t *testing.T) {
	log := &containmentLog{}

	m, err := NewManager(config.CoreConfig{RollbackStrikes: 3}, t.TempDir(), log)
	require.NoError(t, err)
	t.Cleanup(func() { m.release() })
	require.True(t, m.containment, "the daemon-style manager keeps the kill-on-close job containment")
	require.Nil(t, m.job, "no containment job handle exists before any spawn")

	tm, err := NewTransientManager(config.CoreConfig{RollbackStrikes: 3}, t.TempDir(), log)
	require.NoError(t, err)
	t.Cleanup(func() { tm.release() })
	require.False(t, tm.containment,
		"the transient one-shot manager must NOT carry the job containment (audit P2-1)")
	require.Nil(t, tm.job, "no containment job handle exists before any spawn")
}
