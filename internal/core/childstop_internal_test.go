package core

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The windows child-stop ladder pins (plan ADDENDUM §2): graceful console
// ctrl event to the child's own process group → BOUNDED wait for the reap
// → os.Process.Kill() ONLY as the last-resort escalation (the unix
// SIGKILL-after-graceful-timeout ladder's windows mirror). The driver is
// GOOS-neutral (closures carry the per-OS primitives) so the ORDER is
// pinned by the locally-runnable suite; the windows primitives themselves
// (GenerateConsoleCtrlEvent, CREATE_NEW_PROCESS_GROUP, Job Object) are
// pinned by the windows-tagged suite (CI leg).

// TestStopLadderNilGracefulIsPlainKill pins the unix shape: with no
// graceful primitive (unix has no console ctrl events), the ladder IS the
// pre-S2 behavior — kill then reap, nothing else, kill error propagated.
func TestStopLadderNilGracefulIsPlainKill(t *testing.T) {
	killed, reaped := 0, 0
	prims := childStopPrimitives{
		reaped: func() <-chan struct{} {
			ch := make(chan struct{})
			close(ch)
			return ch
		},
		kill: func() error { killed++; reaped++; return nil },
	}
	err := stopChildWithLadder(prims, time.Minute, func(string, ...any) {})
	require.NoError(t, err)
	assert.Equal(t, 1, killed, "exactly one kill")
	assert.Equal(t, 1, reaped, "the kill path reaps too")
}

// TestStopLadderNilGracefulPropagatesKillError pins the error contract:
// the unix kill error surfaces verbatim (os.ErrProcessDone tolerance lives
// in the primitive, exactly as before).
func TestStopLadderNilGracefulPropagatesKillError(t *testing.T) {
	prims := childStopPrimitives{
		reaped: func() <-chan struct{} {
			ch := make(chan struct{})
			close(ch)
			return ch
		},
		kill: func() error { return errors.New("kill failed loudly") },
	}
	err := stopChildWithLadder(prims, time.Minute, func(string, ...any) {})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kill failed loudly")
}

// TestStopLadderGracefulExitSkipsKill pins the happy path: the graceful
// event lands, the child reaps within the bound → Kill is NEVER called.
func TestStopLadderGracefulExitSkipsKill(t *testing.T) {
	gracefulCalled, killed := 0, 0
	done := make(chan struct{})
	close(done)
	prims := childStopPrimitives{
		graceful: func() error { gracefulCalled++; return nil },
		reaped:   func() <-chan struct{} { return done },
		kill:     func() error { killed++; return nil },
	}
	err := stopChildWithLadder(prims, time.Minute, func(string, ...any) {})
	require.NoError(t, err)
	assert.Equal(t, 1, gracefulCalled)
	assert.Zero(t, killed, "a graceful exit never escalates to Kill")
}

// TestStopLadderGracefulTimeoutEscalatesToKill pins the bounded wait: a
// child that ignores the ctrl event is killed after the bound — never an
// unbounded hang (the ADDENDUM §2 "ladder must still be bounded" rule).
// The kill fake closes the reap channel after killing — the model of the
// real reaper (exec.Wait returns once the child dies, closing waitDone).
func TestStopLadderGracefulTimeoutEscalatesToKill(t *testing.T) {
	gracefulCalled, killed := 0, 0
	reaped := make(chan struct{})
	prims := childStopPrimitives{
		graceful: func() error { gracefulCalled++; return nil },
		reaped:   func() <-chan struct{} { return reaped },
		kill: func() error {
			killed++
			close(reaped) // the real reaper closes waitDone after Wait returns
			return nil
		},
	}
	logs := &[]string{}
	start := time.Now()
	err := stopChildWithLadder(prims, 20*time.Millisecond, func(f string, _ ...any) {
		*logs = append(*logs, f)
	})
	require.NoError(t, err)
	assert.Equal(t, 1, gracefulCalled)
	assert.Equal(t, 1, killed, "the bound expired → Kill escalates")
	assert.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond, "the graceful wait was bounded, not skipped")
	assert.NotEmpty(t, *logs, "the escalation is loud")
}

// TestStopLadderGracefulErrorEscalatesToKill pins the failure escalation:
// a FAILING graceful primitive (e.g. no console on a service context)
// logs loud and escalates to Kill immediately — the containment never
// depends on the graceful mechanism succeeding.
func TestStopLadderGracefulErrorEscalatesToKill(t *testing.T) {
	killed := 0
	done := make(chan struct{})
	close(done)
	prims := childStopPrimitives{
		graceful: func() error { return errors.New("no console attached") },
		reaped:   func() <-chan struct{} { return done },
		kill: func() error {
			killed++
			return nil
		},
	}
	logs := &[]string{}
	err := stopChildWithLadder(prims, time.Minute, func(f string, a ...any) {
		*logs = append(*logs, fmt.Sprintf(f, a...))
	})
	require.NoError(t, err)
	assert.Equal(t, 1, killed, "graceful failure → immediate Kill escalation")
	require.NotEmpty(t, *logs)
	assert.Contains(t, (*logs)[0], "no console attached")
}

// TestStopLadderKillErrorSurfaces pins the terminal failure: a failing
// Kill after escalation is the ladder's error (loud, never swallowed).
// The graceful wait here is bounded tiny — a child that never exits and a
// kill that fails are both loud failures, never hangs.
func TestStopLadderKillErrorSurfaces(t *testing.T) {
	reaped := make(chan struct{})
	prims := childStopPrimitives{
		graceful: func() error { return nil },
		reaped:   func() <-chan struct{} { return reaped },
		kill:     func() error { return errors.New("terminate refused") },
	}
	err := stopChildWithLadder(prims, 5*time.Millisecond, func(string, ...any) {})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminate refused")
}
