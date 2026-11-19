package cli

// The incident-#3 detector (deferred minor): a vanished unit file leaves
// systemd's Restart=always powerless — the loaded unit keeps running but
// nothing restarts the daemon after a watchdog kill, and the 2026-11-12
// incident sat in exactly that state until a manual `assay install`. The
// daemon cannot reinstall itself (allowlist discipline — no self-install),
// but it MUST see the state: one loud line per detection turns silent death
// into a flagged state. Detection only — never repair.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnitFileGuardLogsOneLoudLineWhenMissing(t *testing.T) {
	var log strings.Builder
	g := &unitFileGuard{
		out:  &log,
		path: filepath.Join(t.TempDir(), "assay-watch.service"),
		stat: func(string) (os.FileInfo, error) { return nil, fs.ErrNotExist },
	}
	g.check()
	out := log.String()
	assert.Contains(t, out, "missing on disk")
	// The mechanism is named per OS (per-OS excellence): systemd on linux,
	// launchd on darwin, the service manager elsewhere — the semantic pin
	// is "the loud line names the restart mechanism the missing file
	// disarms", whichever mechanism THIS OS has.
	assert.Contains(t, out,
		unitFileSupervisorName()+" will not restart this daemon")
	assert.Contains(t, out, "re-run assay install")
	assert.Contains(t, out, g.path, "the loud line names the missing path")
	assert.Equal(t, 1, strings.Count(out, "\n"), "ONE loud line — a flagged state, not a warning block")
}

func TestUnitFileGuardSilentWhenPresent(t *testing.T) {
	var log strings.Builder
	g := &unitFileGuard{
		out:  &log,
		path: filepath.Join(t.TempDir(), "assay-watch.service"),
		stat: os.Stat,
	}
	require.NoError(t, os.WriteFile(g.path, []byte("[Unit]\n"), 0o600))
	g.check()
	assert.Empty(t, log.String(), "a present unit file is the healthy state — silence")
}

func TestUnitFileGuardInactiveWithoutPath(t *testing.T) {
	var log strings.Builder
	called := false
	g := &unitFileGuard{
		out:  &log,
		path: "", // no unit-file platform (windows SCM, unknown init)
		stat: func(string) (os.FileInfo, error) { called = true; return nil, nil },
	}
	g.check()
	assert.Empty(t, log.String())
	assert.False(t, called, "an inactive platform performs no stat at all")
}

func TestUnitFileGuardStatErrorIsLoudNotSilent(t *testing.T) {
	var log strings.Builder
	g := &unitFileGuard{
		out:  &log,
		path: "/unit/assay-watch.service",
		stat: func(string) (os.FileInfo, error) { return nil, errors.New("permission denied") },
	}
	g.check()
	out := log.String()
	assert.Contains(t, out, "permission denied", "a stat error that is not NotExist must still fail loud — silent would hide the flagged state")
	assert.Contains(t, out,
		unitFileSupervisorName()+" will not restart this daemon")
}

// TestUnitFileSupervisorNamePerOS pins the mechanism-name mapping per OS —
// the loud line's honesty contract is naming THIS platform's restart
// mechanism (a darwin line saying "systemd" would be a lie, not polish).
func TestUnitFileSupervisorNamePerOS(t *testing.T) {
	switch runtime.GOOS {
	case "linux":
		assert.Equal(t, "systemd", unitFileSupervisorName())
	case "darwin":
		assert.Equal(t, "launchd", unitFileSupervisorName())
	default:
		assert.Equal(t, "the service manager", unitFileSupervisorName())
	}
}

func TestResolveDaemonUnitPathPerOS(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := resolveDaemonUnitPath()
	switch runtime.GOOS {
	case "linux":
		assert.Equal(t,
			filepath.Join(home, ".config", "systemd", "user", "assay-watch.service"), path)
	case "darwin":
		assert.Equal(t,
			filepath.Join(home, "Library", "LaunchAgents", "assay-watch.plist"), path)
	default:
		assert.Empty(t, path, "no unit-file platform — the check is inactive there")
	}
}

// TestSchedulerChecksUnitFileEachDueWave: the periodic leg is the scheduler's
// due-wave instant (bounded: one stat per wave, hourly in production — never
// a tight ticker).
func TestSchedulerChecksUnitFileEachDueWave(t *testing.T) {
	clock := newFakeClock()
	waves := &waveRecorder{}
	sched := newTestScheduler(clock, waves, false)
	checks := make(chan struct{}, 8)
	sched.unitFileCheck = func() { checks <- struct{}{} }

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = sched.run(stop, nil)
		close(done)
	}()

	// The initial wave runs before the loop (the startup leg's neighbor);
	// the periodic check fires at the first DUE wave. Advance the clock to
	// the armed due instant (the wave's 10m silent advance leaves the first
	// re-arm at 50m — start-anchored).
	waitForWaves(t, waves, 1)
	waitArmed(t, clock, 1)
	clock.advance(50 * time.Minute)
	waitForWaves(t, waves, 2)
	select {
	case <-checks:
	case <-time.After(2 * time.Second):
		t.Fatal("the scheduler never ran the periodic unit-file check at the due wave")
	}

	close(stop)
	<-done
}
