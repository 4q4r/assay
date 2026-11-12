//go:build unix

package install

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeS6 records every s6-svc / s6-svscanctl / s6-svstat invocation
// (hermetic — the real binaries only exist under s6 supervision).
type fakeS6 struct {
	svcCalls       [][]string
	svscanCalls    [][]string
	svstatCalls    [][]string
	script         map[string][]scripted // last-arg or flag keyed
	svstatUpRounds int                   // how many svstat probes still report up
}

func newFakeS6() *fakeS6 { return &fakeS6{script: map[string][]scripted{}} }

func (f *fakeS6) expect(key string, out string, err error) {
	f.script[key] = append(f.script[key], scripted{out: out, err: err})
}

func (f *fakeS6) Svc(args ...string) (string, error) {
	f.svcCalls = append(f.svcCalls, args)
	return f.replay(args[len(args)-1])
}

func (f *fakeS6) Svscanctl(args ...string) (string, error) {
	f.svscanCalls = append(f.svscanCalls, args)
	return f.replay(args[len(args)-1])
}

func (f *fakeS6) Svstat(args ...string) (string, error) {
	f.svstatCalls = append(f.svstatCalls, args)
	if f.svstatUpRounds > 0 {
		f.svstatUpRounds--
		return "up (pid 4242) 30s\n", nil
	}
	if q, ok := f.script["svstat"]; ok && len(q) > 0 {
		s := q[0]
		f.script["svstat"] = q[1:]
		return s.out, s.err
	}
	return "down 5s\n", nil
}

func (f *fakeS6) replay(key string) (string, error) {
	if q, ok := f.script[key]; ok && len(q) > 0 {
		s := q[0]
		f.script[key] = q[1:]
		return s.out, s.err
	}
	return "", nil
}

func s6Sched(f *fakeS6, scanDir string) *S6Scheduler {
	s := NewS6Scheduler(f, scanDir)
	s.verifyInterval = time.Millisecond
	s.verifyAttempts = 3
	s.stopInterval = time.Millisecond
	s.stopAttempts = 3
	return s
}

// ---------------------------------------------------------------------------
// Allowlist — s6-svc -d / s6-svscanctl -a / s6-svstat, own artifact only
// ---------------------------------------------------------------------------

func TestS6AllowlistIsExactlyThePinnedShapes(t *testing.T) {
	scan := "/home/u/scandir"
	watch := scan + "/assay-watch"
	require.NoError(t, validateS6Svc([]string{"-d", watch}))
	require.NoError(t, validateS6Svscanctl([]string{"-a", scan}))
	require.NoError(t, validateS6Svstat([]string{watch}))
	for _, bad := range []struct {
		kind string
		args []string
	}{
		{"svc", []string{"-u", watch}},         // up is never sent — activation is the dir + rescan
		{"svc", []string{"-d", "assay-watch"}}, // relative
		{"svc", []string{"-d", scan}},          // the scandir itself is not a service dir
		{"svscanctl", []string{"-n", scan}},    // -n kills unmatched supervisors — never ours
		{"svscanctl", []string{"-t", scan}},    // terminate the whole tree — never
		{"svscanctl", []string{"-q", scan}},    // hard stop of the whole tree — never
		{"svstat", []string{scan}},             // scandir is not a service
		{"svstat", []string{}},                 // no dir
	} {
		var err error
		switch bad.kind {
		case "svc":
			err = validateS6SvcForScanDir(bad.args, scan)
		case "svscanctl":
			err = validateS6SvscanctlForScanDir(bad.args, scan)
		default:
			err = validateS6SvstatForScanDir(bad.args, scan)
		}
		require.Error(t, err, "invocation %v (%s) must be refused", bad.args, bad.kind)
		assert.Contains(t, err.Error(), "allowlist")
	}
	// The BOUND refusals: right shape, wrong scandir — the scheduler can
	// never touch a foreign scan tree even with a well-formed invocation.
	require.Error(t, validateS6SvcForScanDir([]string{"-d", "/other/scandir/assay-watch"}, scan))
	require.Error(t, validateS6SvscanctlForScanDir([]string{"-a", "/other"}, scan))
	require.Error(t, validateS6SvstatForScanDir([]string{"/other/scandir/assay-watch"}, scan))
	// The pinned GOOD shapes validate against our own scandir.
	require.NoError(t, validateS6SvcForScanDir([]string{"-d", watch}, scan))
	require.NoError(t, validateS6SvscanctlForScanDir([]string{"-a", scan}, scan))
	require.NoError(t, validateS6SvstatForScanDir([]string{watch}, scan))
}

// ---------------------------------------------------------------------------
// Install: service dir + shared run script + s6-svscanctl -a + verify
// ---------------------------------------------------------------------------

func TestS6InstallWritesServiceDirAndRescans(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, "data")
	scanDir := filepath.Join(home, "scandir")
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	f := newFakeS6()
	f.expect("svstat", "up (pid 4242) 30s\n", nil)
	s := s6Sched(f, scanDir)
	spec := SchedulerInstallSpec{
		RunningBinary: filepath.Join(home, "running-assay"),
		BinDir:        filepath.Join(home, "bin"),
		ConfigPath:    filepath.Join(home, "custom.toml"),
		DataDir:       dataDir,
	}
	res, err := s.Install(spec)
	require.NoError(t, err)

	runPath := filepath.Join(scanDir, "assay-watch", "run")
	raw, err := os.ReadFile(runPath)
	require.NoError(t, err)
	st, err := os.Stat(runPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), st.Mode().Perm(), "run scripts are 0755 (§3.2, same contract as runit)")
	assert.Contains(t, string(raw), `watch -c "`+spec.ConfigPath+`"`)
	require.Len(t, f.svscanCalls, 1)
	assert.Equal(t, []string{"-a", scanDir}, f.svscanCalls[0], "activation = s6-svscanctl -a <scandir> (§3.2)")
	require.Len(t, f.svstatCalls, 1)
	assert.Equal(t, runPath, res.UnitPaths[0])
	assert.True(t, res.ServiceActive)
}

func TestS6InstallVerifyRequiresUp(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	f := newFakeS6()
	// First probe reports down (start race), second reports up.
	f.script["svstat"] = []scripted{{out: "down 0s\n", err: nil}, {out: "up (pid 7) 1s\n", err: nil}}
	s := s6Sched(f, filepath.Join(home, "scandir"))
	res, err := s.Install(SchedulerInstallSpec{
		RunningBinary: filepath.Join(home, "running-assay"),
		BinDir:        filepath.Join(home, "bin"),
		DataDir:       filepath.Join(home, "data"),
	})
	require.NoError(t, err)
	require.True(t, res.ServiceActive)
	require.Len(t, f.svstatCalls, 2)
}

func TestS6InstallVerifyTimeoutIsLoud(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	f := newFakeS6()
	f.script["svstat"] = []scripted{{out: "down 0s\n", err: nil}}
	s := s6Sched(f, filepath.Join(home, "scandir"))
	_, err := s.Install(SchedulerInstallSpec{
		RunningBinary: filepath.Join(home, "running-assay"),
		BinDir:        filepath.Join(home, "bin"),
		DataDir:       filepath.Join(home, "data"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s6-svstat")
	assert.Contains(t, err.Error(), filepath.Join(home, "scandir", "assay-watch"))
}

// ---------------------------------------------------------------------------
// Uninstall: the VERIFIED live-stop contract — s6-svc -d (SIGTERM + no
// restart), bounded wait for down, remove dir, rescan. s6-svscanctl -n is
// NOT a stop command (it only kills supervisors unmatched by the last scan).
// ---------------------------------------------------------------------------

func TestS6UninstallLiveStopOrderPinned(t *testing.T) {
	home := t.TempDir()
	scanDir := filepath.Join(home, "scandir")
	watchDir := filepath.Join(scanDir, "assay-watch")
	require.NoError(t, os.MkdirAll(watchDir, 0o750))
	f := newFakeS6()
	f.svstatUpRounds = 1 // one probe still up, then down
	s := s6Sched(f, scanDir)
	res, err := s.Uninstall(SchedulerUninstallSpec{DataDir: filepath.Join(home, "data")})
	require.NoError(t, err)

	require.Len(t, f.svcCalls, 1, "exactly one s6-svc -d live-stop")
	assert.Equal(t, []string{"-d", watchDir}, f.svcCalls[0])
	// svstat polled until down before the dir removal + rescan.
	require.GreaterOrEqual(t, len(f.svstatCalls), 2)
	require.Len(t, f.svscanCalls, 1)
	assert.Equal(t, []string{"-a", scanDir}, f.svscanCalls[0])
	_, err = os.Stat(watchDir)
	assert.True(t, os.IsNotExist(err), "the service dir is removed after the service is down")
	assert.Contains(t, res.DisabledUnits, "assay-watch")
}

func TestS6UninstallTimeoutWaitingForDownIsLoud(t *testing.T) {
	home := t.TempDir()
	scanDir := filepath.Join(home, "scandir")
	require.NoError(t, os.MkdirAll(filepath.Join(scanDir, "assay-watch"), 0o750))
	f := newFakeS6()
	f.svstatUpRounds = 99 // never goes down
	s := s6Sched(f, scanDir)
	_, err := s.Uninstall(SchedulerUninstallSpec{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s6-svc -d")
	// The service dir must NOT be removed while the service is still up
	// (removing it would orphan the supervise process — s6 flags the service
	// inactive and nothing ever stops it).
	_, statErr := os.Stat(filepath.Join(scanDir, "assay-watch"))
	require.NoError(t, statErr)
	assert.Empty(t, f.svscanCalls)
}

func TestS6UninstallAbsentDirNoop(t *testing.T) {
	s := s6Sched(newFakeS6(), filepath.Join(t.TempDir(), "scandir"))
	res, err := s.Uninstall(SchedulerUninstallSpec{})
	require.NoError(t, err)
	assert.Empty(t, res.DisabledUnits)
	assert.Empty(t, res.RemovedUnits)
}

func TestS6StatusAndHeldRegistration(t *testing.T) {
	home := t.TempDir()
	scanDir := filepath.Join(home, "scandir")
	f := newFakeS6()
	f.expect("svstat", "up (pid 99) 5s\n", nil)
	s := s6Sched(f, scanDir)
	require.NoError(t, os.MkdirAll(filepath.Join(scanDir, "assay-watch"), 0o750))
	st, err := s.Status()
	require.NoError(t, err)
	assert.True(t, st.Active)
	assert.Contains(t, st.Note, "s6-supervise")
	held, where := s.HeldRegistration()
	assert.True(t, held)
	assert.Equal(t, filepath.Join(scanDir, "assay-watch"), where)
}

func TestS6SystemLevelNoteShape(t *testing.T) {
	fix := newProcFixture(t)
	fix.addProc(t, 1, 0, "s6-svscan", []string{"s6-svscan", "/run/service"}, "")
	note := SystemLevelS6Note(fix.fs())
	require.NotEmpty(t, note)
	assert.Contains(t, note, "system level")
	assert.Contains(t, note, "no elevation")
	// No root s6-svscan → no note.
	empty := newProcFixture(t)
	assert.Empty(t, SystemLevelS6Note(empty.fs()))
}
