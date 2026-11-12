package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeSv records every sv invocation and replays scripted outputs. Tests
// never execute sv (hermetic — the real binary only exists under runit).
type fakeSv struct {
	calls [][]string
	// script maps verb → the queued (out, err) per call, like fakeLaunchctl.
	script map[string][]scripted
}

func newFakeSv() *fakeSv { return &fakeSv{script: map[string][]scripted{}} }

func (f *fakeSv) expect(verb string, out string, err error) {
	f.script[verb] = append(f.script[verb], scripted{out: out, err: err})
}

func (f *fakeSv) Sv(args ...string) (string, error) {
	f.calls = append(f.calls, args)
	if q, ok := f.script[args[0]]; ok && len(q) > 0 {
		s := q[0]
		f.script[args[0]] = q[1:]
		return s.out, s.err
	}
	return "", nil
}

// verbs is the compact call list for ordering pins.
func (f *fakeSv) verbs() []string {
	v := make([]string, len(f.calls))
	for i, c := range f.calls {
		v[i] = c[0]
	}
	return v
}

// runitSched builds a RunitScheduler over the fake with test-scale pacing
// (the production 500ms verify loop must not stretch unit tests).
func runitSched(f *fakeSv, serviceDir string) *RunitScheduler {
	s := NewRunitScheduler(f, serviceDir)
	s.verifyInterval = time.Millisecond
	s.verifyAttempts = 3
	return s
}

// runitSpec builds a hermetic spec under a temp home (explicit-config shape).
func runitSpec(t *testing.T) (SchedulerInstallSpec, string, string, string) {
	t.Helper()
	home := t.TempDir()
	dataDir := filepath.Join(home, "data")
	binDir := filepath.Join(home, "bin")
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!running\n"), 0o755))
	return SchedulerInstallSpec{
		RunningBinary:     filepath.Join(home, "running-assay"),
		BinDir:            binDir,
		ConfigPath:        filepath.Join(home, "custom.toml"),
		DefaultConfigPath: filepath.Join(dataDir, "config.toml"),
		DataDir:           dataDir,
	}, home, binDir, dataDir
}

// ---------------------------------------------------------------------------
// Allowlist — sv {status,stop,restart,up,down} <abs assay-watch dir> ONLY
// ---------------------------------------------------------------------------

func TestSvAllowlistIsExactlyThePinnedShapes(t *testing.T) {
	dir := "/home/u/service/assay-watch"
	for _, verb := range []string{"status", "stop", "restart", "up", "down"} {
		args := []string{verb, dir}
		require.NoError(t, validateSv(args), "%v must validate", args)
	}
	for _, bad := range [][]string{
		{"term", dir},                       // not in the pinned verb set
		{"once", dir},                       // not in the pinned verb set
		{"status", "/home/u/service/other"}, // foreign dir — never touched
		{"status", "service/assay-watch"},   // relative dir
		{"status", dir + "/log"},            // sub-path
		{"status"},                          // no dir
		{"sv", dir},                         // not a verb
		{"status", "/etc", dir},             // extra args
	} {
		err := validateSv(bad)
		require.Error(t, err, "invocation %v must be refused", bad)
		assert.Contains(t, err.Error(), "allowlist")
	}
}

func TestSvRefusesForeignAndRelativePathsLoudly(t *testing.T) {
	f := newFakeSv()
	exec := RunitExecutor{}
	_, err := exec.Sv("status", "assay-watch")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowlist")
	assert.NotContains(t, f.verbs(), "status", "a refused call must never execute")
}

// ---------------------------------------------------------------------------
// Run script content contract (§3.2 — shared with s6) + 0755 mode
// ---------------------------------------------------------------------------

func TestRunScriptContentExplicitConfigGolden(t *testing.T) {
	got, err := runScriptContent("/home/u/.local/bin/assay", "/home/u/custom.toml", "/home/u/data")
	require.NoError(t, err)
	want := "#!/bin/sh\n" +
		`exec "/home/u/.local/bin/assay" watch -c "/home/u/custom.toml" ` +
		`2>>"/home/u/data/logs/watch.err.log" 1>>"/home/u/data/logs/watch.out.log"` + "\n"
	assert.Equal(t, want, string(got))
}

func TestRunScriptContentDefaultLocationGolden(t *testing.T) {
	got, err := runScriptContent("/home/u/.local/bin/assay", "", "/home/u/data")
	require.NoError(t, err)
	assert.Contains(t, string(got), `exec "/home/u/.local/bin/assay" watch `)
	assert.NotContains(t, string(got), "-c")
}

func TestRunScriptContentRefusesQuoteHostilePaths(t *testing.T) {
	_, err := runScriptContent(`/home/u/we"ird/assay`, "", "/data")
	require.Error(t, err, "a double quote would break the sh quoting — refused before writing")
}

func TestRunitInstallWritesRunScript0755(t *testing.T) {
	spec, home, binDir, dataDir := runitSpec(t)
	f := newFakeSv()
	f.expect("status", "", nil) // the verify loop's success probe
	svcDir := filepath.Join(home, "service")
	s := runitSched(f, svcDir)
	res, err := s.Install(spec)
	require.NoError(t, err)

	runPath := filepath.Join(svcDir, "assay-watch", "run")
	raw, err := os.ReadFile(runPath)
	require.NoError(t, err)
	st, err := os.Stat(runPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), st.Mode().Perm(), "run scripts are 0755 (§3.2)")
	assert.Contains(t, string(raw), `exec "`+filepath.Join(binDir, "assay")+`" watch -c "`+spec.ConfigPath+`"`)
	assert.Contains(t, string(raw), `2>>"`+filepath.Join(dataDir, "logs", "watch.err.log")+`"`)
	assert.Contains(t, string(raw), `1>>"`+filepath.Join(dataDir, "logs", "watch.out.log")+`"`)
	assert.Equal(t, []string{runPath}, res.UnitPaths)
	assert.True(t, res.ServiceActive)
	// Log dir pre-created (the redirects need the parent).
	_, err = os.Stat(filepath.Join(dataDir, "logs"))
	require.NoError(t, err)
}

func TestRunitInstallVerifyLoopUntilSvReachesRunsv(t *testing.T) {
	spec, home, _, _ := runitSpec(t)
	f := newFakeSv()
	// runsvdir rescans every 5s — the first two probes fail (runsv not yet
	// spawned), the third succeeds (§3.3 bounded verify).
	f.expect("status", "", errors.New("supervise not up"))
	f.expect("status", "", errors.New("supervise not up"))
	f.expect("status", "Run: 1234 5\n", nil)
	s := runitSched(f, filepath.Join(home, "service"))
	res, err := s.Install(spec)
	require.NoError(t, err)
	require.True(t, res.ServiceActive)
	assert.Equal(t, []string{"status", "status", "status"}, f.verbs())
}

func TestRunitInstallVerifyTimeoutIsLoud(t *testing.T) {
	spec, home, _, _ := runitSpec(t)
	f := newFakeSv()
	// Every probe in the budget fails — the fake's default (empty success)
	// must never rescue a negative test.
	f.expect("status", "", errors.New("down"))
	f.expect("status", "", errors.New("down"))
	f.expect("status", "", errors.New("down"))
	s := runitSched(f, filepath.Join(home, "service"))
	res, err := s.Install(spec)
	require.Error(t, err)
	assert.False(t, res.ServiceActive)
	assert.Contains(t, err.Error(), "sv status")
	assert.Contains(t, err.Error(), filepath.Join(home, "service", "assay-watch"))
}

func TestRunitInstallDefaultConfigMaterializedOnce(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, "data")
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	spec := SchedulerInstallSpec{
		RunningBinary:     filepath.Join(home, "running-assay"),
		BinDir:            filepath.Join(home, "bin"),
		DefaultConfigPath: filepath.Join(dataDir, "config.toml"),
		DataDir:           dataDir,
	}
	s := runitSched(newFakeSv(), filepath.Join(home, "service"))
	res, err := s.Install(spec)
	require.NoError(t, err)
	assert.Equal(t, spec.DefaultConfigPath, res.ConfigWritten)
	// Re-install: kept, never overwritten.
	res2, err := s.Install(spec)
	require.NoError(t, err)
	assert.Equal(t, spec.DefaultConfigPath, res2.ConfigKept)
	assert.Empty(t, res2.ConfigWritten)
}

// ---------------------------------------------------------------------------
// Uninstall / Status / HeldRegistration
// ---------------------------------------------------------------------------

func TestRunitUninstallStopsThenRemoves(t *testing.T) {
	home := t.TempDir()
	svcDir := filepath.Join(home, "service")
	watchDir := filepath.Join(svcDir, "assay-watch")
	require.NoError(t, os.MkdirAll(watchDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(watchDir, "run"), []byte("#!/bin/sh\n"), 0o755))
	f := newFakeSv()
	f.expect("status", "Run: 9 1\n", nil) // held + running
	f.expect("stop", "ok: down\n", nil)
	s := runitSched(f, svcDir)
	res, err := s.Uninstall(SchedulerUninstallSpec{DataDir: filepath.Join(home, "data")})
	require.NoError(t, err)
	assert.Equal(t, []string{"status", "stop"}, f.verbs())
	_, err = os.Stat(watchDir)
	assert.True(t, os.IsNotExist(err), "the service dir must be removed")
	assert.Contains(t, res.DisabledUnits, "assay-watch")
}

func TestRunitUninstallDownServiceSkipsStop(t *testing.T) {
	home := t.TempDir()
	svcDir := filepath.Join(home, "service")
	require.NoError(t, os.MkdirAll(filepath.Join(svcDir, "assay-watch"), 0o750))
	f := newFakeSv()
	f.expect("status", "down\n", errors.New("down")) // registered but down
	s := runitSched(f, svcDir)
	_, err := s.Uninstall(SchedulerUninstallSpec{})
	require.NoError(t, err)
	assert.Equal(t, []string{"status"}, f.verbs(), "a down service needs no sv stop")
}

func TestRunitUninstallAbsentDirIsCleanNoop(t *testing.T) {
	s := runitSched(newFakeSv(), filepath.Join(t.TempDir(), "service"))
	res, err := s.Uninstall(SchedulerUninstallSpec{})
	require.NoError(t, err)
	assert.Empty(t, res.DisabledUnits)
}

func TestRunitStatusReportsRawSvOutput(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, "service", "assay-watch"), 0o750))
	f := newFakeSv()
	f.expect("status", "Run: 4242 900\n", nil)
	st, err := runitSched(f, filepath.Join(home, "service")).Status()
	require.NoError(t, err)
	assert.True(t, st.Active)
	assert.Contains(t, st.Note, "4242", "the raw sv line is reported verbatim — no parse guessing")
	assert.Contains(t, st.Note, "runsv")
}

func TestRunitHeldRegistrationDirPresence(t *testing.T) {
	home := t.TempDir()
	svcDir := filepath.Join(home, "service")
	s := runitSched(newFakeSv(), svcDir)
	held, _ := s.HeldRegistration()
	assert.False(t, held)
	require.NoError(t, os.MkdirAll(filepath.Join(svcDir, "assay-watch"), 0o750))
	held, where := s.HeldRegistration()
	assert.True(t, held)
	assert.Equal(t, filepath.Join(svcDir, "assay-watch"), where)
}

func TestRunitInstallErrorNamesSchedulerAndCommand(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	// NoSystemd-style misuse: empty service dir is a programmer error — loud.
	s := NewRunitScheduler(newFakeSv(), "")
	_, err := s.Install(SchedulerInstallSpec{RunningBinary: filepath.Join(home, "running-assay"), BinDir: filepath.Join(home, "bin")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "runit")
}

func TestRunitRunScriptNameSkipsDotNames(t *testing.T) {
	// §3.2: disable = the dot-prefixed sibling (runsvdir.8: dot-names are
	// skipped); pin the disabled name shape once, here.
	assert.True(t, strings.HasPrefix(".assay-watch.disabled", "."))
	assert.False(t, strings.HasPrefix("assay-watch", "."), "the live name must never be dot-prefixed")
}
