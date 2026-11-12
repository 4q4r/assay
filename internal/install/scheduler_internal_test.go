package install

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fixture /proc trees — hermetic detection (no real /proc is ever read in
// tests; §3.1 mandates the injected procFS seam).
// ---------------------------------------------------------------------------

// procFixture builds a /proc-shaped tree under a temp dir: numeric dirs
// carrying comm/cmdline/status/cwd entries, exactly what the production
// procFS reads from the real /proc.
type procFixture struct {
	root string
}

func newProcFixture(t *testing.T) *procFixture {
	t.Helper()
	return &procFixture{root: t.TempDir()}
}

// addProc plants one process: pid, owner uid, comm (trailing newline
// optional — the parser trims), argv list, and the cwd symlink target
// ("" = no cwd entry).
func (f *procFixture) addProc(t *testing.T, pid int, uid int, comm string, argv []string, cwd string) {
	t.Helper()
	dir := filepath.Join(f.root, strconv.Itoa(pid))
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644))
	line := strings.Join(argv, "\x00")
	if len(argv) > 0 {
		line += "\x00"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cmdline"), []byte(line), 0o644))
	status := "Name:\t" + comm + "\nUid:\t" + strconv.Itoa(uid) + "\t" +
		strconv.Itoa(uid) + "\t" + strconv.Itoa(uid) + "\t" + strconv.Itoa(uid) + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644))
	if cwd != "" {
		require.NoError(t, os.Symlink(cwd, filepath.Join(dir, "cwd")))
	}
}

func (f *procFixture) fs() ProcFS { return newFixtureProcFS(f.root) } //nolint:ireturn // the seam is an interface by design

// fakeProbe is a scripted Detect probe seam (systemd / rc-status / cron).
func fakeProbe(err error) func() error { return func() error { return err } }

// testExecutors wires an Executors with everything inert except what a test
// overrides: no systemd session, no sv, failing rc-status, unusable cron —
// the "nothing detected" baseline every order pin starts from.
func testExecutors(home string) *Executors {
	return &Executors{
		Home:           home,
		SystemdProbe:   fakeProbe(assert.AnError),
		SystemdUnitDir: filepath.Join(home, ".config", "systemd", "user"),
		Runit:          nil,
		SvOnPath:       func() bool { return false },
		OpenRC:         nil,
		RCStatusProbe:  fakeProbe(assert.AnError),
		Cron:           nil,
		CronUsable:     fakeProbe(assert.AnError),
	}
}

// ---------------------------------------------------------------------------
// §3.1 detection order — BINDING order, first match wins
// ---------------------------------------------------------------------------

func TestDetectSystemdFirstBeatsEverything(t *testing.T) {
	home := t.TempDir()
	fix := newProcFixture(t)
	// runit, openrc and s6 all present — systemd still wins (§3.1 order 1).
	fix.addProc(t, 100, 1000, "runsvdir", []string{"runsvdir", home + "/service"}, home+"/service")
	fix.addProc(t, 101, 1000, "openrc-user", []string{"openrc-user"}, "")
	fix.addProc(t, 102, 1000, "s6-svscan", []string{"s6-svscan"}, home+"/scan")
	exec := testExecutors(home)
	exec.SystemdProbe = fakeProbe(nil) // the ONLY signal systemd needs
	sched := Detect(fix.fs(), exec)
	assert.Equal(t, "systemd-user", sched.Name())
}

func TestDetectRunitFromRunsvdirCmdline(t *testing.T) {
	home := t.TempDir()
	fix := newProcFixture(t)
	// runsvdir with a NON-default service dir arg — the dir comes from the
	// cmdline (§3.1.2: resolved from the process cmdline, never assumed),
	// resolved against the process cwd when relative.
	fix.addProc(t, 200, 1000, "runsvdir",
		[]string{"/usr/bin/runsvdir", "-L", "/tmp/log", "/home/u/custom-services"}, "")
	exec := testExecutors(home)
	exec.SvOnPath = func() bool { return true }
	sched := Detect(fix.fs(), exec)
	require.Equal(t, "runit", sched.Name())
	rs, ok := sched.(*RunitScheduler)
	require.True(t, ok, "Detect must return the concrete RunitScheduler")
	assert.Equal(t, "/home/u/custom-services", rs.ServiceDir)
}

func TestDetectRunitRelativeDirResolvedAgainstProcCwd(t *testing.T) {
	home := t.TempDir()
	fix := newProcFixture(t)
	fix.addProc(t, 201, 1000, "runsvdir", []string{"runsvdir", "my-services"}, "/home/u/svcroot")
	exec := testExecutors(home)
	exec.SvOnPath = func() bool { return true }
	sched := Detect(fix.fs(), exec)
	require.Equal(t, "runit", sched.Name())
	assert.Equal(t, "/home/u/svcroot/my-services", sched.(*RunitScheduler).ServiceDir)
}

func TestDetectRunitRequiresSvOnPath(t *testing.T) {
	home := t.TempDir()
	fix := newProcFixture(t)
	fix.addProc(t, 202, 1000, "runsvdir", []string{"runsvdir", home + "/service"}, home+"/service")
	exec := testExecutors(home)
	exec.SvOnPath = func() bool { return false } // §3.1.2: AND sv on PATH
	assert.Equal(t, "foreground", Detect(fix.fs(), exec).Name())
}

func TestDetectRunitZombieEmptyCmdlineDetectsNothingInsteadOfPanicking(t *testing.T) {
	home := t.TempDir()
	fix := newProcFixture(t)
	// P2-1 (S3 review): a zombie's /proc cmdline is EMPTY while comm is
	// retained — an own-uid exiting runsvdir (or any own-uid process whose
	// comm carries the prefix) must detect as not-runit, never panic
	// (nil[1:] slice-bounds). A runsvdir with no dir argument cannot name a
	// service dir anyway. Pins BOTH consumers of detectRunitServiceDir
	// (Detect and HeldByAny).
	fix.addProc(t, 210, 1000, "runsvdir", nil, "")
	exec := testExecutors(home)
	exec.SvOnPath = func() bool { return true }
	assert.Equal(t, "foreground", Detect(fix.fs(), exec).Name())
	_, _, held := HeldByAny(fix.fs(), exec)
	assert.False(t, held)
}

func TestDetectRunitForeignUidRunsvdirIgnored(t *testing.T) {
	home := t.TempDir()
	fix := newProcFixture(t)
	fix.addProc(t, 203, 0, "runsvdir", []string{"runsvdir", "/services"}, "") // root-owned
	exec := testExecutors(home)
	exec.SvOnPath = func() bool { return true }
	assert.Equal(t, "foreground", Detect(fix.fs(), exec).Name())
}

func TestDetectOpenRCFromOpenrcUserProcess(t *testing.T) {
	home := t.TempDir()
	fix := newProcFixture(t)
	fix.addProc(t, 300, 1000, "openrc-user", []string{"openrc-user"}, "")
	sched := Detect(fix.fs(), testExecutors(home))
	assert.Equal(t, "openrc-user", sched.Name())
}

func TestDetectOpenRCFromRcStatusProbe(t *testing.T) {
	home := t.TempDir()
	exec := testExecutors(home)
	exec.RCStatusProbe = fakeProbe(nil) // §3.1.3: OR rc-status --user exits 0
	assert.Equal(t, "openrc-user", Detect(newProcFixture(t).fs(), exec).Name())
}

func TestDetectOpenRCBelow060FallsThrough(t *testing.T) {
	home := t.TempDir()
	// No openrc-user process, rc-status --user fails (pre-0.60 or absent):
	// NOT detected — falls through (§3.1.3).
	assert.Equal(t, "foreground", Detect(newProcFixture(t).fs(), testExecutors(home)).Name())
}

func TestDetectS6ScanDirFromProcCwd(t *testing.T) {
	home := t.TempDir()
	fix := newProcFixture(t)
	// §3.1.4: the scandir IS the detected s6-svscan's cwd (skarnet:
	// "the scanner scans the current directory for subdirectories").
	fix.addProc(t, 400, 1000, "s6-svscan", []string{"s6-svscan"}, "/home/u/scandir")
	sched := Detect(fix.fs(), testExecutors(home))
	require.Equal(t, "s6", sched.Name())
	assert.Equal(t, "/home/u/scandir", sched.(*S6Scheduler).ScanDir)
}

func TestDetectS6SystemLevelPID1FallsThroughWithNote(t *testing.T) {
	home := t.TempDir()
	fix := newProcFixture(t)
	// PID1 = s6-svscan owned by root: does NOT qualify (no-sudo) — falls
	// through, and the system-level note is available for status (§3.1.4).
	fix.addProc(t, 1, 0, "s6-svscan", []string{"/sbin/s6-svscan", "/run/service"}, "")
	exec := testExecutors(home)
	assert.Equal(t, "foreground", Detect(fix.fs(), exec).Name())
	note := SystemLevelS6Note(fix.fs())
	assert.Contains(t, note, "s6")
	assert.Contains(t, note, "no elevation")
}

func TestDetectCronWhenCrontabUsable(t *testing.T) {
	home := t.TempDir()
	exec := testExecutors(home)
	exec.CronUsable = fakeProbe(nil) // §3.1.5: crontab usable
	assert.Equal(t, "cron", Detect(newProcFixture(t).fs(), exec).Name())
}

func TestDetectForegroundWhenNothingMatches(t *testing.T) {
	home := t.TempDir()
	assert.Equal(t, "foreground", Detect(newProcFixture(t).fs(), testExecutors(home)).Name())
}

// ---------------------------------------------------------------------------
// procFS — the consumer-side /proc seam and its production implementation
// ---------------------------------------------------------------------------

func TestOSProcFSReadsFixtureTree(t *testing.T) {
	fix := newProcFixture(t)
	fix.addProc(t, 500, 1000, "s6-svscan", []string{"s6-svscan", "-v"}, "/scan/dir")
	fs := fix.fs()
	ids, err := fs.ProcIDs()
	require.NoError(t, err)
	assert.Equal(t, []string{"500"}, ids)
	comm, err := fs.ReadProcFile("500", "comm")
	require.NoError(t, err)
	assert.Equal(t, "s6-svscan", comm)
	cmdline, err := fs.ReadProcFile("500", "cmdline")
	require.NoError(t, err)
	assert.Equal(t, []string{"s6-svscan", "-v"}, splitCmdline(cmdline))
	cwd, err := fs.ProcCwd("500")
	require.NoError(t, err)
	assert.Equal(t, "/scan/dir", cwd)
}

func TestOSProcFSNonNumericDirsSkipped(t *testing.T) {
	fix := newProcFixture(t)
	fix.addProc(t, 501, 0, "init", []string{"/sbin/init"}, "")
	require.NoError(t, os.MkdirAll(filepath.Join(fix.root, "sys"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(fix.root, "uptime"), []byte("1"), 0o644))
	ids, err := fix.fs().ProcIDs()
	require.NoError(t, err)
	assert.Equal(t, []string{"501"}, ids)
}

func TestProcUIDParseFromStatusLine(t *testing.T) {
	fix := newProcFixture(t)
	fix.addProc(t, 502, 4242, "runsvdir", []string{"runsvdir", "/svc"}, "")
	uid, err := procUID(fix.fs(), "502")
	require.NoError(t, err)
	assert.Equal(t, 4242, uid)
}

// ---------------------------------------------------------------------------
// §3.1 end — cross-scheduler HeldRegistration scan (double-install refusal
// input; the W5 stampede class)
// ---------------------------------------------------------------------------

func TestHeldByAnySystemdUnitFile(t *testing.T) {
	home := t.TempDir()
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	require.NoError(t, os.MkdirAll(unitDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(unitDir, WatchService), []byte("x"), 0o644))
	exec := testExecutors(home)
	holder, loc, ok := HeldByAny(newProcFixture(t).fs(), exec)
	require.True(t, ok)
	assert.Equal(t, "systemd-user", holder)
	assert.Equal(t, filepath.Join(unitDir, WatchService), loc)
}

func TestHeldByAnyRunitServiceDirDetected(t *testing.T) {
	home := t.TempDir()
	fix := newProcFixture(t)
	fix.addProc(t, 600, 1000, "runsvdir", []string{"runsvdir", home + "/service"}, home+"/service")
	require.NoError(t, os.MkdirAll(filepath.Join(home, "service", "assay-watch"), 0o750))
	holder, loc, ok := HeldByAny(fix.fs(), testExecutors(home))
	require.True(t, ok)
	assert.Equal(t, "runit", holder)
	assert.Equal(t, filepath.Join(home, "service", "assay-watch"), loc)
}

func TestHeldByAnyRunitDefaultDirWhenNotRunning(t *testing.T) {
	home := t.TempDir()
	// No runsvdir running — the default ~/service/assay-watch leftover still
	// counts as a registration (loud beats silent).
	require.NoError(t, os.MkdirAll(filepath.Join(home, "service", "assay-watch"), 0o750))
	holder, _, ok := HeldByAny(newProcFixture(t).fs(), testExecutors(home))
	require.True(t, ok)
	assert.Equal(t, "runit", holder)
}

func TestHeldByAnyRunitDotDisabledDirIsNotHeld(t *testing.T) {
	home := t.TempDir()
	// §3.2: dot-prefixed names are skipped by runsvdir — a disabled service
	// is NOT a live registration.
	require.NoError(t, os.MkdirAll(filepath.Join(home, "service", ".assay-watch.disabled.1"), 0o750))
	_, _, ok := HeldByAny(newProcFixture(t).fs(), testExecutors(home))
	assert.False(t, ok)
}

func TestHeldByAnyOpenRCScript(t *testing.T) {
	home := t.TempDir()
	initDir := filepath.Join(home, ".config", "rc", "init.d")
	require.NoError(t, os.MkdirAll(initDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(initDir, "assay-watch"), []byte("x"), 0o644))
	holder, loc, ok := HeldByAny(newProcFixture(t).fs(), testExecutors(home))
	require.True(t, ok)
	assert.Equal(t, "openrc-user", holder)
	assert.Equal(t, filepath.Join(initDir, "assay-watch"), loc)
}

func TestHeldByAnyS6OnlyWithLiveScanner(t *testing.T) {
	home := t.TempDir()
	// Dir exists but no s6-svscan runs: nothing can launch it — not held
	// (the scandir convention is never invented, §3.2 s6).
	require.NoError(t, os.MkdirAll(filepath.Join(home, "scan", "assay-watch"), 0o750))
	fix := newProcFixture(t)
	fix.addProc(t, 700, 1000, "s6-svscan", []string{"s6-svscan"}, home+"/scan")
	holder, loc, ok := HeldByAny(fix.fs(), testExecutors(home))
	require.True(t, ok)
	assert.Equal(t, "s6", holder)
	assert.Equal(t, filepath.Join(home, "scan", "assay-watch"), loc)
}

func TestHeldByAnyCronMarkerLine(t *testing.T) {
	home := t.TempDir()
	fc := &fakeCrontab{read: "@reboot /old/bin/assay watch >> /old/log 2>&1 # assay-watch\n"}
	exec := testExecutors(home)
	exec.Cron = fc
	exec.CronUsable = fakeProbe(nil)
	holder, _, ok := HeldByAny(newProcFixture(t).fs(), exec)
	require.True(t, ok)
	assert.Equal(t, "cron", holder)
}

func TestHeldByAnyScanOrderDeterministic(t *testing.T) {
	home := t.TempDir()
	// systemd AND runit both hold: the scan reports systemd (its scan
	// position is first — the refusal message is deterministic).
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	require.NoError(t, os.MkdirAll(unitDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(unitDir, WatchService), []byte("x"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "service", "assay-watch"), 0o750))
	holder, _, ok := HeldByAny(newProcFixture(t).fs(), testExecutors(home))
	require.True(t, ok)
	assert.Equal(t, "systemd-user", holder)
}

func TestHeldByAnyNothingHeld(t *testing.T) {
	_, _, ok := HeldByAny(newProcFixture(t).fs(), testExecutors(t.TempDir()))
	assert.False(t, ok)
}
