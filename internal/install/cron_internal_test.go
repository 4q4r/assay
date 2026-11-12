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

// fakeCrontab records crontab invocations with their stdin payloads and
// replays a stored table for -l (hermetic — no real spool is touched).
type fakeCrontab struct {
	calls    [][]string
	stdins   []string
	read     string // the stored crontab returned by -l
	readErr  error  // -l error (e.g. "no crontab for user")
	writeErr error
	removed  bool
}

func (f *fakeCrontab) Crontab(args []string, stdin string) (string, error) {
	f.calls = append(f.calls, args)
	f.stdins = append(f.stdins, stdin)
	switch {
	case equalArgs(args, []string{"-l"}):
		return f.read, f.readErr
	case equalArgs(args, []string{"-"}):
		if f.writeErr != nil {
			return "", f.writeErr
		}
		f.read = stdin // the spool is replaced by what we wrote
		return "", nil
	case equalArgs(args, []string{"-r"}):
		f.removed = true
		f.read = ""
		return "", nil
	}
	return "", errors.New("fakeCrontab: unexpected invocation")
}

func cronSched(f *fakeCrontab) *CronScheduler {
	s := NewCronScheduler(f)
	s.verifyInterval = time.Millisecond
	s.verifyAttempts = 3
	return s
}

func cronSpec(t *testing.T) (SchedulerInstallSpec, string, string) {
	t.Helper()
	home := t.TempDir()
	dataDir := filepath.Join(home, "data")
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!x\n"), 0o755))
	return SchedulerInstallSpec{
		RunningBinary: filepath.Join(home, "running-assay"),
		BinDir:        filepath.Join(home, "bin"),
		ConfigPath:    filepath.Join(home, "custom.toml"),
		DataDir:       dataDir,
	}, filepath.Join(home, "bin"), dataDir
}

// ---------------------------------------------------------------------------
// Allowlist — crontab -l / crontab - / crontab -r exactly
// ---------------------------------------------------------------------------

func TestCrontabAllowlistIsExactlyThreeShapes(t *testing.T) {
	require.NoError(t, validateCrontab([]string{"-l"}, ""))
	require.NoError(t, validateCrontab([]string{"-"}, "any content"))
	require.NoError(t, validateCrontab([]string{"-r"}, ""))
	for _, bad := range []struct {
		args  []string
		stdin string
		why   string
	}{
		{[]string{"-e"}, "", "interactive edit is never ours"},
		{[]string{"-u", "root", "-l"}, "", "foreign user spools are never touched"},
		{[]string{"-r"}, "content", "crontab -r carries no stdin — a non-empty stdin is a caller bug"},
		{[]string{"-l"}, "content", "crontab -l carries no stdin"},
		{[]string{}, "", "no empty invocations"},
		{[]string{"-"}, "", "an empty write would wipe the spool — refused"},
	} {
		err := validateCrontab(bad.args, bad.stdin)
		require.Error(t, err, "invocation %v (stdin %q) must be refused: %s", bad.args, bad.stdin, bad.why)
		assert.Contains(t, err.Error(), "allowlist")
	}
}

// ---------------------------------------------------------------------------
// Marker line golden + idempotent add/remove (§3.2)
// ---------------------------------------------------------------------------

func TestCronLineGoldenExplicitConfig(t *testing.T) {
	got, err := cronLine("/home/u/.local/bin/assay", "/home/u/custom.toml", "/home/u/data")
	require.NoError(t, err)
	assert.Equal(t,
		`@reboot "/home/u/.local/bin/assay" watch -c "/home/u/custom.toml" >> "/home/u/data/logs/watch.out.log" 2>&1 # assay-watch`,
		got)
}

func TestCronLineGoldenDefaultLocation(t *testing.T) {
	got, err := cronLine("/home/u/.local/bin/assay", "", "/home/u/data")
	require.NoError(t, err)
	assert.Contains(t, got, `@reboot "/home/u/.local/bin/assay" watch >> `)
	assert.NotContains(t, got, "-c")
}

func TestCronLineRefusesCrontabHostilePaths(t *testing.T) {
	for _, bin := range []string{`/home/u/a"b/assay`, "/home/u/a%b", "/home/u/a\nb/assay"} {
		_, err := cronLineData(bin, "", "/data")
		require.Error(t, err, "path %q must be refused (percent = newline in crontab commands; quotes break sh)", bin)
	}
}

func TestCronLineRefusesShellExpansionPaths(t *testing.T) {
	// P3-1 (S3 review): a crontab command line runs under sh — $var and
	// backticks EXPAND at job-run time (a silently-broken path). Every field
	// (binary, config, data dir) is refused before any spool write.
	for _, hostile := range []string{"/opt/$HOME/assay", "/opt/a`id`/assay"} {
		_, err := cronLineData("/bin/assay", "", hostile)
		require.Error(t, err, "data dir %q must be refused", hostile)
		assert.Contains(t, err.Error(), "hostile")
		_, err = cronLineData(hostile, "", "/data")
		require.Error(t, err, "binary path %q must be refused", hostile)
		assert.Contains(t, err.Error(), "hostile")
		_, err = cronLineData("/bin/assay", hostile, "/data")
		require.Error(t, err, "config path %q must be refused", hostile)
		assert.Contains(t, err.Error(), "hostile")
	}
}

func TestCronInstallAppendsMarkedLine(t *testing.T) {
	spec, binDir, dataDir := cronSpec(t)
	f := &fakeCrontab{read: "*/5 * * * * /usr/bin/something\n"}
	s := cronSched(f)
	res, err := s.Install(spec)
	require.NoError(t, err)
	assert.True(t, res.ServiceActive)
	assert.True(t, res.ConfigKept == "" || res.ConfigWritten != "", "explicit-config installs touch no config")

	// Read → append → write via crontab - (§3.2 atomic spool update), then
	// the bounded read-back verify (§3.3) is the third call.
	require.Len(t, f.calls, 3, "read (crontab -l), write (crontab -), verify (crontab -l)")
	assert.Equal(t, []string{"-l"}, f.calls[0])
	assert.Equal(t, []string{"-"}, f.calls[1])
	written := f.stdins[1]
	assert.Contains(t, written, "*/5 * * * * /usr/bin/something", "foreign lines are preserved verbatim")
	assert.Contains(t, written, "# assay-watch")
	assert.Contains(t, written, `@reboot "`+filepath.Join(binDir, "assay")+`" watch -c "`+spec.ConfigPath+`" >> "`+
		filepath.Join(dataDir, "logs", "watch.out.log")+`" 2>&1 # assay-watch`)
	// Log dir pre-created.
	_, err = os.Stat(filepath.Join(dataDir, "logs"))
	require.NoError(t, err)
}

func TestCronInstallReplacesOwnLineIdempotently(t *testing.T) {
	spec, _, _ := cronSpec(t)
	old := "@reboot /old/path/assay watch >> /old/log 2>&1 # assay-watch\n"
	f := &fakeCrontab{read: "0 0 * * * daily-job\n" + old}
	s := cronSched(f)
	_, err := s.Install(spec)
	require.NoError(t, err)
	written := f.stdins[1]
	assert.NotContains(t, written, "/old/path/assay", "the previous assay-watch line is replaced (idempotent add)")
	assert.Contains(t, written, "0 0 * * * daily-job")
	assert.Equal(t, 1, strings.Count(written, "# assay-watch"), "exactly one marked line after a re-install")
}

func TestCronInstallVerifyReadsBack(t *testing.T) {
	spec, _, _ := cronSpec(t)
	f := &fakeCrontab{read: "*/5 * * * * x\n"}
	// After the write the fake spool contains the line → the read-back verify
	// finds the marker immediately.
	s := cronSched(f)
	_, err := s.Install(spec)
	require.NoError(t, err)
	assert.Contains(t, f.read, "# assay-watch")
}

func TestCronInstallWriteFailureIsLoud(t *testing.T) {
	spec, _, _ := cronSpec(t)
	f := &fakeCrontab{readErr: errors.New("no crontab for user"), writeErr: errors.New("spool unwritable")}
	s := cronSched(f)
	_, err := s.Install(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "crontab -")
}

func TestCronUninstallFiltersMarkerAndRemovesWhenEmpty(t *testing.T) {
	home := t.TempDir()
	f := &fakeCrontab{read: "@reboot /old/assay watch >> /old/log 2>&1 # assay-watch\n"}
	s := cronSched(f)
	res, err := s.Uninstall(SchedulerUninstallSpec{DataDir: filepath.Join(home, "data")})
	require.NoError(t, err)
	// Only the marked line existed → the filtered spool is empty → crontab -r
	// directly (§3.2: empty result → crontab -r; no empty write is ever sent).
	require.Len(t, f.calls, 2)
	assert.Equal(t, []string{"-l"}, f.calls[0])
	assert.Equal(t, []string{"-r"}, f.calls[1])
	assert.True(t, f.removed)
	assert.Empty(t, f.read)
	assert.Contains(t, res.RemovedUnits, "crontab (@reboot assay-watch)")
}

func TestCronUninstallKeepsForeignLinesWithoutRemoval(t *testing.T) {
	f := &fakeCrontab{read: "0 0 * * * keepme\n@reboot /old/assay watch 2>&1 # assay-watch\n"}
	s := cronSched(f)
	_, err := s.Uninstall(SchedulerUninstallSpec{})
	require.NoError(t, err)
	// Foreign lines remain → written back, never crontab -r.
	assert.Equal(t, "0 0 * * * keepme\n", f.stdins[1])
	assert.False(t, f.removed)
}

func TestCronUninstallAbsentLineNoop(t *testing.T) {
	f := &fakeCrontab{readErr: errors.New("no crontab for user")}
	s := cronSched(f)
	res, err := s.Uninstall(SchedulerUninstallSpec{})
	require.NoError(t, err)
	// The -l read happens (its "no crontab" answer = an empty spool) — and
	// nothing is ever written or removed.
	assert.Equal(t, [][]string{{"-l"}}, f.calls)
	assert.Empty(t, res.RemovedUnits)
	assert.False(t, f.removed)
}

func TestCronStatusHonestNoSupervision(t *testing.T) {
	f := &fakeCrontab{read: "@reboot /old/assay watch 2>&1 # assay-watch\n"}
	st, err := cronSched(f).Status()
	require.NoError(t, err)
	assert.True(t, st.Active, "a registered @reboot line is an active registration")
	assert.Contains(t, st.Note, "no supervision")
	assert.Contains(t, st.Note, "no crash restart")
}

func TestCronHeldRegistrationMarkerPresence(t *testing.T) {
	f := &fakeCrontab{read: ""}
	held, _ := cronSched(f).HeldRegistration()
	assert.False(t, held)
	f.read = "@reboot /bin/assay watch 2>&1 # assay-watch\n"
	held, _ = cronSched(f).HeldRegistration()
	assert.True(t, held)
}

func TestCronUsableProbeSemantics(t *testing.T) {
	// §3.1.5: crontab usable = -l exit 0 OR "no crontab for user"; anything
	// else (binary missing, permission failure) = unusable.
	require.NoError(t, cronUsable(&fakeCrontab{read: "x\n"}))
	require.NoError(t, cronUsable(&fakeCrontab{readErr: errors.New("no crontab for u")}))
	err := cronUsable(&fakeCrontab{readErr: errors.New("crontab: command not found")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "crontab")
}
