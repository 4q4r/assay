package activate_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"assay/internal/activate"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sleepXray is a fake xray that exits 0 after sleeping (proves deadline
// behavior on the real child process — a clock seam cannot fake SIGKILL).
func sleepXray(t *testing.T, dir string, seconds string) string {
	t.Helper()
	path := filepath.Join(dir, "sleepy-xray.sh")
	body := "#!/bin/sh\nsleep " + seconds + "\necho \"Configuration OK\"\nexit 0\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o755))
	return path
}

// TestTestTimeoutBoundsTheTestGate pins [activate].test_timeout: >0 bounds
// the `xray run -test` child (a hanging binary fails the gate fast), 0 means
// NO deadline — current behavior preserved, documented.
func TestTestTimeoutBoundsTheTestGate(t *testing.T) {
	t.Run("hanging gate fails fast under the deadline", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "config.json")
		rendered := filepath.Join(dir, "rendered.json")
		writeConfig(t, target)
		require.NoError(t, os.WriteFile(rendered, []byte(`{"v":1}`), 0o644))

		start := time.Now()
		_, err := activate.Run(activate.Input{
			RenderedPath: rendered, TargetPath: target,
			XrayBin:     sleepXray(t, dir, "30"),
			TestTimeout: 100 * time.Millisecond,
		})
		require.Error(t, err, "a gate exceeding the deadline must fail loud")
		assert.Less(t, time.Since(start), 15*time.Second,
			"the deadline must cut the child, not wait out its full sleep")
		assert.NotContains(t, err.Error(), "Configuration OK")
	})

	t.Run("zero means no deadline", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "config.json")
		rendered := filepath.Join(dir, "rendered.json")
		writeConfig(t, target)
		require.NoError(t, os.WriteFile(rendered, []byte(`{"v":2}`), 0o644))

		res, err := activate.Run(activate.Input{
			RenderedPath: rendered, TargetPath: target,
			XrayBin:     sleepXray(t, dir, "1"), // longer than any default deadline
			TestTimeout: 0,
		})
		require.NoError(t, err, "test_timeout 0 = no deadline (current behavior)")
		assert.True(t, res.TestPassed)
	})
}

// TestServiceNameInRestartHint pins [activate].service_name: the printed
// restart hint names the configured unit; the zero value falls back to
// xray-raw.service (behavior preservation).
func TestServiceNameInRestartHint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	writeConfig(t, target)
	require.NoError(t, os.WriteFile(rendered, []byte(`{"v":3}`), 0o644))

	res, err := activate.Run(activate.Input{
		RenderedPath: rendered, TargetPath: target,
		XrayBin: fakeXray(t, dir, "ok"), ServiceName: "xray-custom.service",
	})
	require.NoError(t, err)
	assert.Contains(t, res.RestartHint, "systemctl --user restart xray-custom.service")
	assert.NotContains(t, res.RestartHint, "xray-raw.service")
}

// TestBackupKeepRetention pins [activate].backup_keep: after a successful
// new backup write only the N newest .bak-<ts> files remain; 0 = unlimited;
// a deletion failure is LOUD and aborts before the live target is replaced.
func TestBackupKeepRetention(t *testing.T) {
	writeBackup := func(t *testing.T, dir, stamp string) {
		t.Helper()
		require.NoError(t, os.MkdirAll(dir, 0o750))
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "config.json.bak-"+stamp), []byte("old"), 0o600))
	}
	base := func(t *testing.T) (string, string, string) {
		t.Helper()
		dir := t.TempDir()
		target := filepath.Join(dir, "config.json")
		rendered := filepath.Join(dir, "rendered.json")
		writeConfig(t, target)
		require.NoError(t, os.WriteFile(rendered, []byte(`{"v":9}`), 0o644))
		return dir, target, rendered
	}

	t.Run("keep 2 prunes the oldest", func(t *testing.T) {
		dir, target, rendered := base(t)
		backupDir := filepath.Join(dir, "backups")
		writeBackup(t, backupDir, "20200101-000000")
		writeBackup(t, backupDir, "20250101-000000")
		writeBackup(t, backupDir, "20250601-000000")

		res, err := activate.Run(activate.Input{
			RenderedPath: rendered, TargetPath: target,
			XrayBin: fakeXray(t, dir, "ok"), Backup: true, BackupDir: backupDir,
			BackupKeep: 2,
		})
		require.NoError(t, err)
		remaining, globErr := filepath.Glob(filepath.Join(backupDir, "config.json.bak-*"))
		require.NoError(t, globErr)
		assert.Len(t, remaining, 2, "keep=2: the two newest backups survive")
		assert.Contains(t, remaining, res.BackupPath, "the fresh backup is among them")
		assert.NotContains(t, remaining, filepath.Join(backupDir, "config.json.bak-20200101-000000"))
	})

	t.Run("keep 0 is unlimited", func(t *testing.T) {
		dir, target, rendered := base(t)
		backupDir := filepath.Join(dir, "backups")
		writeBackup(t, backupDir, "20200101-000000")
		writeBackup(t, backupDir, "20250101-000000")

		_, err := activate.Run(activate.Input{
			RenderedPath: rendered, TargetPath: target,
			XrayBin: fakeXray(t, dir, "ok"), Backup: true, BackupDir: backupDir,
		})
		require.NoError(t, err)
		remaining, globErr := filepath.Glob(filepath.Join(backupDir, "config.json.bak-*"))
		require.NoError(t, globErr)
		assert.Len(t, remaining, 3, "keep=0 never deletes")
	})

	t.Run("deletion failure is loud and blocks the replace", func(t *testing.T) {
		dir, target, rendered := base(t)
		backupDir := filepath.Join(dir, "backups")
		// Non-empty dir wearing an OLD backup stamp → retention must try to
		// delete it and fail loud.
		stub := filepath.Join(backupDir, "config.json.bak-20200101-000000")
		require.NoError(t, os.MkdirAll(stub, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(stub, "x"), []byte("s"), 0o600))
		before, readErr := os.ReadFile(target)
		require.NoError(t, readErr)

		_, err := activate.Run(activate.Input{
			RenderedPath: rendered, TargetPath: target,
			XrayBin: fakeXray(t, dir, "ok"), Backup: true, BackupDir: backupDir,
			BackupKeep: 1,
		})
		require.Error(t, err, "never silently lose rollback depth without an error")
		after, readErr := os.ReadFile(target)
		require.NoError(t, readErr)
		assert.Equal(t, string(before), string(after),
			"a retention failure must abort before the live config is replaced")
	})
}

// failingXrayWithPipeHolder writes a fake xray that exits 3 (a REAL config
// failure) immediately, while a grandchild `sleep 5` inherits and holds the
// stdio pipes open — the exact geometry where WaitDelay must release the
// parent without turning the real exit status into a fake "timed out".
func failingXrayWithPipeHolder(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "failing-xray.sh")
	body := "#!/bin/sh\nsleep 5 &\necho \"invalid config: duplicate inbound tag\" >&2\nexit 3\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o755))
	return path
}

// TestGateStartFailureIsNotATimeout pins the M-2 residual discrimination
// (W7): a child that never STARTED (bad xray_bin path — exec error, no
// process) coinciding with an elapsed deadline must read as "start failed",
// never as "timed out". The old predicate classified any non-own-exit error
// under an expired deadline as a timeout, which told the owner the config
// was hanging when in fact the binary path was broken.
func TestGateStartFailureIsNotATimeout(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	writeConfig(t, target)
	require.NoError(t, os.WriteFile(rendered, []byte(`{"v":1}`), 0o644))

	// TestTimeout=1ns pre-expires the deadline before Start runs, so the
	// start error lands under an elapsed clock — exactly the geometry the
	// old code mislabeled as a timeout. Deterministic: the binary never
	// exists, no process is ever spawned, nothing sleeps.
	_, err := activate.Run(activate.Input{
		RenderedPath: rendered, TargetPath: target,
		XrayBin:     filepath.Join(dir, "no-such-xray"),
		TestTimeout: 1 * time.Nanosecond,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start failed",
		"a child that never started must be reported as a start failure")
	assert.NotContains(t, err.Error(), "timed out",
		"a start failure must never be mislabeled as a timeout")
	assert.Contains(t, err.Error(), "no-such-xray", "the failure must name the binary path")
}

// TestGateOwnExitAtDeadlineReportsTheExit pins M-2: a non-zero exit that
// lands at (or past) the deadline instant is the child's OWN failure — a real
// config problem the operator must see — and must be reported as such, never
// as "timed out". The old predicate (any error + elapsed deadline = timeout)
// mislabeled exactly this shape. Deterministic: the script exits in
// milliseconds, the grandchild holds the pipes past the deadline, so Wait
// returns the real ExitError only after WaitDelay — with ctx already expired.
func TestGateOwnExitAtDeadlineReportsTheExit(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	writeConfig(t, target)
	require.NoError(t, os.WriteFile(rendered, []byte(`{"v":1}`), 0o644))

	_, err := activate.Run(activate.Input{
		RenderedPath: rendered, TargetPath: target,
		XrayBin:     failingXrayWithPipeHolder(t, dir),
		TestTimeout: 500 * time.Millisecond,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exit status 3",
		"a real non-zero exit must surface its status even when the deadline fired")
	assert.Contains(t, err.Error(), "invalid config",
		"the child's own stderr must reach the operator")
	assert.NotContains(t, err.Error(), "timed out",
		"an own exit must never be mislabeled as a timeout")
}
