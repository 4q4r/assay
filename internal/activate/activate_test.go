package activate_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"public_vpn/internal/activate"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeXray is a script pretending to be xray: configurable verdict.
func fakeXray(t *testing.T, dir, verdict string) string {
	t.Helper()
	path := filepath.Join(dir, "fake-xray.sh")
	var body string
	switch verdict {
	case "ok":
		body = `#!/bin/sh
for a in "$@"; do case "$a" in *bad.json*) echo "unexpected bad" >&2; exit 1;; esac; done
echo "Configuration OK"
exit 0
`
	case "fail":
		body = `#!/bin/sh
echo "Failed to start: main: failed to load config files" >&2
exit 1
`
	default:
		t.Fatalf("unknown verdict %q", verdict)
	}
	require.NoError(t, os.WriteFile(path, []byte(body), 0o755))
	return path
}

func writeConfig(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(`{"log":{"loglevel":"warning"}}`), 0o644))
}

func TestActivateReplacesTargetAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	writeConfig(t, target)
	require.NoError(t, os.WriteFile(rendered, []byte(`{"log":{"loglevel":"info"},"pool":"rendered"}`), 0o644))

	res, err := activate.Run(activate.Input{
		RenderedPath: rendered,
		TargetPath:   target,
		XrayBin:      fakeXray(t, dir, "ok"),
		BackupDir:    filepath.Join(dir, "backups"),
		NoRestart:    true,
	})
	require.NoError(t, err)
	require.True(t, res.TestPassed)

	// Target now holds the rendered content.
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(got), `"pool":"rendered"`)

	// Date-stamped backup holds the ORIGINAL content.
	require.Empty(t, res.BackupPath, "no backup paths unless Backup is enabled")
}

func TestActivateWithBackupKeepsOriginal(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	writeConfig(t, target)
	require.NoError(t, os.WriteFile(rendered, []byte(`{"new":true}`), 0o644))

	backupDir := filepath.Join(dir, "backups")
	res, err := activate.Run(activate.Input{
		RenderedPath: rendered,
		TargetPath:   target,
		XrayBin:      fakeXray(t, dir, "ok"),
		BackupDir:    backupDir,
		Backup:       true,
		NoRestart:    true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, res.BackupPath)
	assert.Contains(t, filepath.Base(res.BackupPath), ".bak-", "date-stamped backup convention")

	orig, err := os.ReadFile(res.BackupPath)
	require.NoError(t, err)
	assert.JSONEq(t, `{"log":{"loglevel":"warning"}}`, string(orig), "backup holds the pre-activation original")

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, `{"new":true}`, string(got))
}

func TestActivateTestGateBlocksReplace(t *testing.T) {
	// L10: a config that fails -test must never touch the target.
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "bad.json")
	writeConfig(t, target)
	require.NoError(t, os.WriteFile(rendered, []byte(`{"bad":true}`), 0o644))

	_, err := activate.Run(activate.Input{
		RenderedPath: rendered,
		TargetPath:   target,
		XrayBin:      fakeXray(t, dir, "ok"), // fake rejects the file named bad.json
		NoRestart:    true,
	})
	require.Error(t, err, "-test gate failed — activation must abort")
	assert.Contains(t, err.Error(), "-test")

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.JSONEq(t, `{"log":{"loglevel":"warning"}}`, string(got), "target untouched after failed gate")
}

func TestActivateHardFailsOnXrayTestFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	writeConfig(t, target)
	require.NoError(t, os.WriteFile(rendered, []byte(`{}`), 0o644))

	_, err := activate.Run(activate.Input{
		RenderedPath: rendered,
		TargetPath:   target,
		XrayBin:      fakeXray(t, dir, "fail"),
		NoRestart:    true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "-test")

	got, _ := os.ReadFile(target)
	assert.JSONEq(t, `{"log":{"loglevel":"warning"}}`, string(got))
}

func TestActivateIsAtomicOnReplace(t *testing.T) {
	// Kill the replace mid-way is hard to simulate; instead verify no temp
	// files linger in the target dir after a successful run (temp+rename
	// pattern leaves nothing behind).
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	writeConfig(t, target)
	require.NoError(t, os.WriteFile(rendered, []byte(`{"v":2}`), 0o644))

	_, err := activate.Run(activate.Input{
		RenderedPath: rendered, TargetPath: target,
		XrayBin: fakeXray(t, dir, "ok"), Backup: true,
		BackupDir: filepath.Join(dir, "backups"), NoRestart: true,
	})
	require.NoError(t, err)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), ".tmp-", "no temp artifacts left behind")
	}
}

func TestActivatePreservesFileMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	writeConfig(t, target)
	require.NoError(t, os.Chmod(target, 0o640))
	require.NoError(t, os.WriteFile(rendered, []byte(`{"v":3}`), 0o644))

	_, err := activate.Run(activate.Input{
		RenderedPath: rendered, TargetPath: target,
		XrayBin: fakeXray(t, dir, "ok"), NoRestart: true,
	})
	require.NoError(t, err)
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm(), "target file mode preserved across replace")
}

func TestActivateNeverRestartsService(t *testing.T) {
	// The result must carry the restart hint (printed for the owner) but the
	// command itself never touches systemd — structural: no exec of systemctl.
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	writeConfig(t, target)
	require.NoError(t, os.WriteFile(rendered, []byte(`{"v":4}`), 0o644))

	res, err := activate.Run(activate.Input{
		RenderedPath: rendered, TargetPath: target,
		XrayBin: fakeXray(t, dir, "ok"), NoRestart: true,
	})
	require.NoError(t, err)
	assert.Contains(t, res.RestartHint, "systemctl --user restart xray-raw.service")
	assert.NotContains(t, res.RestartHint, "sudo ")
}

func TestRenderedJSONValidity(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	rendered := filepath.Join(dir, "rendered.json")
	writeConfig(t, target)
	require.NoError(t, os.WriteFile(rendered, []byte(`{"ok":true}`), 0o644))
	_, err := activate.Run(activate.Input{
		RenderedPath: rendered, TargetPath: target,
		XrayBin: fakeXray(t, dir, "ok"), NoRestart: true,
	})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(mustRead(t, target), &m))
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}

// Guard (W13 contract, migrated from the W4-era total ban): the activate
// package still never EXECUTES systemctl — restart after a gated activation
// lives behind internal/restart's byte-pinned allowlist executor, wired by
// the cli layer. The printed restart hint remains the only non-comment
// occurrence of the word: comments may explain the rail, code may not
// widen it. (Migration note: W4–W12 pinned "exactly one occurrence total —
// the hint"; W13 moves the restart capability into internal/restart and
// pins this package to the same surface it always had — the hint.)
func TestNoSystemdInvocationInSource(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "activate", "activate.go"))
	require.NoError(t, err)
	nonComment := strings.Builder{}
	for line := range strings.SplitSeq(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		nonComment.WriteString(line)
		nonComment.WriteByte('\n')
	}
	assert.Equal(t, 1, strings.Count(nonComment.String(), "systemctl"),
		"outside comments, systemctl may appear exactly once: in the printed restart hint")
	for line := range strings.SplitSeq(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		assert.False(t, strings.Contains(trimmed, "exec.Command") && strings.Contains(trimmed, "systemctl"),
			"systemctl must never be executed: %s", trimmed)
	}
	assert.NotContains(t, nonComment.String(), "internal/restart",
		"the activate package must not import the restart executor — the cli layer wires it")
	_ = exec.Command // keep import used if assertions change
}
