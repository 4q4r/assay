package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/install"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCtl records systemctl invocations — the CLI-level seam twin of the
// install package's fake executor. Tests never execute systemd.
type fakeCtl struct {
	calls [][]string
}

func (f *fakeCtl) Systemctl(args ...string) error {
	f.calls = append(f.calls, args)
	return nil
}

func writeWaveConfig(t *testing.T, dir string, refresh, speedtest time.Duration) string {
	t.Helper()
	// Hermetic session probe (install/uninstall check for a user session).
	run := filepath.Join(dir, "run")
	require.NoError(t, os.MkdirAll(filepath.Join(run, "systemd"), 0o755))
	t.Setenv("XDG_RUNTIME_DIR", run)
	cfgPath := filepath.Join(dir, "config.toml")
	refreshSpan := (config.Duration{Duration: refresh}).String()
	speedSpan := (config.Duration{Duration: speedtest}).String()
	body := fmt.Sprintf(`
data_dir = %q
[sources.dummy]
repo = "owner/repo"
discovery = "github-contents"
include = ["vless.txt"]

[maintain]
refresh_interval = %q
speedtest_interval = %q
`, filepath.Join(dir, "data"), refreshSpan, speedSpan)
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	return cfgPath
}

// TestRunInstallEndToEnd renders the units from config intervals into a fake
// HOME and verifies the exact systemctl sequence — the mocked integration
// gate for the whole install surface (never executes systemctl).
func TestRunInstallEndToEnd(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	ex := &fakeCtl{}

	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath, installOptions{
		binDir:  binDir,
		unitDir: unitDir,
		exec:    ex,
	}))
	out := buf.String()
	assert.Contains(t, out, "timers active:    refresh every 8h, speedtest every 240h (OnUnitActiveSec)")

	// Exact allowed command set, in order.
	require.Len(t, ex.calls, 2)
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[0])
	assert.Equal(t, []string{"--user", "enable", "--now", install.RefreshTimer, install.SpeedtestTimer}, ex.calls[1])

	// Unit content rendered from the CONFIG intervals.
	timer, err := os.ReadFile(filepath.Join(unitDir, install.RefreshTimer))
	require.NoError(t, err)
	assert.Regexp(t, `(?m)^OnUnitActiveSec=8h$`, string(timer))
	speedTimer, err := os.ReadFile(filepath.Join(unitDir, install.SpeedtestTimer))
	require.NoError(t, err)
	assert.Regexp(t, `(?m)^OnUnitActiveSec=240h$`, string(speedTimer))

	service, err := os.ReadFile(filepath.Join(unitDir, install.RefreshService))
	require.NoError(t, err)
	assert.Contains(t, string(service), "maintain -c "+cfgPath)
}

// I-1 pins (W5 fix round): systemd ExecStart= splits argv on whitespace and
// does not de-quote, so a whitespace-bearing binary or config path renders a
// unit that passes install but dies at timer-fire time ("Command ... is not
// executable"). runInstall must refuse such paths LOUD, before anything is
// copied or written.

func TestRunInstallRejectsWhitespaceInBinDir(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)
	binDir := filepath.Join(home, "my bin") // SPACE in the path
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	ex := &fakeCtl{}

	buf := &bytes.Buffer{}
	err := runInstall(buf, mustLoad(t, cfgPath), cfgPath, installOptions{
		binDir: binDir, unitDir: unitDir, exec: ex,
	})
	require.Error(t, err, "a whitespace bin dir would render a broken ExecStart")
	assert.Contains(t, err.Error(), "--bin-dir")
	assert.Contains(t, err.Error(), "whitespace")
	assert.Contains(t, err.Error(), "ExecStart cannot carry unquoted whitespace")
	_, statErr := os.Stat(binDir)
	assert.True(t, os.IsNotExist(statErr), "nothing may be copied before validation refuses")
	assert.Empty(t, ex.calls, "no systemctl interaction on a rejected install")
}

func TestRunInstallRejectsWhitespaceInConfigPath(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, "bin")
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)
	tabbed := filepath.Join(home, "with\ttab.toml") // TAB in the path
	require.NoError(t, os.Rename(cfgPath, tabbed))
	ex := &fakeCtl{}

	buf := &bytes.Buffer{}
	err := runInstall(buf, mustLoad(t, tabbed), tabbed, installOptions{
		binDir: binDir, unitDir: unitDir, exec: ex,
	})
	require.Error(t, err, "a whitespace config path would render a broken ExecStart")
	assert.Contains(t, err.Error(), "--config")
	assert.Contains(t, err.Error(), "whitespace")
	assert.Contains(t, err.Error(), "ExecStart cannot carry unquoted whitespace")
	assert.Empty(t, ex.calls, "no systemctl interaction on a rejected install")
}

// TestRunInstallAcceptsWhitespaceUnitDir pins the W7 item 8 verdict: a
// whitespace-bearing --unit-dir is HARMLESS and must NOT be refused.
// Unlike --bin-dir/--config (I-1: their paths land INSIDE ExecStart=, which
// systemd argv-splits on whitespace), the unit dir never enters the unit
// file — it is only where the unit FILES are written, and systemd's own
// discovery/parsing accepts whitespace paths there: `systemd-analyze
// verify` on rendered units loads all four from
// "/tmp/.../unit dir with space/" with EXIT=0, byte-identical to a plain
// dir (probed 2026-10-28, probe has teeth — it failed the unrendered
// templates and a missing ExecStart binary earlier in the same session).
// enable(1) symlink creation and uninstall(8) removal are plain POSIX
// filesystem operations on the dir, equally whitespace-tolerant.
func TestRunInstallAcceptsWhitespaceUnitDir(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)
	unitDir := filepath.Join(home, "my units dir") // SPACE and no I-1 refusal
	ex := &fakeCtl{}

	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath, installOptions{
		binDir:  filepath.Join(home, "bin"),
		unitDir: unitDir,
		exec:    ex,
	}), "a whitespace unit dir is harmless — install must accept it")

	// The four units landed in the whitespace dir, rendered as usual.
	timer, err := os.ReadFile(filepath.Join(unitDir, install.RefreshTimer))
	require.NoError(t, err)
	assert.Regexp(t, `(?m)^OnUnitActiveSec=6h$`, string(timer))
	for _, name := range install.UnitNames() {
		_, err := os.Stat(filepath.Join(unitDir, name))
		require.NoError(t, err, "unit %s must be written into the whitespace dir", name)
	}
	// The exact allowlisted systemctl sequence is unchanged.
	require.Len(t, ex.calls, 2)
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[0])
	assert.Equal(t, []string{"--user", "enable", "--now", install.RefreshTimer, install.SpeedtestTimer}, ex.calls[1])
}

func TestRunInstallNoSystemdSkipsUnits(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)
	ex := &fakeCtl{}
	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath, installOptions{
		binDir:    filepath.Join(home, "bin"),
		noSystemd: true,
		exec:      ex,
	}))
	assert.Empty(t, ex.calls)
	assert.Contains(t, buf.String(), "--no-systemd")
}

func TestRunUninstallDisablesAndRemoves(t *testing.T) {
	home := t.TempDir()
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)
	ex := &fakeCtl{}
	require.NoError(t, runInstall(&bytes.Buffer{}, mustLoad(t, cfgPath), cfgPath,
		installOptions{binDir: filepath.Join(home, "bin"), unitDir: unitDir, exec: ex}))

	buf := &bytes.Buffer{}
	require.NoError(t, runUninstall(buf, mustLoad(t, cfgPath), cfgPath,
		uninstallOptions{unitDir: unitDir, exec: ex}))
	require.Len(t, ex.calls, 4) // install: reload+enable, uninstall: disable + daemon-reload (I-2)
	assert.Equal(t, []string{"--user", "disable", "--now", install.RefreshTimer, install.SpeedtestTimer}, ex.calls[2])
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[3], "I-2: post-removal reload flushes ghost units")
	assert.Contains(t, buf.String(), "user data kept")
	for _, name := range install.UnitNames() {
		_, err := os.Stat(filepath.Join(unitDir, name))
		assert.True(t, os.IsNotExist(err))
	}
}

func TestRunUninstallPurgeRequiresConfig(t *testing.T) {
	// The runner itself must refuse (not just the cobra layer): a purge
	// without the config cannot resolve the data dir — and must never fall
	// through to a partial uninstall.
	err := runUninstall(&bytes.Buffer{}, nil, filepath.Join(t.TempDir(), "nope.toml"),
		uninstallOptions{unitDir: t.TempDir(), purge: true, exec: &fakeCtl{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--purge needs the config")
}

func TestRunUninstallPurgeRemovesConfigAndDataDir(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)
	dataDir := filepath.Join(home, "data")
	require.NoError(t, os.MkdirAll(dataDir, 0o750))
	ex := &fakeCtl{}

	buf := &bytes.Buffer{}
	require.NoError(t, runUninstall(buf, mustLoad(t, cfgPath), cfgPath,
		uninstallOptions{unitDir: t.TempDir(), purge: true, exec: ex}))
	assert.Contains(t, buf.String(), "purged:")
	_, err := os.Stat(cfgPath)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(dataDir)
	assert.True(t, os.IsNotExist(err))
}

// TestStatusShowsInstallState pins the status extension: binary, units,
// timers, configured-vs-installed periods, and the MISMATCH hint when the
// config drifted after the last install.
func TestStatusShowsInstallState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "run", "systemd"), 0o755))

	binDir := filepath.Join(home, ".local", "bin")
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)
	ex := &fakeCtl{}
	require.NoError(t, runInstall(&bytes.Buffer{}, mustLoad(t, cfgPath), cfgPath,
		installOptions{binDir: binDir, unitDir: unitDir, exec: ex}))

	// The enable step is faked, so create the wants-symlinks it would create.
	wants := filepath.Join(unitDir, "timers.target.wants")
	require.NoError(t, os.MkdirAll(wants, 0o755))
	for _, name := range []string{install.RefreshTimer, install.SpeedtestTimer} {
		require.NoError(t, os.Symlink(filepath.Join(unitDir, name), filepath.Join(wants, name)))
	}

	status := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(status)
	require.NoError(t, runStatus(cmd, mustLoad(t, cfgPath), cfgPath))
	out := status.String()
	assert.Contains(t, out, "install:")
	assert.Contains(t, out, "binary:    "+filepath.Join(binDir, "publicvpn"))
	assert.Contains(t, out, "units:     4/4 present")
	assert.Contains(t, out, "timers:    2/2 enabled")
	assert.Contains(t, out, "refresh:   configured 6h0m0s, installed 6h0m0s")
	assert.Contains(t, out, "speedtest: configured 168h0m0s, installed 168h0m0s")
	assert.NotContains(t, out, "MISMATCH")

	// Drift the configured refresh period: status must flag the mismatch.
	drifted := writeWaveConfig(t, home, 9*time.Hour, 168*time.Hour)
	status.Reset()
	require.NoError(t, runStatus(cmd, mustLoad(t, drifted), drifted))
	assert.Contains(t, status.String(), "MISMATCH", "config drift after install must be flagged")
	assert.Contains(t, status.String(), "re-run `publicvpn install")
}

// TestStatusHelpDocumentsDefaultDirDetection pins the M-1 caveat in the
// user-facing help: status detects installs at the DEFAULT dirs only, and
// custom --bin-dir/--unit-dir installs are not tracked (no state file).
func TestStatusHelpDocumentsDefaultDirDetection(t *testing.T) {
	cfgPath := writeWaveConfig(t, t.TempDir(), 6*time.Hour, 168*time.Hour)
	cmd := newStatusCommand(&cfgPath)
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	require.NoError(t, cmd.Help())
	help := out.String()
	assert.Contains(t, help, "DEFAULT directories only")
	assert.Contains(t, help, "~/.local/bin")
	assert.Contains(t, help, "~/.config/systemd/user")
	assert.Contains(t, help, "--bin-dir")
	assert.Contains(t, help, "--unit-dir")
	assert.Contains(t, help, "state file")
}

func mustLoad(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.Load(path)
	require.NoError(t, err)
	return cfg
}
