package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/install"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Round-7 items 10, 11, and the CLI surface of item 9.

// TestInstallRelativeExplicitResolvesAgainstInjectedCWD pins the unified
// resolution contract: a relative explicit -c under `install` resolves
// against the injected cwd — the SAME single scheme config.Resolve applies
// to every other command (the pre-fix code passed cwd="" and silently fell
// back to the process-cwd scheme inside config.Resolve; the observable
// result is identical in production — the unification removes the dual
// mechanism, the pin characterizes the contract).
func TestInstallRelativeExplicitResolvesAgainstInjectedCWD(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	t.Chdir(dir)
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("data_dir = \""+t.TempDir()+"\"\n"), 0o600))

	res, err := resolveInstallPath("./config.toml")
	require.NoError(t, err)
	assert.Equal(t, config.SourceExplicit, res.Source, "the explicit -c wins")
	assert.Equal(t, cfgPath, res.Path,
		"a relative explicit -c under install resolves against the injected cwd")
}

// TestStatusHonorsBinAndUnitDirs pins round-7 item 11: printInstallStatus
// no longer hardcodes ~/.local/bin and ~/.config/systemd/user — it reads
// the --bin-dir/--unit-dir values (defaults unchanged), so an install made
// with custom dirs IS tracked.
func TestStatusHonorsBinAndUnitDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	binDir := filepath.Join(t.TempDir(), "custom-bin")
	unitDir := filepath.Join(t.TempDir(), "custom-units")
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)

	// Fake a custom-dir install: the binary and the unit file in place.
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "publicvpn"), []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.MkdirAll(unitDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(unitDir, install.WatchService), []byte("[Unit]\n"), 0o644))

	cmd := newStatusCommand(&cfgPath)
	require.NoError(t, cmd.Flags().Set("bin-dir", binDir))
	require.NoError(t, cmd.Flags().Set("unit-dir", unitDir))
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))

	text := out.String()
	assert.Contains(t, text, "binary:    "+filepath.Join(binDir, "publicvpn"),
		"status must look in the --bin-dir it was given:\n%s", text)
	assert.Contains(t, text, install.WatchService+" present in "+unitDir,
		"status must look in the --unit-dir it was given:\n%s", text)
	assert.NotContains(t, text, "not installed",
		"the custom-dir install must be recognized, not reported missing:\n%s", text)
}

// TestStatusDefaultDirsUnchanged pins the defaults: without flags, status
// inspects the same default dirs install writes to.
func TestStatusDefaultDirsUnchanged(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgPath := writeWaveConfig(t, home, 6*time.Hour, 168*time.Hour)

	cmd := newStatusCommand(&cfgPath)
	defBin := filepath.Join(home, ".local", "bin")
	defUnit := filepath.Join(home, ".config", "systemd", "user")
	require.NoError(t, os.MkdirAll(defBin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(defBin, "publicvpn"), []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.MkdirAll(defUnit, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(defUnit, install.WatchService), []byte("[Unit]\n"), 0o644))

	out := &bytes.Buffer{}
	cmd.SetOut(out)
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
	assert.Contains(t, out.String(), "binary:    "+filepath.Join(defBin, "publicvpn"),
		"defaults must stay the install defaults")
}

// TestReportConfigSourcePrintsWarnings pins the CLI surface of the XDG
// validation (round-7 item 9): resolution warnings print loud next to the
// config-source line on every command.
func TestReportConfigSourcePrintsWarnings(t *testing.T) {
	res := &config.Resolved{
		Config: &config.Config{}, Source: config.SourceConfigless,
		Warnings: []string{"XDG_DATA_HOME=\"rel\" is relative — treated as unset"},
	}
	out := &bytes.Buffer{}
	reportConfigSource(out, res)
	assert.Contains(t, out.String(), "config: configless (built-in defaults)\n")
	assert.Contains(t, out.String(), "warning: XDG_DATA_HOME=",
		"resolution warnings must print loud next to the config line")
}
