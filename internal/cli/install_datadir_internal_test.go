//go:build linux

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/install"
	"assay/internal/platform"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The DataDir defect (docker acceptance 2026-11-13): every install that
// materializes nothing — explicit -c installs AND re-installs where the
// config already exists — rendered SchedulerInstallSpec.DataDir EMPTY, so
// the runit/s6/openrc scripts carried RELATIVE log/pidfile paths and the
// daemon never booted while `sv status`/`rc-service status` still exited 0.
// These tests drive the REAL runit renderer through the CLI seams (the
// recorded-executor pattern from internal/install's runit suite): the run
// script on disk is the proof, not a fake's spec recording.

// recordedSv is the cli-level SvExecutor double: records invocations,
// replays success (the activation verify passes on the first probe).
type recordedSv struct {
	calls [][]string
}

func (f *recordedSv) Sv(args ...string) (string, error) {
	f.calls = append(f.calls, args)
	return "", nil
}

// runScriptOf reads the rendered run script a runit install wrote.
func runScriptOf(t *testing.T, serviceDir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(serviceDir, install.WatchDirName, "run"))
	require.NoError(t, err, "the install must render the run script")
	return string(raw)
}

// TestInstallRunitExplicitConfigRunScriptCarriesAbsoluteLogPaths pins the
// -c face of the defect: the resolved config's data dir anchors the log
// redirects — never the empty prefix that renders `2>>"logs/..."` relative
// to the service dir (where no logs/ exists, so the daemon cannot boot).
func TestInstallRunitExplicitConfigRunScriptCarriesAbsoluteLogPaths(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour) // data_dir = <home>/data
	sv := &recordedSv{}
	runit := install.NewRunitScheduler(sv, filepath.Join(home, "service"))
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) { return runit, "", "" })
	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath, func() installOptions {
		o := linuxOpts(binDir, filepath.Join(home, "units"))
		o.embedsConfig = true // the explicit -c shape: nothing materializes
		return o
	}()))
	script := runScriptOf(t, filepath.Join(home, "service"))
	want := filepath.Join(home, "data")
	assert.Contains(t, script, `2>>"`+filepath.Join(want, "logs", "watch.err.log")+`"`,
		"stderr redirect must anchor at the resolved data dir")
	assert.Contains(t, script, `1>>"`+filepath.Join(want, "logs", "watch.out.log")+`"`,
		"stdout redirect must anchor at the resolved data dir")
	assert.NotContains(t, script, `>>"logs/`, "a relative log anchor is the empty-DataDir defect itself")
	assert.Contains(t, script, `watch -c "`+cfgPath+`"`, "the -c install embeds its config")
}

// TestInstallRunitReinstallRunScriptCarriesAbsoluteLogPaths pins the
// re-install face: a second install over an existing config (no -c, nothing
// left to materialize) must resolve the data dir the same way — the
// acceptance run took a LIVE daemon down exactly here.
func TestInstallRunitReinstallRunScriptCarriesAbsoluteLogPaths(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	sv := &recordedSv{}
	runit := install.NewRunitScheduler(sv, filepath.Join(home, "service"))
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) { return runit, "", "" })
	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath,
		linuxOpts(binDir, filepath.Join(home, "units"))))
	script := runScriptOf(t, filepath.Join(home, "service"))
	want := filepath.Join(home, "data")
	assert.Contains(t, script, `2>>"`+filepath.Join(want, "logs", "watch.err.log")+`"`)
	assert.Contains(t, script, `1>>"`+filepath.Join(want, "logs", "watch.out.log")+`"`)
	assert.NotContains(t, script, `>>"logs/`, "a relative log anchor is the empty-DataDir defect itself")
}

// ---------------------------------------------------------------------------
// resolveDataDir semantics — direct pins on the helper the behavioral tests
// above exercise end-to-end through the real runit renderer.
// ---------------------------------------------------------------------------

// TestResolveDataDirUsesResolvedConfigDataDir: the resolved config's data
// dir wins (absolute verbatim, ~ expanded — the convention every consumer
// applies via config.ExpandHome).
func TestResolveDataDirUsesResolvedConfigDataDir(t *testing.T) {
	home := t.TempDir()
	dir, err := resolveDataDir(&config.Config{DataDir: filepath.Join(home, "data")})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, "data"), dir)

	dir, err = resolveDataDir(&config.Config{DataDir: "~/data"})
	require.NoError(t, err)
	realHome, rerr := os.UserHomeDir()
	require.NoError(t, rerr)
	assert.Equal(t, filepath.Join(realHome, "data"), dir)
}

// TestResolveDataDirRefusesRelativeDataDir: a relative data_dir would render
// the same relative-anchor defect — refused loud before anything is written.
func TestResolveDataDirRefusesRelativeDataDir(t *testing.T) {
	_, err := resolveDataDir(&config.Config{DataDir: "relative/data"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "relative")
	assert.Contains(t, err.Error(), "absolute")
}

// TestResolveDataDirFallsToPlatformDefault: no resolved config (nil) falls
// to the platform DefaultDataDir seam under $HOME (XDG pinned empty — the
// env var is part of the linux resolution contract).
func TestResolveDataDirFallsToPlatformDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	dir, err := resolveDataDir(nil)
	require.NoError(t, err)
	want, ok := platform.DefaultDataDir(runtime.GOOS, home)
	require.True(t, ok)
	assert.Equal(t, want, dir)
}
