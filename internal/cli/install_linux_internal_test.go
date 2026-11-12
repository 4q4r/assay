package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/core"
	"assay/internal/install"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The linux scheduler branch (plan §3.3, Stage S3): detect → refuse-on-held
// → render+activate via the matched scheduler → bounded verify. The tests
// drive the CLI seams (linuxSchedulerProbe, linuxHost) with fakes — the cobra
// layer never touches /proc, sv, rc-*, s6-*, or crontab.

// withLinuxScheduler swaps the CLI seams for the linux branch and restores
// them after the test.
func withLinuxScheduler(t *testing.T, probe func(string) (install.Scheduler, string, string)) {
	t.Helper()
	oldHost, oldProbe := linuxHost, linuxSchedulerProbe
	linuxHost = func() bool { return true }
	linuxSchedulerProbe = probe
	t.Cleanup(func() {
		linuxHost = oldHost
		linuxSchedulerProbe = oldProbe
	})
}

// stubCoreBootstrap replaces the D4 core-bootstrap seam (no network) for the
// tests that pass a non-nil cfg.
func stubCoreBootstrap(t *testing.T, calls *int) {
	t.Helper()
	ensureCoreBinary = func(_ context.Context, _ config.CoreConfig, _ string, _ io.Writer) error {
		*calls++
		return nil
	}
	t.Cleanup(func() { ensureCoreBinary = core.EnsureCoreBinary })
}

// linuxOpts builds install options for the linux branch tests.
func linuxOpts(binDir, unitDir string) installOptions {
	return installOptions{
		binDir:  binDir,
		unitDir: unitDir,
		color:   false,
	}
}

func TestInstallLinuxSystemdDetectedFallsThroughToGenericPath(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	ex := &fakeCtl{}
	coreCalls := 0
	stubCoreBootstrap(t, &coreCalls)
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) {
		return &fakeScheduler{name: "systemd-user"}, "", ""
	})
	// The fall-through drives the generic path for real (fake executor): the
	// EXACT systemd sequence — daemon-reload then enable --now — unchanged.
	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath, func() installOptions {
		o := linuxOpts(binDir, unitDir)
		o.exec = ex
		o.embedsConfig = true
		return o
	}()))
	require.Len(t, ex.calls, 2)
	assert.Equal(t, []string{"--user", "daemon-reload"}, ex.calls[0])
	assert.Equal(t, []string{"--user", "enable", "--now", install.WatchService}, ex.calls[1])
	out := buf.String()
	assert.Contains(t, out, "daemon active:    assay watch (Restart=always)")
	assert.NotContains(t, out, "no supervisor detected")
	assert.NotContains(t, out, "refusing double registration")
	assert.NotContains(t, out, "scheduler:        ", "no linux-scheduler summary for the systemd fall-through")
}

func TestInstallLinuxRunitDetectedRunsRunitScheduler(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	coreCalls := 0
	stubCoreBootstrap(t, &coreCalls)
	runit := &fakeScheduler{
		name: "runit", available: true,
		installRes: install.Result{BinaryPath: filepath.Join(binDir, "assay"), ServiceActive: true},
	}
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) {
		return runit, "", ""
	})
	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath, func() installOptions {
		o := linuxOpts(binDir, unitDir)
		o.materializePath = filepath.Join(home, "data", "config.toml") // the configless flow
		return o
	}()))
	// The scheduler owned the whole flow: copyBinary + materialize + activate
	// land inside Install (fake records the spec); the summary names runit.
	spec := runit.installSpec
	assert.Equal(t, binDir, spec.BinDir)
	assert.Equal(t, filepath.Join(home, "data"), spec.DataDir)
	assert.Equal(t, filepath.Join(home, "data", "config.toml"), spec.DefaultConfigPath)
	assert.Empty(t, spec.ConfigPath, "configless installs embed no -c")
	assert.Contains(t, buf.String(), "scheduler:        runit")
	assert.Equal(t, 1, coreCalls, "the D4 core bootstrap rides the linux branch too")
}

func TestInstallLinuxRefusesWhenAnotherSchedulerHolds(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	unitFile := filepath.Join(home, ".config", "systemd", "user", install.WatchService)
	runit := &fakeScheduler{name: "runit", available: true}
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) {
		return runit, "systemd-user", unitFile
	})
	buf := &bytes.Buffer{}
	err := runInstall(buf, mustLoad(t, cfgPath), cfgPath, linuxOpts(filepath.Join(home, "bin"), filepath.Join(home, "units")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "systemd-user")
	assert.Contains(t, err.Error(), "runit")
	assert.Contains(t, err.Error(), unitFile)
	assert.Contains(t, err.Error(), "uninstall")
}

func TestInstallLinuxRefusesReverseWhenRunitHoldsAndSystemdDetected(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	ex := &fakeCtl{}
	watchDir := filepath.Join(home, "service", "assay-watch")
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) {
		return &fakeScheduler{name: "systemd-user"}, "runit", watchDir
	})
	buf := &bytes.Buffer{}
	err := runInstall(buf, mustLoad(t, cfgPath), cfgPath, func() installOptions {
		o := linuxOpts(filepath.Join(home, ".local", "bin"), filepath.Join(home, ".config", "systemd", "user"))
		o.exec = ex
		o.embedsConfig = true
		return o
	}())
	// Even the systemd path is refused — the holder scan runs BEFORE the
	// fall-through (two schedulers launching waves = the W5 stampede class).
	require.Error(t, err)
	assert.Contains(t, err.Error(), "runit")
	assert.Contains(t, err.Error(), "systemd-user")
	assert.Empty(t, ex.calls, "nothing was enabled — the refusal precedes any systemd activity")
}

func TestInstallLinuxSameSchedulerReinstallIsIdempotent(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	coreCalls := 0
	stubCoreBootstrap(t, &coreCalls)
	runit := &fakeScheduler{name: "runit", available: true}
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) {
		return runit, "runit", filepath.Join(home, "service", "assay-watch")
	})
	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath,
		linuxOpts(filepath.Join(home, "bin"), filepath.Join(home, "units"))))
	assert.NotEmpty(t, runit.installSpec.BinDir, "the re-install proceeded — same scheduler is idempotent, not refused")
}

func TestInstallLinuxForegroundPrintsExactInstructions(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	fg := &fakeScheduler{
		name: "foreground", available: true,
		installRes: install.Result{
			BinaryPath:  filepath.Join(home, "bin", "assay"),
			ServiceNote: "no scheduler detected",
		},
	}
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) { return fg, "", "" })
	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath,
		linuxOpts(filepath.Join(home, "bin"), filepath.Join(home, "units"))))
	out := buf.String()
	assert.Contains(t, out, "foreground")
	assert.Contains(t, out, "assay watch")
	assert.Contains(t, out, "no supervision")
}

func TestInstallLinuxSchedulerFailureIsLoud(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	s6 := &fakeScheduler{
		name: "s6", available: true,
		installErr: errors.New("s6 activation not verified"),
	}
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) { return s6, "", "" })
	buf := &bytes.Buffer{}
	err := runInstall(buf, mustLoad(t, cfgPath), cfgPath,
		linuxOpts(filepath.Join(home, "bin"), filepath.Join(home, "units")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s6")
}

func TestInstallNoSchedulerFlagSkipsSchedulers(t *testing.T) {
	home := t.TempDir()
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	ex := &fakeCtl{}
	coreCalls := 0
	stubCoreBootstrap(t, &coreCalls)
	probeRan := false
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) {
		probeRan = true
		return &fakeScheduler{name: "runit", available: true}, "", ""
	})
	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath, func() installOptions {
		o := linuxOpts(filepath.Join(home, ".local", "bin"), unitDir)
		o.exec = ex
		o.noScheduler = true
		return o
	}()))
	assert.False(t, probeRan, "--no-scheduler skips detection entirely")
	assert.Contains(t, buf.String(), "--no-scheduler", "the binary-only summary names the flag")
}

func TestInstallNoSystemdAliasWarnsAndBehavesIdentically(t *testing.T) {
	home := t.TempDir()
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	ex := &fakeCtl{}
	coreCalls := 0
	stubCoreBootstrap(t, &coreCalls)
	probeRan := false
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) {
		probeRan = true
		return &fakeScheduler{name: "runit", available: true}, "", ""
	})
	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath, func() installOptions {
		o := linuxOpts(filepath.Join(home, ".local", "bin"), unitDir)
		o.exec = ex
		o.noSystemd = true // the alias — treated as noScheduler with a loud rename warning
		return o
	}()))
	assert.False(t, probeRan, "--no-systemd (the alias) skips schedulers identically")
	assert.Contains(t, buf.String(), "--no-scheduler", "the loud alias names its replacement")
	assert.Contains(t, buf.String(), "renamed", "the warning says the flag was renamed")
}

func TestInstallNoSchedulerOnLinuxStillCopiesBinaryAndMaterializes(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	withLinuxScheduler(t, func(string) (install.Scheduler, string, string) {
		return &fakeScheduler{name: "runit", available: true}, "", ""
	})
	buf := &bytes.Buffer{}
	require.NoError(t, runInstall(buf, mustLoad(t, cfgPath), cfgPath, func() installOptions {
		o := linuxOpts(binDir, filepath.Join(home, "units"))
		o.noScheduler = true
		o.materializePath = filepath.Join(home, "data", "config.toml")
		return o
	}()))
	_, err := os.Stat(filepath.Join(binDir, "assay"))
	require.NoError(t, err, "the binary copy still happens")
	assert.FileExists(t, filepath.Join(home, "data", "config.toml"),
		"the default config is still materialized (configless install)")
}
