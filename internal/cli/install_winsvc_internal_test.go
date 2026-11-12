package cli

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"assay/internal/config"
	"assay/internal/core"
	"assay/internal/install"
	"assay/internal/platform"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The windows install/uninstall/status branch pins (plan §2.2.4/§2.2.5/
// §2.2.7-§2.2.10): the CLI routes to the windows-service scheduler through
// the consumer-side `scheduler` seam — these tests drive the cobra-level
// flow with a recorded double, so the wiring is pinned on linux while the
// real SCM calls are pinned by the windows-tagged suite (CI leg).

// fakeWinSvcCliScheduler records the scheduler seam calls (the CLI-flow
// double — distinct from the install package's SCM-call double).
type fakeWinSvcCliScheduler struct {
	installSpecs []install.SchedulerInstallSpec
	uninstallOps []install.SchedulerUninstallSpec
	installRes   install.Result
	installErr   error
	status       install.SchedulerStatus
	held         bool
	heldWhere    string
	uninstallRes install.UninstallResult
	uninstallErr error
}

func (f *fakeWinSvcCliScheduler) Name() string { return "windows-service" }

func (f *fakeWinSvcCliScheduler) Available() (bool, string) { return true, "" }

func (f *fakeWinSvcCliScheduler) Install(spec install.SchedulerInstallSpec) (install.Result, error) {
	f.installSpecs = append(f.installSpecs, spec)
	if f.installErr != nil {
		return install.Result{}, f.installErr
	}
	return f.installRes, nil
}

func (f *fakeWinSvcCliScheduler) Uninstall(spec install.SchedulerUninstallSpec) (install.UninstallResult, error) {
	f.uninstallOps = append(f.uninstallOps, spec)
	if f.uninstallErr != nil {
		return install.UninstallResult{}, f.uninstallErr
	}
	return f.uninstallRes, nil
}

func (f *fakeWinSvcCliScheduler) Status() (install.SchedulerStatus, error) {
	return f.status, nil
}

func (f *fakeWinSvcCliScheduler) HeldRegistration() (bool, string) {
	return f.held, f.heldWhere
}

// withWindowsHost routes the CLI branches to windows for the test's
// duration and installs the given scheduler double.
func withWindowsHost(t *testing.T, sched scheduler) {
	t.Helper()
	prevHost, prevFactory := windowsHost, winsvcSchedulerFactory
	windowsHost = func() bool { return true }
	winsvcSchedulerFactory = func() scheduler { return sched }
	t.Cleanup(func() {
		windowsHost, winsvcSchedulerFactory = prevHost, prevFactory
	})
}

// winSvcCliConfig builds the daemon config for the CLI-flow tests (serve
// fake core on a test-band port; data dir = the materialize target's dir).
func winSvcCliConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	local := filepath.Join(dir, "AppData", "Local")
	dataDir := filepath.Join(local, "assay")
	t.Setenv("LOCALAPPDATA", local)
	home := filepath.Join(dir, "home")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfg := &config.Config{
		DataDir: dataDir,
		Core: config.CoreConfig{
			XrayBin:   cliFakeBinary(t),
			SocksPort: nextCoreTestPort(),
			HTTPPort:  nextCoreTestPort() + 1,
			Loglevel:  "warning",
		},
	}
	return cfg, dataDir
}

// TestInstallWindowsBranchPins pins the CLI routing: the windows branch
// calls the scheduler with the always-explicit config (§2.2.5 — the
// configless install passes DefaultConfigPath and the scheduler embeds it),
// runs the D4 core bootstrap, and prints the windows summary naming the
// SCM entry, the recovery actions, and the unrotated-log path.
func TestInstallWindowsBranchPins(t *testing.T) {
	cfg, dataDir := winSvcCliConfig(t)
	sched := &fakeWinSvcCliScheduler{
		installRes: install.Result{
			BinaryPath:    filepath.Join(dataDir, "bin", "assay.exe"),
			ConfigWritten: filepath.Join(dataDir, "config.toml"),
			UnitPaths:     []string{install.WinSvcName + " (SCM database entry)"},
			ServiceActive: true,
			ServiceNote:   "already running",
		},
	}
	withWindowsHost(t, sched)
	// The core bootstrap is stubbed (no network in unit tests).
	ensureCoreBinary = func(_ context.Context, _ config.CoreConfig, _ string, _ io.Writer) error {
		return nil
	}
	t.Cleanup(func() { ensureCoreBinary = core.EnsureCoreBinary })

	out := &syncWriter{}
	err := runInstall(out, cfg, "", installOptions{
		binDir:          installBinDirDefault("windows"),
		materializePath: filepath.Join(dataDir, "config.toml"),
		color:           false,
	})
	require.NoError(t, err)

	require.Len(t, sched.installSpecs, 1)
	spec := sched.installSpecs[0]
	assert.Equal(t, filepath.Join(dataDir, "config.toml"), spec.DefaultConfigPath,
		"configless → the materialize target rides DefaultConfigPath")
	assert.Empty(t, spec.ConfigPath, "no explicit -c → ConfigPath empty; the scheduler embeds the default")
	assert.Equal(t, dataDir, spec.DataDir)
	assert.Equal(t, filepath.Join(dataDir, "bin"), spec.BinDir, "the §2.2.10 bin dir")

	// The summary is loud and windows-honest:
	for _, want := range []string{
		"SCM database entry",
		"assay.exe",
		filepath.Join(dataDir, "logs", "watch.log"),
	} {
		assert.Contains(t, out.String(), want, "summary must name %s", want)
	}
}

// TestInstallWindowsBranchExplicitConfigPins pins the explicit--c routing:
// the absolute -c rides ConfigPath (embedded verbatim), no materialization.
func TestInstallWindowsBranchExplicitConfigPins(t *testing.T) {
	cfg, _ := winSvcCliConfig(t)
	sched := &fakeWinSvcCliScheduler{
		installRes: install.Result{ServiceActive: true},
	}
	withWindowsHost(t, sched)
	ensureCoreBinary = func(_ context.Context, _ config.CoreConfig, _ string, _ io.Writer) error {
		return nil
	}
	t.Cleanup(func() { ensureCoreBinary = core.EnsureCoreBinary })

	explicit := filepath.Join(t.TempDir(), "custom", "config.toml")
	out := &syncWriter{}
	err := runInstall(out, cfg, explicit, installOptions{
		binDir:       installBinDirDefault("windows"),
		embedsConfig: true,
		color:        false,
	})
	require.NoError(t, err)
	require.Len(t, sched.installSpecs, 1)
	abs, aerr := filepath.Abs(explicit)
	require.NoError(t, aerr)
	assert.Equal(t, abs, sched.installSpecs[0].ConfigPath)
	assert.Empty(t, sched.installSpecs[0].DefaultConfigPath)
}

// TestUninstallWindowsBranchPins pins the uninstall routing: DataDir from
// the resolved config, the purge passthrough, and the honest summary.
func TestUninstallWindowsBranchPins(t *testing.T) {
	cfg, dataDir := winSvcCliConfig(t)
	sched := &fakeWinSvcCliScheduler{
		uninstallRes: install.UninstallResult{
			DisabledUnits: []string{install.WinSvcName},
			RemovedUnits:  []string{install.WinSvcName},
			CoreRemoved:   []string{filepath.Join(dataDir, "bin", "xray.exe")},
		},
	}
	withWindowsHost(t, sched)

	out := &syncWriter{}
	err := runUninstall(out, cfg, "", uninstallOptions{})
	require.NoError(t, err)
	require.Len(t, sched.uninstallOps, 1)
	assert.Equal(t, dataDir, sched.uninstallOps[0].DataDir)
	assert.Empty(t, sched.uninstallOps[0].PurgeConfigPath)
	assert.Contains(t, out.String(), install.WinSvcName)
	assert.Contains(t, out.String(), "user data kept")

	// Purge passthrough:
	sched2 := &fakeWinSvcCliScheduler{}
	withWindowsHost(t, sched2)
	out2 := &syncWriter{}
	err = runUninstall(out2, cfg, filepath.Join(dataDir, "config.toml"), uninstallOptions{purge: true})
	require.NoError(t, err)
	require.Len(t, sched2.uninstallOps, 1)
	assert.Equal(t, filepath.Join(dataDir, "config.toml"), sched2.uninstallOps[0].PurgeConfigPath)
	assert.Equal(t, dataDir, sched2.uninstallOps[0].PurgeDataDir)
}

// TestStatusWindowsBranchPins pins the status routing: the scheduler's
// state+pid renders with the mechanism notes (§2.2.8 + ADDENDUM §1
// honesty). The binary name renders through the platform table (the test
// host's GOOS decides the spelling; the windows CI leg sees assay.exe).
func TestStatusWindowsBranchPins(t *testing.T) {
	_, dataDir := winSvcCliConfig(t)
	sched := &fakeWinSvcCliScheduler{
		status: install.SchedulerStatus{
			Active: true,
			PID:    4242,
			Note:   "recovery: ServiceRestart after 5s; hang detection: self-watchdog → clean self-exit → SCM recovery-actions restart",
		},
	}
	withWindowsHost(t, sched)

	out := &syncWriter{}
	printWinSvcStatus(out, filepath.Join(dataDir, "bin"), false)
	text := out.String()
	assert.Contains(t, text, platform.AssayBinaryName(runtime.GOOS))
	assert.Contains(t, text, "4242")
	assert.Contains(t, text, "ServiceRestart")
	assert.Contains(t, text, "self-watchdog")
	assert.Contains(t, text, `%LOCALAPPDATA%\assay\logs\watch.log`)
	assert.Contains(t, text, platform.CoreBinaryName("windows"), "the core row names xray.exe")
}

// TestInstallBinDirDefaultTable pins the §2.2.10 bin-dir default: unix
// keeps ~/.local/bin; windows resolves %LOCALAPPDATA%\assay\bin (never a
// PATH modification — the summary points at the PowerShell line instead).
func TestInstallBinDirDefaultTable(t *testing.T) {
	// The VALUE is pinned per GOOS; the separator is the host's filepath
	// artifact (a windows host produces '\\' natively — this linux-run
	// comparison normalizes both sides so only the value is judged).
	norm := func(p string) string { return strings.ReplaceAll(p, `\`, "/") }
	t.Setenv("LOCALAPPDATA", `C:\Users\u\AppData\Local`)
	assert.Equal(t, norm(`C:\Users\u\AppData\Local\assay\bin`), norm(installBinDirDefault("windows")))
	// LOCALAPPDATA empty → the home-profile fallback (the §4.2 pattern).
	t.Setenv("LOCALAPPDATA", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	assert.Equal(t, norm(filepath.Join(home, "AppData", "Local", "assay", "bin")),
		norm(installBinDirDefault("windows")))
	assert.Equal(t, "~/.local/bin", installBinDirDefault("linux"))
	assert.Equal(t, "~/.local/bin", installBinDirDefault("darwin"))
}

// TestSchedulerFactoryRefusesOutsideWindows pins the loud dead-path
// contract of the non-windows factory: the scheduler it hands out refuses
// Available() with a windows-naming reason (never a nil scheduler — no
// silent nil-deref landmine).
func TestSchedulerFactoryRefusesOutsideWindows(t *testing.T) {
	sched := newRefusingWinSvcScheduler()
	require.NotNil(t, sched)
	avail, reason := sched.Available()
	assert.False(t, avail)
	assert.Contains(t, reason, "windows")
}

// TestInstallWindowsSchedulerFailureIsLoud pins the owner UX rule at the
// CLI layer: a scheduler failure propagates (with its exact-command text
// built inside the scheduler), never swallowed into a fake success.
func TestInstallWindowsSchedulerFailureIsLoud(t *testing.T) {
	cfg, _ := winSvcCliConfig(t)
	sched := &fakeWinSvcCliScheduler{installErr: errors.New("CreateService refused: access is denied")}
	withWindowsHost(t, sched)
	ensureCoreBinary = func(_ context.Context, _ config.CoreConfig, _ string, _ io.Writer) error {
		return nil
	}
	t.Cleanup(func() { ensureCoreBinary = core.EnsureCoreBinary })

	err := runInstall(&syncWriter{}, cfg, "", installOptions{
		binDir:          installBinDirDefault("windows"),
		materializePath: filepath.Join(t.TempDir(), "config.toml"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CreateService")
}
