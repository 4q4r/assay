package cli

import (
	"bytes"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"assay/internal/config"
	"assay/internal/install"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeScheduler records the lifecycle calls the CLI makes on the per-OS
// scheduler seam (the consumer-side interface — tests never touch real
// launchctl from the cli layer).
type fakeScheduler struct {
	name          string
	available     bool
	availReason   string
	installSpec   install.LaunchdInstallSpec
	installRes    install.Result
	installErr    error
	uninstallSpec install.LaunchdUninstallSpec
	uninstallRes  install.UninstallResult
	status        install.SchedulerStatus
	held          bool
	heldWhere     string
}

func (f *fakeScheduler) Name() string { return f.name }

func (f *fakeScheduler) Available() (bool, string) { return f.available, f.availReason }

func (f *fakeScheduler) Install(spec install.LaunchdInstallSpec) (install.Result, error) {
	f.installSpec = spec
	return f.installRes, f.installErr
}

func (f *fakeScheduler) Uninstall(spec install.LaunchdUninstallSpec) (install.UninstallResult, error) {
	f.uninstallSpec = spec
	return f.uninstallRes, nil
}

func (f *fakeScheduler) Status() (install.SchedulerStatus, error) { return f.status, nil }

func (f *fakeScheduler) HeldRegistration() (bool, string) { return f.held, f.heldWhere }

// withDarwinScheduler swaps the CLI seams for the darwin branch (host probe
// + scheduler factory) and restores them after the test.
func withDarwinScheduler(t *testing.T, f *fakeScheduler) {
	t.Helper()
	oldHost, oldFactory := darwinHost, launchdSchedulerFactory
	darwinHost = func() bool { return true }
	launchdSchedulerFactory = func() scheduler { return f }
	t.Cleanup(func() {
		darwinHost = oldHost
		launchdSchedulerFactory = oldFactory
	})
}

func launchdTestConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir}
	return cfg, dir
}

// TestInstallDarwinBranchUsesLaunchdScheduler pins the darwin branch of
// `assay install`: it drives the scheduler seam with the §1.2.6 spec —
// binary copy target, default-config materialization target, data dir, and
// the ~/Library/LaunchAgents agent dir — and prints a loud summary naming
// the plist and the mechanism.
func TestInstallDarwinBranchUsesLaunchdScheduler(t *testing.T) {
	f := &fakeScheduler{
		name:      "launchd",
		available: true,
		installRes: install.Result{
			BinaryPath:    "/Users/u/.local/bin/assay",
			UnitPaths:     []string{"/Users/u/Library/LaunchAgents/assay-watch.plist"},
			ServiceActive: true,
		},
	}
	withDarwinScheduler(t, f)
	cfg, dir := launchdTestConfig(t)
	out := &bytes.Buffer{}

	opts := installOptions{
		binDir:          filepath.Join(dir, "bin"),
		materializePath: filepath.Join(dir, "config.toml"),
	}
	err := runInstall(out, cfg, "", opts)
	require.NoError(t, err)

	spec := f.installSpec
	assert.Equal(t, filepath.Join(dir, "bin"), spec.BinDir)
	assert.Equal(t, filepath.Join(dir, "config.toml"), spec.DefaultConfigPath,
		"default-location install: the materialization target rides the spec")
	assert.Equal(t, dir, spec.DataDir)
	assert.NotEmpty(t, spec.RunningBinary, "the running image path rides the spec")
	assert.True(t, strings.HasSuffix(spec.AgentDir, filepath.Join("Library", "LaunchAgents")),
		"the agent dir is ~/Library/LaunchAgents (got %s)", spec.AgentDir)
	assert.Empty(t, spec.ConfigPath, "no explicit -c → plain `watch` in ProgramArguments")

	s := out.String()
	assert.Contains(t, s, "assay-watch.plist")
	assert.Contains(t, s, "KeepAlive", "the summary names the supervision contract")
	assert.Contains(t, s, "self-watchdog", "the summary names the hang mechanism honestly")
}

// TestInstallDarwinExplicitConfigSpec pins the explicit -c install: the
// config path rides the spec verbatim (absolute), NO materialization
// target, and the agent runs `watch -c <path>`.
func TestInstallDarwinExplicitConfigSpec(t *testing.T) {
	f := &fakeScheduler{name: "launchd", available: true}
	withDarwinScheduler(t, f)
	cfg, dir := launchdTestConfig(t)
	out := &bytes.Buffer{}

	custom := filepath.Join(dir, "custom", "config.toml")
	opts := installOptions{
		binDir:       filepath.Join(dir, "bin"),
		embedsConfig: true,
	}
	err := runInstall(out, cfg, custom, opts)
	require.NoError(t, err)
	abs, aerr := filepath.Abs(custom)
	require.NoError(t, aerr)
	assert.Equal(t, abs, f.installSpec.ConfigPath, "an explicit -c rides the spec (resolved absolute)")
	assert.Empty(t, f.installSpec.DefaultConfigPath, "explicit-config installs never materialize")
}

// TestInstallDarwinUnavailableRefuses pins the availability gate: a
// scheduler that reports unavailable fails the install LOUD with the
// reason — never a silent skip to another mechanism.
func TestInstallDarwinUnavailableRefuses(t *testing.T) {
	f := &fakeScheduler{name: "launchd", available: false, availReason: "launchctl not found on PATH"}
	withDarwinScheduler(t, f)
	cfg, dir := launchdTestConfig(t)
	out := &bytes.Buffer{}

	opts := installOptions{binDir: filepath.Join(dir, "bin")}
	err := runInstall(out, cfg, "", opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "launchctl not found on PATH")
}

// TestUninstallDarwinBranch pins the darwin uninstall: bootout via the
// scheduler, plist removal, managed-core teardown on the resolved data dir,
// purge passthrough.
func TestUninstallDarwinBranch(t *testing.T) {
	f := &fakeScheduler{name: "launchd", available: true}
	withDarwinScheduler(t, f)
	cfg, dir := launchdTestConfig(t)
	out := &bytes.Buffer{}

	err := runUninstall(out, cfg, filepath.Join(dir, "config.toml"), uninstallOptions{purge: true})
	require.NoError(t, err)
	assert.Equal(t, dir, f.uninstallSpec.DataDir, "the managed-core teardown uses the resolved data dir")
	assert.Equal(t, filepath.Join(dir, "config.toml"), f.uninstallSpec.PurgeConfigPath)
	assert.Equal(t, dir, f.uninstallSpec.PurgeDataDir)
	assert.True(t, strings.HasSuffix(f.uninstallSpec.AgentDir, filepath.Join("Library", "LaunchAgents")))
}

// TestStatusDarwinBranchNamesTheMechanism pins the §1.2.8 + ADDENDUM §1
// status: the print-derived state and pid, plus the HONEST mechanism note
// ("self-watchdog → KeepAlive restart") — no silent systemd parity claims.
func TestStatusDarwinBranchNamesTheMechanism(t *testing.T) {
	f := &fakeScheduler{
		name:      "launchd",
		available: true,
		status: install.SchedulerStatus{
			Active: true,
			PID:    4242,
			Note:   "KeepAlive restart on exit; hang detection: self-watchdog → KeepAlive restart",
		},
	}
	withDarwinScheduler(t, f)
	cfg, dir := launchdTestConfig(t)
	out := &bytes.Buffer{}

	printInstallStatus(out, cfg, "", filepath.Join(dir, "bin"), filepath.Join(dir, "unit"), false)
	s := out.String()
	assert.Contains(t, s, "4242", "the print-derived PID renders")
	assert.Contains(t, s, "self-watchdog → KeepAlive restart", "the mechanism note renders verbatim")
}

// TestStatusDarwinNotInstalled pins the unregistered host: Active=false →
// the status says so and points at install, never invents state.
func TestStatusDarwinNotInstalled(t *testing.T) {
	f := &fakeScheduler{
		name:      "launchd",
		available: true,
		status: install.SchedulerStatus{
			Active: false,
			Note:   "agent not registered (assay-watch — run `assay install`)",
		},
	}
	withDarwinScheduler(t, f)
	cfg, dir := launchdTestConfig(t)
	out := &bytes.Buffer{}

	printInstallStatus(out, cfg, "", filepath.Join(dir, "bin"), filepath.Join(dir, "unit"), false)
	assert.Contains(t, out.String(), "not registered")
}

// TestDarwinHostProbeReadsRuntime pins the production host probe: on this
// host it reads runtime.GOOS (false everywhere but darwin — the linux path
// keeps the systemd branch untouched).
func TestDarwinHostProbeReadsRuntime(t *testing.T) {
	assert.Equal(t, runtime.GOOS == "darwin", darwinHost(),
		"the production probe mirrors runtime.GOOS exactly")
}

// TestInstallFlagSanityOnDarwin pins that --no-systemd keeps its
// binary-only meaning on darwin too: the branch is skipped, the systemd
// NoSystemd flow runs (binary + config only), and NO launchd scheduler is
// consulted.
func TestInstallFlagSanityOnDarwin(t *testing.T) {
	consulted := false
	f := &fakeScheduler{name: "launchd", available: true}
	withDarwinScheduler(t, f)
	oldFactory := launchdSchedulerFactory
	launchdSchedulerFactory = func() scheduler {
		consulted = true
		return f
	}
	t.Cleanup(func() { launchdSchedulerFactory = oldFactory })

	cfg, dir := launchdTestConfig(t)
	out := &bytes.Buffer{}
	opts := installOptions{
		binDir:          filepath.Join(dir, "bin"),
		noSystemd:       true,
		materializePath: filepath.Join(dir, "config.toml"),
	}
	// The systemd NoSystemd flow needs the running binary resolution only —
	// it copies the current test binary (the same pattern installOpts uses).
	err := runInstall(out, cfg, "", opts)
	require.NoError(t, err)
	assert.False(t, consulted, "--no-systemd skips the launchd scheduler (binary + config only)")
	assert.Contains(t, out.String(), "--no-systemd")
}
