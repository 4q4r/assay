//go:build unix

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/core"
	"assay/internal/install"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// managedCoreFixture plants the managed core artifacts (the D4 download
// layout) plus one user-data file in the config's data dir.
func managedCoreFixture(t *testing.T, dataDir string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "bin"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "bin", "xray"),
		[]byte("#!/bin/sh\nexit 0\n"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "share", "xray"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "share", "xray", "geoip.dat"),
		[]byte("GEOIP"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "nodes.jsonl"), []byte("{}\n"), 0o600))
}

// TestInstallGuaranteesCoreBeforeFirstWave (plan test 4): `assay install`
// runs the D4 core bootstrap step — on a clean data dir the managed binary
// EXISTS afterward (install guarantees the core before the first wave), the
// bootstrap receives the resolved data dir, and the step runs on the
// --no-systemd path too. The download mechanics are hermetically stubbed
// here (they are pinned against the httptest release fixture in
// internal/core); this pin is the WIRING: which step runs, with what.
func TestInstallGuaranteesCoreBeforeFirstWave(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	cfg := mustLoad(t, cfgPath)

	var gotDataDir string
	var gotCore config.CoreConfig
	orig := ensureCoreBinary
	ensureCoreBinary = func(_ context.Context, cc config.CoreConfig, dataDir string, _ io.Writer) error {
		gotCore = cc
		gotDataDir = dataDir
		bin := filepath.Join(dataDir, "bin", "xray")
		require.NoError(t, os.MkdirAll(filepath.Dir(bin), 0o750))
		return os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	}
	t.Cleanup(func() { ensureCoreBinary = orig })

	buf := &strings.Builder{}
	require.NoError(t, runInstall(buf, cfg, cfgPath, installOptions{
		binDir:       filepath.Join(home, "bin"),
		unitDir:      filepath.Join(home, "units"),
		noSystemd:    true,
		embedsConfig: true,
	}))

	wantData := filepath.Join(home, "data")
	assert.Equal(t, wantData, gotDataDir, "the bootstrap receives the resolved data dir")
	assert.Empty(t, gotCore.XrayBin, "the bootstrap receives the config's [core] surface")
	_, err := os.Stat(filepath.Join(wantData, "bin", "xray"))
	require.NoError(t, err, "install guarantees the managed binary exists before the first wave (D4)")
}

// TestInstallCoreBootstrapFailureIsLoudNonFatal: a failed download does NOT
// fail the install — it lands as a loud WARNING and install completes (the
// daemon's waves retry through auto-update).
func TestInstallCoreBootstrapFailureIsLoudNonFatal(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	cfg := mustLoad(t, cfgPath)

	orig := ensureCoreBinary
	ensureCoreBinary = func(context.Context, config.CoreConfig, string, io.Writer) error {
		return assert.AnError
	}
	t.Cleanup(func() { ensureCoreBinary = orig })

	buf := &strings.Builder{}
	require.NoError(t, runInstall(buf, cfg, cfgPath, installOptions{
		binDir:       filepath.Join(home, "bin"),
		unitDir:      filepath.Join(home, "units"),
		noSystemd:    true,
		embedsConfig: true,
	}), "a failed core download must not fail the install")
	assert.Contains(t, buf.String(), "WARNING", "the failure is loud")
	assert.Contains(t, buf.String(), "core bootstrap", "the failure names the bootstrap step")
}

// TestUninstallRemovesCore (plan test 5): `assay uninstall` removes the
// managed core artifacts (bin/xray + share/xray) — the D4 teardown — while
// keeping the rest of the data dir; --purge remains the explicit opt-in
// that ALSO removes the config + the whole data dir.
func TestUninstallRemovesCore(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	cfg := mustLoad(t, cfgPath)
	dataDir := filepath.Join(home, "data")
	managedCoreFixture(t, dataDir)
	unitDir := filepath.Join(home, ".config", "systemd", "user")

	buf := &strings.Builder{}
	require.NoError(t, runUninstall(buf, cfg, cfgPath,
		uninstallOptions{unitDir: unitDir, exec: &fakeCtl{}}))

	_, err := os.Stat(filepath.Join(dataDir, "bin", "xray"))
	assert.True(t, os.IsNotExist(err), "the managed core binary is removed")
	_, err = os.Stat(filepath.Join(dataDir, "share", "xray"))
	assert.True(t, os.IsNotExist(err), "the managed asset dir is removed")
	_, err = os.Stat(filepath.Join(dataDir, "nodes.jsonl"))
	require.NoError(t, err, "user pipeline data is KEPT by the plain uninstall")
	assert.Contains(t, buf.String(), "core removed", "the teardown reports the core artifacts")

	// The opt-in purge: config + data dir (everything, core included).
	require.NoError(t, runUninstall(&strings.Builder{}, cfg, cfgPath,
		uninstallOptions{unitDir: unitDir, exec: &fakeCtl{}, purge: true}))
	_, err = os.Stat(dataDir)
	assert.True(t, os.IsNotExist(err), "the purge removes the data dir (opt-in)")
}

// TestUninstallWithoutConfigSkipsCoreRemoval: an unresolvable config means
// no known data dir — the plain uninstall completes without guessing paths
// (and without failing).
func TestUninstallWithoutConfigSkipsCoreRemoval(t *testing.T) {
	buf := &strings.Builder{}
	require.NoError(t, runUninstall(buf, nil, "",
		uninstallOptions{unitDir: t.TempDir(), exec: &fakeCtl{}}),
		"no config = no data dir = no core artifacts to remove; the uninstall completes")
	assert.NotContains(t, buf.String(), "core removed")
}

// TestCoreAutoUpdateStageInertWhenOverridden (S5 wave wiring): the wave's
// auto-update stage with an overridden [core].xray_bin is inert — the
// ONE-TIME loud INFO lands, no error, no network.
func TestCoreAutoUpdateStageInertWhenOverridden(t *testing.T) {
	f := newOwnFixture(t) // [core].xray_bin = the fake binary (an override)
	mgr := f.ownManager(t)
	t.Cleanup(func() { _ = mgr.Stop(); mgr.Release() }) // stop the fake core + free the lock handle (windows cannot remove an open core.lock)

	require.NoError(t, runCoreAutoUpdateStageWithManager(f.cmd, f.cfg, mgr))
	require.NoError(t, runCoreAutoUpdateStageWithManager(f.cmd, f.cfg, mgr))
	assert.Equal(t, 1, strings.Count(f.log.String(), "inert"),
		"the S5 INFO is one-time loud across waves")
}

// TestCoreAutoUpdateStageRefusesUnderFlock: the one-shot auto-update stage
// mirrors the activate stage's S3 semantics — under the daemon's flock it
// refuses loud with the exact message, never spawns a second manager.
func TestCoreAutoUpdateStageRefusesUnderFlock(t *testing.T) {
	f := newOwnFixture(t)
	f.writeOwnLive(t, "gen-0")
	holder := f.ownManager(t) // the daemon-style holder
	t.Cleanup(holder.Release) // the lock handle must not outlive the test (no child is spawned here)

	err := runCoreAutoUpdateStage(f.cmd, f.cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(),
		"the daemon owns the core — restart the unit or use watch",
		"the one-shot auto-update refuses under the daemon's flock (S3)")
}

// TestInstallUninstallCoreSurfacePinned guards the uninstall teardown: the
// managed core removal paths are exactly the D4 product dirs (bin/xray +
// share/xray under the data dir) — nothing else in the data dir is touched
// without --purge (the install-package twin pins the details).
func TestInstallUninstallCoreSurfacePinned(t *testing.T) {
	home := t.TempDir()
	cfgPath := writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour)
	dataDir := filepath.Join(home, "data")
	managedCoreFixture(t, dataDir)

	orig := installExecutor
	ex := &fakeCtl{}
	installExecutor = func() install.Executor { return ex }
	t.Cleanup(func() { installExecutor = orig })

	root := newTestRoot()
	buf := &strings.Builder{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"--config", cfgPath, "uninstall"})
	require.NoError(t, root.Execute(), "cobra-level uninstall with a config: %s", buf.String())

	_, err := os.Stat(filepath.Join(dataDir, "bin", "xray"))
	assert.True(t, os.IsNotExist(err), "the cobra uninstall removed the managed core")
	_, err = os.Stat(filepath.Join(dataDir, "nodes.jsonl"))
	assert.NoError(t, err, "user data survives the cobra uninstall")
}

// TestOneShotWaveSharedManagerCompletesCoreStages (fix I-1): the daemon-less
// one-shot wave's core-touching stages (activate + core-auto-update) SHARE
// ONE manager — the wave completes end-to-end with NO false "the daemon owns
// the core" refusal, the auto-update stage actually RUNS (its inert INFO
// lands on the overridden binary), and the flock is released after the wave
// (a second wave in the same process completes too).
//
// RED at HEAD: the two stages were independent nil-managed funcs — activate's
// transient manager took the singleton flock and never released it, so the
// core-auto-update stage's OWN manager got EWOULDBLOCK milliseconds later and
// the wave ABORTED after a fully successful activation with the false
// daemon-owns message.
func TestOneShotWaveSharedManagerCompletesCoreStages(t *testing.T) {
	f := newOwnFixture(t) // [core].xray_bin = the fake (override → AutoUpdate inert, hermetic)
	f.writeOwnLive(t, "gen-0")
	f.writeOwnCandidate(t, "gen-candidate")
	// Kill whatever core the LAST successful wave left behind — registered
	// BEFORE the first wave so a mid-wave failure can never leak a serve
	// child into the port band (the RED probe of this very test leaked one).
	t.Cleanup(func() {
		if pid := cliPIDFromPidFile(t, f.p.dataDir); pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})

	runWave := func() error {
		// The runOneShotMaintainWave composition with the data stages
		// no-op'd for hermeticity — activate + coreAutoUpdate stay the REAL
		// runners (the I-1 subjects), and they SHARE the wave's one manager.
		// NewTransientManager mirrors the production composition 1:1 (the
		// audit P2-1 constructor: lock-only release, no job containment).
		mgr, merr := core.NewTransientManager(f.cfg.Core, f.p.dataDir, f.log)
		if merr != nil {
			return merr
		}
		defer mgr.Release()
		stages := defaultMaintainStages(maintainOptions{}, mgr)
		noop := func(*cobra.Command, *config.Config) error { return nil }
		stages.fetch, stages.parse, stages.filter = noop, noop, noop
		stages.probe, stages.pluginStatsEnrich = noop, noop
		stages.stats, stages.prune, stages.selectS, stages.render = noop, noop, noop, noop
		return runMaintain(f.out, f.cfg, maintainOptions{}, stages)
	}

	require.NoError(t, runWave(), "the one-shot wave must complete (no false flock refusal)")
	out := f.out.String()
	assert.NotContains(t, out, "the daemon owns the core",
		"the false S3 refusal must never fire in a daemon-less wave")
	assert.Contains(t, out, "activation complete", "the activate stage ran fully")
	assert.Contains(t, f.log.String(), "inert",
		"the core-auto-update stage RAN (S5 inert INFO) instead of being refused")
	assert.NotContains(t, f.log.String(), "rollback refused",
		"no manager machinery refusal may fire")

	// Release is lock-only: a second wave in the SAME process completes (the
	// first wave's manager did not leave the flock held), and the core the
	// first wave spawned keeps serving (A2 — the teardown never stops it).
	require.NoError(t, runWave(), "the flock must be released after the wave")
	assert.True(t, coreServing(f.cfg.Core.SocksPort),
		"the core spawned/kept by the waves keeps serving (A2)")
}

// TestCoreAutoUpdateStageSwallowsFailuresLoud (fix M-2): a FAILING
// AutoUpdate through the stage returns NIL — the wave continues — with the
// loud WARNING in the journal. The failure is injected hermetically: the
// bound USER-LOCAL core binary cannot answer `version`, and the
// current-version read runs BEFORE any network (pinned at the core level by
// TestAutoUpdateFailsFastOnUnreadableCurrentBinaryBeforeNetwork), so the
// stage fails without touching GitHub.
func TestCoreAutoUpdateStageSwallowsFailuresLoud(t *testing.T) {
	userLocal, _ := injectCoreBinSeams(t)
	dir := t.TempDir()
	port := nextCoreTestPort()
	require.NoError(t, os.MkdirAll(filepath.Dir(userLocal), 0o750))
	require.NoError(t, os.WriteFile(userLocal, []byte("#!/bin/sh\nexit 1\n"), 0o755))
	cfg := &config.Config{
		DataDir: dir,
		Core:    config.CoreConfig{AutoUpdate: true, SocksPort: port, HTTPPort: port + 1},
	}
	out := &syncBuffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	mgr, err := core.NewManager(cfg.Core, dir, out)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(); mgr.Release() }) // exported teardown + lock handle (release is core-internal)

	require.NoError(t, runCoreAutoUpdateStageWithManager(cmd, cfg, mgr),
		"the stage must SWALLOW the AutoUpdate failure — the wave continues (D4/S5)")
	text := out.String()
	assert.Contains(t, text, "WARNING: core auto-update:", "the failure is loud")
	assert.Contains(t, text, "the wave continues", "the swallow names the wave-continues contract")
}
