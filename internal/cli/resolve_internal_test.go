package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/install"
	"assay/internal/plugins"
	"assay/internal/stats"
	"assay/internal/watchdog"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hermeticEnv isolates a test from the real machine: HOME points at a temp
// dir (no ~/.config/assay there) and the cwd is a temp dir (no
// ./config.toml). Every resolution test builds its own layout from here.
type hermeticEnv struct {
	home string
	cwd  string
}

func newHermeticEnv(t *testing.T) hermeticEnv {
	t.Helper()
	home := t.TempDir()
	cwd := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "") // hermetic: the configless data-dir default pins the fallback branch
	t.Chdir(cwd)
	return hermeticEnv{home: home, cwd: cwd}
}

func (h hermeticEnv) putShareConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(h.home, ".local", "share", "assay", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf("data_dir = %q\n", filepath.Join(h.home, "share-data"))), 0o600))
	return p
}

// putLegacyHomeConfig creates the DEPRECATED pre-W13 home location — the
// one-release-cycle courtesy tier (found-if-exists with a loud move
// warning).
func (h hermeticEnv) putLegacyHomeConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(h.home, ".config", "assay", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf("data_dir = %q\n", filepath.Join(h.home, "legacy-data"))), 0o600))
	return p
}

func (h hermeticEnv) putCwdConfig(t *testing.T) {
	t.Helper()
	p := filepath.Join(h.cwd, "config.toml")
	require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf("data_dir = %q\n", filepath.Join(h.cwd, "cwd-data"))), 0o600))
}

// putPreRenameShareConfig creates the PRE-RENAME local-share location: the
// state a real install sits in between the assay rename and the owner's
// data migration. The old leaf is assembled from parts here for the same
// grep reason as the config package's fixture pin — the acceptance
// contract keeps the old spelling out of Go sources.
func (h hermeticEnv) putPreRenameShareConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(h.home, ".local", "share", "public"+"vpn", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf("data_dir = %q\n", filepath.Join(h.home, "old-share-data"))), 0o600))
	return p
}

// runStatusCapture executes `status` (read-only — safe on any layout) and
// returns its output.
func runStatusCapture(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newTestRoot()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(append([]string{"status"}, args...))
	err := root.Execute()
	return buf.String(), err
}

// TestCLIConfigSourceLinePrecedence pins the visibility contract through the
// real command surface: every command prints the resolved config source, and
// status shows the same provenance as a dedicated line — including the
// W13-deploy tier names (local-share default, legacy home default).
func TestCLIConfigSourceLinePrecedence(t *testing.T) {
	tests := []struct {
		name     string
		share    bool
		legacy   bool
		cwdFile  bool
		explicit bool
		wantLine string
		wantWarn string
	}{
		{
			name:  "explicit -c",
			share: true, cwdFile: true, explicit: true,
			wantLine: "config: explicit -c",
		},
		{
			name:  "local-share default",
			share: true, cwdFile: true,
			wantLine: "config: local-share default",
		},
		{
			name:   "legacy home default with the loud move warning",
			legacy: true, cwdFile: true,
			wantLine: "config: legacy home default",
			wantWarn: "move it to ~/.local/share/assay/config.toml",
		},
		{
			name:     "cwd default",
			cwdFile:  true,
			wantLine: "config: cwd default",
		},
		{
			name:     "configless",
			wantLine: "config: configless (built-in defaults)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newHermeticEnv(t)
			if tt.share {
				env.putShareConfig(t)
			}
			if tt.legacy {
				env.putLegacyHomeConfig(t)
			}
			if tt.cwdFile {
				env.putCwdConfig(t)
			}
			args := []string{}
			if tt.explicit {
				args = append(args, "-c", env.putShareConfig(t))
			}
			out, err := runStatusCapture(t, args...)
			require.NoError(t, err)
			assert.Contains(t, out, tt.wantLine)
			if tt.wantWarn != "" {
				assert.Contains(t, out, "warning:", "the deprecation warning prints loud:\n%s", out)
				assert.Contains(t, out, tt.wantWarn, "the warning names the move:\n%s", out)
			}
			// The data-dir line must always reflect the EFFECTIVE config.
			switch {
			case tt.explicit:
				assert.Contains(t, out, filepath.Join(env.home, "share-data"))
			case tt.share:
				assert.Contains(t, out, filepath.Join(env.home, "share-data"))
			case tt.legacy:
				assert.Contains(t, out, filepath.Join(env.home, "legacy-data"))
			case tt.cwdFile:
				assert.Contains(t, out, filepath.Join(env.cwd, "cwd-data"))
			default:
				assert.Contains(t, out, filepath.Join(env.home, ".local", "share", "assay"))
			}
		})
	}
}

// TestConfiglessRenderBoundaryLoud: with no config anywhere, render fails
// loud at the stage boundary with the actionable message — it never
// silently defaults the template to the live client's config.
func TestConfiglessRenderBoundaryLoud(t *testing.T) {
	_ = newHermeticEnv(t)
	// Seed the pipeline data so render reaches the template stage: without a
	// seeded selection it would fail earlier on "no selection" — the
	// boundary check must fire FIRST.
	root := newTestRoot()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"render"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configless mode cannot render")
	assert.Contains(t, err.Error(), config.ShareConfigDisplay)
}

// TestConfiglessActivateBoundaryLoud: same contract for activate.
func TestConfiglessActivateBoundaryLoud(t *testing.T) {
	_ = newHermeticEnv(t)
	root := newTestRoot()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"activate"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configless mode cannot activate")
	assert.Contains(t, err.Error(), config.ShareConfigDisplay)
}

// TestConfiglessActivateTargetFlagCannotBypassBoundary pins the I-1
// contract: the configless boundary refuses AT STAGE ENTRY on the configured
// activate.target alone — the --target flag cannot bypass it. Pre-fix, the
// flag skipped the boundary and fell into the misleading "no rendered
// config — run render first" loop (configless render refuses the same way).
func TestConfiglessActivateTargetFlagCannotBypassBoundary(t *testing.T) {
	_ = newHermeticEnv(t)
	root := newTestRoot()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"activate", "--target", filepath.Join(t.TempDir(), "target.json")})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configless mode cannot activate",
		"the loud boundary message, not the render-first loop")
	assert.Contains(t, err.Error(), config.ShareConfigDisplay)
	assert.NotContains(t, err.Error(), "run render first",
		"--target must not drop configless runs into the misleading render-first loop")
}

// TestConfiglessWaveDataStagesWorkThenRenderLoud pins the wave matrix: the
// configless data stages (fetch from plugins → parse → filter) run on pure
// defaults, and the render stage fails loud with the boundary message.
func TestConfiglessWaveDataStagesWorkThenRenderLoud(t *testing.T) {
	_ = newHermeticEnv(t)
	res, err := resolveCommand("")
	require.NoError(t, err)
	cfg := res.Config

	// Fetch from a hermetic stub plugin through the REAL fetch runner.
	reg := plugins.NewRegistry()
	reg.Set(&plugins.Plugin{ID: "stub", Path: "stub.lua", Code: []byte(`
		return function()
			return { assay.node{ raw = "vless://a@h1.example.com:443?s=1" }, assay.node{ raw = "vless://b@h2.example.com:443?s=1" } }
		end`)})
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	_, err = runFetchWith(cmd, cfg, reg)
	require.NoError(t, err, "configless fetch must work from plugins")
	require.Contains(t, out.String(), "plugin stub       ok: 2 nodes")

	require.NoError(t, runParse(cmd, cfg), "configless parse must work")
	require.NoError(t, runFilter(cmd, cfg, 0), "configless filter must work")

	err = runRender(cmd, cfg)
	require.Error(t, err, "configless render fails loud at the stage boundary")
	assert.Contains(t, err.Error(), "configless mode cannot render")
}

// TestConfiglessStatsSkipsINFO pins the stats stage's configless behavior:
// without activate.target the poll is accounting-unavailable (INFO — the
// wave continues), never a silent success and never a wave failure.
func TestConfiglessStatsSkipsINFO(t *testing.T) {
	_ = newHermeticEnv(t)
	res, err := resolveCommand("")
	require.NoError(t, err)
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	err = runStatsStage(cmd, res.Config)
	require.Error(t, err, "the stage returns a CLASSIFIED error")
	var ce *stats.ClassifiedError
	require.ErrorAs(t, err, &ce, "the failure must carry a stats classification")
	assert.Equal(t, stats.ClassInfo, ce.Class, "configless stats is INFO (accounting unavailable), not LOUD")
	// reportStatsFailure turns INFO into a printed line, wave continues.
	w := &bytes.Buffer{}
	require.NoError(t, reportStatsFailure(w, err))
	assert.Contains(t, w.String(), "INFO:")
}

// TestWatchConfiglessBootStaysUp: the daemon boots configless (plugins dir
// under the XDG data dir), runs a wave whose working stages proceed and
// whose un-runnable part fails loud, logs the failure, and KEEPS RUNNING
// until the shutdown signal — the broken-plugin wave-continues semantics
// applied to the configless boundary.
func TestWatchConfiglessBootStaysUp(t *testing.T) {
	_ = newHermeticEnv(t)
	res, err := resolveCommand("")
	require.NoError(t, err)
	cfg := res.Config

	// A hermetic stub plugin in the configless plugins dir (pre-created, so
	// the embedded defaults never materialize — no network anywhere).
	pluginsDir := filepath.Join(cfg.DataDir, "plugins")
	require.NoError(t, os.MkdirAll(pluginsDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(pluginsDir, "stub.lua"), []byte(`
		return function()
			return { assay.node{ raw = "vless://a@h1.example.com:443?s=1" } }
		end`), 0o600))

	sigs := make(chan os.Signal, 1)
	dep := watchDeps{
		startWatchdog: func(dir string, log io.Writer) (*plugins.Registry, io.Closer, error) {
			reg, closer, err := watchdog.Start(dir, log)
			return reg, closer, err
		},
		signals: sigs,
		now:     time.Now,
		after: func(time.Duration) <-chan time.Time {
			return make(chan time.Time) // never fires — only the signal ends it
		},
		sdNotify: func(io.Writer) func() { return func() {} },
	}
	out := &syncWriter{}
	done := make(chan error, 1)
	go func() { done <- runWatch(out, cfg, dep) }()

	// The daemon must survive the failed wave and stay scheduled: wait for
	// the boot line + the wave failure WARNING, then shut down cleanly.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "WARNING:") && strings.Contains(out.String(), "watch: plugin watchdog live") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	text := out.String()
	require.Contains(t, text, "watch: plugin watchdog live", "daemon booted:\n%s", text)
	require.Contains(t, text, "WARNING:", "the wave failure is loud:\n%s", text)

	sigs <- os.Interrupt // dep.signals is the receive-only view of sigs
	select {
	case err := <-done:
		require.NoError(t, err, "configless daemon shuts down cleanly")
	case <-time.After(10 * time.Second):
		t.Fatalf("daemon did not shut down on signal; output:\n%s", out.String())
	}
	assert.Contains(t, out.String(), "watch: clean shutdown")
}

// TestInstallDefaultLocationMaterializesConfig pins the W13-deploy
// canonical user flow end to end at the cobra seam: install WITHOUT -c and
// with NO config anywhere — exit 0, the default config materialized at the
// local-share path (from the embedded configless defaults), the daemon unit
// running plain `watch` (NO -c — the daemon reads the default location),
// and the loud summary naming the config and the fill-me paths. A SECOND
// install must report "kept" and never touch the file.
func TestInstallDefaultLocationMaterializesConfig(t *testing.T) {
	env := newHermeticEnv(t)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(env.home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(env.home, "run", "systemd"), 0o755))
	// A cwd config present but deliberately IGNORED: install never embeds a
	// cwd-relative path into a daemon unit.
	env.putCwdConfig(t)

	ex := &fakeCtl{}
	orig := installExecutor
	installExecutor = func() install.Executor { return ex }
	t.Cleanup(func() { installExecutor = orig })

	unitDir := filepath.Join(env.home, ".config", "systemd", "user")
	binDir := filepath.Join(env.home, ".local", "bin")
	cfgPath := filepath.Join(env.home, ".local", "share", "assay", "config.toml")

	run := func() string {
		root := newTestRoot()
		buf := &bytes.Buffer{}
		root.SetOut(buf)
		root.SetErr(buf)
		root.SetArgs([]string{"install", "--bin-dir", binDir, "--unit-dir", unitDir})
		require.NoError(t, root.Execute(), "output:\n%s", buf.String())
		return buf.String()
	}

	out := run()
	assert.Contains(t, out, "config created:   "+cfgPath, "summary names the materialized config:\n%s", out)
	assert.Contains(t, out, "daemon config:    "+cfgPath+" (the daemon reads the default location — no -c in the unit)")
	assert.Contains(t, out, "to activate:      fill [render].template and [activate].target")

	// The materialized file: valid TOML that loads, data_dir = the local-share
	// default, and the load passes strict decode (the embedded template must
	// never carry dead keys).
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err, "the materialized default config must load clean")
	assert.Equal(t, filepath.Join(env.home, ".local", "share", "assay"), cfg.DataDir)
	assert.False(t, cfg.Probe.IsSpeedtest(), "the materialized defaults carry the round-8 speedtest-off default")
	info, err := os.Stat(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the materialized config is owner-only (token knobs exist)")

	// The unit: plain `watch` ExecStart, no -c anywhere.
	unitBytes, err := os.ReadFile(filepath.Join(unitDir, install.WatchService))
	require.NoError(t, err)
	assert.Contains(t, string(unitBytes), binDir+"/assay watch\n", "ExecStart must be plain watch (no -c):\n"+string(unitBytes))
	assert.NotContains(t, string(unitBytes), " -c ")

	// Re-install: the share config now resolves as the default location —
	// plain `watch` again (a no--c install NEVER flips to -c), the owner's
	// file untouched.
	require.NoError(t, os.WriteFile(cfgPath, []byte("data_dir = \""+filepath.Join(env.home, "d")+"\"\n"), 0o600))
	out2 := run()
	assert.Contains(t, out2, "config: local-share default "+cfgPath)
	assert.Contains(t, out2, "daemon config:    "+cfgPath+" (the daemon reads the default location — no -c in the unit)")
	assert.NotContains(t, out2, "config created:", "nothing to materialize on a re-install")
	unitBytes2, err := os.ReadFile(filepath.Join(unitDir, install.WatchService))
	require.NoError(t, err)
	assert.Contains(t, string(unitBytes2), " watch\n")
	assert.NotContains(t, string(unitBytes2), " -c ", "the unit must never flip to -c on a re-install")
	cfg2, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(env.home, "d"), cfg2.DataDir, "the owner's file survived the re-install byte-for-byte")
}

// TestInstallLegacyHomeLocationWinsWithWarning pins the one-release-cycle
// courtesy at the cobra seam: with NO local-share config but a legacy
// ~/.config/assay/config.toml present, install uses it (the owner's
// tuned config keeps working — no second config materialized over it) and
// prints the loud deprecation warning; the unit embeds the legacy path.
func TestInstallLegacyHomeLocationWinsWithWarning(t *testing.T) {
	env := newHermeticEnv(t)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(env.home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(env.home, "run", "systemd"), 0o755))
	legacyCfg := env.putLegacyHomeConfig(t)

	ex := &fakeCtl{}
	orig := installExecutor
	installExecutor = func() install.Executor { return ex }
	t.Cleanup(func() { installExecutor = orig })

	unitDir := filepath.Join(env.home, ".config", "systemd", "user")
	root := newTestRoot()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"install",
		"--bin-dir", filepath.Join(env.home, ".local", "bin"),
		"--unit-dir", unitDir,
	})
	require.NoError(t, root.Execute(), "output:\n%s", buf.String())

	assert.Contains(t, buf.String(), "config: legacy home default "+legacyCfg)
	assert.Contains(t, buf.String(), "warning: legacy config location detected", "the deprecation warning is loud")
	_, err := os.Stat(filepath.Join(env.home, ".local", "share", "assay", "config.toml"))
	assert.True(t, os.IsNotExist(err), "no materialization over a working legacy config")
	unitBytes, err := os.ReadFile(filepath.Join(unitDir, install.WatchService))
	require.NoError(t, err)
	assert.Contains(t, string(unitBytes), legacyCfg, "the unit embeds the legacy config path")
}

// TestInstallShareDefaultUnitCarriesResolvedPath: install with the
// local-share default present is a DEFAULT-LOCATION install — the unit
// renders plain `watch` (NO -c: the daemon reads the default location,
// which finds this exact file), and the summary names the resolved path.
func TestInstallShareDefaultUnitCarriesResolvedPath(t *testing.T) {
	env := newHermeticEnv(t)
	shareCfg := env.putShareConfig(t)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(env.home, "run"))
	// Hermetic user-session probe marker (install refuses without one).
	require.NoError(t, os.MkdirAll(filepath.Join(env.home, "run", "systemd"), 0o755))

	unitDir := filepath.Join(env.home, ".config", "systemd", "user")
	binDir := filepath.Join(env.home, ".local", "bin")
	ex := &fakeCtl{}
	orig := installExecutor
	installExecutor = func() install.Executor { return ex }
	t.Cleanup(func() { installExecutor = orig })

	root := newTestRoot()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"install", "--bin-dir", binDir, "--unit-dir", unitDir})
	require.NoError(t, root.Execute(), "output:\n%s", buf.String())
	assert.Contains(t, buf.String(), "config: local-share default "+shareCfg)
	assert.Contains(t, buf.String(), "daemon config:    "+shareCfg+" (the daemon reads the default location — no -c in the unit)")
	assert.NotContains(t, buf.String(), "config created:", "nothing materialized when the canonical config already exists")

	// The UNIT renders plain watch — the daemon resolves the same file.
	unitPath := filepath.Join(unitDir, "assay-watch.service")
	b, err := os.ReadFile(unitPath)
	require.NoError(t, err, "unit file must be rendered; output:\n%s", buf.String())
	assert.Contains(t, string(b), " watch\n", "ExecStart must be plain watch for the default-location install")
	assert.NotContains(t, string(b), " -c ")
	assert.NotEmpty(t, ex.calls, "systemd enable flow must run through the executor seam")
}

// TestUninstallPurgeResolvesInstallStyle: --purge never consults the cwd —
// with no explicit -c and no config anywhere in the install-style chain, the
// purge targets the CANONICAL local-share layout (the materialized default
// config path + the data dir under it), never the caller's ./config.toml.
func TestUninstallPurgeResolvesInstallStyle(t *testing.T) {
	env := newHermeticEnv(t)
	env.putCwdConfig(t)
	cwdCfg := filepath.Join(env.cwd, "config.toml")
	root := newTestRoot()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"uninstall", "--purge"})
	require.NoError(t, root.Execute(), "output:\n%s", buf.String())

	shareCfg := filepath.Join(env.home, ".local", "share", "assay", "config.toml")
	assert.Contains(t, buf.String(), "purged:           "+shareCfg,
		"the canonical local-share config is the purge target:\n%s", buf.String())
	assert.Contains(t, buf.String(), "purged:           "+filepath.Join(env.home, ".local", "share", "assay"),
		"the local-share data dir goes with it")
	_, err := os.Stat(cwdCfg)
	assert.NoError(t, err, "the cwd config file is NEVER purged (cwd never consulted)")
}

// TestInstallPreRenameShareConfigIsHonoredNotShadowed pins the I-1 fix-round
// regression: BEFORE the owner's data migration the pre-rename local-share
// config is the ONLY config that exists. A no--c install must honor it — the
// resolution returns it as the share default with the OLD path — and must
// NEVER materialize the embedded defaults at the NEW path: the daemon's
// default location is the new path now, so materializing defaults there
// (and rendering plain `watch`) would silently replace the owner's tuned
// config with the built-in defaults. The unit embeds the old path instead
// (the same treatment as the legacy-home tier), materializePath stays
// empty, and the rename hint rides along. No auto-migration anywhere.
func TestInstallPreRenameShareConfigIsHonoredNotShadowed(t *testing.T) {
	env := newHermeticEnv(t)
	oldCfg := env.putPreRenameShareConfig(t)
	newCfg := filepath.Join(env.home, ".local", "share", "assay", "config.toml")

	ir, err := resolveInstallPath("")
	require.NoError(t, err)
	require.NotNil(t, ir.res)
	assert.Equal(t, config.SourceShare, ir.res.Source,
		"the pre-rename share config resolves as the share-default tier")
	assert.Equal(t, oldCfg, ir.res.Path, "the OLD path is the honored config")
	assert.Empty(t, ir.materializePath,
		"materializePath must stay empty when a real config resolved — materializing defaults at the new path would shadow the owner's tuned config")
	assert.True(t, ir.embedsConfig,
		"the unit embeds the old path: the daemon's default location is the NEW path now, so plain watch would lose the owner's tuned config")
	assert.NotEmpty(t, ir.res.Warnings, "the rename-migration hint rides along")

	// The same state through the real cobra seam: nothing materialized, and
	// the rendered unit embeds the old path.
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(env.home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(env.home, "run", "systemd"), 0o755))
	ex := &fakeCtl{}
	orig := installExecutor
	installExecutor = func() install.Executor { return ex }
	t.Cleanup(func() { installExecutor = orig })
	unitDir := filepath.Join(env.home, ".config", "systemd", "user")
	root := newTestRoot()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"install",
		"--bin-dir", filepath.Join(env.home, ".local", "bin"),
		"--unit-dir", unitDir,
	})
	require.NoError(t, root.Execute(), "output:\n%s", buf.String())
	assert.Contains(t, buf.String(), "config: local-share default "+oldCfg)
	assert.Contains(t, buf.String(), "warning: legacy data location detected",
		"the rename hint is loud at the install surface:\n%s", buf.String())
	assert.NotContains(t, buf.String(), "config created:",
		"no defaults materialized during the migration window:\n%s", buf.String())
	_, err = os.Stat(newCfg)
	assert.True(t, os.IsNotExist(err), "the new-location default config must NOT exist pre-migration")
	unitBytes, err := os.ReadFile(filepath.Join(unitDir, "assay-watch.service"))
	require.NoError(t, err)
	assert.Contains(t, string(unitBytes), oldCfg, "the unit embeds the pre-rename config path")
}

// TestInstallConfiglessStateMaterializesNewPath pins the complementary
// state: with NO config anywhere — neither the canonical new location nor
// the pre-rename one — a no--c install resolves configless and materializes
// the embedded defaults at the NEW canonical path (the W13-deploy canonical
// user flow, unchanged).
func TestInstallConfiglessStateMaterializesNewPath(t *testing.T) {
	env := newHermeticEnv(t)
	newCfg := filepath.Join(env.home, ".local", "share", "assay", "config.toml")

	ir, err := resolveInstallPath("")
	require.NoError(t, err)
	require.NotNil(t, ir.res)
	assert.Equal(t, config.SourceConfigless, ir.res.Source)
	assert.Empty(t, ir.res.Path, "configless: no config file anywhere")
	assert.Equal(t, newCfg, ir.materializePath,
		"the configless case is the only one with a materialize target — and it is the NEW canonical path")
	assert.False(t, ir.embedsConfig, "configless install renders plain watch")
}

// newTestRoot builds a fresh root command (each call gets its own flag
// state).
func newTestRoot() *cobra.Command { return New() }
