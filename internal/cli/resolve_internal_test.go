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

	"public_vpn/internal/config"
	"public_vpn/internal/install"
	"public_vpn/internal/plugins"
	"public_vpn/internal/stats"
	"public_vpn/internal/watchdog"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hermeticEnv isolates a test from the real machine: HOME points at a temp
// dir (no ~/.config/publicvpn there) and the cwd is a temp dir (no
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

func (h hermeticEnv) putHomeConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(h.home, ".config", "publicvpn", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf("data_dir = %q\n", filepath.Join(h.home, "home-data"))), 0o600))
	return p
}

func (h hermeticEnv) putCwdConfig(t *testing.T) {
	t.Helper()
	p := filepath.Join(h.cwd, "config.toml")
	require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf("data_dir = %q\n", filepath.Join(h.cwd, "cwd-data"))), 0o600))
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
// status shows the same provenance as a dedicated line.
func TestCLIConfigSourceLinePrecedence(t *testing.T) {
	tests := []struct {
		name      string
		homeFile  bool
		cwdFile   bool
		explicit  bool
		wantLine  string
		noHomeCfg bool
	}{
		{
			name:     "explicit -c",
			homeFile: true, cwdFile: true, explicit: true,
			wantLine: "config: explicit -c",
		},
		{
			name:     "home default",
			homeFile: true, cwdFile: true,
			wantLine: "config: home default",
		},
		{
			name:     "cwd default",
			homeFile: false, cwdFile: true,
			wantLine: "config: cwd default",
		},
		{
			name:     "configless",
			homeFile: false, cwdFile: false,
			wantLine: "config: configless (built-in defaults)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newHermeticEnv(t)
			if tt.homeFile {
				env.putHomeConfig(t)
			}
			if tt.cwdFile {
				env.putCwdConfig(t)
			}
			args := []string{}
			if tt.explicit {
				args = append(args, "-c", env.putHomeConfig(t))
			}
			out, err := runStatusCapture(t, args...)
			require.NoError(t, err)
			assert.Contains(t, out, tt.wantLine)
			// The data-dir line must always reflect the EFFECTIVE config:
			// configless points at the XDG default under the injected HOME.
			if tt.homeFile && !tt.explicit {
				assert.Contains(t, out, filepath.Join(env.home, "home-data"))
			}
			if tt.cwdFile && !tt.homeFile {
				assert.Contains(t, out, filepath.Join(env.cwd, "cwd-data"))
			}
			if !tt.homeFile && !tt.cwdFile {
				assert.Contains(t, out, filepath.Join(env.home, ".local", "share", "publicvpn"))
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
	assert.Contains(t, err.Error(), config.HomeConfigDisplay)
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
	assert.Contains(t, err.Error(), config.HomeConfigDisplay)
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
	assert.Contains(t, err.Error(), config.HomeConfigDisplay)
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
			return { publicvpn.node{ raw = "vless://a@h1.example.com:443?s=1" }, publicvpn.node{ raw = "vless://b@h2.example.com:443?s=1" } }
		end`)})
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	require.NoError(t, runFetchWith(cmd, cfg, reg), "configless fetch must work from plugins")
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
			return { publicvpn.node{ raw = "vless://a@h1.example.com:443?s=1" } }
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

// TestInstallWithoutResolvableConfigLoud: install REQUIRES a config (the
// unit embeds its path). With no explicit -c and no home default, install
// fails loud with guidance — cwd alone is NOT enough for install.
func TestInstallWithoutResolvableConfigLoud(t *testing.T) {
	env := newHermeticEnv(t)
	env.putCwdConfig(t) // cwd default deliberately present: install ignores it
	root := newTestRoot()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"install", "--no-systemd"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "install requires a config")
	assert.Contains(t, err.Error(), config.HomeConfigDisplay)
}

// TestInstallHomeDefaultUnitCarriesResolvedPath: install with the home
// default renders the daemon unit referencing the RESOLVED ABSOLUTE config
// path.
func TestInstallHomeDefaultUnitCarriesResolvedPath(t *testing.T) {
	env := newHermeticEnv(t)
	homeCfg := env.putHomeConfig(t)
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
	assert.Contains(t, buf.String(), "config: home default "+homeCfg)

	// The UNIT FILE embeds the resolved absolute home config path.
	unitPath := filepath.Join(unitDir, "public_vpn-watch.service")
	b, err := os.ReadFile(unitPath)
	require.NoError(t, err, "unit file must be rendered; output:\n%s", buf.String())
	assert.Contains(t, string(b), homeCfg, "the unit must embed the resolved home config path")
	assert.NotEmpty(t, ex.calls, "systemd enable flow must run through the executor seam")
}

// TestUninstallPurgeResolvesInstallStyle: --purge resolves the config the
// same way install does (explicit → home default → loud; never the cwd
// default — a purge must never depend on the caller's cwd).
func TestUninstallPurgeResolvesInstallStyle(t *testing.T) {
	env := newHermeticEnv(t)
	env.putCwdConfig(t)
	root := newTestRoot()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"uninstall", "--purge"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "install requires a config")
}

// newTestRoot builds a fresh root command (each call gets its own flag
// state).
func newTestRoot() *cobra.Command { return New() }
