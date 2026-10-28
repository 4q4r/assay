package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"public_vpn/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeMinimalConfig writes the smallest valid config into dir and returns
// its absolute path. data_dir points into the same dir, so parallel cases
// never share state.
func writeMinimalConfig(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	body := "data_dir = " + quote(filepath.Join(dir, "data-"+name)) + "\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func quote(s string) string { return "\"" + s + "\"" }

// TestResolvePrecedence pins the W12 config resolution contract: ONE file
// wins whole — explicit -c, else the home default, else the cwd default,
// else fully configless. There is no merging, ever (owner house rule).
func TestResolvePrecedence(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()

	homeCfg := filepath.Join(home, ".config", "publicvpn", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(homeCfg), 0o750))
	writeMinimalConfig(t, filepath.Dir(homeCfg), "config.toml")
	cwdCfg := writeMinimalConfig(t, cwd, "config.toml")
	explicitCfg := writeMinimalConfig(t, t.TempDir(), "explicit.toml")

	tests := []struct {
		name     string
		explicit string
		home     string
		cwd      string
		homeFile bool
		cwdFile  bool
		want     config.SourceKind
		wantPath string
	}{
		{
			name:     "explicit wins over everything",
			explicit: explicitCfg, home: home, cwd: cwd, homeFile: true, cwdFile: true,
			want: config.SourceExplicit, wantPath: explicitCfg,
		},
		{
			name:     "home default beats cwd default",
			explicit: "", home: home, cwd: cwd, homeFile: true, cwdFile: true,
			want: config.SourceHome, wantPath: homeCfg,
		},
		{
			name:     "cwd default when no home file",
			explicit: "", home: home, cwd: cwd, homeFile: false, cwdFile: true,
			want: config.SourceCwd, wantPath: cwdCfg,
		},
		{
			name:     "configless when nothing exists",
			explicit: "", home: home, cwd: cwd, homeFile: false, cwdFile: false,
			want: config.SourceConfigless, wantPath: "",
		},
		{
			name:     "home default without any cwd file",
			explicit: "", home: home, cwd: cwd, homeFile: true, cwdFile: false,
			want: config.SourceHome, wantPath: homeCfg,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Rebuild the home/cwd files per case so cases stay independent.
			homeCfgPath := filepath.Join(tt.home, ".config", "publicvpn", "config.toml")
			if tt.homeFile {
				require.NoError(t, os.MkdirAll(filepath.Dir(homeCfgPath), 0o750))
				require.NoError(t, os.WriteFile(homeCfgPath, []byte("data_dir = \""+filepath.Join(tt.home, "d")+"\"\n"), 0o600))
			} else {
				require.NoError(t, os.RemoveAll(homeCfgPath))
			}
			cwdCfgPath := filepath.Join(tt.cwd, "config.toml")
			if tt.cwdFile {
				require.NoError(t, os.WriteFile(cwdCfgPath, []byte("data_dir = \""+filepath.Join(tt.cwd, "d")+"\"\n"), 0o600))
			} else if err := os.Remove(cwdCfgPath); err != nil && !os.IsNotExist(err) {
				require.NoError(t, err)
			}

			res, err := config.Resolve(tt.explicit, tt.home, tt.cwd)
			require.NoError(t, err)
			require.NotNil(t, res.Config)
			assert.Equal(t, tt.want, res.Source)
			assert.Equal(t, tt.wantPath, res.Path)
		})
	}
}

// TestResolveExplicitMissingFailsLoud: an explicit -c that does not exist is
// a hard error naming the path — never a silent fall-through to defaults.
func TestResolveExplicitMissingFailsLoud(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.toml")
	_, err := config.Resolve(missing, t.TempDir(), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config not found")
	assert.Contains(t, err.Error(), missing)
}

// TestConfiglessDefaults pins the configless shape: data_dir is the XDG
// default under the injected home; every previously-required knob carries
// its default; render.template and activate.target are deliberately EMPTY —
// they are the loud stage boundaries (configless mode cannot render/activate).
func TestConfiglessDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", "") // hermetic: pin the fallback branch
	res, err := config.Resolve("", home, t.TempDir())
	require.NoError(t, err)
	require.Equal(t, config.SourceConfigless, res.Source)
	cfg := res.Config

	assert.Equal(t, filepath.Join(home, ".local", "share", "publicvpn"), cfg.DataDir,
		"data_dir defaults to the XDG data dir")
	assert.Equal(t, filepath.Join(cfg.DataDir, "plugins"), cfg.Plugins.Dir,
		"plugins dir defaults under the configless data_dir")
	assert.Equal(t, config.DefaultDoHURL, cfg.Geo.DoHURL)
	assert.Equal(t, "firefox", cfg.Render.TLSFingerprint)
	assert.Equal(t, config.DefaultTLSFingerprint, cfg.Render.TLSFingerprint)
	assert.Equal(t, 1440, cfg.Render.TCPMaxSeg)
	assert.Equal(t, config.DefaultRefreshInterval, cfg.Maintain.RefreshInterval.Duration)
	assert.Equal(t, config.DefaultUserAgent, cfg.HTTP.UserAgent)
	assert.Empty(t, cfg.Render.Template, "render.template stays empty: the configless render boundary")
	assert.Empty(t, cfg.Activate.Target, "activate.target stays empty: the configless activate boundary")
}

// TestResolveRelativeExplicitUsesInjectedCWD pins the M-2 contract: a
// relative explicit -c resolves against the INJECTED cwd, never the process
// cwd — hermetic resolution stays injectable end to end. The process cwd
// deliberately holds a DIFFERENT config.toml: process-cwd resolution would
// load the wrong file; injected-cwd resolution must load the injected one.
func TestResolveRelativeExplicitUsesInjectedCWD(t *testing.T) {
	procCwd := t.TempDir()
	otherCfg := writeMinimalConfig(t, procCwd, "config.toml")
	injected := t.TempDir()
	injectedCfg := writeMinimalConfig(t, injected, "config.toml")
	t.Chdir(procCwd)

	res, err := config.Resolve("config.toml", t.TempDir(), injected)
	require.NoError(t, err)
	require.Equal(t, config.SourceExplicit, res.Source)
	assert.Equal(t, injectedCfg, res.Path,
		"relative -c resolves against the injected cwd, not the process cwd")
	assert.NotEqual(t, otherCfg, res.Path)
}

// TestFileLoadKeepsRenderTargetDefaults pins the unchanged file-loaded
// behavior: a real config file still receives the template/target defaults
// (strict decode and defaults are untouched by the configless wave).
func TestFileLoadKeepsRenderTargetDefaults(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalConfig(t, dir, "config.toml")
	res, err := config.Resolve(path, t.TempDir(), t.TempDir())
	require.NoError(t, err)
	require.Equal(t, config.SourceExplicit, res.Source)
	assert.Equal(t, "~/projects/xray-raw/config.json", res.Config.Render.Template)
	assert.Equal(t, "~/projects/xray-raw/config.json", res.Config.Activate.Target)
}

// TestDefaultDataDirHonorsXDGDataHome pins the M-1 contract: when
// XDG_DATA_HOME is set (non-empty), the configless data dir is
// $XDG_DATA_HOME/publicvpn; when it is unset/empty, the fallback is
// <home>/.local/share/publicvpn. t.Setenv keeps both branches hermetic —
// no ambient environment leaks into either.
func TestDefaultDataDirHonorsXDGDataHome(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)
	assert.Equal(t, filepath.Join(xdg, "publicvpn"), config.DefaultDataDir(home),
		"a set XDG_DATA_HOME wins")

	t.Setenv("XDG_DATA_HOME", "")
	assert.Equal(t, filepath.Join(home, ".local", "share", "publicvpn"), config.DefaultDataDir(home),
		"empty XDG_DATA_HOME falls back to ~/.local/share/publicvpn")
}

// TestConfiglessResolutionUsesXDGDataHome pins the same contract through the
// full resolution: a configless run places data_dir under a set
// XDG_DATA_HOME.
func TestConfiglessResolutionUsesXDGDataHome(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)
	res, err := config.Resolve("", t.TempDir(), t.TempDir())
	require.NoError(t, err)
	require.Equal(t, config.SourceConfigless, res.Source)
	assert.Equal(t, filepath.Join(xdg, "publicvpn"), res.Config.DataDir)
}

// TestConfiglessEmptyHomeIsLoud pins the M-3 guard: an empty home reaching
// the configless fallback is API misuse — every caller must inject a real
// home. Pre-fix the guard was missing and the resolution silently built a
// RELATIVE data dir (.local/share/publicvpn), scattering state into
// whatever directory the process happened to stand in.
func TestConfiglessEmptyHomeIsLoud(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	cwd := t.TempDir() // no config here: resolution reaches the configless fallback
	_, err := config.Resolve("", "", cwd)
	require.Error(t, err, "empty home at the configless fallback is API misuse — loud error")
	assert.Contains(t, err.Error(), "empty home")
}

// TestSourceKindStrings pins the provenance strings every command prints.
func TestSourceKindStrings(t *testing.T) {
	assert.Equal(t, "explicit -c", config.SourceExplicit.String())
	assert.Equal(t, "home default", config.SourceHome.String())
	assert.Equal(t, "cwd default", config.SourceCwd.String())
	assert.Equal(t, "configless (built-in defaults)", config.SourceConfigless.String())
}

// TestDefaultHomeConfigPathAndDataDir pin the two path literals the docs and
// the loud messages reference.
func TestDefaultHomeConfigPathAndDataDir(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "") // hermetic: pin the fallback branch
	home := "/home/tester"
	assert.Equal(t, "/home/tester/.config/publicvpn/config.toml", config.DefaultHomeConfigPath(home))
	assert.Equal(t, "/home/tester/.local/share/publicvpn", config.DefaultDataDir(home))
}
