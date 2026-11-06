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

// TestResolvePrecedence pins the config resolution contract (W13-deploy
// rework): ONE file wins whole — explicit -c, else the local-share default
// (~/.local/share/publicvpn/config.toml, $XDG_DATA_HOME honored), else the
// DEPRECATED legacy home location (~/.config/publicvpn/config.toml,
// found-if-exists courtesy with a loud move warning — one release cycle),
// else the cwd default, else fully configless. There is no merging, ever
// (owner house rule).
func TestResolvePrecedence(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		share    bool
		legacy   bool
		cwdFile  bool
		want     config.SourceKind
		wantWarn string
	}{
		{
			name:     "explicit wins over everything",
			explicit: "EXPLICIT", share: true, legacy: true, cwdFile: true,
			want: config.SourceExplicit,
		},
		{
			name:  "share default beats cwd default",
			share: true, cwdFile: true,
			want: config.SourceShare,
		},
		{
			name:    "cwd default when no share file",
			cwdFile: true,
			want:    config.SourceCwd,
		},
		{
			name: "configless when nothing exists",
			want: config.SourceConfigless,
		},
		{
			name:   "legacy home location wins over cwd with a loud move warning",
			legacy: true, cwdFile: true,
			want:     config.SourceLegacyHome,
			wantWarn: "move it to ~/.local/share/publicvpn/config.toml",
		},
		{
			name:  "share beats legacy; the ignored legacy file still warns",
			share: true, legacy: true,
			want:     config.SourceShare,
			wantWarn: "legacy config location",
		},
		{
			name:  "share default without any cwd file",
			share: true,
			want:  config.SourceShare,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			cwd := t.TempDir()
			explicitCfg := writeMinimalConfig(t, t.TempDir(), "explicit.toml")

			shareCfg := filepath.Join(home, ".local", "share", "publicvpn", "config.toml")
			if tt.share {
				require.NoError(t, os.MkdirAll(filepath.Dir(shareCfg), 0o750))
				require.NoError(t, os.WriteFile(shareCfg,
					[]byte("data_dir = \""+filepath.Join(home, "share-data")+"\"\n"), 0o600))
			}
			legacyCfg := filepath.Join(home, ".config", "publicvpn", "config.toml")
			if tt.legacy {
				require.NoError(t, os.MkdirAll(filepath.Dir(legacyCfg), 0o750))
				require.NoError(t, os.WriteFile(legacyCfg,
					[]byte("data_dir = \""+filepath.Join(home, "legacy-data")+"\"\n"), 0o600))
			}
			cwdCfg := filepath.Join(cwd, "config.toml")
			if tt.cwdFile {
				require.NoError(t, os.WriteFile(cwdCfg,
					[]byte("data_dir = \""+filepath.Join(cwd, "cwd-data")+"\"\n"), 0o600))
			}

			explicit := tt.explicit
			if explicit == "EXPLICIT" {
				explicit = explicitCfg
			}
			res, err := config.Resolve(explicit, home, cwd)
			require.NoError(t, err)
			require.NotNil(t, res.Config)
			assert.Equal(t, tt.want, res.Source)
			switch tt.want {
			case config.SourceExplicit:
				assert.Equal(t, explicitCfg, res.Path)
			case config.SourceShare:
				assert.Equal(t, shareCfg, res.Path)
			case config.SourceLegacyHome:
				assert.Equal(t, legacyCfg, res.Path)
			case config.SourceCwd:
				assert.Equal(t, cwdCfg, res.Path)
			case config.SourceConfigless:
				assert.Empty(t, res.Path)
			}
			if tt.wantWarn == "" {
				assert.Empty(t, res.Warnings, "no warnings expected")
			} else {
				require.Len(t, res.Warnings, 1, "the legacy location must carry exactly one loud warning")
				assert.Contains(t, res.Warnings[0], tt.wantWarn)
				assert.Contains(t, res.Warnings[0], "deprecated")
			}
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
	assert.True(t, cfg.Geo.UnlockProbesEnabled(),
		"unlock_probes defaults ON in the configless path too (owner ruling 2026-11-06)")
	assert.True(t, cfg.Probe.TCPPrefilterEnabled(),
		"tcp_prefilter defaults ON in the configless path too (wave-1 probe-optimization default)")
	assert.Equal(t, config.DefaultProbePrefilterWorkers, cfg.Probe.TCPPrefilterWorkers)
	assert.Equal(t, config.DefaultProbePrefilterTimeout, cfg.Probe.TCPPrefilterTimeout.Duration)
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

// TestSourceKindStrings pins the provenance strings every command prints
// (the W13-deploy tier names: the local-share default and the deprecated
// legacy home location).
func TestSourceKindStrings(t *testing.T) {
	assert.Equal(t, "explicit -c", config.SourceExplicit.String())
	assert.Equal(t, "local-share default", config.SourceShare.String())
	assert.Equal(t, "legacy home default", config.SourceLegacyHome.String())
	assert.Equal(t, "cwd default", config.SourceCwd.String())
	assert.Equal(t, "configless (built-in defaults)", config.SourceConfigless.String())
}

// TestDefaultConfigPathLiterals pin the three path literals the docs and
// the loud messages reference: the canonical local-share config, the
// deprecated legacy location, and the data dir.
func TestDefaultConfigPathLiterals(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "") // hermetic: pin the fallback branch
	home := "/home/tester"
	assert.Equal(t, "/home/tester/.local/share/publicvpn/config.toml", config.DefaultShareConfigPath(home))
	assert.Equal(t, "/home/tester/.config/publicvpn/config.toml", config.LegacyHomeConfigPath(home))
	assert.Equal(t, "/home/tester/.local/share/publicvpn", config.DefaultDataDir(home))
	assert.Equal(t, "~/.local/share/publicvpn/config.toml", config.ShareConfigDisplay)
	assert.Equal(t, "~/.config/publicvpn/config.toml", config.LegacyHomeConfigDisplay)
}

// TestShareConfigTierHonorsXDGDataHome pins the M-1 contract for the
// local-share CONFIG tier (not just the data dir): a set ABSOLUTE
// XDG_DATA_HOME moves the tier-2 config path to $XDG_DATA_HOME/publicvpn —
// the same root DefaultDataDir uses, one scheme for the whole local-share
// layout. A set-but-RELATIVE XDG_DATA_HOME is spec-invalid: treated as
// unset, the home fallback applies, and the resolution carries the loud
// violation warning.
func TestShareConfigTierHonorsXDGDataHome(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	shareCfg := filepath.Join(xdg, "publicvpn", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(shareCfg), 0o750))
	require.NoError(t, os.WriteFile(shareCfg,
		[]byte("data_dir = \""+filepath.Join(xdg, "publicvpn", "d")+"\"\n"), 0o600))

	t.Run("absolute XDG moves the tier", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", xdg)
		res, err := config.Resolve("", home, t.TempDir())
		require.NoError(t, err)
		assert.Equal(t, config.SourceShare, res.Source)
		assert.Equal(t, shareCfg, res.Path)
	})

	t.Run("relative XDG treated as unset with the loud warning", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "relative/path")
		// The relative-XDG root does not exist under home, so the resolution
		// falls through to configless — but the violation warning must fire.
		res, err := config.Resolve("", home, t.TempDir())
		require.NoError(t, err)
		assert.Equal(t, config.SourceConfigless, res.Source)
		require.NotEmpty(t, res.Warnings)
		assert.Contains(t, res.Warnings[0], "XDG_DATA_HOME")
	})
}
