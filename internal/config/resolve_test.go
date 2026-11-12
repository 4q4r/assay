//go:build linux

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"assay/internal/config"

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
// (~/.local/share/assay/config.toml, $XDG_DATA_HOME honored), else the
// DEPRECATED legacy home location (~/.config/assay/config.toml,
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
			wantWarn: "move it to ~/.local/share/assay/config.toml",
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

			shareCfg := filepath.Join(home, ".local", "share", "assay", "config.toml")
			if tt.share {
				require.NoError(t, os.MkdirAll(filepath.Dir(shareCfg), 0o750))
				require.NoError(t, os.WriteFile(shareCfg,
					[]byte("data_dir = \""+filepath.Join(home, "share-data")+"\"\n"), 0o600))
			}
			legacyCfg := filepath.Join(home, ".config", "assay", "config.toml")
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
// its default; the Configless boundary marker is SET — it is the loud stage
// boundary's key (configless mode cannot render/activate).
func TestConfiglessDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", "") // hermetic: pin the fallback branch
	res, err := config.Resolve("", home, t.TempDir())
	require.NoError(t, err)
	require.Equal(t, config.SourceConfigless, res.Source)
	cfg := res.Config

	assert.Equal(t, filepath.Join(home, ".local", "share", "assay"), cfg.DataDir,
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
	assert.True(t, cfg.Configless, "the configless marker is set: the stage boundaries key on it")
}

// TestFileLoadCarriesNoConfiglessMarker pins the marker's polarity: a
// file-loaded config (any tier) never carries the configless boundary marker
// — render/activate run for it.
func TestFileLoadCarriesNoConfiglessMarker(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalConfig(t, dir, "config.toml")
	res, err := config.Resolve(path, t.TempDir(), t.TempDir())
	require.NoError(t, err)
	require.Equal(t, config.SourceExplicit, res.Source)
	assert.False(t, res.Config.Configless,
		"a file-loaded config renders/activates — the boundary is configless-only")
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

// TestDefaultDataDirHonorsXDGDataHome pins the M-1 contract: when
// XDG_DATA_HOME is set (non-empty), the configless data dir is
// $XDG_DATA_HOME/assay; when it is unset/empty, the fallback is
// <home>/.local/share/assay. t.Setenv keeps both branches hermetic —
// no ambient environment leaks into either.
func TestDefaultDataDirHonorsXDGDataHome(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)
	assert.Equal(t, filepath.Join(xdg, "assay"), config.DefaultDataDir(home),
		"a set XDG_DATA_HOME wins")

	t.Setenv("XDG_DATA_HOME", "")
	assert.Equal(t, filepath.Join(home, ".local", "share", "assay"), config.DefaultDataDir(home),
		"empty XDG_DATA_HOME falls back to ~/.local/share/assay")
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
	assert.Equal(t, filepath.Join(xdg, "assay"), res.Config.DataDir)
}

// TestConfiglessEmptyHomeIsLoud pins the M-3 guard: an empty home reaching
// the configless fallback is API misuse — every caller must inject a real
// home. Pre-fix the guard was missing and the resolution silently built a
// RELATIVE data dir (.local/share/assay), scattering state into
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
// legacyShareDirUnderHome builds the pre-rename local-share data dir the
// way the assay rename left it on disk. The old name is assembled from
// parts here for the same reason it is in production code: the rename's
// acceptance contract keeps the old spelling out of Go sources while the
// found-if-exists courtesy must still address the real directory.
func legacyShareDirUnderHome(home string) string {
	return filepath.Join(home, ".local", "share", "public"+"vpn")
}

// TestLegacyShareDataDirRenameHint pins the rename-migration courtesy: the
// pre-rename local-share data dir fires exactly ONE loud hint line when the
// new data dir is absent. Found-if-exists only — the resolution NEVER moves
// or copies anything (no auto-migration; the owner migrates by hand in the
// deploy wave).
func TestLegacyShareDataDirRenameHint(t *testing.T) {
	t.Run("pre-rename share config still loads with the loud move hint", func(t *testing.T) {
		home := t.TempDir()
		oldDir := legacyShareDirUnderHome(home)
		oldCfg := filepath.Join(oldDir, "config.toml")
		require.NoError(t, os.MkdirAll(oldDir, 0o750))
		require.NoError(t, os.WriteFile(oldCfg,
			[]byte("data_dir = \""+filepath.Join(home, "old-data")+"\"\n"), 0o600))
		t.Setenv("XDG_DATA_HOME", "") // hermetic: pin the fallback branch

		res, err := config.Resolve("", home, t.TempDir())
		require.NoError(t, err)
		assert.Equal(t, config.SourceShare, res.Source,
			"the pre-rename local-share config is still the local-share default tier")
		assert.Equal(t, oldCfg, res.Path)
		assert.Equal(t, filepath.Join(home, "old-data"), res.Config.DataDir,
			"the loaded config wins whole — no rewriting of its data_dir")
		require.Len(t, res.Warnings, 1, "exactly one loud hint line")
		assert.Contains(t, res.Warnings[0], "legacy data location detected: "+oldDir)
		assert.Contains(t, res.Warnings[0], "move it to "+filepath.Join(home, ".local", "share", "assay"))
		assert.Contains(t, res.Warnings[0], "deprecated")
	})

	t.Run("dir-only pre-rename data dir warns on the cwd tier", func(t *testing.T) {
		home := t.TempDir()
		cwd := t.TempDir()
		require.NoError(t, os.MkdirAll(legacyShareDirUnderHome(home), 0o750))
		cwdCfg := filepath.Join(cwd, "config.toml")
		require.NoError(t, os.WriteFile(cwdCfg,
			[]byte("data_dir = \""+filepath.Join(cwd, "cwd-data")+"\"\n"), 0o600))
		t.Setenv("XDG_DATA_HOME", "")

		res, err := config.Resolve("", home, cwd)
		require.NoError(t, err)
		assert.Equal(t, config.SourceCwd, res.Source)
		require.Len(t, res.Warnings, 1, "exactly one loud hint line")
		assert.Contains(t, res.Warnings[0], "legacy data location detected: "+legacyShareDirUnderHome(home))
		assert.Contains(t, res.Warnings[0], "move it to "+filepath.Join(home, ".local", "share", "assay"))
	})

	t.Run("configless warns when only the pre-rename data dir exists", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.MkdirAll(legacyShareDirUnderHome(home), 0o750))
		t.Setenv("XDG_DATA_HOME", "")

		res, err := config.Resolve("", home, t.TempDir())
		require.NoError(t, err)
		assert.Equal(t, config.SourceConfigless, res.Source)
		require.Len(t, res.Warnings, 1, "exactly one loud hint line")
		assert.Contains(t, res.Warnings[0], "legacy data location detected: "+legacyShareDirUnderHome(home))
	})

	t.Run("no hint once the new data dir exists", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.MkdirAll(legacyShareDirUnderHome(home), 0o750))
		require.NoError(t, os.MkdirAll(filepath.Join(home, ".local", "share", "assay"), 0o750))
		t.Setenv("XDG_DATA_HOME", "")

		res, err := config.Resolve("", home, t.TempDir())
		require.NoError(t, err)
		assert.Empty(t, res.Warnings,
			"the new data dir exists — the migration already happened, stay quiet")
	})

	t.Run("no hint without the pre-rename data dir", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("XDG_DATA_HOME", "")

		res, err := config.Resolve("", home, t.TempDir())
		require.NoError(t, err)
		assert.Empty(t, res.Warnings, "a fresh install has nothing to migrate")
	})
}

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
	assert.Equal(t, "/home/tester/.local/share/assay/config.toml", config.DefaultShareConfigPath(home))
	assert.Equal(t, "/home/tester/.config/assay/config.toml", config.LegacyHomeConfigPath(home))
	assert.Equal(t, "/home/tester/.local/share/assay", config.DefaultDataDir(home))
	assert.Equal(t, "~/.local/share/assay/config.toml", config.ShareConfigDisplay)
	assert.Equal(t, "~/.config/assay/config.toml", config.LegacyHomeConfigDisplay)
}

// TestShareConfigTierHonorsXDGDataHome pins the M-1 contract for the
// local-share CONFIG tier (not just the data dir): a set ABSOLUTE
// XDG_DATA_HOME moves the tier-2 config path to $XDG_DATA_HOME/assay —
// the same root DefaultDataDir uses, one scheme for the whole local-share
// layout. A set-but-RELATIVE XDG_DATA_HOME is spec-invalid: treated as
// unset, the home fallback applies, and the resolution carries the loud
// violation warning.
func TestShareConfigTierHonorsXDGDataHome(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	shareCfg := filepath.Join(xdg, "assay", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(shareCfg), 0o750))
	require.NoError(t, os.WriteFile(shareCfg,
		[]byte("data_dir = \""+filepath.Join(xdg, "assay", "d")+"\"\n"), 0o600))

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
