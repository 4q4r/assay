package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFullConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
data_dir = "/tmp/publicvpn-test-data"

[sources.matin]
repo = "MatinGhanbari/v2ray-configs"
discovery = "github-contents"
include = ["vless.txt", "all_sub.txt", "super-sub.txt"]
enabled = true

[sources.radikal]
repo = "0xRadikal/Free-v2ray-Configs"
discovery = "manifest"
manifest = "index.json"
include = ["secure/"]
enabled = true

[sources.tvc]
enabled = false

[fetch]
timeout = "20s"
retries = 2
concurrency = 3
github_token = "gh_test_token"

[probe]
path = "~/.local/bin/xray-knife"
timeout = "8s"
threads = 20
speedtest = false
check_preset = ""
url_success_threshold = 1.0
db_path = "xray-knife.db"

[geo]
endpoint = "http://ip-api.com/batch"
batch_size = 100
per_minute = 15
ttl = "24h"

[select]
per_country_cap = 4
soft_cap = 25
city_expand_threshold = 25
ceiling = 40

[render]
template = "~/projects/xray-raw/config.json"
output_dir = "rendered"
stats_port = 15490

[[render.pool_routes]]
balancer = "pool_de"
domains = ["geosite:netflix"]

[activate]
target = "~/projects/xray-raw/config.json"
xray_bin = "/usr/bin/xray"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	cfg, err := config.Load(path)
	require.NoError(t, err)

	assert.Equal(t, "/tmp/publicvpn-test-data", cfg.DataDir)
	assert.Len(t, cfg.Sources, 3)
	matin := cfg.Sources["matin"]
	assert.Equal(t, "github-contents", matin.Discovery)
	assert.True(t, matin.IsEnabled())
	assert.Equal(t, []string{"vless.txt", "all_sub.txt", "super-sub.txt"}, matin.Include)
	radikal := cfg.Sources["radikal"]
	assert.Equal(t, "manifest", radikal.Discovery)
	assert.Equal(t, "index.json", radikal.Manifest)
	assert.False(t, cfg.Sources["tvc"].IsEnabled())

	assert.Equal(t, 20*time.Second, cfg.Fetch.Timeout.Duration)
	assert.Equal(t, 2, cfg.Fetch.Retries)
	assert.Equal(t, 3, cfg.Fetch.Concurrency)
	assert.Equal(t, "gh_test_token", cfg.Fetch.GitHubToken)

	assert.Equal(t, "~/.local/bin/xray-knife", cfg.Probe.Path)
	assert.Equal(t, 8*time.Second, cfg.Probe.Timeout.Duration)
	assert.Equal(t, 20, cfg.Probe.Threads)
	assert.False(t, cfg.Probe.Speedtest)

	assert.Equal(t, 100, cfg.Geo.BatchSize)
	assert.Equal(t, 15, cfg.Geo.PerMinute)
	assert.Equal(t, 24*time.Hour, cfg.Geo.TTL.Duration)

	assert.Equal(t, 4, cfg.Select.PerCountryCap)
	assert.Equal(t, 25, cfg.Select.SoftCap)
	assert.Equal(t, 25, cfg.Select.CityExpandThreshold)
	assert.Equal(t, 40, cfg.Select.Ceiling)

	assert.Equal(t, 15490, cfg.Render.StatsPort)
	require.Len(t, cfg.Render.PoolRoutes, 1)
	assert.Equal(t, "pool_de", cfg.Render.PoolRoutes[0].Balancer)
	assert.Equal(t, []string{"geosite:netflix"}, cfg.Render.PoolRoutes[0].Domains)

	assert.Equal(t, "/usr/bin/xray", cfg.Activate.XrayBin)
}

func TestDefaultsAreApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	minimal := `
data_dir = "/tmp/publicvpn-defaults"

[sources.matin]
repo = "MatinGhanbari/v2ray-configs"
discovery = "github-contents"
`
	require.NoError(t, os.WriteFile(path, []byte(minimal), 0o644))
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, cfg.Fetch.Timeout.Duration)
	assert.Equal(t, 3, cfg.Fetch.Retries)
	assert.Equal(t, 4, cfg.Fetch.Concurrency)
	assert.True(t, cfg.Sources["matin"].IsEnabled(), "a declared source defaults to enabled")
	assert.Equal(t, "~/.local/bin/xray-knife", cfg.Probe.Path)
	assert.Equal(t, 10*time.Second, cfg.Probe.Timeout.Duration)
	assert.Equal(t, 20, cfg.Probe.Threads)
	assert.Equal(t, "http://ip-api.com/batch", cfg.Geo.Endpoint)
	assert.Equal(t, 100, cfg.Geo.BatchSize)
	assert.Equal(t, 15, cfg.Geo.PerMinute)
	assert.Equal(t, 24*time.Hour, cfg.Geo.TTL.Duration)
	assert.Equal(t, 3, cfg.Select.PerCountryCap)
	assert.Equal(t, 25, cfg.Select.SoftCap)
	assert.Equal(t, 25, cfg.Select.CityExpandThreshold)
	assert.Equal(t, 40, cfg.Select.Ceiling)
	assert.Equal(t, 15490, cfg.Render.StatsPort)
	assert.Equal(t, "~/projects/xray-raw/config.json", cfg.Render.Template)
	assert.Equal(t, "~/projects/xray-raw/config.json", cfg.Activate.Target)
	assert.Equal(t, "/usr/bin/xray", cfg.Activate.XrayBin)
}

func TestUnknownSourceKeyFailsLoud(t *testing.T) {
	// Owner convention: unknown config keys fail loudly (hhauto api.auth_users precedent).
	path := filepath.Join(t.TempDir(), "config.toml")
	content := `
data_dir = "/tmp/x"

[fetch]
time_out = "30s"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	_, err := config.Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "strict mode", "unknown keys must fail loudly")
}

func TestValidationRejectsBadConfig(t *testing.T) {
	t.Run("no enabled sources", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[sources.tvc]
enabled = false
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := config.Load(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no enabled sources")
	})

	t.Run("bad discovery method", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[sources.matin]
repo = "a/b"
discovery = "telepathy"
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := config.Load(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "discovery")
	})

	t.Run("cap window invalid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[sources.matin]
repo = "a/b"
discovery = "github-contents"

[select]
per_country_cap = 0
soft_cap = 25
city_expand_threshold = 25
ceiling = 10
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := config.Load(path)
		require.Error(t, err)
	})

	t.Run("geo endpoint must be http (ip-api free tier is HTTP-only)", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[sources.matin]
repo = "a/b"
discovery = "github-contents"

[geo]
endpoint = "https://ip-api.com/batch"
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := config.Load(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "http")
	})

	t.Run("stats port must be unprivileged", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[sources.matin]
repo = "a/b"
discovery = "github-contents"

[render]
stats_port = 80
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := config.Load(path)
		require.Error(t, err)
	})
}

// TestFilterSourceCapConfigParsesAndValidates pins the [filter] section:
// source_cap defaults to unlimited (0) and negative values fail validation
// (review finding 6).
func TestFilterSourceCapConfigParsesAndValidates(t *testing.T) {
	base := func(caps string) string {
		return fmt.Sprintf(`
data_dir = "/tmp/publicvpn-test"
[sources.s]
repo = "owner/repo"
discovery = "github-contents"
include = ["vless.txt"]
[filter]
source_cap = %s
`, caps)
	}
	write := func(content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	cfg, err := config.Load(write(base("2")))
	require.NoError(t, err)
	assert.Equal(t, 2, cfg.Filter.SourceCap)

	_, err = config.Load(write(base("-1")))
	require.Error(t, err, "negative cap is a config error, not unlimited")
	assert.Contains(t, err.Error(), "source_cap")
}
