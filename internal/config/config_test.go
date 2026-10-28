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

// TestMaintainSectionParsesAndDefaults pins the W4 [maintain] section:
// prune_dead_after defaults to 48h when absent, parses Go durations when set,
// rejects negatives loudly, and unknown keys inside the section fail the
// strict decode (owner convention).
func TestMaintainSectionParsesAndDefaults(t *testing.T) {
	write := func(content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	base := `data_dir = "/tmp/publicvpn-maintain"
[sources.s]
repo = "owner/repo"
discovery = "github-contents"
include = ["vless.txt"]
`

	t.Run("absent section defaults to 48h", func(t *testing.T) {
		cfg, err := config.Load(write(base))
		require.NoError(t, err)
		assert.Equal(t, 48*time.Hour, cfg.Maintain.PruneDeadAfter.Duration,
			"maintain.prune_dead_after must default to 48h (DESIGN §4.9)")
	})

	t.Run("explicit value parses", func(t *testing.T) {
		cfg, err := config.Load(write(base + "\n[maintain]\nprune_dead_after = \"72h\"\n"))
		require.NoError(t, err)
		assert.Equal(t, 72*time.Hour, cfg.Maintain.PruneDeadAfter.Duration)
	})

	t.Run("negative value fails loud", func(t *testing.T) {
		_, err := config.Load(write(base + "\n[maintain]\nprune_dead_after = \"-1h\"\n"))
		require.Error(t, err, "a negative prune window is a config error, not 'never prune'")
		assert.Contains(t, err.Error(), "prune_dead_after")
	})

	t.Run("unknown key fails strict decode", func(t *testing.T) {
		_, err := config.Load(write(base + "\n[maintain]\nprune_dead_aftr = \"48h\"\n"))
		require.Error(t, err, "unknown keys inside [maintain] must fail the strict decode (owner convention)")
		assert.Contains(t, err.Error(), "strict mode")
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

// writeCfg writes a TOML body to a temp file and returns its path.
func writeCfg(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

func load(t *testing.T, body string) *config.Config {
	t.Helper()
	cfg, err := config.Load(writeCfg(t, body))
	require.NoError(t, err)
	return cfg
}

// TestMaintainIntervalsDefaultsFloorAndStrict pins the W5 knobs: defaults
// 6h/168h, a 5-minute floor with loud failure below, and strict decoding.
func TestMaintainIntervalsDefaultsFloorAndStrict(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n[sources.s]\nrepo = \"o/r\"\ndiscovery = \"github-contents\"\n")
		assert.Equal(t, 6*time.Hour, cfg.Maintain.RefreshInterval.Duration)
		assert.Equal(t, 168*time.Hour, cfg.Maintain.SpeedtestInterval.Duration)
	})
	t.Run("custom values parse", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n[sources.s]\nrepo = \"o/r\"\ndiscovery = \"github-contents\"\n[maintain]\nrefresh_interval = \"90m\"\nspeedtest_interval = \"240h\"\n")
		assert.Equal(t, 90*time.Minute, cfg.Maintain.RefreshInterval.Duration)
		assert.Equal(t, 240*time.Hour, cfg.Maintain.SpeedtestInterval.Duration)
	})
	t.Run("below floor fails loud", func(t *testing.T) {
		for name, val := range map[string]string{
			"refresh_interval":   `"4m"`,
			"speedtest_interval": `"1m"`,
		} {
			_, err := config.Load(writeCfg(t, "data_dir = \"d\"\n[sources.s]\nrepo = \"o/r\"\ndiscovery = \"github-contents\"\n[maintain]\n"+name+" = "+val+"\n"))
			require.Error(t, err, "%s below the 5m floor must fail", name)
			assert.Contains(t, err.Error(), "5m0s")
		}
	})
	t.Run("unknown maintain key fails loud", func(t *testing.T) {
		_, err := config.Load(writeCfg(t, "data_dir = \"d\"\n[sources.s]\nrepo = \"o/r\"\ndiscovery = \"github-contents\"\n[maintain]\nrefresh_intervalz = \"6h\"\n"))
		require.Error(t, err)
	})
}

// TestFilterProtocolsAndAllowInsecureConfig pins the W5 filter policy knobs.
func TestFilterProtocolsAndAllowInsecureConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n[sources.s]\nrepo = \"o/r\"\ndiscovery = \"github-contents\"\n")
		assert.Equal(t, []string{"vless", "vmess", "trojan"}, cfg.Filter.Protocols)
		assert.False(t, cfg.Filter.AllowInsecure)
	})
	t.Run("ss opt-in", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n[sources.s]\nrepo = \"o/r\"\ndiscovery = \"github-contents\"\n[filter]\nprotocols = [\"vless\", \"ss\"]\nallow_insecure = true\n")
		assert.Equal(t, []string{"vless", "ss"}, cfg.Filter.Protocols)
		assert.True(t, cfg.Filter.AllowInsecure)
	})
	t.Run("unknown scheme fails loud", func(t *testing.T) {
		_, err := config.Load(writeCfg(t, "data_dir = \"d\"\n[sources.s]\nrepo = \"o/r\"\ndiscovery = \"github-contents\"\n[filter]\nprotocols = [\"vless\", \"tuic\"]\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tuic")
	})
}
