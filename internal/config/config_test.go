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
doh_url = "https://dns.google/resolve"
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
	assert.Equal(t, "/tmp/publicvpn-test-data/plugins", cfg.Plugins.Dir, "plugins dir defaults under data_dir")

	assert.Equal(t, 20*time.Second, cfg.Fetch.Timeout.Duration)
	assert.Equal(t, 2, cfg.Fetch.Retries)
	assert.Equal(t, 3, cfg.Fetch.Concurrency)
	assert.Equal(t, "gh_test_token", cfg.Fetch.GitHubToken)

	assert.Equal(t, "~/.local/bin/xray-knife", cfg.Probe.Path)
	assert.Equal(t, 8*time.Second, cfg.Probe.Timeout.Duration)
	assert.Equal(t, 20, cfg.Probe.Threads)
	require.NotNil(t, cfg.Probe.Speedtest)
	assert.False(t, *cfg.Probe.Speedtest, "explicit speedtest=false is honored")
	assert.False(t, cfg.Probe.IsSpeedtest())

	assert.Equal(t, 24*time.Hour, cfg.Geo.TTL.Duration)
	assert.Equal(t, "https://dns.google/resolve", cfg.Geo.DoHURL, "explicit doh_url from the full config")

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

`
	require.NoError(t, os.WriteFile(path, []byte(minimal), 0o644))
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, cfg.Fetch.Timeout.Duration)
	assert.Equal(t, 3, cfg.Fetch.Retries)
	assert.Equal(t, 4, cfg.Fetch.Concurrency)
	assert.True(t, cfg.Probe.IsSpeedtest(), "speedtest defaults to ON (W10 owner ruling)")
	assert.Nil(t, cfg.Probe.Speedtest)
	assert.Equal(t, "~/.local/bin/xray-knife", cfg.Probe.Path)
	assert.Equal(t, 10*time.Second, cfg.Probe.Timeout.Duration)
	assert.Equal(t, 20, cfg.Probe.Threads)
	assert.Equal(t, "https://dns.google/resolve", cfg.Geo.DoHURL, "doh_url defaults to the dns.google/resolve DoH endpoint")
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
	t.Run("removed [sources.*] section fails loud with the migration path", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[sources.matin]
repo = "MatinGhanbari/v2ray-configs"
discovery = "github-contents"
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := config.Load(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "[sources.*] section was removed")
		assert.Contains(t, err.Error(), "[plugins]")
		assert.Contains(t, err.Error(), "matin, epodonios, radikal, haker, stintikvpn")
	})

	t.Run("unknown key still fails loud", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[frobnicate]
level = 11
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := config.Load(path)
		require.Error(t, err)
		// go-toml strict mode names no field in the message (the known
		// generic-message behavior — the [sources] migration check above
		// exists precisely to give the loud, actionable variant).
		assert.Contains(t, err.Error(), "strict mode")
	})

	t.Run("cap window invalid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"


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

	t.Run("removed [geo] batch keys fail loud naming the exact keys and the replacement", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[geo]
endpoint = "http://ip-api.com/batch"
batch_size = 100
per_minute = 15
ttl = "24h"
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := config.Load(path)
		require.Error(t, err)
		msg := err.Error()
		// The loud migration must name EVERY dead key and the replacement.
		assert.Contains(t, msg, "geo.endpoint")
		assert.Contains(t, msg, "geo.batch_size")
		assert.Contains(t, msg, "geo.per_minute")
		assert.Contains(t, msg, "removed")
		assert.Contains(t, msg, "self-report", "the replacement (per-node in-tunnel self-report) must be named")
		assert.Contains(t, msg, "[geo].doh_url", "the surviving fallback knob must be named")
		assert.Contains(t, msg, "Delete the dead key(s)", "the owner must be told exactly what to do")
	})

	t.Run("geo.doh_url must be https (DoH is a TLS protocol)", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[geo]
doh_url = "http://dns.google/resolve"
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := config.Load(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
		assert.Contains(t, err.Error(), "geo.doh_url")
	})

	t.Run("stats port must be unprivileged", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"


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

// TestMaintainIntervalsDefaultsFloorAndStrict pins the maintain knobs:
// defaults 1h (W10)/168h, a 5-minute floor with loud failure below, and
// strict decoding.
func TestMaintainIntervalsDefaultsFloorAndStrict(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n")
		assert.Equal(t, time.Hour, cfg.Maintain.RefreshInterval.Duration, "refresh default is 1h (W10 owner ruling)")
		assert.Equal(t, 168*time.Hour, cfg.Maintain.SpeedtestInterval.Duration)
	})
	t.Run("custom values parse", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n[maintain]\nrefresh_interval = \"90m\"\nspeedtest_interval = \"240h\"\n")
		assert.Equal(t, 90*time.Minute, cfg.Maintain.RefreshInterval.Duration)
		assert.Equal(t, 240*time.Hour, cfg.Maintain.SpeedtestInterval.Duration)
	})
	t.Run("below floor fails loud", func(t *testing.T) {
		for name, val := range map[string]string{
			"refresh_interval":   `"4m"`,
			"speedtest_interval": `"1m"`,
		} {
			_, err := config.Load(writeCfg(t, "data_dir = \"d\"\n[maintain]\n"+name+" = "+val+"\n"))
			require.Error(t, err, "%s below the 5m floor must fail", name)
			assert.Contains(t, err.Error(), "5m0s")
		}
	})
	t.Run("unknown maintain key fails loud", func(t *testing.T) {
		_, err := config.Load(writeCfg(t, "data_dir = \"d\"\n[maintain]\nrefresh_intervalz = \"6h\"\n"))
		require.Error(t, err)
	})
}

// TestFilterProtocolsAndAllowInsecureConfig pins the W5 filter policy knobs.
func TestFilterProtocolsAndAllowInsecureConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n")
		assert.Equal(t, []string{"vless", "vmess", "trojan"}, cfg.Filter.Protocols)
		assert.False(t, cfg.Filter.AllowInsecure)
	})
	t.Run("ss opt-in", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n[filter]\nprotocols = [\"vless\", \"ss\"]\nallow_insecure = true\n")
		assert.Equal(t, []string{"vless", "ss"}, cfg.Filter.Protocols)
		assert.True(t, cfg.Filter.AllowInsecure)
	})
	t.Run("unknown scheme fails loud", func(t *testing.T) {
		_, err := config.Load(writeCfg(t, "data_dir = \"d\"\n[filter]\nprotocols = [\"vless\", \"tuic\"]\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tuic")
	})
}

// w6Base is the minimal valid config body every W6 knob test builds on.
const w6Base = "data_dir = \"d\"\n"

// TestW6PoolInboundTagsDeduplicatedAtLoad pins M-4: duplicate entries in
// [render].pool_inbound_tags are collapsed at config load — order preserved,
// FIRST occurrence wins (a later re-appearance must not resurrect the tag).
func TestW6PoolInboundTagsDeduplicatedAtLoad(t *testing.T) {
	cfg := load(t, w6Base+`[render]
pool_inbound_tags = ["socks-in", "socks-in", "tun-in", "tun-in", "socks-in", "http-in"]
`)
	assert.Equal(t, []string{"socks-in", "tun-in", "http-in"}, cfg.Render.PoolInboundTags,
		"duplicates must collapse at load: first occurrence wins, order preserved")
}

// TestW6KnobDefaults pins the owner-ruled defaults of every W6 knob: absent
// keys must reproduce today's exact behavior (the W6 binding ruling — defaults
// preserve current behavior, and NO artificial floor/ceiling/range validation
// exists on any of them; only sign correctness is structural).
func TestW6KnobDefaults(t *testing.T) {
	cfg := load(t, w6Base)

	// Gap-0
	assert.Equal(t, 6*time.Hour, cfg.Fetch.CacheMaxAge.Duration)
	// P1
	require.NotNil(t, cfg.Activate.TestTimeout, "activate.test_timeout must default (30s), not nil")
	assert.Equal(t, 30*time.Second, cfg.Activate.TestTimeout.Duration)
	assert.Equal(t, []string{"socks-in", "http-in"}, cfg.Render.PoolInboundTags)
	assert.Equal(t, "60s", cfg.Render.ObservatoryInterval)
	assert.Equal(t, 1440, cfg.Render.TCPMaxSeg)
	assert.Equal(t, time.Duration(0), cfg.Probe.SkipFreshWithin.Duration, "probe everything by default")
	// P2
	assert.Equal(t, "firefox", cfg.Render.TLSFingerprint)
	assert.InDelta(t, 0.2, cfg.Render.BalancerTolerance, 1e-9)
	assert.Equal(t, "https://api.github.com", cfg.Fetch.APIBase)
	assert.Equal(t, "https://raw.githubusercontent.com", cfg.Fetch.RawBase)
	assert.Equal(t, "public_vpn (pipeline; contact: owner)", cfg.HTTP.UserAgent)
	assert.Equal(t, "xray-raw.service", cfg.Activate.ServiceName)
	assert.Equal(t, 10*time.Second, cfg.Maintain.StatsTimeout.Duration)
	assert.InDelta(t, 1.2, cfg.Select.TieBandRTTTolerance, 1e-9)
	assert.Equal(t, 0, cfg.Activate.BackupKeep, "0 = unlimited retention")
	assert.Equal(t, 0, cfg.Maintain.PruneBackupKeep, "0 = unlimited retention")
}

// TestW6KnobsParseExplicitValues pins that every W6 knob accepts its value
// verbatim — STRING passthrough stays a passthrough (no canonicalization),
// durations and numbers parse, and none of them carries a range bound.
func TestW6KnobsParseExplicitValues(t *testing.T) {
	cfg := load(t, w6Base+`
[fetch]
cache_max_age = "90m"
api_base = "https://ghmirror.example.net"
raw_base = "https://raw-mirror.example.net"

[http]
user_agent = "publicvpn/6 (custom)"

[probe]
skip_fresh_within = "15m"

[select]
tie_band_rtt_tolerance = 2.5

[render]
pool_inbound_tags = ["socks-in", "http-in", "tun-in"]
observatory_interval = "45s"
tcp_max_seg = 1380
tls_fingerprint = "chrome"
balancer_tolerance = 0.5

[activate]
test_timeout = "1m"
service_name = "xray-custom.service"
backup_keep = 3

[maintain]
stats_timeout = "20s"
prune_backup_keep = 5
`)
	assert.Equal(t, 90*time.Minute, cfg.Fetch.CacheMaxAge.Duration)
	assert.Equal(t, "https://ghmirror.example.net", cfg.Fetch.APIBase)
	assert.Equal(t, "https://raw-mirror.example.net", cfg.Fetch.RawBase)
	assert.Equal(t, "publicvpn/6 (custom)", cfg.HTTP.UserAgent)
	assert.Equal(t, 15*time.Minute, cfg.Probe.SkipFreshWithin.Duration)
	assert.InDelta(t, 2.5, cfg.Select.TieBandRTTTolerance, 1e-9)
	assert.Equal(t, []string{"socks-in", "http-in", "tun-in"}, cfg.Render.PoolInboundTags)
	assert.Equal(t, "45s", cfg.Render.ObservatoryInterval, "string passthrough: rendered verbatim")
	assert.Equal(t, 1380, cfg.Render.TCPMaxSeg)
	assert.Equal(t, "chrome", cfg.Render.TLSFingerprint)
	assert.InDelta(t, 0.5, cfg.Render.BalancerTolerance, 1e-9)
	require.NotNil(t, cfg.Activate.TestTimeout)
	assert.Equal(t, time.Minute, cfg.Activate.TestTimeout.Duration)
	assert.Equal(t, "xray-custom.service", cfg.Activate.ServiceName)
	assert.Equal(t, 3, cfg.Activate.BackupKeep)
	assert.Equal(t, 20*time.Second, cfg.Maintain.StatsTimeout.Duration)
	assert.Equal(t, 5, cfg.Maintain.PruneBackupKeep)
}

// TestW6ZeroSemantics pins the owner-specified zero meanings: an explicit
// cache_max_age = "0s" means ALWAYS fetch (never the 6h default), an explicit
// test_timeout = "0s" means NO -test deadline, and 0 stays the unlimited /
// probe-everything default for the retention and freshness knobs.
func TestW6ZeroSemantics(t *testing.T) {
	t.Run("cache_max_age 0s = always fetch", func(t *testing.T) {
		cfg := load(t, w6Base+"[fetch]\ncache_max_age = \"0s\"\n")
		require.NotNil(t, cfg.Fetch.CacheMaxAge, "an explicit 0s must survive as 0, not collapse into the default")
		assert.Equal(t, time.Duration(0), cfg.Fetch.CacheMaxAge.Duration)
	})
	t.Run("test_timeout 0s = no deadline", func(t *testing.T) {
		cfg := load(t, w6Base+"[activate]\ntest_timeout = \"0s\"\n")
		require.NotNil(t, cfg.Activate.TestTimeout)
		assert.Equal(t, time.Duration(0), cfg.Activate.TestTimeout.Duration)
	})
	t.Run("backup keep 0 = unlimited", func(t *testing.T) {
		cfg := load(t, w6Base+"[activate]\nbackup_keep = 0\n[maintain]\nprune_backup_keep = 0\n")
		assert.Equal(t, 0, cfg.Activate.BackupKeep)
		assert.Equal(t, 0, cfg.Maintain.PruneBackupKeep)
	})
	t.Run("skip_fresh_within 0s = probe everything", func(t *testing.T) {
		cfg := load(t, w6Base+"[probe]\nskip_fresh_within = \"0s\"\n")
		assert.Equal(t, time.Duration(0), cfg.Probe.SkipFreshWithin.Duration)
	})
}

// TestW6NegativeValuesAreStructurallyInvalid pins the ONLY structural check
// the owner ruled in: negative numbers are sign-invalid, on every numeric W6
// knob. This is not a range bound — every non-negative value must load.
func TestW6NegativeValuesAreStructurallyInvalid(t *testing.T) {
	cases := map[string]string{
		"fetch.cache_max_age":           "[fetch]\ncache_max_age = \"-1s\"\n",
		"activate.test_timeout":         "[activate]\ntest_timeout = \"-5s\"\n",
		"activate.backup_keep":          "[activate]\nbackup_keep = -1\n",
		"probe.skip_fresh_within":       "[probe]\nskip_fresh_within = \"-1s\"\n",
		"select.tie_band_rtt_tolerance": "[select]\ntie_band_rtt_tolerance = -0.5\n",
		"render.tcp_max_seg":            "[render]\ntcp_max_seg = -1\n",
		"render.balancer_tolerance":     "[render]\nbalancer_tolerance = -0.2\n",
		"maintain.stats_timeout":        "[maintain]\nstats_timeout = \"-1s\"\n",
		"maintain.prune_backup_keep":    "[maintain]\nprune_backup_keep = -2\n",
		"plugins.run_timeout":           "[plugins]\nrun_timeout = \"-1s\"\n",
	}
	for name, section := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(writeCfg(t, w6Base+section))
			require.Error(t, err, "%s: a negative value is structurally invalid", name)
			assert.Contains(t, err.Error(), name)
		})
	}
}

// TestW6UnboundedValuesLoad pins the owner ruling directly: values far below
// or above the analyst's rejected recommendations MUST load — no floor, no
// ceiling, no range on any W6 knob.
func TestW6UnboundedValuesLoad(t *testing.T) {
	cfg := load(t, w6Base+`
[fetch]
cache_max_age = "1s"

[probe]
skip_fresh_within = "1s"

[select]
tie_band_rtt_tolerance = 100.0

[render]
observatory_interval = "5s"
tcp_max_seg = 1
balancer_tolerance = 99.0

[activate]
test_timeout = "1s"
backup_keep = 1

[maintain]
stats_timeout = "1s"
prune_backup_keep = 1
`)
	assert.Equal(t, time.Second, cfg.Fetch.CacheMaxAge.Duration)
	assert.Equal(t, time.Second, cfg.Probe.SkipFreshWithin.Duration)
	assert.InDelta(t, 100.0, cfg.Select.TieBandRTTTolerance, 1e-9)
	assert.Equal(t, "5s", cfg.Render.ObservatoryInterval)
	assert.Equal(t, 1, cfg.Render.TCPMaxSeg)
	assert.InDelta(t, 99.0, cfg.Render.BalancerTolerance, 1e-9)
	require.NotNil(t, cfg.Activate.TestTimeout)
	assert.Equal(t, time.Second, cfg.Activate.TestTimeout.Duration)
	assert.Equal(t, 1, cfg.Activate.BackupKeep)
	assert.Equal(t, time.Second, cfg.Maintain.StatsTimeout.Duration)
	assert.Equal(t, 1, cfg.Maintain.PruneBackupKeep)
}

// TestPluginRunTimeoutConfigParsesAndDefaults pins the W10 I-1 knob: unset →
// the 120s default; an explicit value passes through; an explicit "0s" means
// UNBOUNDED (owner ruling — no artificial floor, the same 0-semantics class
// as activate.test_timeout).
func TestPluginRunTimeoutConfigParsesAndDefaults(t *testing.T) {
	cfg := load(t, w6Base+"")
	require.NotNil(t, cfg.Plugins.RunTimeout, "the knob resolves to a value even when unset")
	assert.Equal(t, config.DefaultPluginRunTimeout, cfg.Plugins.RunTimeout.Duration,
		"unset run_timeout = the 120s default")

	cfg = load(t, w6Base+"[plugins]\nrun_timeout = \"45s\"\n")
	require.NotNil(t, cfg.Plugins.RunTimeout)
	assert.Equal(t, 45*time.Second, cfg.Plugins.RunTimeout.Duration, "explicit value passes through")

	cfg = load(t, w6Base+"[plugins]\nrun_timeout = \"0s\"\n")
	require.NotNil(t, cfg.Plugins.RunTimeout)
	assert.Equal(t, time.Duration(0), cfg.Plugins.RunTimeout.Duration,
		"explicit 0s = unbounded (no artificial floor)")
}

// TestW6UnknownKeysFailStrict pins that the strict decode covers every new W6
// section and key (owner convention: unknown keys never pass silently).
func TestW6UnknownKeysFailStrict(t *testing.T) {
	for _, section := range []string{
		"[http]\nuser_agentx = \"x\"\n",
		"[fetch]\ncache_max_agex = \"6h\"\n",
		"[render]\ntcp_max_segg = 1440\n",
		"[activate]\nbackup_keeep = 1\n",
		"[maintain]\nstats_timeoutx = \"10s\"\n",
	} {
		_, err := config.Load(writeCfg(t, w6Base+section))
		require.Error(t, err, "unknown key must fail the strict decode")
		assert.Contains(t, err.Error(), "strict mode")
	}
}
