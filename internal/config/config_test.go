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
timeout = "8s"
threads = 20
speedtest = false
attempts = 2
speedtest_url = "https://example.test/down"

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

	assert.Equal(t, 8*time.Second, cfg.Probe.Timeout.Duration)
	assert.Equal(t, 20, cfg.Probe.Threads)
	assert.Equal(t, 2, cfg.Probe.Attempts)
	assert.Equal(t, "https://example.test/down", cfg.Probe.SpeedtestURL)
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
	assert.False(t, cfg.Probe.IsSpeedtest(), "speedtest defaults OFF (round-8 owner ruling — supersedes the W10 default-ON)")
	assert.Nil(t, cfg.Probe.Speedtest)
	assert.Equal(t, 10*time.Second, cfg.Probe.Timeout.Duration)
	assert.Equal(t, 12, cfg.Probe.Threads, "wave3: default lowered 32→12 (12 concurrent batches saturate the boot ceiling)")
	assert.Equal(t, 3, cfg.Probe.Attempts)
	assert.Equal(t, "https://dns.google/resolve", cfg.Geo.DoHURL, "doh_url defaults to the dns.google/resolve DoH endpoint")
	assert.Equal(t, "https://ipinfo.io/json", cfg.Geo.HTTPSURL, "https_url defaults to the keyless ipinfo.io/json self-geo endpoint")
	assert.Equal(t, 24*time.Hour, cfg.Geo.TTL.Duration)
	require.NotNil(t, cfg.Geo.UnlockProbes)
	assert.True(t, *cfg.Geo.UnlockProbes, "unlock_probes defaults ON (owner ruling 2026-11-06)")
	assert.True(t, cfg.Geo.UnlockProbesEnabled(), "absent knob = unlock stage on")
	// W19 owner order («259 живых, значит 259 раскидываются по балансирам»):
	// absent/0 = ALL alive nodes go active — every cap knob defaults
	// UNBOUNDED; an explicit positive number stays a cap (no-floor/no-ceiling
	// ruling class: knobs stay, defaults flip).
	assert.Equal(t, 0, cfg.Select.PerCountryCap, "absent = unlimited per country")
	assert.Equal(t, 0, cfg.Select.SoftCap, "absent = unbounded global selection")
	assert.Equal(t, 0, cfg.Select.CityExpandThreshold, "absent = expansion off (moot when unbounded)")
	assert.Equal(t, 0, cfg.Select.Ceiling, "absent = unbounded ceiling")
	assert.Equal(t, 15490, cfg.Render.StatsPort)
	assert.Equal(t, "~/projects/xray-raw/config.json", cfg.Render.Template)
	assert.Equal(t, "~/projects/xray-raw/config.json", cfg.Activate.Target)
	assert.Equal(t, "/usr/bin/xray", cfg.Activate.XrayBin)
	assert.True(t, cfg.Probe.CalibrationEnabled, "calibration defaults ON")
	assert.InDelta(t, 10.0, cfg.Probe.CalibrationBase, 1e-9)
	assert.InDelta(t, 1.0, cfg.Probe.CalibrationMargin, 1e-9)
	assert.Equal(t, "country", cfg.Probe.Granularity)
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
		assert.Contains(t, err.Error(), "matin, radikal, stintikvpn, etc.")
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

	t.Run("geo.https_url must be https (structural scheme check, not an allowlist)", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[geo]
https_url = "http://ipinfo.io/json"
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := config.Load(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
		assert.Contains(t, err.Error(), "geo.https_url")
	})

	t.Run("geo.https_url accepts ANY https endpoint verbatim (owner ruling: plain string knob, no allowlist)", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
data_dir = "/tmp/x"

[geo]
https_url = "https://geo.self-hosted.example/internal/json"
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		cfg, err := config.Load(path)
		require.NoError(t, err)
		assert.Equal(t, "https://geo.self-hosted.example/internal/json", cfg.Geo.HTTPSURL,
			"the endpoint is a passthrough string — structural https check only")
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

// TestAutoRestartKnobDefaultsToTrue pins [maintain].auto_restart (W13, the
// owner's hands-off ruling): unset = TRUE — the daemon restarts the live
// xray client after every gated activation; an explicit false restores the
// manual-restart semantics (the hint is printed instead).
func TestAutoRestartKnobDefaultsToTrue(t *testing.T) {
	write := func(content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	base := `data_dir = "/tmp/publicvpn-autorestart"
`

	t.Run("unset defaults to true (hands-off)", func(t *testing.T) {
		cfg, err := config.Load(write(base))
		require.NoError(t, err)
		assert.True(t, cfg.Maintain.AutoRestartEnabled(),
			"auto_restart must default to true — zero manual restarts is the approved premise")
	})

	t.Run("explicit false restores manual semantics", func(t *testing.T) {
		cfg, err := config.Load(write(base + "\n[maintain]\nauto_restart = false\n"))
		require.NoError(t, err)
		assert.False(t, cfg.Maintain.AutoRestartEnabled())
	})

	t.Run("explicit true parses", func(t *testing.T) {
		cfg, err := config.Load(write(base + "\n[maintain]\nauto_restart = true\n"))
		require.NoError(t, err)
		assert.True(t, cfg.Maintain.AutoRestartEnabled())
	})

	t.Run("unknown key still fails strict decode", func(t *testing.T) {
		_, err := config.Load(write(base + "\n[maintain]\nauto_restartt = true\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "strict mode")
	})
}

// TestUnlockProbesKnobDefaultsTrue pins [geo].unlock_probes (owner ruling
// 2026-11-06: unlock probes ship ON by default, like the ip quality fields
// they carry): absent = TRUE (materialized by applyGeoDefaults), an
// explicit false keeps the stage off, an explicit true parses. The knob is
// tri-state (*bool) exactly like [maintain].auto_restart.
func TestUnlockProbesKnobDefaultsTrue(t *testing.T) {
	write := func(content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	base := `data_dir = "/tmp/publicvpn-unlockprobes"
`

	t.Run("absent defaults to true (owner flip)", func(t *testing.T) {
		cfg, err := config.Load(write(base))
		require.NoError(t, err)
		require.NotNil(t, cfg.Geo.UnlockProbes, "applyGeoDefaults materializes the absent knob")
		assert.True(t, *cfg.Geo.UnlockProbes)
		assert.True(t, cfg.Geo.UnlockProbesEnabled(),
			"unlock_probes must default to true — the unlock stage runs without an explicit knob")
	})

	t.Run("explicit false keeps the stage off", func(t *testing.T) {
		cfg, err := config.Load(write(base + "\n[geo]\nunlock_probes = false\n"))
		require.NoError(t, err)
		require.NotNil(t, cfg.Geo.UnlockProbes)
		assert.False(t, *cfg.Geo.UnlockProbes)
		assert.False(t, cfg.Geo.UnlockProbesEnabled())
	})

	t.Run("explicit true parses", func(t *testing.T) {
		cfg, err := config.Load(write(base + "\n[geo]\nunlock_probes = true\n"))
		require.NoError(t, err)
		require.NotNil(t, cfg.Geo.UnlockProbes)
		assert.True(t, *cfg.Geo.UnlockProbes)
		assert.True(t, cfg.Geo.UnlockProbesEnabled())
	})

	t.Run("unknown key still fails strict decode", func(t *testing.T) {
		_, err := config.Load(write(base + "\n[geo]\nunlock_probbes = true\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "strict mode")
	})
}

// TestTCPPrefilterKnobDefaultsOn pins [probe].tcp_prefilter (owner-approved
// probe-optimization program, 2026-11-06): absent = TRUE (materialized by
// applyProbeDefaults, wave-1 TCP pre-filter runs on every wave), an explicit
// false keeps the stage off, an explicit true parses, and the worker/timeout
// knobs materialize their defaults. The knob is tri-state (*bool) exactly
// like [geo].unlock_probes.
func TestTCPPrefilterKnobDefaultsOn(t *testing.T) {
	write := func(content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	base := `data_dir = "/tmp/publicvpn-tcpprefilter"
`

	t.Run("absent defaults to true (owner default)", func(t *testing.T) {
		cfg, err := config.Load(write(base))
		require.NoError(t, err)
		require.NotNil(t, cfg.Probe.TCPPrefilter, "applyProbeDefaults materializes the absent knob")
		assert.True(t, *cfg.Probe.TCPPrefilter)
		assert.True(t, cfg.Probe.TCPPrefilterEnabled(),
			"tcp_prefilter must default to true — the wave-1 pre-filter runs without an explicit knob")
		assert.Equal(t, config.DefaultProbePrefilterWorkers, cfg.Probe.TCPPrefilterWorkers,
			"workers default materializes")
		assert.Equal(t, config.DefaultProbePrefilterTimeout, cfg.Probe.TCPPrefilterTimeout.Duration,
			"timeout default materializes")
	})

	t.Run("explicit false keeps the stage off", func(t *testing.T) {
		cfg, err := config.Load(write(base + "\n[probe]\ntcp_prefilter = false\n"))
		require.NoError(t, err)
		require.NotNil(t, cfg.Probe.TCPPrefilter)
		assert.False(t, *cfg.Probe.TCPPrefilter)
		assert.False(t, cfg.Probe.TCPPrefilterEnabled())
	})

	t.Run("explicit true and explicit values parse", func(t *testing.T) {
		cfg, err := config.Load(write(base + "\n[probe]\ntcp_prefilter = true\ntcp_prefilter_workers = 64\ntcp_prefilter_timeout = \"2s\"\n"))
		require.NoError(t, err)
		require.NotNil(t, cfg.Probe.TCPPrefilter)
		assert.True(t, *cfg.Probe.TCPPrefilter)
		assert.True(t, cfg.Probe.TCPPrefilterEnabled())
		assert.Equal(t, 64, cfg.Probe.TCPPrefilterWorkers)
		assert.Equal(t, 2*time.Second, cfg.Probe.TCPPrefilterTimeout.Duration)
	})

	t.Run("unknown key still fails strict decode", func(t *testing.T) {
		_, err := config.Load(write(base + "\n[probe]\ntcp_prefilteeer = true\n"))
		require.Error(t, err)
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
// strict decoding. speedtest_interval is a TRI-STATE pointer (round-8):
// absent → the 168h default (the weekly wave exists), explicit "0s" → 0 =
// the speedtest wave is DISABLED entirely (the owner's «выключи» at the
// schedule level), a positive value below the floor fails loud.
func TestMaintainIntervalsDefaultsFloorAndStrict(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n")
		assert.Equal(t, time.Hour, cfg.Maintain.RefreshInterval.Duration, "refresh default is 1h (W10 owner ruling)")
		require.NotNil(t, cfg.Maintain.SpeedtestInterval)
		assert.Equal(t, 168*time.Hour, cfg.Maintain.SpeedtestInterval.Duration)
	})
	t.Run("custom values parse", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n[maintain]\nrefresh_interval = \"90m\"\nspeedtest_interval = \"240h\"\n")
		assert.Equal(t, 90*time.Minute, cfg.Maintain.RefreshInterval.Duration)
		require.NotNil(t, cfg.Maintain.SpeedtestInterval)
		assert.Equal(t, 240*time.Hour, cfg.Maintain.SpeedtestInterval.Duration)
	})
	t.Run("explicit 0s disables the speedtest wave", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n[maintain]\nspeedtest_interval = \"0s\"\n")
		require.NotNil(t, cfg.Maintain.SpeedtestInterval, "explicit 0s must stay an explicit zero, never re-defaulted")
		assert.Zero(t, cfg.Maintain.SpeedtestInterval.Duration)
		assert.False(t, cfg.Maintain.SpeedtestWaveEnabled(), "0s = no speedtest wave at all")
		assert.Zero(t, cfg.Maintain.SpeedtestWavePeriod())
		// refresh keeps its default — disabling speedtest never touches the
		// refresh cadence.
		assert.Equal(t, time.Hour, cfg.Maintain.RefreshInterval.Duration)
	})
	t.Run("absent keeps the wave enabled at the default", func(t *testing.T) {
		cfg := load(t, "data_dir = \"d\"\n")
		assert.True(t, cfg.Maintain.SpeedtestWaveEnabled())
		assert.Equal(t, 168*time.Hour, cfg.Maintain.SpeedtestWavePeriod())
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
	t.Run("negative speedtest_interval fails loud", func(t *testing.T) {
		_, err := config.Load(writeCfg(t, "data_dir = \"d\"\n[maintain]\nspeedtest_interval = \"-5m\"\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "negative is structurally invalid")
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
		assert.Equal(t, []string{"vless", "vmess", "trojan", "ss", "hysteria2"}, cfg.Filter.Protocols)
		assert.False(t, cfg.Filter.AllowInsecure)
	})
	t.Run("explicit subset", func(t *testing.T) {
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
	assert.Empty(t, cfg.Render.ObservatoryInterval,
		"W19: absent observatory_interval = ADAPTIVE (render computes max(60s, ceil(N×200ms)) from the active count); explicit stays verbatim")
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

// TestSelectCapsUnboundedValidation pins the W19 structural contract: the
// flip makes 0 = UNBOUNDED legal for every select cap, negative values stay
// structurally invalid, and the artificial per_country_cap 1..10 range is
// GONE (owner no-floor/no-ceiling ruling — an explicit cap of any size is the
// operator's call). ceiling < soft_cap remains invalid only when both are
// positive constraints.
func TestSelectCapsUnboundedValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(t *testing.T, body string) *config.Config {
		t.Helper()
		path := filepath.Join(dir, "cfg.toml")
		require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
		cfg, err := config.Load(path)
		require.NoError(t, err)
		return cfg
	}

	// All-zero select block loads and stays zero (unbounded everywhere).
	cfg := write(t, "data_dir = \"/tmp/x\"\n[select]\n")
	assert.Zero(t, cfg.Select.PerCountryCap)
	assert.Zero(t, cfg.Select.SoftCap)
	assert.Zero(t, cfg.Select.CityExpandThreshold)
	assert.Zero(t, cfg.Select.Ceiling)

	// An explicit cap of any positive size is structurally valid (no range).
	cfg = write(t, "data_dir = \"/tmp/x\"\n[select]\nper_country_cap = 100\nsoft_cap = 5000\nceiling = 9000\ncity_expand_threshold = 300\n")
	assert.Equal(t, 100, cfg.Select.PerCountryCap)
	assert.Equal(t, 5000, cfg.Select.SoftCap)
	assert.Equal(t, 9000, cfg.Select.Ceiling)
	assert.Equal(t, 300, cfg.Select.CityExpandThreshold)

	// Negative values remain structurally invalid (sign correctness only).
	for _, body := range []string{
		"per_country_cap = -1",
		"soft_cap = -1",
		"ceiling = -1",
		"city_expand_threshold = -1",
	} {
		path := filepath.Join(dir, "neg.toml")
		require.NoError(t, os.WriteFile(path, []byte("data_dir = \"/tmp/x\"\n[select]\n"+body+"\n"), 0o644))
		_, err := config.Load(path)
		require.Error(t, err, "negative %s must fail loud", body)
	}

	// ceiling below soft_cap: invalid when both are positive constraints…
	path := filepath.Join(dir, "cross.toml")
	require.NoError(t, os.WriteFile(path, []byte("data_dir = \"/tmp/x\"\n[select]\nsoft_cap = 40\nceiling = 30\n"), 0o644))
	_, err := config.Load(path)
	require.Error(t, err, "ceiling 30 < soft_cap 40 must fail loud")
	// …but an absent (unbounded) ceiling coexists with an explicit soft cap.
	require.NoError(t, os.WriteFile(path, []byte("data_dir = \"/tmp/x\"\n[select]\nsoft_cap = 40\n"), 0o644))
	_, err = config.Load(path)
	require.NoError(t, err, "soft_cap without ceiling = expansion bounded only by the alive count")
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

// --- W14: real-xray probe engine, protocols default ALL, knife removal. ---

// TestW14ProtocolsDefaultAll pins the round-7 owner ruling (14c): with
// [filter].protocols unset, EVERY rendered protocol is accepted —
// vless, vmess, trojan, ss, hysteria2. The security filter (reality/tls,
// allow_insecure=false default) is unaffected: protocol breadth is not a
// license for insecure links.
func TestW14ProtocolsDefaultAll(t *testing.T) {
	cfg := load(t, w6Base)
	assert.Equal(t, []string{"vless", "vmess", "trojan", "ss", "hysteria2"}, cfg.Filter.Protocols)
}

// TestW14ProbeKnobsDefaults pins the real-xray probe wave defaults: the
// knife keys are gone (path/db_path/check_preset/url_success_threshold/
// max_passed do not exist), attempts defaults to 3, the speedtest URL is the
// Cloudflare 25 MB sample, and threads (now parallel temp-instance workers)
// defaults to 32 (W19: saturates the boot-serialization ceiling — bounded
// wave wall time as the pool grows; the semaphore still bounds load).
func TestW14ProbeKnobsDefaults(t *testing.T) {
	cfg := load(t, w6Base)
	p := cfg.Probe
	assert.Equal(t, 3, p.Attempts)
	assert.Equal(t, 12, p.Threads)
	assert.Equal(t, "https://speed.cloudflare.com/__down?bytes=25000000", p.SpeedtestURL)
	assert.Equal(t, 10*time.Second, p.Timeout.Duration)
	assert.Equal(t, 30*time.Second, p.SpeedtestTimeout.Duration)
	assert.Equal(t, "https://cloudflare.com/cdn-cgi/trace", p.URL)
	// (the speedtest default pins live in TestSpeedtestTriState — round-8)
}

// TestSpeedtestTriStatePins the round-8 pointer semantics: nil (absent) →
// the new default false; an explicit true STAYS true (existing configs with
// speedtest = true keep it); an explicit false stays false. The dedicated
// weekly speedtest wave ([maintain].speedtest_interval) is unaffected: it
// carries -S semantics regardless of this knob (refresh waves become
// probe-only, the speedtest wave still speedtests).
func TestSpeedtestTriState(t *testing.T) {
	t.Run("nil defaults to false", func(t *testing.T) {
		cfg := load(t, w6Base)
		assert.False(t, cfg.Probe.IsSpeedtest())
		assert.Nil(t, cfg.Probe.Speedtest)
	})
	t.Run("explicit true stays true", func(t *testing.T) {
		cfg := load(t, w6Base+"[probe]\nspeedtest = true\n")
		require.NotNil(t, cfg.Probe.Speedtest)
		assert.True(t, *cfg.Probe.Speedtest)
		assert.True(t, cfg.Probe.IsSpeedtest())
	})
	t.Run("explicit false stays false", func(t *testing.T) {
		cfg := load(t, w6Base+"[probe]\nspeedtest = false\n")
		require.NotNil(t, cfg.Probe.Speedtest)
		assert.False(t, *cfg.Probe.Speedtest)
		assert.False(t, cfg.Probe.IsSpeedtest())
	})
}

// TestW14ExplicitProbeKnobsLoad pins that explicit values load unchanged
// (owner ruling: no range bounds — structural checks only).
func TestW14ExplicitProbeKnobsLoad(t *testing.T) {
	cfg := load(t, w6Base+`[probe]
threads = 24
attempts = 1
speedtest_url = "https://example.test/down?bytes=1000"
speedtest = false
`)
	p := cfg.Probe
	assert.Equal(t, 24, p.Threads)
	assert.Equal(t, 1, p.Attempts)
	assert.Equal(t, "https://example.test/down?bytes=1000", p.SpeedtestURL)
	assert.False(t, p.IsSpeedtest())
}

// TestW14RemovedKnifeKeysFailLoud pins the loud migration: every removed
// xray-knife key inside [probe] fails the load naming the dead key and the
// migration path (house style — never a bare strict-decode error).
func TestW14RemovedKnifeKeysFailLoud(t *testing.T) {
	for _, key := range []string{"path", "db_path", "check_preset", "url_success_threshold", "max_passed"} {
		t.Run(key, func(t *testing.T) {
			body := fmt.Sprintf("data_dir = \"d\"\n[probe]\n%s = \"x\"\n", key)
			if key == "url_success_threshold" || key == "max_passed" {
				body = fmt.Sprintf("data_dir = \"d\"\n[probe]\n%s = 1.0\n", key)
			}
			_, err := config.Load(writeCfg(t, body))
			require.Error(t, err, "removed knife key %s must fail the load loud", key)
			assert.Contains(t, err.Error(), key)
			assert.Contains(t, err.Error(), "xray-knife", "the migration text must name the removed engine")
		})
	}
}

// TestW14ProbeKnobValidation pins the structural checks on the surviving
// knobs: a negative attempt/worker count is sign-invalid (0 = unset →
// default, the W6 convention). No range bounds (owner ruling).
func TestW14ProbeKnobValidation(t *testing.T) {
	_, err := config.Load(writeCfg(t, w6Base+"[probe]\nattempts = -1\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "probe.attempts")

	_, err = config.Load(writeCfg(t, w6Base+"[probe]\nthreads = -1\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "probe.threads")
}

// TestProbeBatchKnobsDefaults pins the 0 → default semantics for the new
// batch knobs (no artificial floor/ceiling — 0 means "unset → default").
func TestProbeBatchKnobsDefaults(t *testing.T) {
	cfg := load(t, w6Base)
	assert.Equal(t, config.DefaultProbeBatchSize, cfg.Probe.BatchSize)
	assert.Equal(t, config.DefaultProbeBatchConcurrency, cfg.Probe.BatchConcurrency)
}

// TestProbeBatchKnobsExplicitLoad pins that explicit values load unchanged.
func TestProbeBatchKnobsExplicitLoad(t *testing.T) {
	cfg := load(t, w6Base+`[probe]
batch_size = 25
batch_concurrency = 7
`)
	assert.Equal(t, 25, cfg.Probe.BatchSize)
	assert.Equal(t, 7, cfg.Probe.BatchConcurrency)
}

// TestProbeBatchKnobsValidation pins the structural sign checks.
func TestProbeBatchKnobsValidation(t *testing.T) {
	_, err := config.Load(writeCfg(t, w6Base+"[probe]\nbatch_size = -1\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "probe.batch_size")

	_, err = config.Load(writeCfg(t, w6Base+"[probe]\nbatch_concurrency = -1\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "probe.batch_concurrency")
}

// TestGeoSelfReportConcurrencyDefault pins the 0 → default semantics.
func TestGeoSelfReportConcurrencyDefault(t *testing.T) {
	cfg := load(t, w6Base)
	assert.Equal(t, config.DefaultGeoSelfReportConcurrency, cfg.Geo.SelfReportConcurrency)
}

// TestGeoSelfReportConcurrencyExplicit pins that explicit values load unchanged.
func TestGeoSelfReportConcurrencyExplicit(t *testing.T) {
	cfg := load(t, w6Base+`[geo]
self_report_concurrency = 12
`)
	assert.Equal(t, 12, cfg.Geo.SelfReportConcurrency)
}

// TestGeoSelfReportConcurrencyValidation pins the structural sign check.
func TestGeoSelfReportConcurrencyValidation(t *testing.T) {
	_, err := config.Load(writeCfg(t, w6Base+"[geo]\nself_report_concurrency = -1\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "geo.self_report_concurrency")
}

// TestPluginsConfigThresholds pins the Task 1 plugin liveness thresholds:
// max_duplicate_percent and min_live_percent. Both are nil by default
// (disabled), explicit 0 means disabled, positive values enable the check,
// negative values are structurally invalid. No upper bound (owner ruling).
func TestPluginsConfigThresholds(t *testing.T) {
	t.Run("nil defaults (disabled by default)", func(t *testing.T) {
		cfg := load(t, w6Base)
		assert.Nil(t, cfg.Plugins.MaxDuplicatePercent, "max_duplicate_percent must be nil by default")
		assert.Nil(t, cfg.Plugins.MinLivePercent, "min_live_percent must be nil by default")
	})

	t.Run("explicit 0 means disabled", func(t *testing.T) {
		cfg := load(t, w6Base+`
[plugins]
max_duplicate_percent = 0
min_live_percent = 0
`)
		require.NotNil(t, cfg.Plugins.MaxDuplicatePercent)
		require.NotNil(t, cfg.Plugins.MinLivePercent)
		assert.InDelta(t, 0.0, *cfg.Plugins.MaxDuplicatePercent, 1e-9)
		assert.InDelta(t, 0.0, *cfg.Plugins.MinLivePercent, 1e-9)
	})

	t.Run("positive values enable the check", func(t *testing.T) {
		cfg := load(t, w6Base+`
[plugins]
max_duplicate_percent = 15.5
min_live_percent = 80.0
`)
		require.NotNil(t, cfg.Plugins.MaxDuplicatePercent)
		require.NotNil(t, cfg.Plugins.MinLivePercent)
		assert.InDelta(t, 15.5, *cfg.Plugins.MaxDuplicatePercent, 1e-9)
		assert.InDelta(t, 80.0, *cfg.Plugins.MinLivePercent, 1e-9)
	})

	t.Run("negative max_duplicate_percent fails validation", func(t *testing.T) {
		_, err := config.Load(writeCfg(t, w6Base+`
[plugins]
max_duplicate_percent = -1.0
`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "plugins.max_duplicate_percent")
		assert.Contains(t, err.Error(), "negative is structurally invalid")
	})

	t.Run("negative min_live_percent fails validation", func(t *testing.T) {
		_, err := config.Load(writeCfg(t, w6Base+`
[plugins]
min_live_percent = -5.0
`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "plugins.min_live_percent")
		assert.Contains(t, err.Error(), "negative is structurally invalid")
	})

	t.Run("no upper bound on thresholds (owner ruling)", func(t *testing.T) {
		cfg := load(t, w6Base+`
[plugins]
max_duplicate_percent = 1000.0
min_live_percent = 500.0
`)
		require.NotNil(t, cfg.Plugins.MaxDuplicatePercent)
		require.NotNil(t, cfg.Plugins.MinLivePercent)
		assert.InDelta(t, 1000.0, *cfg.Plugins.MaxDuplicatePercent, 1e-9)
		assert.InDelta(t, 500.0, *cfg.Plugins.MinLivePercent, 1e-9)
	})

	t.Run("unknown plugins key fails strict decode", func(t *testing.T) {
		_, err := config.Load(writeCfg(t, w6Base+`
[plugins]
max_duplicate_percnt = 10.0
`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "strict mode")
	})
}

// TestSelectOnlyClean pins the only_clean knob: nil by default (no filter),
// explicit true enables clean-only selection.
func TestSelectOnlyClean(t *testing.T) {
	t.Run("default nil (no filter)", func(t *testing.T) {
		cfg := load(t, w6Base)
		assert.Nil(t, cfg.Select.OnlyClean)
	})
	t.Run("explicit true enables filter", func(t *testing.T) {
		cfg := load(t, w6Base+"[select]\nonly_clean = true\n")
		require.NotNil(t, cfg.Select.OnlyClean)
		assert.True(t, *cfg.Select.OnlyClean)
	})
	t.Run("explicit false disables filter", func(t *testing.T) {
		cfg := load(t, w6Base+"[select]\nonly_clean = false\n")
		require.NotNil(t, cfg.Select.OnlyClean)
		assert.False(t, *cfg.Select.OnlyClean)
	})
}
