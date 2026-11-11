package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// retiredKeysFixture is the S4 enumeration exercised end to end: every
// retired/re-homed knob the self-held-core pivot retires, each carrying a
// distinctive value so the re-home assertions cannot pass by accident.
const retiredKeysFixture = `
data_dir = %q

[activate]
target = "~/old/target.json"
xray_bin = "/opt/retired/xray"
asset_dir = "~/old/assets"
service_name = "old-unit.service"
backup_dir = "old-backups"

[render]
template = "~/old/template.json"
output_dir = "old-rendered"
stats_port = 15499
pool_inbound_tags = ["socks-in", "http-in"]

[maintain]
auto_restart = false
`

// retiredKeyPaths is the exact ten-key S4 list: every present key must
// produce EXACTLY ONE warning line, no more, no less.
var retiredKeyPaths = []string{
	"activate.target",
	"activate.xray_bin",
	"activate.asset_dir",
	"activate.service_name",
	"activate.backup_dir",
	"render.template",
	"render.output_dir",
	"render.stats_port",
	"render.pool_inbound_tags",
	"maintain.auto_restart",
}

// writeCoreConfig writes a config body to <dir>/config.toml and returns the
// file path (hermetic: every test owns its directories).
func writeCoreConfig(t *testing.T, dir string, body string) string {
	t.Helper()
	path := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// TestCoreDefaultsAbsentSection pins the verbatim [core] defaults when the
// section is absent from the file AND on the configless path: socks 10810,
// http 10811, api 15491, auto_update true, update_interval 24h,
// rollback_strikes 3, loglevel "warning", per-country off, and the managed
// binary default <data>/bin/xray resolved by CoreXrayBin.
func TestCoreDefaultsAbsentSection(t *testing.T) {
	dir := t.TempDir()
	path := writeCoreConfig(t, dir,
		fmt.Sprintf("data_dir = %q\n", filepath.Join(dir, "data")))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, 10810, cfg.Core.SocksPort)
	assert.Equal(t, 10811, cfg.Core.HTTPPort)
	assert.Equal(t, 15491, cfg.Core.APIPort)
	assert.True(t, cfg.Core.AutoUpdate, "auto_update defaults ON (D4)")
	assert.Equal(t, 24*time.Hour, cfg.Core.UpdateInterval.Duration)
	assert.Equal(t, 3, cfg.Core.RollbackStrikes)
	assert.Equal(t, "warning", cfg.Core.Loglevel)
	assert.False(t, cfg.Core.PerCountryInbounds, "per-country inbounds default OFF (D2)")
	assert.Empty(t, cfg.Core.XrayBin, "the managed default is resolved, not stored")
	assert.Equal(t, filepath.Join(filepath.Join(dir, "data"), "bin", "xray"),
		cfg.CoreXrayBin(), "CoreXrayBin resolves <data>/bin/xray from the data dir")

	// The configless path carries the same defaults, with the managed binary
	// joined from the configless data dir.
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", "")
	res, err := Resolve("", home, t.TempDir())
	require.NoError(t, err)
	require.Equal(t, SourceConfigless, res.Source)
	assert.Equal(t, 10810, res.Config.Core.SocksPort)
	assert.Equal(t, 10811, res.Config.Core.HTTPPort)
	assert.Equal(t, 15491, res.Config.Core.APIPort)
	assert.True(t, res.Config.Core.AutoUpdate)
	assert.Equal(t, 24*time.Hour, res.Config.Core.UpdateInterval.Duration)
	assert.Equal(t, 3, res.Config.Core.RollbackStrikes)
	assert.Equal(t, "warning", res.Config.Core.Loglevel)
	assert.False(t, res.Config.Core.PerCountryInbounds)
	assert.Equal(t, filepath.Join(DefaultDataDir(home), "bin", "xray"),
		res.Config.CoreXrayBin())
}

// TestCoreExplicitValuesSurvive pins the flip side: every explicit [core]
// knob survives decode verbatim, including auto_update = false (the default
// is pre-seeded BEFORE decode so the explicit value cannot be clobbered)
// and the xray_bin override (CoreXrayBin returns it instead of the managed
// default).
func TestCoreExplicitValuesSurvive(t *testing.T) {
	dir := t.TempDir()
	body := `
data_dir = %q

[core]
xray_bin = "/usr/local/bin/xray"
auto_update = false
update_interval = "48h"
socks_port = 10820
http_port = 10821
api_port = 15492
per_country_inbounds = true
rollback_strikes = 5
loglevel = "info"
`
	path := writeCoreConfig(t, dir,
		fmt.Sprintf(body, filepath.Join(dir, "data")))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, "/usr/local/bin/xray", cfg.Core.XrayBin)
	assert.False(t, cfg.Core.AutoUpdate, "an explicit auto_update = false must survive")
	assert.Equal(t, 48*time.Hour, cfg.Core.UpdateInterval.Duration)
	assert.Equal(t, 10820, cfg.Core.SocksPort)
	assert.Equal(t, 10821, cfg.Core.HTTPPort)
	assert.Equal(t, 15492, cfg.Core.APIPort)
	assert.True(t, cfg.Core.PerCountryInbounds)
	assert.Equal(t, 5, cfg.Core.RollbackStrikes)
	assert.Equal(t, "info", cfg.Core.Loglevel)
	assert.Equal(t, "/usr/local/bin/xray", cfg.CoreXrayBin(),
		"an explicit xray_bin override wins over the managed default")
}

// TestRetiredKeysParseAndWarn pins the S4 parse-and-warn contract: a config
// carrying all ten retired keys decodes OK (the daemon never refuses to
// start on them), the resolution carries EXACTLY ONE warning line per key
// through the resolve warning sink, and the two re-homed values land on
// [core] (stats_port → core.api_port; activate.xray_bin → core.xray_bin).
func TestRetiredKeysParseAndWarn(t *testing.T) {
	dir := t.TempDir()
	path := writeCoreConfig(t, dir,
		fmt.Sprintf(retiredKeysFixture, filepath.Join(dir, "data")))

	res, err := Resolve(path, t.TempDir(), t.TempDir())
	require.NoError(t, err, "retired keys must parse-and-warn, never fail the load")

	// Exactly one warning line per retired key, no other warnings.
	require.Len(t, res.Warnings, len(retiredKeyPaths),
		"exactly one warning per retired key")
	joined := strings.Join(res.Warnings, "\n")
	for _, key := range retiredKeyPaths {
		assert.Equal(t, 1, strings.Count(joined, key),
			"warning sink must name %s exactly once", key)
	}

	// The re-homed values land on [core].
	assert.Equal(t, 15499, res.Config.Core.APIPort,
		"render.stats_port re-homes to core.api_port")
	assert.Equal(t, "/opt/retired/xray", res.Config.Core.XrayBin,
		"activate.xray_bin re-homes to core.xray_bin")
	assert.Equal(t, "/opt/retired/xray", res.Config.CoreXrayBin())

	// The re-home must carry through plain Load too: Config.Core is correct
	// on every decode path (the warnings are the only sink-dependent part).
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, 15499, cfg.Core.APIPort)
	assert.Equal(t, "/opt/retired/xray", cfg.Core.XrayBin)
}

// TestRetiredKeysYieldToCoreKnob pins the re-home precedence: when the new
// [core] knob is set explicitly, it WINS over the retired value; the retired
// key still warns exactly once, honestly naming that its value was not
// carried (a warning claiming a re-home that did not happen would be a lie).
func TestRetiredKeysYieldToCoreKnob(t *testing.T) {
	dir := t.TempDir()
	body := `
data_dir = %q

[core]
api_port = 15492
xray_bin = "/usr/local/bin/xray"

[activate]
xray_bin = "/opt/retired/xray"

[render]
stats_port = 15499
`
	path := writeCoreConfig(t, dir,
		fmt.Sprintf(body, filepath.Join(dir, "data")))

	res, err := Resolve(path, t.TempDir(), t.TempDir())
	require.NoError(t, err)

	assert.Equal(t, 15492, res.Config.Core.APIPort, "the explicit [core] knob wins")
	assert.Equal(t, "/usr/local/bin/xray", res.Config.Core.XrayBin)

	require.Len(t, res.Warnings, 2, "both retired keys still warn exactly once")
	joined := strings.Join(res.Warnings, "\n")
	assert.Contains(t, joined, "activate.xray_bin")
	assert.Contains(t, joined, "render.stats_port")
	assert.NotContains(t, joined, "re-homed to core.api_port",
		"the stats_port value was NOT carried — the warning must not claim it was")
	assert.NotContains(t, joined, "re-homed to core.xray_bin")
}

// TestUnknownKeyStillStrict is the regression guard on the leniency: the
// retired-key warn-and-continue contract must NOT loosen the strict decode
// for any other key — a truly unknown knob still fails the load loud
// (owner convention: unknown keys never pass silently).
func TestUnknownKeyStillStrict(t *testing.T) {
	dir := t.TempDir()
	body := `
data_dir = %q

[fetch]
unknown_knob = 1
`
	path := writeCoreConfig(t, dir,
		fmt.Sprintf(body, filepath.Join(dir, "data")))

	_, err := Load(path)
	require.Error(t, err, "unknown keys keep today's strict-decode error")
	assert.Contains(t, err.Error(), "strict mode")
}
