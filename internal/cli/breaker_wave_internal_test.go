package cli

import (
	"bytes"
	"path/filepath"
	"testing"

	"assay/internal/config"
	"assay/internal/plugins"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Round-7 item 6 — the breaker at wave level: the failure of a run
// (abandonment or loud run error) feeds the registry counter; hitting the
// limit auto-disables the plugin LOUD; disabled plugins are excluded from
// subsequent waves; the wave reports disabled plugins in its output.
//
// The state lives in the SHARED registry: one-shot runs get a fresh
// registry per process (state per wave, and each plugin runs at most once
// per wave — at any limit ≥ 2 a one-shot wave can never trip the breaker by
// itself; an explicit limit of 1 trips on the first failure regardless —
// pinned below); the watch daemon passes its watchdog-maintained registry,
// so counts and disables PERSIST across waves for the daemon's lifetime.
// No file: a daemon restart is deliberately a fresh chance (the operator
// restarts after fixing plugin files; WatchdogSec restarts behave the same).

// failingPluginCode is a plugin whose RUN fails loud (discover returns a
// non-table — the engine rejects it), unlike a Compile failure which
// LoadDir already handles.
const failingPluginCode = `return function() return "not-a-node-table" end`

func breakerFixtureRegistry(t *testing.T) *plugins.Registry {
	t.Helper()
	reg := plugins.NewRegistry()
	reg.Set(&plugins.Plugin{ID: "healthy", Path: "healthy.lua", Code: []byte(
		`return function() return { assay.node{ raw = "vless://a@h:1?s=1" } } end`)})
	reg.Set(&plugins.Plugin{ID: "flaky", Path: "flaky.lua", Code: []byte(failingPluginCode)})
	return reg
}

func breakerRunWave(t *testing.T, cfg *config.Config, reg *plugins.Registry) string {
	t.Helper()
	out := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	_, err := runFetchWith(cmd, cfg, reg, nil)
	require.NoError(t, err)
	return out.String()
}

func TestWaveBreakerTripsAndDisablesLoud(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir, Plugins: config.PluginsConfig{Dir: filepath.Join(dir, "plugins")}}
	reg := breakerFixtureRegistry(t)

	// Four prior consecutive failures (earlier waves in the daemon): this
	// wave's single failure hits the limit of 5 and must disable + say so.
	for range 4 {
		reg.RecordFailure("flaky", 5)
	}
	out := breakerRunWave(t, cfg, reg)

	assert.Contains(t, out, "plugin flaky",
		"the failing run must still be reported:\n%s", out)
	assert.Contains(t, out, "DISABLED",
		"hitting the limit must disable the plugin loud:\n%s", out)
	assert.Contains(t, out, "5 consecutive failures",
		"the loud line must carry the count:\n%s", out)
	assert.Contains(t, out, "breaker: 1 plugin(s) disabled — flaky",
		"the wave must list disabled plugins for the operator:\n%s", out)

	// Next wave: the disabled plugin is excluded — no run, no failure line.
	out2 := breakerRunWave(t, cfg, reg)
	assert.NotContains(t, out2, "plugin flaky",
		"a disabled plugin must be excluded from subsequent waves:\n%s", out2)
	assert.Contains(t, out2, "breaker: 1 plugin(s) disabled — flaky",
		"disabled plugins stay visible in wave output:\n%s", out2)
	assert.Contains(t, out2, "plugin healthy    ok:",
		"healthy plugins keep running:\n%s", out2)
}

func TestWaveBreakerDisabledPluginExcludedFromWave(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir, Plugins: config.PluginsConfig{Dir: filepath.Join(dir, "plugins")}}
	reg := breakerFixtureRegistry(t)
	for range 5 {
		reg.RecordFailure("flaky", 5)
	}

	out := breakerRunWave(t, cfg, reg)
	assert.NotContains(t, out, "plugin flaky",
		"a pre-disabled plugin must not run:\n%s", out)
	assert.Contains(t, out, "plugin healthy    ok: 1 node",
		"the healthy plugin is unaffected:\n%s", out)
}

func TestWaveBreakerUnlimitedNeverDisables(t *testing.T) {
	dir := t.TempDir()
	unlimited := 0
	cfg := &config.Config{
		DataDir: dir,
		Plugins: config.PluginsConfig{Dir: filepath.Join(dir, "plugins"), MaxConsecutiveFailures: &unlimited},
	}
	reg := breakerFixtureRegistry(t)
	for range 10 {
		reg.RecordFailure("flaky", 0)
	}

	out := breakerRunWave(t, cfg, reg)
	assert.NotContains(t, out, "DISABLED", "unlimited mode never disables:\n%s", out)
	assert.NotContains(t, out, "breaker:", "no disabled summary when nothing is disabled:\n%s", out)
}

func TestWaveBreakerOneShotFreshRegistryNeverTrips(t *testing.T) {
	// One-shot runs each plugin at most once per wave, so at the default
	// limit (5 ≥ 2) a fresh registry can never trip the breaker within a
	// single wave — even with a failing plugin. Pins the per-wave state
	// semantics honestly; the limit-1 exception is pinned below.
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir, Plugins: config.PluginsConfig{Dir: filepath.Join(dir, "plugins")}}
	reg := breakerFixtureRegistry(t)

	out := breakerRunWave(t, cfg, reg)
	assert.NotContains(t, out, "DISABLED",
		"a single failure in a fresh one-shot registry must not disable:\n%s", out)
}

func TestWaveBreakerLimitOneTripsOnFirstFailureOneShot(t *testing.T) {
	// The documented exception (review Minor-1): an explicit
	// max_consecutive_failures = 1 trips on the VERY FIRST failure — a
	// one-shot wave included, because its single run can fail once and one
	// failure IS the limit. Characterizes the boundary the docs state.
	dir := t.TempDir()
	limitOne := 1
	cfg := &config.Config{
		DataDir: dir,
		Plugins: config.PluginsConfig{Dir: filepath.Join(dir, "plugins"), MaxConsecutiveFailures: &limitOne},
	}
	reg := breakerFixtureRegistry(t)

	out := breakerRunWave(t, cfg, reg)
	assert.Contains(t, out, "plugin flaky",
		"the failing run must still be reported:\n%s", out)
	assert.Contains(t, out, "DISABLED after 1 consecutive failures (breaker limit 1)",
		"limit 1 must trip on the first failure even in a one-shot wave:\n%s", out)
	assert.Contains(t, out, "breaker: 1 plugin(s) disabled — flaky",
		"the wave must list the tripped plugin:\n%s", out)
}
