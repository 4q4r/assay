package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"public_vpn/internal/config"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stageRecorder is a mock stage set: every stage appends its name to the
// order slice and optionally fails with its scripted error.
type stageRecorder struct {
	order []string
	fail  map[string]error
}

func (r *stageRecorder) stage(name string) func(*cobra.Command, *config.Config) error {
	return func(_ *cobra.Command, _ *config.Config) error {
		if err := r.fail[name]; err != nil {
			return err
		}
		r.order = append(r.order, name)
		return nil
	}
}

func (r *stageRecorder) stages() *maintainStages {
	return &maintainStages{
		fetch:    r.stage("fetch"),
		parse:    r.stage("parse"),
		filter:   r.stage("filter"),
		probe:    r.stage("probe"),
		stats:    r.stage("stats"),
		prune:    r.stage("prune"),
		selectS:  r.stage("select"),
		render:   r.stage("render"),
		activate: r.stage("activate"),
	}
}

func maintainCfg(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DataDir: t.TempDir(),
		Activate: config.ActivateConfig{
			Target:  filepath.Join(t.TempDir(), "live-config.json"),
			XrayBin: "/usr/bin/xray",
		},
	}
}

func runMaintainForTest(t *testing.T, cfg *config.Config, opts maintainOptions, stages *maintainStages) string {
	t.Helper()
	buf := &bytes.Buffer{}
	require.NoError(t, runMaintain(buf, cfg, opts, stages))
	return buf.String()
}

func TestMaintainRunsFullStageOrderInWaveOrder(t *testing.T) {
	rec := &stageRecorder{}
	runMaintainForTest(t, maintainCfg(t), maintainOptions{}, rec.stages())
	assert.Equal(t, []string{"fetch", "parse", "filter", "probe", "stats", "prune", "select", "render", "activate"},
		rec.order, "one invocation = the full refresh wave (classification rides the probe stage — the separate geo stage is merged into the batch lifecycle)")
}

func TestMaintainNoActivateSkipsActivationButRenders(t *testing.T) {
	rec := &stageRecorder{}
	runMaintainForTest(t, maintainCfg(t), maintainOptions{noActivate: true}, rec.stages())
	assert.NotContains(t, rec.order, "activate", "--no-activate: render+diff only")
	assert.Contains(t, rec.order, "render")
	assert.Equal(t, []string{"fetch", "parse", "filter", "probe", "stats", "prune", "select", "render"}, rec.order)
}

func TestMaintainSkipProbeSkipsProbeStage(t *testing.T) {
	// --skip-probe reselects from the cold base: the probe stage (now carrying
	// the merged classification pass) is skipped — classification only runs
	// for nodes whose tunnel was just proven hot. Select still re-ranks from
	// the cold base.
	rec := &stageRecorder{}
	runMaintainForTest(t, maintainCfg(t), maintainOptions{skipProbe: true}, rec.stages())
	assert.Equal(t, []string{"fetch", "parse", "filter", "stats", "prune", "select", "render", "activate"}, rec.order)
	assert.NotContains(t, rec.order, "geo",
		"the geo stage is GONE — classification lives inside the probe batch lifecycle")
}

func TestMaintainStageFailureFailsLoudAndStops(t *testing.T) {
	rec := &stageRecorder{fail: map[string]error{"filter": errors.New("filter exploded")}}
	err := runMaintain(&bytes.Buffer{}, maintainCfg(t), maintainOptions{}, rec.stages())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "filter exploded")
	assert.Equal(t, []string{"fetch", "parse"}, rec.order,
		"the wave stops at the first loud failure — select/render/activate never run")
}

func TestMaintainStatsFailureWarnsButWaveContinues(t *testing.T) {
	// The stats poll is accounting, not correctness: an unreachable API
	// inbound (e.g. first run before the owner ever activated) must not block
	// the refresh wave. The failure is surfaced as a loud warning line.
	rec := &stageRecorder{fail: map[string]error{"stats": errors.New("connection refused")}}
	out := runMaintainForTest(t, maintainCfg(t), maintainOptions{}, rec.stages())
	assert.Equal(t, []string{"fetch", "parse", "filter", "probe", "prune", "select", "render", "activate"}, rec.order,
		"the wave continues past a stats failure (the recorder only logs successful stages)")
	assert.Contains(t, out, "stats poll unavailable", "the failure is surfaced, never swallowed")
	assert.Contains(t, out, "connection refused")
}

// --- activate-if-changed (real logic, no mocks) ---

func writeMaintainFiles(t *testing.T, cfg *config.Config, renderedContent, liveContent string) {
	t.Helper()
	p := newPaths(cfg)
	require.NoError(t, os.MkdirAll(p.renderedDir, 0o750))
	require.NoError(t, os.WriteFile(p.rendered, []byte(renderedContent), 0o600))
	require.NoError(t, os.WriteFile(cfg.Activate.Target, []byte(liveContent), 0o600))
}

func TestMaintainActivateSkippedWhenRenderedMatchesLive(t *testing.T) {
	cfg := maintainCfg(t)
	writeMaintainFiles(t, cfg, `{"v":1}`, `{"v":1}`)
	rec := &stageRecorder{}
	stages := rec.stages()
	stages.activate = func(c *cobra.Command, cc *config.Config) error {
		return runActivateStage(c, cc, nil) // nil wiring: the no-op path never reaches systemd
	}

	out := runMaintainForTest(t, cfg, maintainOptions{}, stages)
	assert.Contains(t, out, "no changes", "unchanged render must print a clear no-op line")
	assert.NotContains(t, out, "activation complete")

	live, err := os.ReadFile(cfg.Activate.Target)
	require.NoError(t, err)
	assert.Equal(t, `{"v":1}`, string(live), "live config untouched")
}

func TestMaintainActivatesWhenRenderedDiffers(t *testing.T) {
	cfg := maintainCfg(t)
	fake := fakeXrayForMaintain(t, t.TempDir(), "ok")
	cfg.Activate.XrayBin = fake
	writeMaintainFiles(t, cfg, `{"v":2,"pool":"new"}`, `{"v":1}`)
	rec := &stageRecorder{}
	stages := rec.stages()
	wiring := &restartWiring{Executor: &recordingExecutor{}}
	stages.activate = func(c *cobra.Command, cc *config.Config) error {
		return runActivateStage(c, cc, wiring)
	}

	out := runMaintainForTest(t, cfg, maintainOptions{}, stages)
	assert.Contains(t, out, "activation complete", "differs → activate via the -test gate")
	assert.Contains(t, out, "restart ok", "W13: a real activation restarts the live client (auto_restart defaults on)")

	live, err := os.ReadFile(cfg.Activate.Target)
	require.NoError(t, err)
	assert.JSONEq(t, `{"v":2,"pool":"new"}`, string(live), "target replaced with the rendered config")
}

func TestMaintainFailedTestGateFailsWave(t *testing.T) {
	cfg := maintainCfg(t)
	fake := fakeXrayForMaintain(t, t.TempDir(), "fail") // -test always fails
	cfg.Activate.XrayBin = fake
	writeMaintainFiles(t, cfg, `{"bad":true}`, `{"v":1}`)
	rec := &stageRecorder{}
	stages := rec.stages()
	exec := &recordingExecutor{}
	stages.activate = func(c *cobra.Command, cc *config.Config) error {
		return runActivateStage(c, cc, &restartWiring{Executor: exec})
	}

	err := runMaintain(&bytes.Buffer{}, cfg, maintainOptions{}, stages)
	require.Error(t, err, "a config failing -test must fail the wave loud (L10)")
	assert.Empty(t, exec.calls, "a failed gate never reaches systemd (W13 rail)")
	live, err2 := os.ReadFile(cfg.Activate.Target)
	require.NoError(t, err2)
	assert.Equal(t, `{"v":1}`, string(live), "live config untouched after failed gate")
}

// TestMaintainMissingRenderedConfigIsLoud pins the guard when render produced
// nothing (mocked render in these tests): activation refuses rather than
// replacing the live config with empty bytes.
func TestMaintainMissingRenderedConfigIsLoud(t *testing.T) {
	cfg := maintainCfg(t)
	rec := &stageRecorder{}
	stages := rec.stages()
	exec := &recordingExecutor{}
	stages.activate = func(c *cobra.Command, cc *config.Config) error {
		return runActivateStage(c, cc, &restartWiring{Executor: exec})
	}
	err := runMaintain(&bytes.Buffer{}, cfg, maintainOptions{}, stages)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rendered config")
	assert.Empty(t, exec.calls, "nothing rendered — nothing replaced, nothing restarted")

	_, statErr := os.Stat(cfg.Activate.Target)
	assert.True(t, os.IsNotExist(statErr), "nothing was ever written to the target")
}

// fakeXrayForMaintain mirrors the activate package's fake-xray pattern.
func fakeXrayForMaintain(t *testing.T, dir, verdict string) string {
	t.Helper()
	path := filepath.Join(dir, "fake-maintain-xray.sh")
	var body string
	switch verdict {
	case "ok":
		body = "#!/bin/sh\necho 'Configuration OK'\nexit 0\n"
	case "fail":
		body = "#!/bin/sh\necho 'Failed to start: main: failed to load config files' >&2\nexit 1\n"
	default:
		t.Fatalf("unknown verdict %q", verdict)
	}
	require.NoError(t, os.WriteFile(path, []byte(body), 0o755))
	return path
}

func TestMaintainFlagsExist(t *testing.T) {
	root := New()
	m := findCmd(t, root, "maintain")
	names := map[string]bool{}
	m.Flags().VisitAll(func(f *pflag.Flag) { names[f.Name] = true })
	assert.True(t, names["no-activate"], "--no-activate documented")
	assert.True(t, names["skip-probe"], "--skip-probe documented")
	assert.True(t, names["speedtest"], "--speedtest for the weekly speedtest wave")
}
