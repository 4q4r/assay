package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"assay/internal/config"

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

// --- activate-if-changed (real logic, no mocks; the T4 own-core stage) ---

// ownMaintainFixture is the own-core wave fixture: the recorder stages ride
// around the REAL own activate stage, driven through an injected manager
// (the watch daemon's wiring shape); the spawned fake core is stopped at
// cleanup so nothing leaks past the test.
func ownMaintainFixture(t *testing.T) (*ownFixture, *maintainStages) {
	t.Helper()
	f := newOwnFixture(t)
	mgr := f.ownManager(t)
	t.Cleanup(func() { _ = mgr.Stop() })
	rec := &stageRecorder{}
	stages := rec.stages()
	stages.activate = func(c *cobra.Command, cc *config.Config) error {
		return runActivateStageWithManager(c, cc, mgr)
	}
	return f, stages
}

func TestMaintainActivateSkippedWhenRenderedMatchesLive(t *testing.T) {
	f, stages := ownMaintainFixture(t)
	f.writeOwnLive(t, "gen-0")
	f.writeOwnCandidate(t, "gen-0") // byte-identical steady state

	out := runMaintainForTest(t, f.cfg, maintainOptions{}, stages)
	assert.Contains(t, out, "no changes", "unchanged render must print a clear no-op line")
	assert.NotContains(t, out, "activation complete")

	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.Equal(t, string(ownLiveBytes(f.cfg.Core.SocksPort, "gen-0")), string(live),
		"live config untouched")
}

func TestMaintainActivatesWhenRenderedDiffers(t *testing.T) {
	f, stages := ownMaintainFixture(t)
	f.writeOwnLive(t, "gen-0")
	f.writeOwnCandidate(t, "gen-new")

	out := runMaintainForTest(t, f.cfg, maintainOptions{}, stages)
	assert.Contains(t, out, "activation complete", "differs → activate via the -test gate")
	logs := f.log.String()
	assert.Contains(t, logs, "core: spawned pid",
		"T4: a real activation restarts the OWN core through the core manager")
	assert.Contains(t, logs, "core: health failure 1/",
		"the post-activation health feeds the strike counter (C3; the fake outbound is dead)")

	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.Equal(t, string(ownLiveBytes(f.cfg.Core.SocksPort, "gen-new")), string(live),
		"live.json replaced with the candidate")

	matches, err := filepath.Glob(filepath.Join(f.p.backupDir, "config.json.bak-*"))
	require.NoError(t, err)
	assert.Len(t, matches, 1, "the C1 dated backup exists")
}

func TestMaintainFailedTestGateFailsWave(t *testing.T) {
	f, stages := ownMaintainFixture(t)
	f.writeOwnLive(t, "gen-0")
	// The candidate carries the fake gate's refusal marker: `-test` exits 1.
	require.NoError(t, os.MkdirAll(filepath.Dir(ownCandidatePath(f.p)), 0o750))
	require.NoError(t, os.WriteFile(ownCandidatePath(f.p),
		[]byte(fmt.Sprintf(`{"marker":%q,"inbounds":[{"tag":"in","listen":"127.0.0.1","port":%d,"protocol":"socks"}]}`,
			cliFakeGateFail, f.cfg.Core.SocksPort)), 0o600))

	err := runMaintain(&bytes.Buffer{}, f.cfg, maintainOptions{}, stages)
	require.Error(t, err, "a config failing -test must fail the wave loud (L10)")
	assert.Contains(t, err.Error(), "-test gate failed")
	live, err2 := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err2)
	assert.Equal(t, string(ownLiveBytes(f.cfg.Core.SocksPort, "gen-0")), string(live),
		"live config untouched after failed gate")
	matches, err3 := filepath.Glob(filepath.Join(f.p.backupDir, "config.json.bak-*"))
	require.NoError(t, err3)
	assert.Empty(t, matches, "a failed gate takes no backup")
}

// TestMaintainMissingRenderedConfigIsLoud pins the loud no-op when render
// produced no activation candidate (empty pool / render not run): the wave
// completes, nothing is replaced, nothing restarts (the D7 keep-last-good
// activate layer).
func TestMaintainMissingRenderedConfigIsLoud(t *testing.T) {
	f, stages := ownMaintainFixture(t)

	out := runMaintainForTest(t, f.cfg, maintainOptions{}, stages)
	assert.Contains(t, out, "no rendered own config candidate",
		"the loud line names the state — never a silent no-op")
	assert.NotContains(t, out, "activation complete")

	_, statErr := os.Stat(ownLivePath(f.p))
	assert.True(t, os.IsNotExist(statErr), "nothing was ever written to the live config")
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
