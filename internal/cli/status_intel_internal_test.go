// Phase 4 status intelligence dashboard tests: verdict-threshold bands
// (table-driven), the --json machine-readable contract (field names, order,
// round-trip), the --overlap composition, NO_COLOR / plain-ASCII fallbacks
// (sparkline ladder " ..--==#", funnel bars "=-", verdicts [OK]/[!!]/[XX]),
// cold-start rendering, and the provider table's alignment stability.

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"public_vpn/internal/plugins"
	"public_vpn/internal/stats"
	"public_vpn/internal/ui"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statusIntelFixture builds a data dir with an ENRICHED manifest (post-
// upgrade shape), provider history, and a Phase-1 geo base — the "warm"
// state every dashboard element fills in for.
func statusIntelFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "run", "systemd"), 0o755))

	cfgPath := filepath.Join(home, "config.toml")
	body := "data_dir = " + quotePath(filepath.Join(home, "data")) + `

[maintain]
refresh_interval = "6h"
speedtest_interval = "168h"

[plugins]
max_duplicate_percent = 20.0
min_live_percent = 50.0
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))

	dataDir := filepath.Join(home, "data")
	cacheDir := filepath.Join(dataDir, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o750))

	// Funnel inputs: fetched 3 → filtered 2 → probed 3 (2 alive) → geo clean 1
	// (hosting evidence present) → selected 3 (one unknown-geo node).
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "nodes.jsonl"),
		[]byte("{\"raw\":\"a\"}\n{\"raw\":\"b\"}\n{\"raw\":\"c\"}\n"), 0o600))
	// filtered: REAL node records keyed to the probe store and geo base —
	// the per-provider Phase-1 join (status-side mirror of the enrichment
	// join) attributes them by source.
	filtered := "{\"key\":\"k1\",\"source\":\"plugin_a\",\"scheme\":\"vless\",\"host\":\"a.example\",\"port\":443}\n" +
		"{\"key\":\"k2\",\"source\":\"plugin_b_redundant\",\"scheme\":\"vless\",\"host\":\"b.example\",\"port\":443}\n"
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "filtered.jsonl"), []byte(filtered), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "probe-results.jsonl"),
		[]byte("{\"key\":\"k1\",\"host\":\"h1\",\"alive\":true,\"checked_at\":\"2026-11-04T10:00:00Z\"}\n"+
			"{\"key\":\"k2\",\"host\":\"h2\",\"alive\":true,\"checked_at\":\"2026-11-04T10:00:00Z\"}\n"+
			"{\"key\":\"k3\",\"host\":\"h3\",\"alive\":false,\"checked_at\":\"2026-11-04T10:00:00Z\"}\n"), 0o600))
	// geo base: two records with Phase-1 evidence (one clean residential de
	// with unlock data — plugin_a's live node; one hosting nl — plugin_b's
	// live node), one legacy record (no evidence, dead). Sources attribute
	// each record to its plugin.
	geo := "{\"scheme\":\"vless\",\"host\":\"a.example\",\"port\":443,\"source\":\"plugin_a\",\"country\":\"de\",\"city\":\"Berlin\",\"alive\":true," +
		"\"risk_score\":12,\"is_residential\":true,\"ip_type\":\"Residential\"," +
		"\"media_unlocks\":{\"chatgpt\":\"yes\",\"netflix\":\"full\",\"youtube_region\":\"de\",\"checked_at\":\"2026-11-04T09:00:00Z\"}}\n" +
		"{\"scheme\":\"vless\",\"host\":\"b.example\",\"port\":443,\"source\":\"plugin_b_redundant\",\"country\":\"nl\",\"alive\":true," +
		"\"risk_score\":70,\"is_hosting\":true,\"hosting_flag\":true,\"ip_type\":\"DataCenter\"}\n" +
		"{\"scheme\":\"vmess\",\"host\":\"c.example\",\"port\":443,\"source\":\"plugin_a\",\"country\":\"\",\"alive\":false}\n"
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "geo-base.jsonl"), []byte(geo), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "selection.json"),
		[]byte("{\"cap_applied\":3,\"nodes\":[{\"tag\":\"pool-de-01\",\"key\":\"k1\",\"country\":\"de\"},"+
			"{\"tag\":\"pool-nl-01\",\"key\":\"k2\",\"country\":\"nl\"},"+
			"{\"tag\":\"pool-xx-01\",\"key\":\"k9\",\"country\":\"\"}]}"), 0o600))

	// Manifest: enriched stats + overlap matrix (Go-default field names, the
	// runtime wire shape). Four providers exercise every verdict class of
	// the pool-relative engine:
	//   plugin_a           GOOD (composite 95: strong on every factor, ↑)
	//   plugin_b_redundant POOR (composite 18.75: weakest live/uniqueness)
	//   plugin_c_dead      DEAD (override: 0 live, no history)
	//   plugin_d_mid       WEAK (composite 32.8: cleanliness DROPPED — no
	//                      Phase-1 evidence — weights renormalized to 0.80)
	manifest := map[string]any{
		"fetched_at": "2026-11-04T12:00:00Z",
		"sources":    map[string]any{},
		"plugin_stats": []map[string]any{
			{
				"PluginID": "plugin_a", "TotalNodes": 100, "LiveNodes": 80,
				"DuplicateCount": 10, "HostingCount": 30, "ProxyCount": 20, "CleanCount": 50,
				// Post-F6 enrichment always records the geo-classified count.
				// NOTE: the dashboard's clean% no longer reads these manifest
				// counters — it gates on phase1Evidence over the cold base
				// (unified evidence definition, owner ruling 2026-11-05).
				"ClassifiedCount": 100,
				"UnlockCount":     12, "UniqueYield": 88.0,
				"TopOverlaps": []map[string]any{
					{"plugin_id": "plugin_b_redundant", "percent": 12.0},
				},
			},
			{
				"PluginID": "plugin_b_redundant", "TotalNodes": 50, "LiveNodes": 5,
				"DuplicateCount": 25, "HostingCount": 10, "ProxyCount": 5, "CleanCount": 35,
				"ClassifiedCount": 50,
				"UniqueYield":     8.0,
				"TopOverlaps": []map[string]any{
					{"plugin_id": "plugin_a", "percent": 82.0},
				},
			},
			{
				"PluginID": "plugin_c_dead", "TotalNodes": 200, "LiveNodes": 0,
				"DuplicateCount": 30, "HostingCount": 0, "ProxyCount": 0, "CleanCount": 0,
				"ClassifiedCount": 0,
				"UniqueYield":     30.0,
				"TopOverlaps": []map[string]any{
					{"plugin_id": "plugin_a", "percent": 40.0},
				},
			},
			{
				// The fix-round-1 defect shape: a freshly-ingested source
				// whose wave has NOT reached its enrichment tail — fetch-
				// stage live=0, ZERO provider-history waves. Verdict must be
				// NEW (never DEAD on zero evidence).
				"PluginID": "plugin_e_fresh", "TotalNodes": 500, "LiveNodes": 0,
				"DuplicateCount": 40, "HostingCount": 0, "ProxyCount": 0, "CleanCount": 0,
				"ClassifiedCount": 0,
				"UniqueYield":     20.0,
				"TopOverlaps": []map[string]any{
					{"plugin_id": "plugin_a", "percent": 30.0},
				},
			},
			{
				"PluginID": "plugin_d_mid", "TotalNodes": 80, "LiveNodes": 8,
				"DuplicateCount": 8, "HostingCount": 0, "ProxyCount": 0, "CleanCount": 0,
				// The manifest CLAIMS 80 classified for plugin_d — but the
				// cold base carries no Phase-1 evidence for it. The unified
				// predicate wins: clean% renders n/a and the cleanliness
				// factor drops out of the composite (that is the point).
				"ClassifiedCount": 80,
				"UniqueYield":     45.0,
				"TopOverlaps": []map[string]any{
					{"plugin_id": "plugin_a", "percent": 55.0},
				},
			},
		},
		"plugin_overlap": map[string]any{
			"sets": map[string]any{"plugin_a": 90, "plugin_b_redundant": 46},
			"cells": map[string]any{
				"plugin_a":           map[string]any{"plugin_a": 100.0, "plugin_b_redundant": 12.0},
				"plugin_b_redundant": map[string]any{"plugin_a": 82.0, "plugin_b_redundant": 100.0},
			},
		},
	}
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "manifest.json"),
		mustMarshalJSON(t, manifest), 0o600))

	// Provider history: plugin_a has 6 waves inside the trailing 24h window
	// with rates 0..100% (exercises the whole sparkline ladder, ↑ trend);
	// plugin_d has 6 flat 60% waves (→ trend, no modifier).
	hist := stats.ProviderHistory{Providers: map[string]*stats.ProviderSeries{}}
	series := &stats.ProviderSeries{}
	base := time.Now().UTC().Truncate(time.Hour).Add(-6 * time.Hour)
	lives := []int{0, 20, 40, 60, 80, 100}
	for i, live := range lives {
		ts := base.Add(time.Duration(i) * time.Hour)
		stats.UpdateSeries(series, stats.WaveSnapshot{Timestamp: ts.Unix(), Total: 100, Live: live}, ts)
	}
	hist.Providers["plugin_a"] = series
	flat := &stats.ProviderSeries{}
	for i := range 6 {
		ts := base.Add(time.Duration(i) * time.Hour)
		stats.UpdateSeries(flat, stats.WaveSnapshot{Timestamp: ts.Unix(), Total: 100, Live: 60}, ts)
	}
	hist.Providers["plugin_d_mid"] = flat
	// plugin_c_dead: exactly 3 recorded dead waves — death EARNED (the
	// 3-wave floor of the DEAD override).
	dead := &stats.ProviderSeries{}
	for i := range 3 {
		ts := base.Add(time.Duration(i) * time.Hour)
		stats.UpdateSeries(dead, stats.WaveSnapshot{Timestamp: ts.Unix(), Total: 200, Live: 0}, ts)
	}
	hist.Providers["plugin_c_dead"] = dead
	// plugin_b_redundant: 3 recorded waves — a scored provider (past the
	// NEW gate; its 10% liveness history feeds the 24h-avg column).
	young := &stats.ProviderSeries{}
	for i := range 3 {
		ts := base.Add(time.Duration(i) * time.Hour)
		stats.UpdateSeries(young, stats.WaveSnapshot{Timestamp: ts.Unix(), Total: 50, Live: 5}, ts)
	}
	hist.Providers["plugin_b_redundant"] = young
	// plugin_e_fresh: deliberately NO history entry — the brand-new source.
	require.NoError(t, stats.WriteProviderHistory(
		filepath.Join(dataDir, providerHistoryFile), &hist))
	return cfgPath
}

func quotePath(p string) string { return "\"" + p + "\"" }

// runStatusCaptured executes the full status path with the REAL command
// surface (flags registered by newStatusCommand) while pinning the config
// resolution through the explicit seam.
func runStatusCaptured(t *testing.T, cfgPath string, setFlags func(*cobra.Command)) string {
	t.Helper()
	cmd := newStatusCommand(&cfgPath)
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	if setFlags != nil {
		setFlags(cmd)
	}
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
	return out.String()
}

// ---------------------------------------------------------------------------
// Pool-relative verdict engine (owner ruling 2026-11-05)
// ---------------------------------------------------------------------------

// engineRow builds a synthetic scored row for engine-level tests. waves
// seeds that many recorded history waves (0 = no series — the brand-new
// source shape); every seeded wave is 50/100 liveness inside the 24h window,
// so alive24 stays a test-set field (it is not a composite factor).
func engineRow(id string, live int, alivePct float64, breadth int, cleanPct float64, cleanEvidence bool, unique float64, trend string, waves int) providerRow {
	r := providerRow{
		stats:         plugins.PluginStats{PluginID: id, TotalNodes: 100, LiveNodes: live},
		enriched:      true,
		alivePct:      alivePct,
		geoBreadth:    breadth,
		cleanPct:      cleanPct,
		cleanEvidence: cleanEvidence,
		uniquePct:     unique,
		trend:         trend,
	}
	if waves > 0 {
		s := &stats.ProviderSeries{}
		for i := range waves {
			stats.UpdateSeries(s, stats.WaveSnapshot{
				Timestamp: time.Now().UTC().Add(-time.Duration(waves-i) * time.Hour).Unix(),
				Total:     100, Live: 50,
			}, time.Now().UTC())
		}
		r.history = s
	}
	return r
}

// TestPercentileRanksMidranks pins the competition-midrank percentile:
// tied values share (rank_first+rank_last)/2, normalized (midrank−1)/(N−1).
func TestPercentileRanksMidranks(t *testing.T) {
	tests := []struct {
		name   string
		values []float64
		want   []float64
	}{
		{"no ties", []float64{1, 2, 3}, []float64{0, 0.5, 1}},
		{"reverse order keeps positions", []float64{3, 1, 2}, []float64{1, 0, 0.5}},
		// [5,5,9]: the 5s hold ranks 1–2 → midrank 1.5 → (1.5−1)/2 = 0.25.
		{"tie pool", []float64{5, 5, 9}, []float64{0.25, 0.25, 1}},
		{"all tied", []float64{7, 7, 7}, []float64{0.5, 0.5, 0.5}},
		{"single value", []float64{4.2}, []float64{0.5}},
		{"empty", nil, []float64{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := percentileRanks(tc.values)
			require.Len(t, got, len(tc.want))
			for i := range tc.want {
				assert.InDelta(t, tc.want[i], got[i], 1e-9)
			}
		})
	}
	// Bounds: every rank lands in [0,1] for a randomized pool.
	values := []float64{9, 1, 5, 5, 2, 8, 5, 3}
	for _, r := range percentileRanks(values) {
		assert.GreaterOrEqual(t, r, 0.0)
		assert.LessOrEqual(t, r, 1.0)
	}
}

// TestBandVerdictBoundaries pins the owner bands at the exact edges:
// ≥75 GOOD, 50–75 FAIR, 25–50 WEAK, <25 POOR.
func TestBandVerdictBoundaries(t *testing.T) {
	tests := []struct {
		score     float64
		want      string
		wantColor string
	}{
		{100, verdictGood, ui.Green},
		{75, verdictGood, ui.Green},
		{74.9, verdictFair, ui.Amber},
		{50, verdictFair, ui.Amber},
		{49.9, verdictWeak, ui.Amber},
		{25, verdictWeak, ui.Amber},
		{24.9, verdictPoor, ui.Red},
		{0, verdictPoor, ui.Red},
	}
	for _, tc := range tests {
		word, color := bandVerdict(tc.score)
		assert.Equal(t, tc.want, word, "score %v", tc.score)
		assert.Equal(t, tc.wantColor, color, "score %v", tc.score)
	}
}

// TestPoolRelativeScoreWeightRenorm pins the renormalization: dropped
// factors remove their weight AND value; the available weights sum to 1 for
// any evidence combo (OECD/JRC: aggregate normalized available dimensions
// only — a missing dimension is never a zero).
func TestPoolRelativeScoreWeightRenorm(t *testing.T) {
	all := func(values [5]float64) []verdictFactor {
		return []verdictFactor{
			{weight: verdictWeightLiveCount, value: values[0], available: true},
			{weight: verdictWeightAliveShare, value: values[1], available: true},
			{weight: verdictWeightGeoBreadth, value: values[2], available: true},
			{weight: verdictWeightCleanliness, value: values[3], available: true},
			{weight: verdictWeightUniqueness, value: values[4], available: true},
		}
	}
	t.Run("all-percentiles-one scores 100 regardless of dropout", func(t *testing.T) {
		// Every availability combo renormalizes to weight-sum 1: a provider
		// that tops every available factor must top the scale.
		for _, clean := range []bool{true, false} {
			fs := all([5]float64{1, 1, 1, 1, 1})
			fs[3].available = clean
			assert.InDelta(t, 1.0, poolRelativeScore(fs), 1e-9, "cleanEvidence=%v", clean)
		}
	})
	t.Run("all-percentiles-zero scores 0", func(t *testing.T) {
		fs := all([5]float64{0, 0, 0, 0, 0})
		assert.InDelta(t, 0.0, poolRelativeScore(fs), 1e-9)
	})
	t.Run("dropped factor renormalizes the rest", func(t *testing.T) {
		fs := all([5]float64{0.5, 0.5, 0.25, 0.75, 1})
		fs[3].available = false // cleanliness drops: weight 0.20 leaves
		// (0.30×.5 + 0.15×.5 + 0.20×.25 + 0.15×1) / 0.80 = .425/.80
		assert.InDelta(t, 0.53125, poolRelativeScore(fs), 1e-9)
	})
	t.Run("nothing available scores 0", func(t *testing.T) {
		fs := all([5]float64{1, 1, 1, 1, 1})
		for i := range fs {
			fs[i].available = false
		}
		assert.InDelta(t, 0.0, poolRelativeScore(fs), 1e-9)
	})
}

// TestTrendModifierDeltas pins the ClassifyTrend→delta map and the [0,100]
// clamp.
func TestTrendModifierDeltas(t *testing.T) {
	tests := []struct {
		trend string
		want  float64
	}{
		{stats.TrendUpStrong, 5.0},
		{stats.TrendUp, 2.5},
		{stats.TrendFlat, 0},
		{stats.TrendDown, -2.5},
		{stats.TrendDownStrong, -5.0},
		{"", 0}, // unknown glyph contributes nothing
	}
	for _, tc := range tests {
		row := engineRow("p", 10, 10, 1, 100, true, 50, tc.trend, verdictMinHistoryWaves)
		assert.InDelta(t, tc.want, trendModifier(&row), 1e-9, "trend %q", tc.trend)
	}
	// No history: no modifier even with a (stale) glyph set.
	row := engineRow("p", 10, 10, 1, 100, true, 50, stats.TrendUpStrong, 0)
	assert.InDelta(t, 0.0, trendModifier(&row), 1e-9)

	// Clamp: the modifier fine-tunes within the scale, never beyond it.
	assert.InDelta(t, 100, applyTrendModifier(98, 5), 1e-9)
	assert.InDelta(t, 0, applyTrendModifier(1, -5), 1e-9)
	assert.InDelta(t, 75, applyTrendModifier(72.5, 2.5), 1e-9)
	assert.InDelta(t, 49.9, applyTrendModifier(52.4, -2.5), 1e-9)
}

// TestComputeVerdictsOverridesAndFallback pins the override precedence and
// the small-pool absolute fallback.
func TestComputeVerdictsOverridesAndFallback(t *testing.T) {
	t.Run("NONE outranks DEAD without evidence", func(t *testing.T) {
		// A pre-upgrade manifest row (no enrichment) has no evidence to
		// conclude DEAD from — it stays the honest pending NONE even though
		// its live count is zero. (buildProviderRows constructs rows with
		// verdict NONE; the synthetic row mirrors that.)
		rows := []providerRow{{stats: plugins.PluginStats{PluginID: "cold", TotalNodes: 100}, verdict: verdictNone}}
		computeVerdicts(rows)
		assert.Equal(t, verdictNone, rows[0].verdict)
		assert.Empty(t, rows[0].verdictCol)
	})
	t.Run("DEAD override: 0 live and dead 24h average", func(t *testing.T) {
		rows := []providerRow{
			engineRow("dead", 0, 0, 0, 0, false, 30, "", verdictMinHistoryWaves),
			engineRow("alive", 4, 4, 0, 0, false, 30, "", verdictMinHistoryWaves),
		}
		computeVerdicts(rows)
		assert.Equal(t, verdictDead, rows[0].verdict)
		assert.Equal(t, ui.Red, rows[0].verdictCol)
		assert.Equal(t, verdictFair, rows[1].verdict, "N=2 pool → absolute fallback: alive>0 → FAIR")
	})
	t.Run("recent death escapes the DEAD override", func(t *testing.T) {
		// live==0 but the 24h average is above the floor: the DEAD override
		// does NOT fire — in a scoreable pool the row composite-scores
		// instead (and a composite verdict is never DEAD).
		dying := engineRow("dying", 0, 0, 0, 0, false, 30, "", verdictMinHistoryWaves)
		dying.alive24 = 2.0 // history says it was alive until recently
		rows := []providerRow{
			dying,
			engineRow("a", 40, 40, 1, 100, true, 50, "", verdictMinHistoryWaves),
			engineRow("b", 20, 20, 1, 100, true, 50, "", verdictMinHistoryWaves),
		}
		computeVerdicts(rows)
		assert.NotEqual(t, verdictDead, rows[0].verdict,
			"alive24 above the floor escapes the DEAD override")
	})
	t.Run("N=1 alive pool → FAIR; N=1 dead pool → DEAD (design fallback)", func(t *testing.T) {
		rows := []providerRow{engineRow("solo", 4, 4, 0, 0, false, 99, "", verdictMinHistoryWaves)}
		computeVerdicts(rows)
		assert.Equal(t, verdictFair, rows[0].verdict)
		dead := []providerRow{engineRow("corpse", 0, 0, 0, 0, false, 99, "", verdictMinHistoryWaves)}
		computeVerdicts(dead)
		assert.Equal(t, verdictDead, dead[0].verdict, "N<3 fallback: live==0 → DEAD")
	})
	t.Run("N=3 crosses into the composite", func(t *testing.T) {
		three := []providerRow{
			engineRow("a", 80, 80, 1, 100, true, 88, stats.TrendUpStrong, verdictMinHistoryWaves),
			engineRow("b", 5, 10, 1, 0, true, 8, "", verdictMinHistoryWaves),
			engineRow("c", 8, 10, 0, 0, false, 45, stats.TrendFlat, verdictMinHistoryWaves),
		}
		computeVerdicts(three)
		assert.Equal(t, verdictGood, three[0].verdict, "composite 90+5=95")
		assert.Equal(t, verdictPoor, three[1].verdict, "composite 18.75")
		assert.Equal(t, verdictWeak, three[2].verdict,
			"composite 32.8 with cleanliness dropped (weights renormalized to 0.80)")
	})
}

// TestComputeVerdictsNeverTrips pins that TRIP stays reserved: the constant
// exists for future breaker persistence, and no engine path returns it.
func TestComputeVerdictsNeverTrips(t *testing.T) {
	assert.NotEmpty(t, verdictTrip, "the reserved constant is defined")
	pools := [][]providerRow{
		{engineRow("solo", 0, 0, 0, 0, false, 0, "", 0)},
		{engineRow("a", 4, 4, 0, 0, false, 99, "", verdictMinHistoryWaves),
			engineRow("b", 0, 0, 0, 0, false, 1, "", verdictMinHistoryWaves)},
		{engineRow("a", 80, 80, 1, 100, true, 88, stats.TrendUpStrong, verdictMinHistoryWaves),
			engineRow("b", 5, 10, 1, 0, true, 8, stats.TrendDownStrong, verdictMinHistoryWaves),
			engineRow("c", 8, 10, 0, 0, false, 45, stats.TrendFlat, verdictMinHistoryWaves)},
		{{stats: plugins.PluginStats{PluginID: "cold"}}},
	}
	for _, rows := range pools {
		computeVerdicts(rows)
		for _, r := range rows {
			assert.NotEqual(t, verdictTrip, r.verdict, "TRIP is never returned")
		}
	}
}

// TestProviderCleanEvidenceUnification pins the unified Phase-1 evidence
// definition: clean% exists only where phase1Evidence-classified records
// exist (classified-only numerator AND denominator), and a provider with
// zero classified records carries NO clean evidence — the table renders
// n/a, the JSON null, and the cleanliness factor drops from its composite.
func TestProviderCleanEvidenceUnification(t *testing.T) {
	now := time.Now()
	pgeo := map[string]providerGeoIntel{
		"plugin_p": {Classified: 2, Clean: 1, Breadth: 1}, // 1 of 2 classified are clean
		"plugin_q": {},                                    // no Phase-1 evidence at all
		"plugin_r": {Classified: 3, Clean: 3, Breadth: 0},
	}
	m := &fetchManifest{PluginStats: []plugins.PluginStats{
		{PluginID: "plugin_p", TotalNodes: 100, LiveNodes: 50, UniqueYield: 40},
		{PluginID: "plugin_q", TotalNodes: 60, LiveNodes: 30, ClassifiedCount: 60, UniqueYield: 40},
		{PluginID: "plugin_r", TotalNodes: 20, LiveNodes: 10, ClassifiedCount: 20, UniqueYield: 40},
	}}
	rows := buildProviderRows(m, &stats.ProviderHistory{Providers: map[string]*stats.ProviderSeries{}}, pgeo, now)
	require.Len(t, rows, 3)
	assert.InDelta(t, 50.0, rows[0].cleanPct, 1e-9, "clean% is Clean/Classified")
	assert.True(t, rows[0].cleanEvidence)
	assert.Equal(t, 2, rows[0].classified)
	// plugin_q: the manifest CLAIMS 60 classified — the unified predicate
	// says no Phase-1 evidence; the honest state wins over the counter.
	assert.False(t, rows[1].cleanEvidence, "manifest counters are NOT the evidence source")
	assert.InDelta(t, 0.0, rows[1].cleanPct, 1e-9)
	assert.Equal(t, 0, rows[1].classified)
	assert.True(t, rows[2].cleanEvidence)
}

// ---------------------------------------------------------------------------
// Flags surface
// ---------------------------------------------------------------------------

func TestStatusCommandCarriesIntelFlags(t *testing.T) {
	cfgPath := ""
	cmd := newStatusCommand(&cfgPath)
	require.NotNil(t, cmd.Flags().Lookup("json"), "status carries --json")
	overlap := cmd.Flags().Lookup("overlap")
	require.NotNil(t, overlap, "status carries --overlap")
	assert.Equal(t, "v", overlap.Shorthand, "-v is the overlap shorthand (no conflict on status)")

	bare := &cobra.Command{}
	jsonOut, ov := statusOutputFlags(bare)
	assert.False(t, jsonOut, "a bare command renders the dashboard")
	assert.False(t, ov, "a bare command has no overlap view")
}

// ---------------------------------------------------------------------------
// Cold start (the live tree's pre-upgrade shape)
// ---------------------------------------------------------------------------

// statusColdFixture keeps the manifest zero-enriched (the pre-upgrade
// binary's shape), no provider history, no overlap matrix, no geo base.
func statusColdFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "run", "systemd"), 0o755))
	cfgPath := filepath.Join(home, "config.toml")
	body := "data_dir = " + quotePath(filepath.Join(home, "data")) + `

[maintain]
refresh_interval = "6h"
speedtest_interval = "168h"
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))

	dataDir := filepath.Join(home, "data")
	cacheDir := filepath.Join(dataDir, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "nodes.jsonl"), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "filtered.jsonl"), []byte(""), 0o600))
	manifest := map[string]any{
		"fetched_at": "2026-11-04T12:00:00Z",
		"sources":    map[string]any{},
		"plugin_stats": []map[string]any{
			{"PluginID": "barryfar", "TotalNodes": 18110, "LiveNodes": 0,
				"DuplicateCount": 394, "HostingCount": 0, "ProxyCount": 0, "CleanCount": 0},
		},
	}
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "manifest.json"),
		mustMarshalJSON(t, manifest), 0o600))
	// provider-history.json / geo-base.jsonl / probe-results / selection
	// deliberately absent — the cold start.
	return cfgPath
}

func TestStatusDashboardColdStart(t *testing.T) {
	cfgPath := statusColdFixture(t)
	s := runStatusCaptured(t, cfgPath, nil)

	assert.Contains(t, s, "provider intelligence", "the table section renders")
	assert.Contains(t, s, "calibrating", "no history → the calibrating note")
	assert.Contains(t, s, "n/a", "no enrichment → pending cells")
	assert.Contains(t, s, "liveness/quality columns fill after the plugin-stats enrichment pass",
		"the pending note names the missing pass")
	assert.Contains(t, s, "no ip-quality evidence yet", "quality cold start is explicit")
	assert.Contains(t, s, "no unlock evidence yet", "media cold start is explicit")
	assert.NotContains(t, s, "provider overlap inspection",
		"the matrix view is --overlap-only")
	assert.NotContains(t, s, "\x1b[", "plain mode: zero ANSI")
	assert.Contains(t, s, "0.0%", "an all-zero funnel renders empty shares")

	// --overlap renders the cold-start matrix note instead of a fabricated matrix.
	sOverlap := runStatusCaptured(t, cfgPath, func(cmd *cobra.Command) {
		require.NoError(t, cmd.Flags().Set("overlap", "true"))
	})
	assert.Contains(t, sOverlap,
		"matrix not computed yet — the classification pass builds it during the probe wave",
		"cold overlap is explicit")
	assert.Contains(t, sOverlap, "no strong pruning signal", "advice stays silent without data")
}

// TestStatusJSONColdStartValid pins that --json emits a VALID document even
// on the pre-upgrade tree: verdict NONE, empty sparkline, empty matrix.
func TestStatusJSONColdStartValid(t *testing.T) {
	cfgPath := statusColdFixture(t)
	out := &bytes.Buffer{}
	cmd := newStatusCommand(&cfgPath)
	cmd.SetOut(out)
	require.NoError(t, cmd.Flags().Set("json", "true"))
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))

	var doc statusJSONDoc
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc), "the cold-start payload must parse")
	assert.Equal(t, "1.1", doc.SchemaVersion)
	require.NotEmpty(t, doc.Providers)
	assert.Equal(t, verdictNone, doc.Providers[0].Verdict)
	assert.Nil(t, doc.Providers[0].CleanPct, "no evidence → clean_pct is explicit null")
	assert.Nil(t, doc.Providers[0].ClassifiedCoveragePct, "no evidence → coverage is explicit null")
	assert.Empty(t, doc.Providers[0].Sparkline)
	assert.Empty(t, doc.Providers[0].Overlaps)
	assert.Empty(t, doc.OverlapMatrix)
	assert.Empty(t, doc.Recommendations)
	assert.Equal(t, 0, doc.Pipeline.Fetched)
	assert.NotContains(t, out.String(), "\x1b[", "JSON is color-independent")
	// The raw document carries the explicit nulls (no omitempty).
	assert.Contains(t, out.String(), `"clean_pct": null`)
	assert.Contains(t, out.String(), `"classified_coverage_pct": null`)
}

// ---------------------------------------------------------------------------
// Warm dashboard rendering
// ---------------------------------------------------------------------------

func TestStatusDashboardWarm(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	s := runStatusCaptured(t, cfgPath, nil)

	// New sections.
	assert.Contains(t, s, "pipeline funnel")
	assert.Contains(t, s, "global quality & pool distribution")
	assert.Contains(t, s, "media & unlock summary")
	assert.Contains(t, s, "provider intelligence")

	// Funnel annotations (fetched 3 → filtered 2 → probed 3 → alive 2 →
	// geo clean 1 → selected 3; the fixture carries hosting evidence, so the
	// geo-clean drop keeps the hosting/proxy wording with its count).
	assert.Contains(t, s, "-1 filter policy")
	assert.Contains(t, s, "+1 accumulated store (latest-per-key)")
	assert.Contains(t, s, "-1 hosting/proxy exits + geo fold")
	assert.Contains(t, s, "+2 rank admits beyond geo fold")
	assert.Contains(t, s, "66.7%", "filtered share of fetched")
	// Funnel honesty annotation: one of the three selected nodes carries no
	// geo country evidence.
	assert.Contains(t, s, "geo unknown: 1 (33.3% of selected)")

	// Quality (2 classified: 1 clean residential de, 1 hosting nl; 1 legacy ignored).
	assert.Contains(t, s, "2 classified — clean 1 (50.0%), hosting 1 (50.0%), proxy 0 (0.0%)")
	assert.Contains(t, s, "50.0% clean-residential (1 of 2 classified)")
	assert.Contains(t, s, "2 tagged, 1 unknown — top: de 1, nl 1")

	// Media (one checked record).
	assert.Contains(t, s, "1 exits probed — chatgpt yes 1, netflix full 1")
	assert.Contains(t, s, "youtube: 1 unlocked across de, 0 blocked")
	assert.Contains(t, s, "mean risk 12.0",
		"risk folds only scored (unlock-checked) exits — legacy zeros never drag the mean")

	// Provider table warm cells: sparkline spans the full ladder (max is
	// 100% → the max-relative scale matches the absolute one here), trend is
	// strongly up.
	assert.Contains(t, s, "80 (80.0%)", "current alive cell")
	assert.Contains(t, s, "50.0%", "24h volume-weighted average")
	assert.Contains(t, s, " .--=#", "the sparkline renders (plain mode → pinned ASCII ladder)")
	assert.Contains(t, s, "↑", "the strong up trend arrow")
	assert.Contains(t, s, "plugin_b_re… 12%", "the overlap cell caps partner labels")
	assert.Contains(t, s, "plugin_a 82%", "the owning row renders the full partner id")
	// Clean% honesty: classified>0 renders share ·coverage·; no evidence
	// renders n/a (plugin_c_dead / plugin_d_mid).
	assert.Contains(t, s, "100.0% ·1.0%·", "plugin_a: clean share with classified coverage")
	assert.Contains(t, s, "0.0% ·2.0%·", "plugin_b: 0% clean IS measured — coverage shown")
	// Pool-relative verdicts (worked example in the test fixture comment):
	// plugin_a GOOD, plugin_b POOR, plugin_c DEAD (override — 3 recorded
	// dead waves), plugin_d WEAK (cleanliness dropped), plugin_e_fresh NEW
	// (0 waves — the fix-round-1 defect shape, never DEAD on zero evidence).
	assert.Contains(t, s, "GOOD", "the composite verdict renders")
	assert.Contains(t, s, "POOR", "the weakest composite renders")
	assert.Contains(t, s, "WEAK", "the mid composite renders")
	assert.Contains(t, s, "DEAD", "the earned dead override renders")
	assert.Contains(t, s, "[NEW]", "the brand-new source renders the plain NEW badge")

	// Select chip: cap == selected → the unbounded label (owner cosmetic).
	assert.Contains(t, s, "unbounded · 3 active")
	// The empty `plugins:` header line is gone — the legacy chips follow the
	// table directly.
	assert.NotContains(t, s, "plugins:  \n")

	// Legacy chips keep their exact bytes EXCEPT the owner-ordered
	// dup-links rename (deliberate byte-pin break, 2026-11-05).
	assert.Contains(t, s, "plugin plugin_a: total=100 live=80 (80.0%) dup-links=10 (10.0%)"+
		" hosting=30 (30.0%) proxy=20 (20.0%) clean=50 (50.0%) status=OK")
}

// TestStatusFunnelGeoDropNoteDynamic pins both branches of the dynamic
// geo-clean drop note: zero hosting/proxy evidence names the inversion; a
// non-zero evidence count keeps the dirty-IP wording.
func TestStatusFunnelGeoDropNoteDynamic(t *testing.T) {
	stages := stageCounts{Nodes: 100, Filtered: 90}
	base := buildFunnel(stages, 90, 80, 40, 35, true)
	assert.Contains(t, base[4].Note, "hosting/proxy exits + geo fold",
		"dirty-IP evidence present → the hosting/proxy wording with counts")
	assert.Contains(t, base[4].Note, "-40")

	inverted := buildFunnel(stages, 90, 80, 40, 35, false)
	assert.Contains(t, inverted[4].Note, "probe-store inversion + geo fold (no dirty-IP evidence)",
		"zero evidence → the drop is an inversion, not dirty-IP exits")
	assert.NotContains(t, inverted[4].Note, "hosting/proxy",
		"no fabricated dirty-IP attribution")
}

// TestComputeVerdictsNewState pins the fix-round-1 ruling: a brand-new
// source (enriched manifest row, fewer than 3 recorded history waves) is
// NEW — never DEAD. Death must be EARNED by enough scoring waves; the
// fetch-stage live=0 of an un-enriched wave proves nothing. The 3-wave
// floor is the same one stats.ColdStartMin applies to the Z-score.
func TestComputeVerdictsNewState(t *testing.T) {
	t.Run("0/1/2 waves → NEW (live=0 fetch-stage rows included)", func(t *testing.T) {
		for _, waves := range []int{0, 1, 2} {
			row := engineRow("fresh", 0, 0, 0, 0, false, 20, "", waves)
			rows := []providerRow{row}
			computeVerdicts(rows)
			assert.Equal(t, verdictNew, rows[0].verdict,
				"%d waves: a brand-new source is never DEAD", waves)
			assert.Equal(t, ui.ColorPlainName, rows[0].verdictCol, "%d waves", waves)
		}
	})
	t.Run("exactly 3 waves with live=0 → DEAD (death earned)", func(t *testing.T) {
		rows := []providerRow{engineRow("proven_dead", 0, 0, 0, 0, false, 20, "", verdictMinHistoryWaves)}
		rows[0].alive24 = 0
		computeVerdicts(rows)
		assert.Equal(t, verdictDead, rows[0].verdict)
		assert.Equal(t, ui.Red, rows[0].verdictCol)
	})
	t.Run("NEW outranks a would-be DEAD (0 waves, live=0, dead 24h)", func(t *testing.T) {
		// The reported live defect: live=0 ∧ alive24=0 ∧ zero waves fired
		// isDead on zero evidence. NEW must win that race.
		row := engineRow("defect", 0, 0, 0, 0, false, 20, "", 0)
		rows := []providerRow{row}
		computeVerdicts(rows)
		assert.Equal(t, verdictNew, rows[0].verdict)
		assert.NotEqual(t, verdictDead, rows[0].verdict)
	})
	t.Run("NONE precedence unchanged (unenriched row with 0 waves)", func(t *testing.T) {
		rows := []providerRow{{stats: plugins.PluginStats{PluginID: "cold", TotalNodes: 100}, verdict: verdictNone}}
		computeVerdicts(rows)
		assert.Equal(t, verdictNone, rows[0].verdict, "no enrichment evidence → still NONE, not NEW")
	})
	t.Run("NEW rows never enter the composite pool", func(t *testing.T) {
		// A 2-wave fresh row next to two scored providers: the fresh row
		// stays NEW; the others composite-score as before.
		rows := []providerRow{
			engineRow("fresh", 3, 3, 0, 0, false, 30, "", 2),
			engineRow("a", 80, 80, 1, 100, true, 88, stats.TrendUpStrong, verdictMinHistoryWaves),
			engineRow("b", 20, 20, 1, 100, true, 50, "", verdictMinHistoryWaves),
		}
		computeVerdicts(rows)
		assert.Equal(t, verdictNew, rows[0].verdict)
		assert.NotEqual(t, verdictNew, rows[1].verdict)
		assert.NotEqual(t, verdictNew, rows[2].verdict)
	})
	t.Run("TRIP stays reserved under the NEW precedence", func(t *testing.T) {
		rows := []providerRow{engineRow("x", 0, 0, 0, 0, false, 0, "", 1)}
		computeVerdicts(rows)
		assert.NotEqual(t, verdictTrip, rows[0].verdict)
	})
}

// TestStatusRecommendationsLiveness pins the recommendation rulings:
// keep requires live>0; dead + ≥25% unique = the unique-but-dead class;
// prune ranking is (overlap% desc, live asc).
func TestStatusRecommendationsLiveness(t *testing.T) {
	rows := []providerRow{
		func() providerRow {
			r := engineRow("keep_alive", 40, 40, 1, 100, true, 70, "", verdictMinHistoryWaves)
			r.stats.TopOverlaps = []plugins.OverlapPair{{PluginID: "other", Percent: 5}}
			return r
		}(),
		func() providerRow {
			r := engineRow("unique_but_dead", 0, 0, 0, 0, false, 30, "", verdictMinHistoryWaves)
			r.stats.TopOverlaps = []plugins.OverlapPair{{PluginID: "other", Percent: 40}}
			return r
		}(),
		func() providerRow {
			r := engineRow("redundant_alive", 3, 3, 0, 0, false, 5, "", verdictMinHistoryWaves)
			r.stats.TopOverlaps = []plugins.OverlapPair{{PluginID: "big", Percent: 82}}
			return r
		}(),
		func() providerRow {
			r := engineRow("dead_low_unique", 0, 0, 0, 0, false, 5, "", verdictMinHistoryWaves)
			r.stats.TopOverlaps = []plugins.OverlapPair{{PluginID: "big", Percent: 90}}
			return r
		}(),
		func() providerRow {
			// Dead with ≥60% unique: NOT a keep — keep requires liveness.
			r := engineRow("dead_high_unique", 0, 0, 0, 0, false, 65, "", verdictMinHistoryWaves)
			r.stats.TopOverlaps = []plugins.OverlapPair{{PluginID: "other", Percent: 10}}
			return r
		}(),
	}
	got := recommendations(rows)
	assert.Equal(t, []string{
		// overlap% descending: 90 → 82 → 40 → 10 → 5
		"prune candidate 'dead_low_unique': only 5.0% unique — 90% shared with big",
		"prune candidate 'redundant_alive': only 5.0% unique — 82% shared with big",
		"'unique_but_dead' is unique but dead — verify upstream source (30.0% unique, 0 live nodes)",
		"'dead_high_unique' is unique but dead — verify upstream source (65.0% unique, 0 live nodes)",
		"keep 'keep_alive': 70.0% unique nodes (low overlap, high yield)",
	}, got)
	// Live-ascending tie-break: equal overlap% (90 here) sorts lower live
	// first when ids would sort the other way.
	tie := []providerRow{
		func() providerRow {
			r := engineRow("zz_more_live", 9, 9, 0, 0, false, 5, "", verdictMinHistoryWaves)
			r.stats.TopOverlaps = []plugins.OverlapPair{{PluginID: "big", Percent: 90}}
			return r
		}(),
		func() providerRow {
			r := engineRow("aa_less_live", 1, 1, 0, 0, false, 5, "", verdictMinHistoryWaves)
			r.stats.TopOverlaps = []plugins.OverlapPair{{PluginID: "big", Percent: 90}}
			return r
		}(),
	}
	assert.Equal(t, []string{
		"prune candidate 'aa_less_live': only 5.0% unique — 90% shared with big",
		"prune candidate 'zz_more_live': only 5.0% unique — 90% shared with big",
	}, recommendations(tie), "overlap tie → live ascending")
}

// TestStatusTimestampsLocalTime pins the local-time cosmetic with an
// injected fixed zone — no machine-TZ dependence.
func TestStatusTimestampsLocalTime(t *testing.T) {
	old := time.Local                            //nolint:gosmopolitan // injected fixed zone — the test MUST NOT depend on the machine TZ
	time.Local = time.FixedZone("FIXED", 2*3600) //nolint:gosmopolitan // UTC+2 injection: same reason
	t.Cleanup(func() { time.Local = old })       //nolint:gosmopolitan // restore for sibling tests

	cfgPath := statusIntelFixture(t)
	res := explicitResolved(t, cfgPath)
	p := newPaths(res.Config)
	// A rendered-config artifact with a fixed UTC mtime: 10:00Z → 12:00+02:00.
	stamp := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	require.NoError(t, os.MkdirAll(p.renderedDir, 0o750))
	require.NoError(t, os.WriteFile(p.rendered, []byte("config"), 0o600))
	require.NoError(t, os.Chtimes(p.rendered, stamp, stamp))

	s := runStatusCaptured(t, cfgPath, nil)
	assert.Contains(t, s, "at 2026-11-04T14:00:00+02:00",
		"the fetch stamp renders in the injected local zone (12:00Z + 2h)")
	assert.Contains(t, s, "2026-11-04T12:00:00+02:00",
		"the render mtime renders in the injected local zone (10:00Z + 2h)")
	assert.NotContains(t, s, "2026-11-04T12:00:00Z",
		"no raw UTC fetch stamp leaks into the text view")
}

// TestProviderCleanPercentClassifiedOnlyFlip's premise (F6, owner ruling
// 2026-11-04) lives on in TestProviderCleanEvidenceUnification above: the
// clean share is classified-only, and the evidence source is the unified
// phase1Evidence predicate — never the manifest counters.

func TestStatusDashboardOverlapView(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	s := runStatusCaptured(t, cfgPath, func(cmd *cobra.Command) {
		require.NoError(t, cmd.Flags().Set("overlap", "true"))
	})
	assert.Contains(t, s, "provider overlap inspection")
	assert.Contains(t, s, "100%", "the diagonal is pinned at 100")
	assert.Contains(t, s, "12%", "the a→b overlap share")
	assert.Contains(t, s, "82%", "the b→a overlap share")
	// Pruning advice from the enriched rows: plugin_b_redundant has 8% unique
	// and 82% overlap with plugin_a; plugin_c_dead is dead with 30% unique —
	// the unique-but-dead class; plugin_a keeps (live>0); plugin_d_mid stays
	// silent (alive mid band).
	assert.Contains(t, s, "prune candidate 'plugin_b_redundant': only 8.0% unique — 82% shared with plugin_a")
	assert.Contains(t, s, "'plugin_c_dead' is unique but dead — verify upstream source (30.0% unique, 0 live nodes)")
	assert.Contains(t, s, "keep 'plugin_a': 88.0% unique nodes (low overlap, high yield)")
}

// TestStatusTableAlignmentStability pins the M3 contract on the new tables:
// every line inside one bordered box has the SAME rune width — rows never
// wrap, never collide.
func TestStatusTableAlignmentStability(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	s := runStatusCaptured(t, cfgPath, nil)

	blocks := make([][]int, 0, 2)
	var cur []int
	for line := range strings.SplitSeq(s, "\n") {
		switch {
		case strings.HasPrefix(line, "┌"):
			cur = append(cur[:0], len([]rune(line)))
		case cur != nil && (strings.HasPrefix(line, "│") || strings.HasPrefix(line, "└")):
			cur = append(cur, len([]rune(line)))
			if strings.HasPrefix(line, "└") {
				blocks = append(blocks, cur)
				cur = nil
			}
		}
	}
	require.Len(t, blocks, 2, "the dashboard renders the funnel and provider tables")
	for bi, block := range blocks {
		for i, w := range block {
			assert.Equal(t, block[0], w, "table %d line %d must align with its border box", bi, i)
		}
	}
}

// ---------------------------------------------------------------------------
// NO_COLOR / plain-ASCII fallbacks (pinned ladders)
// ---------------------------------------------------------------------------

func TestStatusDashboardASCIIFallbacks(t *testing.T) {
	cfgPath := statusIntelFixture(t)

	t.Run("plain mode (buffer = color off)", func(t *testing.T) {
		s := runStatusCaptured(t, cfgPath, nil)
		assert.NotContains(t, s, "\x1b[", "zero ANSI")
		assert.NotContains(t, s, "▂", "the unicode sparkline ladder is replaced")
		assert.Contains(t, s, " .--=#", "the pinned ASCII sparkline ladder renders")
		assert.Contains(t, s, "--", "mid-ladder ASCII glyphs render")
		assert.Contains(t, s, " 33.3%", "funnel bars use the =/- ASCII ladder")
		// Verdict words are self-describing and render verbatim in plain
		// mode (the old [OK]/[!!]/[XX] pins belonged to the replaced
		// absolute-band vocabulary); NEW keeps its bracketed badge.
		assert.Contains(t, s, "GOOD", "plain-mode composite verdict")
		assert.Contains(t, s, "WEAK", "plain-mode mid verdict")
		assert.Contains(t, s, "POOR", "plain-mode weak verdict")
		assert.Contains(t, s, "DEAD", "plain-mode earned dead override")
		assert.Contains(t, s, "[NEW]", "plain-mode NEW badge")
		assert.Contains(t, s, "n/a", "NONE keeps its n/a fallback")
	})

	t.Run("--color=always renders unicode + colored verdicts", func(t *testing.T) {
		s := runStatusCaptured(t, cfgPath, func(cmd *cobra.Command) {
			require.NoError(t, cmd.Flags().Set("color", "always"))
		})
		assert.Contains(t, s, "\x1b[", "color on")
		assert.Contains(t, s, "▂", "unicode sparkline under color")
		assert.Contains(t, s, "38;5;46", "GOOD verdict is traffic-light green")
		assert.Contains(t, s, "38;5;214", "WEAK/FAIR verdicts are amber (plugin_d's composite)")
		assert.Contains(t, s, "38;5;196", "POOR/DEAD verdicts are red")
		assert.Contains(t, s, "38;5;240", "the NEW badge is the neutral dim palette")
	})

	t.Run("deterministic across runs", func(t *testing.T) {
		a := runStatusCaptured(t, cfgPath, nil)
		b := runStatusCaptured(t, cfgPath, nil)
		assert.Equal(t, a, b, "two runs render identically (no wall-clock bytes in the text view)")
	})
}

// TestStatusProbesOffCleanNAEverywhere pins the probes-off production state
// as ONE gate test: the geo unlock stage ([geo].unlock_probes) has never
// classified anything, so clean% renders n/a in the table, null in the JSON
// — and the verdict engine STILL produces sensible pool-relative verdicts
// from the remaining factors (cleanliness drops, weights renormalize — that
// is the point of factor dropout).
func TestStatusProbesOffCleanNAEverywhere(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	// Pin the off-state via an EXPLICIT false: the [geo].unlock_probes
	// default flipped ON (owner ruling 2026-11-06), so knob absence no
	// longer means off — the invariant under test (probes off = clean%
	// n/a/null everywhere) is pinned against the explicit knob value.
	f, err := os.OpenFile(cfgPath, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString("\n[geo]\nunlock_probes = false\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	// Rewrite the cold base with legacy-only records (no Phase-1 fields —
	// exactly what waves leave behind while the geo unlock stage is off).
	home := os.Getenv("HOME")
	geo := "{\"scheme\":\"vless\",\"host\":\"a.example\",\"port\":443,\"source\":\"plugin_a\",\"country\":\"de\",\"city\":\"Berlin\",\"alive\":true}\n" +
		"{\"scheme\":\"vless\",\"host\":\"b.example\",\"port\":443,\"source\":\"plugin_b_redundant\",\"country\":\"nl\",\"alive\":true}\n"
	require.NoError(t, os.WriteFile(filepath.Join(home, "data", "geo-base.jsonl"), []byte(geo), 0o600))

	s := runStatusCaptured(t, cfgPath, nil)
	assert.Contains(t, s, "no ip-quality evidence yet", "the global quality section gates on the same predicate")
	assert.NotContains(t, s, "%·", "no coverage suffix anywhere — nothing classified")

	out := &bytes.Buffer{}
	cmd := newStatusCommand(&cfgPath)
	cmd.SetOut(out)
	require.NoError(t, cmd.Flags().Set("json", "true"))
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))

	var doc statusJSONDoc
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc))
	require.Len(t, doc.Providers, 5)
	for _, p := range doc.Providers {
		assert.Nil(t, p.CleanPct, "%s: no Phase-1 evidence → clean_pct null", p.ID)
		assert.Nil(t, p.ClassifiedCoveragePct, "%s: coverage null too", p.ID)
	}
	// The four scored sources still earn measured verdicts from the
	// remaining factors (cleanliness dropped — that is the point of factor
	// dropout); the zero-history fresh source stays NEW.
	assert.Equal(t, verdictGood, doc.Providers[0].Verdict, "plugin_a still tops the pool")
	assert.Equal(t, verdictWeak, doc.Providers[3].Verdict, "plugin_d lands mid-scale without cleanliness")
	assert.Equal(t, verdictNew, doc.Providers[4].Verdict, "plugin_e_fresh: 0 waves → NEW, never DEAD")
	assert.Equal(t, verdictDead, doc.Providers[2].Verdict, "plugin_c_dead keeps its earned DEAD")
}

// ---------------------------------------------------------------------------
// JSON contract
// ---------------------------------------------------------------------------

// TestStatusJSONGolden pins the full schema: field names, order, and values
// against the fixture — the machine-readable twin of the dashboard.
func TestStatusJSONGolden(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	out := &bytes.Buffer{}
	cmd := newStatusCommand(&cfgPath)
	cmd.SetOut(out)
	require.NoError(t, cmd.Flags().Set("json", "true"))
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
	s := out.String()

	// Field order pins (encoding/json emits struct order).
	pairs := []string{
		`"schema_version"`, `"generated_at"`, `"config_source"`, `"pipeline"`,
		`"global_quality"`, `"providers"`, `"overlap_matrix"`, `"recommendations"`,
	}
	pos := -1
	for _, p := range pairs {
		i := strings.Index(s, p)
		require.Greater(t, i, pos, "%s must appear in schema order", p)
		pos = i
	}

	var doc statusJSONDoc
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc))

	// Key-set pin: the top level carries exactly the documented schema.
	var raw map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &raw))
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	assert.Equal(t, []string{
		"config_source", "generated_at", "global_quality", "overlap_matrix",
		"pipeline", "providers", "recommendations", "schema_version",
	}, keys, "the top-level key set is exactly the schema")

	assert.Equal(t, "1.1", doc.SchemaVersion)
	_, err := time.Parse(time.RFC3339, doc.GeneratedAt)
	require.NoError(t, err, "generated_at is RFC3339")
	assert.Contains(t, doc.ConfigSource, "config.toml", "the provenance rides along")

	assert.Equal(t, statusJSONPipeline{
		Fetched: 3, Filtered: 2, Probed: 3, Alive: 2, GeoClean: 1, Selected: 3,
	}, doc.Pipeline)

	// Quality: 2 classified (1 residential), regions de/nl/unknown.
	assert.InDelta(t, 50.0, doc.GlobalQuality.ResidentialPct, 1e-9)
	assert.InDelta(t, 50.0, doc.GlobalQuality.HostingPct, 1e-9)
	assert.Equal(t, []statusJSONRegion{
		{Code: "de", Pct: 33.333333},
		{Code: "nl", Pct: 33.333333},
		{Code: "unknown", Pct: 33.333333},
	}, doc.GlobalQuality.Regional)

	// Providers: sorted by id, full metric set. Verdicts are the
	// pool-relative engine's (fixture worked example):
	// a GOOD 95 · b POOR 18.75 · c DEAD (3 recorded dead waves) · d WEAK
	// 32.8 (clean factor dropped) · e NEW (0 waves — never DEAD).
	require.Len(t, doc.Providers, 5)
	a, b, c, d, e := doc.Providers[0], doc.Providers[1], doc.Providers[2], doc.Providers[3], doc.Providers[4]
	assert.Equal(t, "plugin_a", a.ID)
	assert.Equal(t, 100, a.TotalParsed)
	assert.Equal(t, 80, a.AliveCurrent)
	assert.InDelta(t, 50.0, a.Alive24hAvg, 1e-9, "24h avg comes from stats.WeightedLiveness")
	assert.InDelta(t, 80.0, a.AlivePct, 1e-9)
	require.NotNil(t, a.CleanPct, "Phase-1 evidence → clean_pct is a measured value")
	assert.InDelta(t, 100.0, *a.CleanPct, 1e-9, "1 of 1 classified records is clean")
	require.NotNil(t, a.ClassifiedCoveragePct)
	assert.InDelta(t, 1.0, *a.ClassifiedCoveragePct, 1e-9, "1 classified of 100 parsed")
	assert.InDelta(t, 88.0, a.UniquePct, 1e-9)
	assert.Equal(t, []float64{0, 20, 40, 60, 80, 100}, a.Sparkline,
		"sparkline is the rate history in percent")
	assert.Equal(t, []statusJSONPair{{With: "plugin_b_redundant", Pct: 12}}, a.Overlaps)
	assert.Equal(t, verdictGood, a.Verdict)

	assert.Equal(t, "plugin_b_redundant", b.ID)
	assert.InDelta(t, 10.0, b.AlivePct, 1e-9)
	require.NotNil(t, b.CleanPct)
	assert.InDelta(t, 0.0, *b.CleanPct, 1e-9, "0% clean IS a measurement (1 hosting record)")
	assert.InDelta(t, 2.0, *b.ClassifiedCoveragePct, 1e-9, "1 classified of 50 parsed")
	assert.Equal(t, verdictPoor, b.Verdict, "composite 18.75")
	assert.Equal(t, []float64{10, 10, 10}, b.Sparkline,
		"3 recorded waves — a scored provider (past the NEW gate)")

	assert.Equal(t, "plugin_c_dead", c.ID)
	assert.Nil(t, c.CleanPct, "no Phase-1 evidence → explicit null, never a fabricated 0")
	assert.Nil(t, c.ClassifiedCoveragePct)
	assert.Equal(t, verdictDead, c.Verdict,
		"override: 0 live, dead 24h average, and ENOUGH history (3 waves) to prove death")
	assert.Equal(t, []float64{0, 0, 0}, c.Sparkline, "3 recorded dead waves")

	assert.Equal(t, "plugin_d_mid", d.ID)
	assert.Nil(t, d.CleanPct, "the manifest claims 80 classified — the unified predicate says no evidence")
	assert.Nil(t, d.ClassifiedCoveragePct)
	assert.Equal(t, verdictWeak, d.Verdict, "composite 32.8 with the cleanliness factor dropped")
	assert.Equal(t, []float64{60, 60, 60, 60, 60, 60}, d.Sparkline, "flat 60% history")

	assert.Equal(t, "plugin_e_fresh", e.ID)
	assert.Nil(t, e.CleanPct)
	assert.Nil(t, e.ClassifiedCoveragePct)
	assert.Equal(t, verdictNew, e.Verdict,
		"brand-new source: fetch-stage live=0 with ZERO history waves is NEW, never DEAD")
	assert.Empty(t, e.Sparkline, "no provider history yet")

	// Recommendations mirror the pruning bands with liveness weight:
	// overlap% descending (82 → 40 → 12); the dead provider lands in the
	// unique-but-dead class instead of keep/prune.
	assert.Equal(t, []string{
		"prune candidate 'plugin_b_redundant': only 8.0% unique — 82% shared with plugin_a",
		"'plugin_c_dead' is unique but dead — verify upstream source (30.0% unique, 0 live nodes)",
		"keep 'plugin_a': 88.0% unique nodes (low overlap, high yield)",
	}, doc.Recommendations)

	// Overlap matrix: upper triangle of the sorted ids.
	require.Len(t, doc.OverlapMatrix, 1)
	assert.Equal(t, statusJSONOverlap{A: "plugin_a", B: "plugin_b_redundant", SharedPct: 12},
		doc.OverlapMatrix[0])

	assert.NotContains(t, s, "\x1b[", "JSON output is color-independent")
}

// TestStatusJSONOverlapComposition pins that both flags compose: --json
// --overlap emits the SAME JSON document (the matrix is always included).
func TestStatusJSONOverlapComposition(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	run := func(overlap bool) string {
		out := &bytes.Buffer{}
		cmd := newStatusCommand(&cfgPath)
		cmd.SetOut(out)
		require.NoError(t, cmd.Flags().Set("json", "true"))
		if overlap {
			require.NoError(t, cmd.Flags().Set("overlap", "true"))
		}
		require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
		return out.String()
	}
	assert.Equal(t, run(false), run(true),
		"--overlap must not change the JSON payload (the matrix is always part of it)")
}

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

func TestStatusIntelFormatters(t *testing.T) {
	assert.Equal(t, "14,208", formatCount(14208))
	assert.Equal(t, "1,380,072", formatCount(1380072))
	assert.Equal(t, "999", formatCount(999))
	assert.Equal(t, "0", formatCount(0))

	assert.Equal(t, "short", truncateName("short", 20))
	assert.Equal(t, "exactly-twenty-chars", truncateName("exactly-twenty-chars", 20))
	trunc := truncateName("a-very-long-provider-name-here", 20)
	assert.Len(t, []rune(trunc), 20)
	assert.True(t, strings.HasSuffix(trunc, "…"), "truncation uses an ellipsis")

	assert.Equal(t, strings.Repeat("█", 20)+" 100.0%", funnelBar(100, true))
	assert.Equal(t, strings.Repeat("░", 20)+" 0.0%", funnelBar(0, true))
	assert.Equal(t, strings.Repeat("=", 6)+strings.Repeat("-", 14)+" 33.3%",
		funnelBar(33.3, false))
	assert.Equal(t, strings.Repeat("=", 19)+strings.Repeat("-", 1)+" 99.9%", funnelBar(99.9, false))
	assert.Equal(t, strings.Repeat("-", 20)+" 0.4%", funnelBar(0.4, false))

	assert.Equal(t, " ..--==#", asciiSparklineString(stats.SparklineGlyphs))
	assert.Equal(t, ".-=", asciiSparklineString("▂▄▆"))

	assert.Equal(t, "blocked 12 / yes 40", formatVocab(map[string]int{"blocked": 12, "yes": 40}),
		"vocab counters render key-sorted (deterministic)")
	assert.Equal(t, "no data", formatVocab(map[string]int{}))
}
