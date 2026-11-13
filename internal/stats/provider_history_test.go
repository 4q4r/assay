package stats

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snapAt builds a WaveSnapshot from an RFC3339 second-precision timestamp
// (the struct stores Unix seconds UTC).
func snapAt(ts string, total, live, clean, hosting int, rtt int64) WaveSnapshot {
	v := mustTime(ts)
	return WaveSnapshot{
		Timestamp: v.Unix(),
		Total:     total,
		Live:      live,
		Clean:     clean,
		Hosting:   hosting,
		MedianRTT: rtt,
	}
}

func mustTime(ts string) time.Time {
	v, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		panic("mustTime: bad test timestamp " + ts)
	}
	return v
}

// captureStderr swaps os.Stderr for a pipe around fn (the loud-warning
// channel for library code without a writer seam).
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 8192)
		n, _ := r.Read(buf)
		done <- string(buf[:n])
	}()
	fn()
	require.NoError(t, w.Close())
	os.Stderr = old
	return <-done
}

// TestWriteProviderHistoryOverBudgetWarnsLoud pins F8: the 40KB budget is a
// documented claim, not an enforcement — a dynamic plugin count can exceed
// it, and the writer must announce that loud (non-fatal: the file still
// lands).
func TestWriteProviderHistoryOverBudgetWarnsLoud(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "provider-history.json")
	now := mustTime("2026-11-04T10:00:00Z")

	// Enough providers with full-wave rings that the serialized payload
	// blows past MaxHistoryBytes (each provider also carries the 24-slot
	// diurnal state).
	h := &ProviderHistory{Providers: map[string]*ProviderSeries{}}
	for i := range 120 {
		id := fmt.Sprintf("p%03d", i)
		s := &ProviderSeries{}
		for j := range MaxWaves {
			UpdateSeries(s, WaveSnapshot{
				Timestamp: now.Add(-time.Duration(MaxWaves-j) * time.Hour).Unix(),
				Total:     68686, Live: 50000, Clean: 48000, Hosting: 8000, MedianRTT: 9876,
			}, now)
		}
		h.Providers[id] = s
	}

	var writeErr error
	warning := captureStderr(t, func() {
		writeErr = WriteProviderHistory(path, h)
	})
	require.NoError(t, writeErr, "the budget breach is a warning, never a failure")
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Greater(t, len(b), MaxHistoryBytes, "fixture must actually exceed the budget")
	assert.Contains(t, warning, "WARNING", "the breach is announced loud")
	assert.Contains(t, warning, "budget", "the warning names the exceeded budget")

	// The healthy path stays silent: a small history never warns.
	small := filepath.Join(dir, "small.json")
	quiet := captureStderr(t, func() {
		require.NoError(t, WriteProviderHistory(small, &ProviderHistory{
			Providers: map[string]*ProviderSeries{
				"one": {Waves: []WaveSnapshot{{Timestamp: now.Unix(), Total: 10, Live: 5}}},
			},
		}))
	})
	assert.Empty(t, quiet, "an under-budget write is silent")
}

// --- LivenessRate ---

func TestLivenessRate(t *testing.T) {
	tests := []struct {
		name string
		snap WaveSnapshot
		want float64
	}{
		{"half", snapAt("2026-11-04T10:00:00Z", 100, 50, 0, 0, 0), 0.5},
		{"empty pool is zero not NaN", snapAt("2026-11-04T10:00:00Z", 0, 0, 0, 0, 0), 0},
		{"all alive", snapAt("2026-11-04T10:00:00Z", 10, 10, 0, 0, 0), 1},
		{"none alive", snapAt("2026-11-04T10:00:00Z", 10, 0, 0, 0, 0), 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.InDelta(t, tc.want, LivenessRate(tc.snap), 1e-9)
		})
	}
}

// --- ComputeSparkline ---

func TestComputeSparkline(t *testing.T) {
	tests := []struct {
		name  string
		rates []float64
		want  string
	}{
		{"empty", nil, ""},
		{"all zero anchors to space", []float64{0, 0, 0}, "   "},
		{"all full", []float64{1, 1, 1}, "███"},
		{"absolute scale not min-max stretched", []float64{0.01, 0.5, 0.99}, " ▅█"},
		{"clamped above one", []float64{1.5}, "█"},
		{"negative clamps to zero level", []float64{-0.5}, " "},
		// 8-level glyph ladder: rate 0 → space; 1/7 ≈ 0.143 → ▂; 3/7 ≈ 0.43 → ▄.
		{"level ladder", []float64{0, 0.143, 0.286, 0.43, 0.572, 0.715, 0.858, 1}, " ▂▃▄▅▆▇█"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ComputeSparkline(tc.rates))
		})
	}
	assert.Equal(t, "▃", ComputeSparkline([]float64{0.3}), "one rate = one glyph")
}

// --- ComputeSlope ---

func TestComputeSlope(t *testing.T) {
	tests := []struct {
		name   string
		values []float64
		want   float64
	}{
		{"flat", []float64{0.5, 0.5, 0.5, 0.5}, 0},
		{"perfect rise", []float64{0, 0.1, 0.2, 0.3}, 0.1},
		{"perfect fall", []float64{0.3, 0.2, 0.1, 0}, -0.1},
		{"too short is zero", []float64{0.5}, 0},
		{"nil is zero", nil, 0},
		// OLS over indices: [0,1,1,1] → (nΣxy−ΣxΣy)/(nΣx²−(Σx)²) = 6/20 = 0.3.
		{"ols fit", []float64{0, 1, 1, 1}, 0.3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.InDelta(t, tc.want, ComputeSlope(tc.values), 1e-9)
		})
	}
}

// --- ClassifyTrend ---

func TestClassifyTrend(t *testing.T) {
	tests := []struct {
		name     string
		slope    float64
		momentum float64
		want     string
	}{
		{"strong up needs positive momentum", 0.03, 0.01, "↑"},
		{"strong slope without momentum is weak up", 0.03, -0.01, "↗"},
		{"weak up", 0.006, 0, "↗"},
		{"flat", 0.004, 0.5, "→"},
		{"zero slope flat", 0, 0, "→"},
		{"weak down", -0.006, 0, "↘"},
		{"strong down needs negative momentum", -0.03, -0.01, "↓"},
		{"strong slope without negative momentum is weak down", -0.03, 0.01, "↘"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ClassifyTrend(tc.slope, tc.momentum))
		})
	}
}

// --- SmoothCircular ---

func TestSmoothCircular(t *testing.T) {
	// σ=1.0h circular Gaussian: weights over offsets −2..+2 normalized.
	// Flat profile stays flat.
	flat := [24]float64{}
	for i := range flat {
		flat[i] = 0.5
	}
	got := SmoothCircular(flat, 1.0)
	for h, v := range got {
		assert.InDelta(t, 0.5, v, 1e-9, "flat stays flat at hour %d", h)
	}

	// Single spike at hour 5 spreads into neighbors 4 and 6 (circular).
	// σ=1 kernel taps w = [e⁻², e^-½, 1, e^-½, e⁻²], Σw ≈ 2.4836: the spike
	// keeps w₀/Σw ≈ 0.403 of its mass and total mass is preserved.
	spike := [24]float64{}
	spike[5] = 1.0
	got = SmoothCircular(spike, 1.0)
	assert.InDelta(t, 0.4028, got[5], 1e-3, "spike keeps its normalized center weight")
	assert.InDelta(t, 0.2442, got[4], 1e-3, "±1h neighbor weight")
	assert.Less(t, got[3], got[4], "mass decays with distance")
	assert.InDelta(t, got[3], got[7], 1e-9, "±2h symmetric")
	var mass float64
	for _, v := range got {
		mass += v
	}
	assert.InDelta(t, 1.0, mass, 1e-9, "circular kernel columns sum to 1 — total mass preserved")

	// Wraps: hour 23's neighbors include hours 22 and 0.
	spike = [24]float64{}
	spike[23] = 1.0
	got = SmoothCircular(spike, 1.0)
	assert.InDelta(t, got[0], got[22], 1e-9, "circular wrap symmetric across 0")
	assert.Greater(t, got[0], 0.1, "hour 0 receives the wrapped leak")
}

// --- DiurnalUpdate + Z-score ---

func TestDiurnalZScoreColdStart(t *testing.T) {
	now := mustTime("2026-11-04T10:00:00Z")
	s := &ProviderSeries{}
	// Fewer than ColdStartMin waves: Z forced 0, calibrating.
	for range 2 {
		UpdateSeries(s, snapAt("2026-11-04T09:00:00Z", 100, 80, 70, 20, 100), now)
	}
	z, calibrating := DiurnalZScore(s, 9, 0.8)
	assert.InDelta(t, 0.0, z, 1e-9, "samples < 3 forces Z=0")
	assert.True(t, calibrating)

	// 3..11 waves: Z computed but still calibrating.
	for range 9 {
		UpdateSeries(s, snapAt("2026-11-04T09:30:00Z", 100, 80, 70, 20, 100), now)
	}
	_, calibrating = DiurnalZScore(s, 9, 0.8)
	assert.True(t, calibrating, "calibrating until 12 waves")

	// Wave 12 clears the flag.
	UpdateSeries(s, snapAt("2026-11-04T09:40:00Z", 100, 80, 70, 20, 100), now)
	_, calibrating = DiurnalZScore(s, 9, 0.8)
	assert.False(t, calibrating, "12 waves accumulated — calibrated")
}

func TestDiurnalZScoreDeviation(t *testing.T) {
	now := mustTime("2026-11-04T10:00:00Z")
	s := &ProviderSeries{}
	// Fold a stable 0.8 rate at hour 9, then a spike to 1.0: σ floor keeps Z finite.
	for range 20 {
		UpdateSeries(s, snapAt("2026-11-04T09:00:00Z", 100, 80, 70, 20, 100), now)
	}
	z, calibrating := DiurnalZScore(s, 9, 0.99)
	assert.False(t, calibrating)
	assert.Greater(t, z, 1.0, "above-baseline rate yields positive Z")
	assert.Less(t, z, 50.0, "σ floor 0.05 keeps Z bounded")

	zFlat, _ := DiurnalZScore(s, 9, 0.8)
	assert.InDelta(t, 0.0, zFlat, 0.5, "at-baseline rate yields ~0 Z")
}

// --- WeightedLiveness ---

func TestWeightedLiveness(t *testing.T) {
	now := mustTime("2026-11-04T10:00:00Z")
	waves := []WaveSnapshot{
		snapAt("2026-11-04T09:00:00Z", 100, 100, 0, 0, 0), // in window, weight 100
		snapAt("2026-11-03T20:00:00Z", 300, 0, 0, 0, 0),   // in window, weight 300
		snapAt("2026-11-03T09:59:00Z", 500, 500, 0, 0, 0), // OUTSIDE 24h — excluded
	}
	// (100×1.0 + 300×0.0) / 400 = 0.25 — volume-weighted, not mean-of-rates.
	assert.InDelta(t, 0.25, WeightedLiveness(waves, now), 1e-9)
	assert.InDelta(t, 0.0, WeightedLiveness(nil, now), 1e-9)
	// Empty pool waves contribute zero volume: all-empty → 0.
	empty := []WaveSnapshot{snapAt("2026-11-04T09:00:00Z", 0, 0, 0, 0, 0)}
	assert.InDelta(t, 0.0, WeightedLiveness(empty, now), 1e-9)
}

// --- DHR ---

func TestDiurnalRatio(t *testing.T) {
	now := mustTime("2026-11-04T10:00:00Z")
	s := &ProviderSeries{}
	for range 12 {
		UpdateSeries(s, snapAt("2026-11-04T09:00:00Z", 100, 80, 70, 20, 100), now)
	}
	dhr := DiurnalRatio(s, 9, 0.8)
	assert.InDelta(t, 1.0, dhr, 0.2, "at-baseline rate → DHR ≈ 1")

	assert.InDelta(t, 0.0, DiurnalRatio(s, 9, 0.8-10), 1e-9, "negative rate never flows into DHR")
	// No baseline yet (empty hour): DHR = 0, not Inf/NaN.
	assert.InDelta(t, 0.0, DiurnalRatio(s, 15, 0.5), 1e-9)
}

// --- UpdateSeries: ring buffer + prune + momentum ---

func TestUpdateSeriesRingCap(t *testing.T) {
	now := mustTime("2026-11-04T10:00:00Z")
	s := &ProviderSeries{}
	// 50 half-hour waves all INSIDE the 48h horizon: the 48-entry ring cap
	// alone drops the two oldest.
	for i := range 50 {
		ts := now.Add(-time.Duration(49-i) * 30 * time.Minute).UTC().Format(time.RFC3339)
		UpdateSeries(s, snapAt(ts, 100, 50, 40, 10, 120), now)
	}
	require.Len(t, s.Waves, MaxWaves)
	first := time.Unix(s.Waves[0].Timestamp, 0).UTC()
	// 50 half-hour taps: i=0 (24.5h) and i=1 (24h) dropped by the cap — the
	// oldest survivor is i=2 at 23.5h ago.
	assert.Equal(t, now.Add(-47*30*time.Minute).UTC(), first,
		"cap keeps the NEWEST 48 — oldest two dropped")
	assert.Equal(t, now.Unix(), s.Waves[len(s.Waves)-1].Timestamp)
}

func TestUpdateSeriesHorizonPrune(t *testing.T) {
	now := mustTime("2026-11-04T10:00:00Z")
	s := &ProviderSeries{}
	// Five waves spanning >48h: the 49h-old wave is pruned hard even though
	// the ring has room.
	for _, offset := range []int{49, 36, 24, 12, 0} {
		ts := now.Add(-time.Duration(offset) * time.Hour).UTC().Format(time.RFC3339)
		UpdateSeries(s, snapAt(ts, 100, 50, 40, 10, 120), now)
	}
	require.Len(t, s.Waves, 4)
	first := time.Unix(s.Waves[0].Timestamp, 0).UTC()
	assert.Equal(t, now.Add(-36*time.Hour).UTC(), first, "waves older than 48h never enter the file")

	// Momentum seeded: fast tracks faster than slow, so a steady rate gives ~0 spread.
	assert.True(t, s.EMASeeded)
	assert.InDelta(t, 0.5, s.EMAFast, 1e-9)
	assert.InDelta(t, 0.5, s.EMASlow, 1e-9)
	assert.InDelta(t, 0.0, s.Momentum(), 1e-9)
}

func TestUpdateSeriesMomentumRise(t *testing.T) {
	now := mustTime("2026-11-04T10:00:00Z")
	s := &ProviderSeries{}
	for i := range 10 {
		ts := now.Add(-time.Duration(10-i) * time.Hour).UTC().Format(time.RFC3339)
		UpdateSeries(s, snapAt(ts, 100, 10*i, 0, 0, 0), now) // 0% → 90% rise
	}
	assert.Greater(t, s.EMAFast, s.EMASlow, "a sustained rise puts fast EMA above slow")
	assert.Greater(t, s.Momentum(), 0.0)
	assert.Equal(t, "↑", s.Trend(), "10-wave linear 0→0.9 rise classifies strong up")
}

// --- Sparkline from waves ---

func TestSeriesSparkline(t *testing.T) {
	now := mustTime("2026-11-04T10:00:00Z")
	s := &ProviderSeries{}
	for i := range 4 {
		ts := now.Add(-time.Duration(4-i) * time.Hour).UTC().Format(time.RFC3339)
		UpdateSeries(s, snapAt(ts, 10, 2*i+1, 0, 0, 0), now) // .1 .3 .5 .7
	}
	line := s.Sparkline(8)
	assert.Equal(t, 4, utf8.RuneCountInString(line), "one wave = one glyph")
	assert.Equal(t, ComputeSparkline([]float64{0.1, 0.3, 0.5, 0.7}), line)
	assert.Equal(t, 2, utf8.RuneCountInString(s.Sparkline(2)), "n caps the window to the newest waves")
}

// --- Persistence: round-trip, cold start, determinism, atomicity, budget ---

func TestReadProviderHistoryMissingFile(t *testing.T) {
	h, err := ReadProviderHistory(filepath.Join(t.TempDir(), "absent.json"))
	require.NoError(t, err, "missing file is an empty cold start, never an error")
	require.NotNil(t, h)
	assert.Equal(t, HistoryVersion, h.Version)
	assert.NotNil(t, h.Providers)
	assert.Empty(t, h.Providers)
}

func TestWriteReadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider-history.json")
	now := mustTime("2026-11-04T10:00:00Z")
	_, err := RecordWaveSnapshot(path, "prov-a", snapAt("2026-11-04T09:00:00Z", 4435, 800, 700, 100, 1234), now)
	require.NoError(t, err)
	_, err = RecordWaveSnapshot(path, "prov-b", snapAt("2026-11-04T09:10:00Z", 3998, 500, 480, 10, 900), now)
	require.NoError(t, err)

	h, err := ReadProviderHistory(path)
	require.NoError(t, err)
	require.Len(t, h.Providers, 2)
	m := h.Providers["prov-a"]
	require.NotNil(t, m)
	require.Len(t, m.Waves, 1)
	assert.Equal(t, 4435, m.Waves[0].Total)
	assert.Equal(t, int64(1234), m.Waves[0].MedianRTT)
}

func TestProviderHistoryDeterministicBytes(t *testing.T) {
	dir := t.TempDir()
	build := func(dir string) {
		path := filepath.Join(dir, "provider-history.json")
		now := mustTime("2026-11-04T10:00:00Z")
		for _, id := range []string{"zz", "prov-a", "aa", "prov-b"} {
			for i := range 5 {
				ts := now.Add(-time.Duration(5-i) * time.Hour).UTC().Format(time.RFC3339)
				_, err := RecordWaveSnapshot(path, id, snapAt(ts, 1000+i, 500+i, 400, 50, int64(800+i)), now)
				require.NoError(t, err)
			}
		}
	}
	build(dir)
	a, err := os.ReadFile(filepath.Join(dir, "provider-history.json"))
	require.NoError(t, err)
	other := t.TempDir()
	build(other)
	b, err := os.ReadFile(filepath.Join(other, "provider-history.json"))
	require.NoError(t, err)
	assert.Equal(t, string(a), string(b), "same inputs → byte-identical file (sorted keys, stable floats)")
}

func TestProviderHistoryProvidersAreSortedInJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider-history.json")
	now := mustTime("2026-11-04T10:00:00Z")
	for _, id := range []string{"zz", "aa", "mm"} {
		_, err := RecordWaveSnapshot(path, id, snapAt("2026-11-04T09:00:00Z", 10, 5, 4, 1, 50), now)
		require.NoError(t, err)
	}
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	aa := strings.Index(string(b), `"aa"`)
	mm := strings.Index(string(b), `"mm"`)
	zz := strings.Index(string(b), `"zz"`)
	require.GreaterOrEqual(t, aa, 0)
	require.GreaterOrEqual(t, mm, 0)
	require.GreaterOrEqual(t, zz, 0)
	assert.Less(t, aa, mm)
	assert.Less(t, mm, zz, "providers serialize in sorted key order")
}

func TestProviderHistoryAtomicNoTmpLeftovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "provider-history.json")
	now := mustTime("2026-11-04T10:00:00Z")
	_, err := RecordWaveSnapshot(path, "prov-a", snapAt("2026-11-04T09:00:00Z", 10, 5, 4, 1, 50), now)
	require.NoError(t, err)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "tmp file is renamed away — only the artifact remains")
	info, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS != "windows" { // windows has no POSIX mode bits — ACLs own permissions there
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "state files are owner-private 0600")
	}
}

func TestProviderHistorySizeBudget(t *testing.T) {
	// Max realistic shape: 10 providers × 48 max-size waves (5-digit totals,
	// full diurnal state) must stay under the 40KB file budget.
	dir := t.TempDir()
	path := filepath.Join(dir, "provider-history.json")
	now := mustTime("2026-11-04T10:00:00Z")
	ids := []string{
		"prov-a1", "prov-b2", "prov-c3", "prov-d4", "prov-e5",
		"prov-f6", "prov-g7", "prov-h8", "prov-i9", "prov-j0",
	}
	for _, id := range ids {
		for i := range MaxWaves {
			ts := now.Add(-time.Duration(MaxWaves-i) * time.Hour).UTC().Format(time.RFC3339)
			_, err := RecordWaveSnapshot(path, id, snapAt(ts, 68686, 50000, 48000, 8000, 9876), now)
			require.NoError(t, err)
		}
	}
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Less(t, len(b), 40*1024, "provider-history.json stays under the 40KB budget at max shape: %d bytes", len(b))
	t.Logf("max-shape provider-history.json = %d bytes", len(b))
}

func TestProviderHistoryConcurrentAccess(t *testing.T) {
	// Concurrent recorder + readers must be race-free (run under -race).
	dir := t.TempDir()
	path := filepath.Join(dir, "provider-history.json")
	now := mustTime("2026-11-04T10:00:00Z")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			id := []string{"a", "b", "c", "d", "e", "f", "g", "h"}[i]
			_, _ = RecordWaveSnapshot(path, id, snapAt("2026-11-04T09:00:00Z", 10+i, 5, 4, 1, 50), now)
		})
	}
	for range 8 {
		wg.Go(func() {
			_, _ = ReadProviderHistory(path)
		})
	}
	wg.Wait()
	h, err := ReadProviderHistory(path)
	require.NoError(t, err)
	assert.NotEmpty(t, h.Providers, "concurrent recorders converge on a complete file")
}

func TestProviderHistoryVersionPinned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider-history.json")
	now := mustTime("2026-11-04T10:00:00Z")
	_, err := RecordWaveSnapshot(path, "prov-a", snapAt("2026-11-04T09:00:00Z", 10, 5, 4, 1, 50), now)
	require.NoError(t, err)
	var raw map[string]any
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &raw))
	assert.InDelta(t, float64(HistoryVersion), raw["version"].(float64), 1e-9, "schema is versioned")
	assert.Contains(t, raw, "providers")
}

// --- Max-relative scale (owner ruling 2026-11-05, Stephen Few): per-series
// scaling reveals SHAPE; the adjacent numeric alive% column carries the
// magnitude. The zero glyph renders ONLY for a true 0 value.

func TestComputeSparklineMaxRelative(t *testing.T) {
	tests := []struct {
		name  string
		rates []float64
		want  string
	}{
		{"empty", nil, ""},
		// Flat non-zero series: every point sits at the window max → full bars.
		{"flat series is full bars", []float64{0.5, 0.5, 0.5}, "███"},
		// A true 0 renders the zero glyph even in a max-relative window.
		{"true zero stays level 0", []float64{0, 1.0}, " █"},
		// A tiny positive value never collapses into the zero glyph
		// (round(0.007×7)=0 → bumped to level 1).
		{"positive never reads as zero", []float64{0.001, 1.0}, "▂█"},
		// Shape ladder over a low-alive window (the production regime):
		// rates/max = [.1 .2 .3 .4 .5 1] ×7 → [1 1 2 3 4 7].
		{"low window shape ladder", []float64{0.01, 0.02, 0.03, 0.04, 0.05, 0.1}, "▂▂▃▄▅█"},
		{"all zero window", []float64{0, 0, 0}, "   "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ComputeSparklineScaled(tc.rates, SparklineMaxRelative))
		})
	}
}

func TestSeriesSparklineScaledWindow(t *testing.T) {
	now := mustTime("2026-11-04T10:00:00Z")
	s := &ProviderSeries{}
	// Rates .1 .2 .3 .4 inside a 4-wave window: max-relative vs the WINDOW
	// max (.4), not the absolute 1.0 — the shape fills the ladder.
	for i := range 4 {
		ts := now.Add(-time.Duration(4-i) * time.Hour).UTC().Format(time.RFC3339)
		UpdateSeries(s, snapAt(ts, 100, 10*(i+1), 0, 0, 0), now)
	}
	assert.Equal(t, ComputeSparklineScaled([]float64{0.1, 0.2, 0.3, 0.4}, SparklineMaxRelative),
		s.SparklineScaled(8, SparklineMaxRelative))
	assert.Equal(t, ComputeSparkline([]float64{0.3, 0.4}), s.SparklineScaled(2, SparklineAbsolute),
		"absolute scale via the scaled method matches the classic helper")
	assert.Empty(t, s.SparklineScaled(0, SparklineMaxRelative), "n=0 renders nothing")
}
