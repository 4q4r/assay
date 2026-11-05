package stats

// Provider time-series (Phase 2 of the status intelligence upgrade):
// per-provider wave snapshots persisted to <dataDir>/provider-history.json
// keyed by plugin_id, with a diurnal liveness baseline, dual-EMA momentum,
// OLS trend classification, and a zero-anchored sparkline.
//
// Owner-approved model (2026-11-04): ring buffer of ≤48 wave snapshots
// {timestamp, total, live, clean, hosting, median_rtt_ms} with a hard 48h
// prune; 24h rolling volume-weighted liveness; a diurnal profile B[0..23]
// per UTC hour built with EWMA α=0.20 and circular Gaussian smoothing
// (σ=1.0h) across adjacent hours; DHR = current rate / B(current hour);
// trend = OLS slope over the last 6 waves plus dual-EMA (fast α=0.5, slow
// α=0.2) momentum; Z-score against the diurnal baseline with a σ floor of
// 0.05; graceful cold start (samples < 3 → Z=0 and a calibrating flag until
// 12 waves accumulated). Persistence mirrors internal/store atomicity (tmp →
// fsync → rename); the whole file stays under 40KB; content is deterministic
// given the same inputs (map keys serialize sorted).
//
// Race safety: waves are serial inside the daemon, but `status` and waves run
// in SEPARATE PROCESSES. RecordWaveSnapshot serializes the read-modify-write
// with a package mutex (in-process), and WriteProviderHistory lands through
// store's atomic rename (cross-process readers only ever see a complete old
// or new file — never a torn one).

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"public_vpn/internal/store"
)

// Model constants (owner-approved Phase-2 numbers — every threshold lives
// here so Phase 4's dashboard reads them instead of re-deriving).
const (
	// HistoryVersion is the provider-history.json schema version.
	HistoryVersion = 1
	// MaxWaves is the per-provider ring buffer capacity (hourly waves ≈ 48h).
	MaxWaves = 48
	// WaveHorizon is the hard prune: snapshots older than 48h never persist.
	WaveHorizon = 48 * time.Hour
	// LivenessHorizon is the 24h rolling window for volume-weighted liveness.
	LivenessHorizon = 24 * time.Hour
	// DiurnalAlpha is the per-UTC-hour EWMA factor for the baseline.
	DiurnalAlpha = 0.20
	// DiurnalSigmaHours is the circular Gaussian smoothing width (σ=1.0h).
	DiurnalSigmaHours = 1.0
	// SigmaFloor keeps the Z-score finite for razor-stable baselines.
	SigmaFloor = 0.05
	// ColdStartMin: below this many waves the Z-score reports 0.
	ColdStartMin = 3
	// CalibratedAt: the calibrating flag clears at this many waves.
	CalibratedAt = 12
	// SlopeStrong/SlopeWeak split the five-way trend classification
	// (liveness-rate units per wave; hourly waves → per hour).
	SlopeStrong = 0.02
	SlopeWeak   = 0.005
	// EMAFastAlpha/EMASlowAlpha are the dual-EMA momentum factors.
	EMAFastAlpha = 0.5
	EMASlowAlpha = 0.2
	// DiurnalBaselineFloor guards the DHR denominator (no baseline → DHR 0).
	DiurnalBaselineFloor = 0.01
	// MaxHistoryBytes is the persisted file budget the size test pins.
	MaxHistoryBytes = 40 * 1024
)

// Trend classifications (the exact glyphs the Phase-4 dashboard renders).
const (
	TrendUpStrong   = "↑"
	TrendUp         = "↗"
	TrendFlat       = "→"
	TrendDown       = "↘"
	TrendDownStrong = "↓"
)

// SparklineGlyphs is the zero-anchored 8-level ladder (owner-specified
// literal): level 0 renders as an empty space, not the U+2581 tick, so a
// dead hour reads as a gap instead of a hairline. The levels ascend one
// block element at a time (U+2582 ▂ → U+2588 █) with no duplicates.
const SparklineGlyphs = " ▂▃▄▅▆▇█"

// WaveSnapshot is one wave's per-provider observation. Timestamp is Unix
// epoch seconds UTC: 22-byte RFC3339 strings blow the 40KB file budget at the
// 10-provider × 48-wave max shape; epoch seconds are equally deterministic.
type WaveSnapshot struct {
	Timestamp int64 `json:"ts"` // Unix seconds UTC
	Total     int   `json:"t"`
	Live      int   `json:"l"`
	Clean     int   `json:"c"`
	Hosting   int   `json:"h"`
	MedianRTT int64 `json:"r"` // ms over the provider's alive records; 0 = no evidence
}

// ProviderSeries is one provider's ring buffer plus the persistent state the
// derived analytics need across processes.
type ProviderSeries struct {
	Waves       []WaveSnapshot `json:"waves"`        // oldest → newest, ≤48, pruned >48h
	DiurnalMean [24]float64    `json:"diurnal_mean"` // raw per-UTC-hour EWMA (α=0.20)
	DiurnalVar  [24]float64    `json:"diurnal_var"`  // EWMA of squared deviation
	DiurnalN    [24]int        `json:"diurnal_n"`    // samples folded into each hour
	EMAFast     float64        `json:"ema_fast"`     // α=0.5 momentum tracker
	EMASlow     float64        `json:"ema_slow"`     // α=0.2 momentum tracker
	EMASeeded   bool           `json:"ema_seeded"`   // false until the first wave seeds both EMAs
}

// ProviderHistory is the whole persisted file.
type ProviderHistory struct {
	Version   int                        `json:"version"`
	Providers map[string]*ProviderSeries `json:"providers"`
}

// historyMu serializes the read-modify-write cycle inside one process.
var historyMu sync.Mutex

// LivenessRate is the snapshot's alive share. An empty pool is 0, not NaN.
func LivenessRate(s WaveSnapshot) float64 {
	if s.Total <= 0 {
		return 0
	}
	return float64(s.Live) / float64(s.Total)
}

// SparklineScale selects the value→glyph mapping of the zero-anchored
// 8-level ladder.
type SparklineScale int

const (
	// SparklineAbsolute maps the fixed 0..1 rate scale (never min-max
	// stretched): level = round(rate×7), so 50% liveness is always the mid
	// glyph regardless of the window's spread.
	SparklineAbsolute SparklineScale = iota
	// SparklineMaxRelative maps each value against the provider's OWN window
	// maximum: level = round(value/max×7). Per-series scaling reveals the
	// SHAPE of a flat-lived pool (Stephen Few, "Best Practices for Scaling
	// Sparklines" — per-series scaling = shape; magnitude is carried by the
	// adjacent numeric column, which the provider table's alive% cell does).
	// Domain precedent (metacubexd node scoring) anchors on absolute
	// thresholds — rejected here because this pool's regime (alive ~1.5%)
	// renders any absolute ladder a single bottom glyph: the shape would be
	// dead pixels. The zero glyph renders ONLY for a true 0 value; a small
	// positive value never collapses into it.
	SparklineMaxRelative
)

// ComputeSparkline maps liveness rates onto the zero-anchored 8-level glyph
// ladder at the ABSOLUTE 0..1 scale.
func ComputeSparkline(rates []float64) string {
	return ComputeSparklineScaled(rates, SparklineAbsolute)
}

// ComputeSparklineScaled renders the ladder under the given scale. Both
// variants clamp into the ladder and keep the zero glyph for empty/zero
// values; the max-relative variant additionally guarantees that any positive
// value renders at least level 1 (round-to-zero would lie about a nonzero
// hour).
func ComputeSparklineScaled(rates []float64, scale SparklineScale) string {
	glyphs := []rune(SparklineGlyphs)
	top := float64(len(glyphs) - 1)
	if scale == SparklineMaxRelative {
		top = 0
		for _, r := range rates {
			if r > top {
				top = r
			}
		}
	}
	out := make([]rune, 0, len(rates))
	for _, r := range rates {
		var level int
		switch {
		case scale == SparklineMaxRelative && r > 0:
			level = int(math.Round(r / top * float64(len(glyphs)-1)))
			if level == 0 {
				level = 1 // a positive value never reads as the zero glyph
			}
		case scale == SparklineMaxRelative:
			level = 0 // true 0 (or defensive negative) → the zero glyph
		default:
			level = int(math.Round(r * float64(len(glyphs)-1)))
		}
		level = min(max(level, 0), len(glyphs)-1)
		out = append(out, glyphs[level])
	}
	return string(out)
}

// ComputeSlope is the OLS slope of values over their indices (x = 0..n−1).
// Fewer than two values carry no trend: 0.
func ComputeSlope(values []float64) float64 {
	n := len(values)
	if n < 2 {
		return 0
	}
	var sx, sy, sxx, sxy float64
	for i, v := range values {
		sx += float64(i)
		sy += v
		sxx += float64(i) * float64(i)
		sxy += float64(i) * v
	}
	denom := float64(n)*sxx - sx*sx
	if denom == 0 {
		return 0
	}
	return (float64(n)*sxy - sx*sy) / denom
}

// ClassifyTrend maps slope + momentum onto the five-way ladder. The strong
// arrows require momentum agreement (slope AND fast>slow for ↑); a strong
// slope against its momentum degrades to the weak arrow.
func ClassifyTrend(slope, momentum float64) string {
	switch {
	case slope >= SlopeStrong && momentum > 0:
		return TrendUpStrong
	case slope >= SlopeWeak:
		return TrendUp
	case slope <= -SlopeStrong && momentum < 0:
		return TrendDownStrong
	case slope <= -SlopeWeak:
		return TrendDown
	default:
		return TrendFlat
	}
}

// gaussianKernel builds the normalized circular smoothing weights for the
// offsets −2..+2 at the given σ.
func gaussianKernel(sigma float64) [5]float64 {
	var w [5]float64
	sum := 0.0
	for i := range w {
		off := i - 2
		w[i] = math.Exp(-float64(off*off) / (2 * sigma * sigma))
		sum += w[i]
	}
	for i := range w {
		w[i] /= sum
	}
	return w
}

// SmoothCircular smooths a full 24-hour profile with a normalized circular
// Gaussian of the given σ (hours). This is the PURE array operation — no
// sampling mask; the series accessors below apply the mask themselves.
func SmoothCircular(values [24]float64, sigma float64) [24]float64 {
	k := gaussianKernel(sigma)
	var out [24]float64
	for h := range 24 {
		var acc float64
		for i, wk := range k {
			idx := ((h+i-2)%24 + 24) % 24
			acc += wk * values[idx]
		}
		out[h] = acc
	}
	return out
}

// smoothAt blends the sampled hours around `hour` into one value: each of the
// five kernel taps contributes its per-hour EWMA only when that hour has
// samples, and the weights renormalize over the contributing taps.
func smoothAt(profile *[24]float64, samples *[24]int, hour int, sigma float64) float64 {
	k := gaussianKernel(sigma)
	var acc, wsum float64
	for i, wk := range k {
		idx := ((hour+i-2)%24 + 24) % 24
		if samples[idx] == 0 {
			continue
		}
		acc += wk * profile[idx]
		wsum += wk
	}
	if wsum == 0 {
		return 0
	}
	return acc / wsum
}

// DiurnalMeanAt is the smoothed diurnal baseline B[hour].
func DiurnalMeanAt(s *ProviderSeries, hour int) float64 {
	return smoothAt(&s.DiurnalMean, &s.DiurnalN, hour, DiurnalSigmaHours)
}

// DiurnalSigmaAt is the smoothed per-hour standard deviation with the model's
// 0.05 floor.
func DiurnalSigmaAt(s *ProviderSeries, hour int) float64 {
	smoothed := smoothAt(&s.DiurnalVar, &s.DiurnalN, hour, DiurnalSigmaHours)
	return max(math.Sqrt(smoothed), SigmaFloor)
}

// DiurnalZScore rates `rate` against the hour's diurnal baseline in σ units.
// Cold start: fewer than ColdStartMin waves force Z=0; the calibrating flag
// stays up until CalibratedAt waves have accumulated.
func DiurnalZScore(s *ProviderSeries, hour int, rate float64) (float64, bool) {
	if len(s.Waves) < ColdStartMin {
		return 0, true
	}
	mean := DiurnalMeanAt(s, hour)
	z := (rate - mean) / DiurnalSigmaAt(s, hour)
	return z, len(s.Waves) < CalibratedAt
}

// DiurnalRatio is DHR: the current rate over the hour's baseline. A negative
// rate (never produced upstream) and an unsampled hour both report 0 rather
// than inventing a ratio.
func DiurnalRatio(s *ProviderSeries, hour int, rate float64) float64 {
	if rate < 0 {
		return 0
	}
	baseline := DiurnalMeanAt(s, hour)
	if baseline < DiurnalBaselineFloor {
		return 0
	}
	return rate / baseline
}

// WeightedLiveness folds the waves inside the trailing 24h into one
// volume-weighted rate: Σlive/Σtotal — a 500-node midnight wave moves the
// number five times as much as a 100-node one. An all-empty window is 0.
func WeightedLiveness(waves []WaveSnapshot, now time.Time) float64 {
	cutoff := now.Add(-LivenessHorizon)
	var total, live int
	for _, w := range waves {
		if time.Unix(w.Timestamp, 0).Before(cutoff) {
			continue
		}
		total += w.Total
		live += w.Live
	}
	if total == 0 {
		return 0
	}
	return float64(live) / float64(total)
}

// Momentum is the dual-EMA spread: fast − slow. Positive = improving.
func (s *ProviderSeries) Momentum() float64 {
	return s.EMAFast - s.EMASlow
}

// CurrentRate is the newest wave's liveness rate (0 when the series is empty).
func (s *ProviderSeries) CurrentRate() float64 {
	if len(s.Waves) == 0 {
		return 0
	}
	return LivenessRate(s.Waves[len(s.Waves)-1])
}

// Sparkline renders the newest n waves' liveness rates (all of them when n
// exceeds the ring) at the absolute scale.
func (s *ProviderSeries) Sparkline(n int) string {
	return s.SparklineScaled(n, SparklineAbsolute)
}

// SparklineScaled renders the newest n waves under the given scale (all of
// them when n exceeds the ring).
func (s *ProviderSeries) SparklineScaled(n int, scale SparklineScale) string {
	if n < 0 || len(s.Waves) == 0 {
		return ""
	}
	start := max(len(s.Waves)-n, 0)
	rates := make([]float64, 0, len(s.Waves)-start)
	for _, w := range s.Waves[start:] {
		rates = append(rates, LivenessRate(w))
	}
	return ComputeSparklineScaled(rates, scale)
}

// Trend classifies the last six waves: OLS slope over their liveness rates
// plus the dual-EMA momentum.
func (s *ProviderSeries) Trend() string {
	n := min(len(s.Waves), 6)
	rates := make([]float64, 0, n)
	for _, w := range s.Waves[len(s.Waves)-n:] {
		rates = append(rates, LivenessRate(w))
	}
	return ClassifyTrend(ComputeSlope(rates), s.Momentum())
}

// roundForStore clamps persisted floats to 1e-6 precision: same inputs always
// produce the same bytes, and the EWMA tail noise never bloats the file.
func roundForStore(f float64) float64 {
	return math.Round(f*1e6) / 1e6
}

// UpdateSeries folds one snapshot into a series in place: append, prune
// (>48h, cap 48), update the hour's diurnal EWMA pair, and step the dual-EMA
// momentum state. Non-positive timestamps are dropped defensively (they
// carry no hour key).
func UpdateSeries(s *ProviderSeries, snap WaveSnapshot, now time.Time) {
	if snap.Timestamp <= 0 {
		return
	}
	ts := time.Unix(snap.Timestamp, 0).UTC()

	s.Waves = append(s.Waves, snap)
	cutoff := now.Add(-WaveHorizon)
	kept := s.Waves[:0]
	for _, w := range s.Waves {
		if time.Unix(w.Timestamp, 0).Before(cutoff) {
			continue
		}
		kept = append(kept, w)
	}
	s.Waves = kept
	if len(s.Waves) > MaxWaves {
		s.Waves = s.Waves[len(s.Waves)-MaxWaves:]
	}

	rate := LivenessRate(snap)
	hour := ts.Hour()
	s.DiurnalN[hour]++
	if s.DiurnalN[hour] == 1 {
		s.DiurnalMean[hour] = rate
		s.DiurnalVar[hour] = 0
	} else {
		prevMean := s.DiurnalMean[hour]
		s.DiurnalMean[hour] = prevMean + DiurnalAlpha*(rate-prevMean)
		dev := (rate - s.DiurnalMean[hour]) * (rate - s.DiurnalMean[hour])
		s.DiurnalVar[hour] = (1-DiurnalAlpha)*s.DiurnalVar[hour] + DiurnalAlpha*dev
	}
	s.DiurnalMean[hour] = roundForStore(s.DiurnalMean[hour])
	s.DiurnalVar[hour] = roundForStore(s.DiurnalVar[hour])

	if !s.EMASeeded {
		s.EMAFast, s.EMASlow, s.EMASeeded = rate, rate, true
	} else {
		s.EMAFast = roundForStore(s.EMAFast + EMAFastAlpha*(rate-s.EMAFast))
		s.EMASlow = roundForStore(s.EMASlow + EMASlowAlpha*(rate-s.EMASlow))
	}
}

// ReadProviderHistory loads the persisted history. A missing file is the
// documented empty cold start (never an error, never a crash); any other
// read or decode failure fails loud.
func ReadProviderHistory(path string) (*ProviderHistory, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &ProviderHistory{Version: HistoryVersion, Providers: map[string]*ProviderSeries{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read provider history %s: %w", path, err)
	}
	var h ProviderHistory
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("decode provider history %s: %w", path, err)
	}
	if h.Providers == nil {
		h.Providers = map[string]*ProviderSeries{}
	}
	return &h, nil
}

// WriteProviderHistory persists atomically (tmp → fsync → rename via the
// store's shared primitive) and compactly (the whole file must stay under
// MaxHistoryBytes; encoding/json sorts map keys, so bytes are deterministic).
// A payload over the documented budget is a LOUD, non-fatal warning
// (adversarial review F8): dynamic plugin counts can exceed the shape the
// budget test pins — the write lands, and the operator hears about it.
func WriteProviderHistory(path string, h *ProviderHistory) error {
	h.Version = HistoryVersion
	b, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("marshal provider history: %w", err)
	}
	if len(b) > MaxHistoryBytes {
		fmt.Fprintf(os.Stderr,
			"WARNING: provider history payload is %d bytes — over the %d-byte documented budget "+
				"(dynamic plugin counts); the write continues, prune dead providers or widen the budget\n",
			len(b), MaxHistoryBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return store.WriteFileAtomic(path, func(f *os.File) error {
		_, err := f.Write(b)
		return err
	})
}

// RecordWaveSnapshot is the one-call integration point: load (or cold-start),
// fold the snapshot into the provider's series, persist atomically, and
// return the updated series. Concurrent callers inside one process serialize
// on the package mutex; cross-process readers only ever see complete files.
func RecordWaveSnapshot(path, pluginID string, snap WaveSnapshot, now time.Time) (*ProviderSeries, error) {
	historyMu.Lock()
	defer historyMu.Unlock()

	h, err := ReadProviderHistory(path)
	if err != nil {
		return nil, err
	}
	series, ok := h.Providers[pluginID]
	if !ok || series == nil {
		series = &ProviderSeries{}
		h.Providers[pluginID] = series
	}
	UpdateSeries(series, snap, now)
	if err := WriteProviderHistory(path, h); err != nil {
		return nil, err
	}
	return series, nil
}
