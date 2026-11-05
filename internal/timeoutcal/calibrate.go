package timeoutcal

import (
	"math"
	"sort"
	"time"
)

// Safety rails (internal constants, not config knobs).
const (
	FloorMs   = 3000.0
	CeilingMs = 60000.0
)

// P95 computes the 95th percentile of a sorted-or-unsorted sample (ms).
func P95(values []float64) float64 {
	return Percentile(values, 0.95)
}

// P99 computes the 99th percentile.
func P99(values []float64) float64 {
	return Percentile(values, 0.99)
}

// Percentile computes the p-th percentile (0..1) using linear interpolation.
func Percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	pos := p * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if hi >= len(sorted) {
		hi = len(sorted) - 1
	}
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo] + (sorted[hi]-sorted[lo])*frac
}

// CV computes the coefficient of variation (stddev/mean) of a sample.
func CV(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	if mean == 0 {
		return 0
	}
	var sq float64
	for _, v := range values {
		d := v - mean
		sq += d * d
	}
	std := math.Sqrt(sq / float64(len(values)))
	return std / mean
}

// AdaptiveWindow computes the history window size K and EMA alpha from recent
// p95 values, using the base alpha. Returns (K, alpha).
func AdaptiveWindow(recent []float64) (int, float64) {
	return AdaptiveWindowWithBase(recent, 0.3)
}

// AdaptiveWindowWithBase is like AdaptiveWindow but takes an explicit base alpha.
func AdaptiveWindowWithBase(recent []float64, baseAlpha float64) (int, float64) {
	if baseAlpha <= 0 {
		baseAlpha = 0.3
	}
	cfg := DefaultConfig()
	cfg.Alpha = baseAlpha
	cfg = cfg.normalize()
	minH := cfg.MinHistory
	maxH := cfg.MaxHistory
	thr := cfg.StabilityCVThreshold
	if len(recent) < minH {
		return minH, baseAlpha
	}
	cv := CV(recent)
	if cv < thr {
		k := minH
		v := 5 + int((thr-cv)*100)
		if v > k {
			k = v
		}
		if k > maxH {
			k = maxH
		}
		if k < minH {
			k = minH
		}
		alpha := baseAlpha * (1 + (thr-cv)*5)
		if alpha > 0.5 {
			alpha = 0.5
		}
		if alpha < baseAlpha {
			alpha = baseAlpha
		}
		return k, alpha
	}
	k := max(minH, min(maxH, 20+int((cv-thr)*200)))
	alpha := baseAlpha * (1 - (cv-thr)*3)
	if alpha < 0.1 {
		alpha = 0.1
	}
	if alpha > baseAlpha {
		alpha = baseAlpha
	}
	_ = k
	return k, alpha
}

// AdaptiveAlpha is a convenience alias for the alpha half of AdaptiveWindow.
func AdaptiveAlpha(recent []float64, baseAlpha float64) float64 {
	_, a := AdaptiveWindowWithBase(recent, baseAlpha)
	return a
}

// EMA computes the exponential moving average.
func EMA(current, candidate, alpha float64) float64 {
	return (1-alpha)*current + alpha*candidate
}

// Calibrate computes a new calibrated timeout from an observation.
func Calibrate(key string, obs Observation, current time.Duration) time.Duration {
	return CalibrateWithConfig(DefaultConfig(), key, obs, current)
}

// CalibrateWithConfig is the configurable variant.
func CalibrateWithConfig(cfg Config, _ string, obs Observation, current time.Duration) time.Duration {
	cfg = cfg.normalize()
	if obs.Total < cfg.MinSamples {
		return current
	}
	if len(obs.RTTsMs) == 0 {
		// no successful RTTs; fall back to current
		return current
	}
	timeoutRate := 0.0
	if obs.Total > 0 {
		timeoutRate = float64(obs.TimedOut) / float64(obs.Total)
	}
	p95 := P95(obs.RTTsMs)
	p99 := P99(obs.RTTsMs)
	marginMs := cfg.Margin * 1000.0
	var candidateMs float64
	if timeoutRate > cfg.HighTimeoutRate {
		candidateMs = p99 + marginMs
		if candidateMs < float64(current.Milliseconds()) {
			candidateMs = float64(current.Milliseconds())
		}
	} else {
		candidateMs = p95 + marginMs
	}
	// clamp
	if candidateMs < FloorMs {
		candidateMs = FloorMs
	}
	if candidateMs > CeilingMs {
		candidateMs = CeilingMs
	}
	// EMA smoothing using adaptive window/alpha based on recent history.
	// We need recent p95s; obs carries none, so use candidate as the only sample
	// unless current has a stored EMA. For smoothing we blend current and candidate.
	recent := []float64{p95}
	_, alpha := AdaptiveWindowWithBase(recent, cfg.Alpha)
	// If we have a stored current EMA, blend; otherwise start from candidate.
	currentMs := float64(current.Milliseconds())
	var emaMs float64
	if currentMs == 0 {
		emaMs = candidateMs
	} else {
		emaMs = EMA(currentMs, candidateMs, alpha)
	}
	// hysteresis
	newDur := time.Duration(emaMs) * time.Millisecond
	if math.Abs(float64(newDur.Milliseconds())-float64(current.Milliseconds())) < cfg.MinChange*1000.0 {
		newDur = current
	}
	// monotonic-min safety: never below running min p95+margin of last 3 (use p95+margin)
	minSafeMs := p95 + marginMs
	if minSafeMs < FloorMs {
		minSafeMs = FloorMs
	}
	if float64(newDur.Milliseconds()) < minSafeMs {
		newDur = time.Duration(minSafeMs) * time.Millisecond
	}
	// clamp again
	if newDur < time.Duration(FloorMs)*time.Millisecond {
		newDur = time.Duration(FloorMs) * time.Millisecond
	}
	if newDur > time.Duration(CeilingMs)*time.Millisecond {
		newDur = time.Duration(CeilingMs) * time.Millisecond
	}
	return newDur
}

// TimeoutFor implements the fallback chain city -> country -> global -> base.
func (s *StageState) TimeoutFor(key string) time.Duration {
	if s == nil {
		return 0
	}
	if key != "" && key != "global" {
		if stringsContains(key, ":") {
			if v := cityTimeout(s, key); v > 0 {
				return v
			}
		} else if s.Regions != nil {
			if ks, ok := s.Regions[key]; ok && ks.Current > 0 {
				return ks.Current
			}
		}
	}
	if s.Global.Current > 0 {
		return s.Global.Current
	}
	return s.Base
}

func cityTimeout(s *StageState, key string) time.Duration {
	if s.Cities != nil {
		if ks, ok := s.Cities[key]; ok && ks.Current > 0 {
			return ks.Current
		}
	}
	parts := splitKey(key)
	country := parts[0]
	if s.Regions != nil {
		if ks, ok := s.Regions[country]; ok && ks.Current > 0 {
			return ks.Current
		}
	}
	return 0
}

// stringsContains reports whether sub is in s.
func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func splitKey(key string) []string {
	// split on first ':'.
	for i := range len(key) {
		if key[i] == ':' {
			return []string{key[:i], key[i+1:]}
		}
	}
	return []string{key}
}
