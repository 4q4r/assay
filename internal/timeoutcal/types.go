// Package timeoutcal implements self-calibrating adaptive timeouts for the
// probe and geo waves: p95(observed RTT) + safety margin, EMA smoothing,
// hysteresis, and an adaptive history window driven by the coefficient of
// variation of recent p95 values.
package timeoutcal

import "time"

// Observation is one wave's measured response-time distribution for a single
// calibration key ("global", a country code, or "cc:city").
type Observation struct {
	Key      string    // "global", "ru", "ru:moscow", ...
	Stage    string    // "probe" | "geo"
	Total    int       // total attempted requests
	TimedOut int       // requests that timed out
	RTTsMs   []float64 // successful response times in milliseconds
	At       time.Time
}

// Config tunes the calibration. Zero values fall back to the package defaults.
type Config struct {
	Margin               float64 // safety margin in seconds added to p95 (default 1.0)
	Alpha                float64 // base EMA smoothing factor (default 0.3)
	MinSamples           int     // minimum total before calibrating a key (default 50)
	HighTimeoutRate      float64 // timeout rate above which we use p99 (default 0.15)
	HistorySize          int     // base history window (default 20)
	MinHistory           int     // safety floor for adaptive window (default 3)
	MaxHistory           int     // safety ceiling for adaptive window (default 50)
	StabilityCVThreshold float64 // CV below this = "stable" (default 0.10)
	MinChange            float64 // hysteresis threshold in seconds (default 0.5)
}

// DefaultConfig returns the package defaults.
func DefaultConfig() Config {
	return Config{
		Margin:               1.0,
		Alpha:                0.3,
		MinSamples:           50,
		HighTimeoutRate:      0.15,
		HistorySize:          20,
		MinHistory:           3,
		MaxHistory:           50,
		StabilityCVThreshold: 0.10,
		MinChange:            0.5,
	}
}

// normalize fills zero values with defaults.
func (c Config) normalize() Config {
	d := DefaultConfig()
	if c.Margin <= 0 {
		c.Margin = d.Margin
	}
	if c.Alpha <= 0 {
		c.Alpha = d.Alpha
	}
	if c.MinSamples <= 0 {
		c.MinSamples = d.MinSamples
	}
	if c.HighTimeoutRate <= 0 {
		c.HighTimeoutRate = d.HighTimeoutRate
	}
	if c.HistorySize <= 0 {
		c.HistorySize = d.HistorySize
	}
	if c.MinHistory <= 0 {
		c.MinHistory = d.MinHistory
	}
	if c.MaxHistory <= 0 {
		c.MaxHistory = d.MaxHistory
	}
	if c.StabilityCVThreshold <= 0 {
		c.StabilityCVThreshold = d.StabilityCVThreshold
	}
	if c.MinChange <= 0 {
		c.MinChange = d.MinChange
	}
	if c.MinHistory > c.MaxHistory {
		c.MinHistory = c.MaxHistory
	}
	return c
}

// HistoryEntry records one wave's p95 for a key.
type HistoryEntry struct {
	At    time.Time `json:"at"`
	P95Ms float64   `json:"p95_ms"`
	Rate  float64   `json:"rate"`
	N     int       `json:"n"`
}

// KeyState holds the calibrated state for one key.
type KeyState struct {
	Current     time.Duration  `json:"current"`
	EMAP95Ms    float64        `json:"ema_p95_ms"`
	Rate        float64        `json:"timeout_rate"`
	Waves       int            `json:"waves"`
	HistorySize int            `json:"history_size"`
	History     []HistoryEntry `json:"history"`
}

// StageState holds calibrated state for one stage (probe or geo).
type StageState struct {
	Base    time.Duration       `json:"base"`
	Global  KeyState            `json:"global"`
	Regions map[string]KeyState `json:"regions,omitempty"`
	Cities  map[string]KeyState `json:"cities,omitempty"`
}

// State is the persisted calibration state.
type State struct {
	Probe StageState `json:"probe"`
	Geo   StageState `json:"geo"`
}
