package ui

// Traffic-light thresholds (owner spec, verbatim): <400ms green,
// 400–799ms amber, ≥800ms red. These are code-owned DISPLAY constants —
// not configuration knobs (owner ruling: the values were given verbatim
// and are not adjustable).
const (
	TrafficGreenBelowMS = 400 // < 400 green
	TrafficAmberBelowMS = 800 // 400–799 amber, ≥ 800 red
)

// TrafficName classifies a millisecond value into the traffic-light palette
// name: green (<400), amber (400–799), red (≥800). Values with no data
// (<= 0 — rendered as an em dash) carry NO color: a dash is not a latency.
func TrafficName(ms float64) string {
	switch {
	case ms <= 0:
		return ""
	case ms < TrafficGreenBelowMS:
		return Green
	case ms < TrafficAmberBelowMS:
		return Amber
	default:
		return Red
	}
}
