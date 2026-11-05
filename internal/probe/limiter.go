package probe

import (
	"context"
	"math"
	"sync"
	"time"
)

// AdaptiveLimiter controls worker concurrency dynamically based on network
// metrics (RTT variance and timeout rate) or external feedback.
// It implements a thread-safe token/semaphore window with AIMD-style congestion
// control (Additive Increase, Multiplicative Decrease).
type AdaptiveLimiter struct {
	mu sync.Mutex

	minLimit int // floor concurrency (>= 1)
	maxLimit int // ceiling concurrency (e.g. configured Threads)
	current  int // active concurrency limit
	inFlight int // active tokens acquired

	cond *sync.Cond

	// Metrics window for RTT and timeouts
	rtts        []float64
	timeouts    int
	totalSample int
	windowSize  int

	// Hysteresis / threshold configuration
	highTimeoutRate float64 // e.g. 0.15 (15%)
	highCVThreshold float64 // e.g. 0.50 (high RTT variance)
	lowCVThreshold  float64 // e.g. 0.15 (stable RTT)
	lowTimeoutRate  float64 // e.g. 0.05 (5%)
}

// AdaptiveLimiterConfig specifies parameters for the AdaptiveLimiter.
type AdaptiveLimiterConfig struct {
	MinLimit        int
	MaxLimit        int
	Initial         int
	WindowSize      int
	HighTimeoutRate float64
	HighCVThreshold float64
	LowTimeoutRate  float64
	LowCVThreshold  float64
}

// DefaultAdaptiveLimiterConfig returns standard parameters for dynamic limiting.
func DefaultAdaptiveLimiterConfig(maxLimit int) AdaptiveLimiterConfig {
	if maxLimit < 1 {
		maxLimit = DefaultConcurrency
	}
	minLimit := 1
	initial := maxLimit
	return AdaptiveLimiterConfig{
		MinLimit:        minLimit,
		MaxLimit:        maxLimit,
		Initial:         initial,
		WindowSize:      20,
		HighTimeoutRate: 0.15,
		HighCVThreshold: 0.40,
		LowTimeoutRate:  0.05,
		LowCVThreshold:  0.15,
	}
}

// NewAdaptiveLimiter creates an AdaptiveLimiter.
func NewAdaptiveLimiter(cfg AdaptiveLimiterConfig) *AdaptiveLimiter {
	if cfg.MinLimit < 1 {
		cfg.MinLimit = 1
	}
	if cfg.MaxLimit < cfg.MinLimit {
		cfg.MaxLimit = cfg.MinLimit
	}
	if cfg.Initial < cfg.MinLimit {
		cfg.Initial = cfg.MinLimit
	}
	if cfg.Initial > cfg.MaxLimit {
		cfg.Initial = cfg.MaxLimit
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 20
	}
	if cfg.HighTimeoutRate <= 0 {
		cfg.HighTimeoutRate = 0.15
	}
	if cfg.HighCVThreshold <= 0 {
		cfg.HighCVThreshold = 0.40
	}
	if cfg.LowTimeoutRate <= 0 {
		cfg.LowTimeoutRate = 0.05
	}
	if cfg.LowCVThreshold <= 0 {
		cfg.LowCVThreshold = 0.15
	}

	l := &AdaptiveLimiter{
		minLimit:        cfg.MinLimit,
		maxLimit:        cfg.MaxLimit,
		current:         cfg.Initial,
		windowSize:      cfg.WindowSize,
		highTimeoutRate: cfg.HighTimeoutRate,
		highCVThreshold: cfg.HighCVThreshold,
		lowTimeoutRate:  cfg.LowTimeoutRate,
		lowCVThreshold:  cfg.LowCVThreshold,
		rtts:            make([]float64, 0, cfg.WindowSize),
	}
	l.cond = sync.NewCond(&l.mu)
	return l
}

// Acquire blocks until a concurrency slot is available or context is cancelled.
// Returns error if context is cancelled before acquiring.
func (l *AdaptiveLimiter) Acquire(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// If context has a cancellation, wait with cancellation awareness
	if ctx != nil && ctx.Done() != nil {
		for l.inFlight >= l.current {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Broadcast wakes all waiters so we re-check
			// We use a small timeout channel or poll to allow ctx cancellation
			done := make(chan struct{})
			go func() {
				l.mu.Lock()
				defer l.mu.Unlock()
				select {
				case <-done:
					return
				case <-ctx.Done():
					l.cond.Broadcast()
				}
			}()

			l.cond.Wait()
			close(done)

			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
	} else {
		for l.inFlight >= l.current {
			l.cond.Wait()
		}
	}

	l.inFlight++
	return nil
}

// Release yields an acquired concurrency slot and notifies waiters.
func (l *AdaptiveLimiter) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.inFlight > 0 {
		l.inFlight--
	}
	l.cond.Broadcast()
}

// Current returns the current active concurrency limit.
func (l *AdaptiveLimiter) Current() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.current
}

// InFlight returns the number of currently active jobs.
func (l *AdaptiveLimiter) InFlight() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inFlight
}

// SetLimit directly sets the target concurrency, clamped to [minLimit, maxLimit].
func (l *AdaptiveLimiter) SetLimit(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if n < l.minLimit {
		n = l.minLimit
	}
	if n > l.maxLimit {
		n = l.maxLimit
	}
	l.current = n
	l.cond.Broadcast()
}

// RecordOutcome records an observation (latency, timeout) and adjusts
// active concurrency limit dynamically.
//
//nolint:cyclop // congestion control decision tree
func (l *AdaptiveLimiter) RecordOutcome(rtt time.Duration, timedOut bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.totalSample++
	if timedOut {
		l.timeouts++
	} else {
		l.rtts = append(l.rtts, float64(rtt.Milliseconds()))
		if len(l.rtts) > l.windowSize {
			l.rtts = l.rtts[len(l.rtts)-l.windowSize:]
		}
	}

	// Only evaluate after a minimum batch of observations (at least 5)
	if l.totalSample < 5 {
		return
	}

	timeoutRate := float64(l.timeouts) / float64(l.totalSample)
	cv := 0.0
	if len(l.rtts) >= 3 {
		cv = sampleCV(l.rtts)
	}

	// Reset window stats if sample reaches windowSize to adapt to changing phases
	if l.totalSample >= l.windowSize {
		l.totalSample = 0
		l.timeouts = 0
		// keep half of rtts for continuity
		if len(l.rtts) > l.windowSize/2 {
			l.rtts = l.rtts[len(l.rtts)-l.windowSize/2:]
		}
	}

	// Congestion signal: high timeout rate OR high RTT variance (jitter/bufferbloat)
	if timeoutRate >= l.highTimeoutRate || cv >= l.highCVThreshold {
		// Multiplicative decrease (throttle down by 25-50%)
		decreased := int(math.Floor(float64(l.current) * 0.75))
		if decreased >= l.current {
			decreased = l.current - 1
		}
		if decreased < l.minLimit {
			decreased = l.minLimit
		}
		if decreased != l.current {
			l.current = decreased
			l.cond.Broadcast()
		}
		return
	}

	// Favorable network conditions: low timeout rate AND stable RTT variance
	if timeoutRate <= l.lowTimeoutRate && (cv <= l.lowCVThreshold || len(l.rtts) < 3) {
		// Additive increase
		increased := min(l.current+1, l.maxLimit)
		if increased != l.current {
			l.current = increased
			l.cond.Broadcast()
		}
	}
}

func sampleCV(vals []float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	if mean <= 0 {
		return 0
	}
	var sqDiff float64
	for _, v := range vals {
		d := v - mean
		sqDiff += d * d
	}
	stdDev := math.Sqrt(sqDiff / float64(len(vals)))
	return stdDev / mean
}
