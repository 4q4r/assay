package geo

import (
	"testing"
	"time"

	"public_vpn/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBatchIntervalClampsToFreeTier unit-tests the production clamp directly:
// the free tier allows 15 batch requests/min, so a generous configuration
// (per_minute = 900) must clamp to one batch per 4s — without paying 4s of
// wall time in a behavior test (review finding 3).
func TestBatchIntervalClampsToFreeTier(t *testing.T) {
	assert.Equal(t, 4*time.Second, batchInterval(900), "900/min clamps to the 15/min free-tier ceiling")
	assert.Equal(t, 4*time.Second, batchInterval(15), "the ceiling itself is exact")
	assert.Equal(t, 12*time.Second, batchInterval(5), "below the ceiling the config wins")
	assert.Equal(t, time.Minute, batchInterval(0), "floored at 1/min — never a zero interval")
	assert.Equal(t, time.Minute, batchInterval(-7), "negative config floors at 1/min")
}

// TestNewClientDelegatesToBatchInterval pins that the production constructor
// really builds a burst-1 limiter at the clamped interval: exactly one
// immediate token, then the spacing is real (no burst-y 429 drivers).
func TestNewClientDelegatesToBatchInterval(t *testing.T) {
	cl := NewClient(config.GeoConfig{PerMinute: 900})
	require.NotNil(t, cl.limiter)
	assert.True(t, cl.limiter.Allow(), "burst is 1: the first batch goes immediately")
	assert.False(t, cl.limiter.Allow(), "burst is 1: the second batch must wait out the clamped 4s interval")
}
