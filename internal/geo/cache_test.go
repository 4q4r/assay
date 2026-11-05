package geo

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"public_vpn/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExitGeoCacheHitMiss(t *testing.T) {
	c := NewExitGeoCache()
	defer func() { _ = c.Close() }()
	e := &ExitGeoEntry{Country: "DE"}
	require.NoError(t, c.Set("1.2.3.4", e))
	got, ok := c.Get("1.2.3.4")
	require.True(t, ok)
	assert.Equal(t, "DE", got.Country)
	_, ok = c.Get("9.9.9.9")
	assert.False(t, ok)
	assert.Equal(t, 1, c.Len())
}

func TestExitGeoCacheRenewal(t *testing.T) {
	c := NewExitGeoCache(50*time.Millisecond, 100)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Set("1.2.3.4", &ExitGeoEntry{Country: "DE"}))
	time.Sleep(30 * time.Millisecond)
	// hit renews
	_, ok := c.Get("1.2.3.4")
	require.True(t, ok)
	time.Sleep(30 * time.Millisecond)
	// would have expired without renewal, but renewed
	_, ok = c.Get("1.2.3.4")
	assert.True(t, ok)
}

func TestExitGeoCacheEvictionLRU(t *testing.T) {
	c := NewExitGeoCache(ExitCacheConfig{TTL: time.Hour, MaxEntries: 2, Shards: 1})
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Set("a", &ExitGeoEntry{Country: "A"}))
	require.NoError(t, c.Set("b", &ExitGeoEntry{Country: "B"}))
	// touch a
	_, _ = c.Get("a")
	// insert c evicts LRU (b? actually a touched, b oldest)
	require.NoError(t, c.Set("c", &ExitGeoEntry{Country: "C"}))
	assert.Equal(t, 2, c.Len())
	_, ok := c.Get("b")
	assert.False(t, ok, "b evicted")
}

func TestExitGeoCacheRehydration(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	recs := []*model.GeoRecord{
		{IP: "1.2.3.4", Country: "DE", City: "Berlin", LastSeen: now, FlagsVerified: true, Scheme: "vless", Host: "a.example.com", Port: 443},
		{IP: "1.2.3.4", Country: "FR", City: "Paris", LastSeen: "2020-01-01T00:00:00Z", Scheme: "vless", Host: "a.example.com", Port: 443},
		{IP: "5.5.5.5", Country: "US", LastSeen: now, Scheme: "vless", Host: "b.example.com", Port: 443},
	}

	c := NewExitGeoCache()
	defer func() { _ = c.Close() }()
	c.Rehydrate(recs)
	assert.Equal(t, 2, c.Len())
	got, ok := c.Get("1.2.3.4")
	require.True(t, ok)
	assert.Equal(t, "DE", got.Country, "freshest/verified wins")
}

func TestExitGeoCacheWaveStaleness(t *testing.T) {
	c := NewExitGeoCache(time.Hour, 100, 2)
	defer func() { _ = c.Close() }()
	c.SetCurrentWave(1)
	require.NoError(t, c.Set("1.2.3.4", &ExitGeoEntry{Country: "DE"}))
	// entry WaveSeq=1
	c.SetCurrentWave(4) // 3 behind → stale
	_, ok := c.Get("1.2.3.4")
	assert.False(t, ok)
}

func TestExitGeoCacheConcurrency(t *testing.T) {
	_ = t
	c := NewExitGeoCache()
	defer func() { _ = c.Close() }()
	for range 100 {
		_ = c.Set("ip", &ExitGeoEntry{Country: "DE"})
	}
	done := make(chan struct{})
	workerFn := func() {
		for range 1000 {
			c.Get("ip")
			_ = c.Set("ip2", &ExitGeoEntry{Country: "US"})
		}
		done <- struct{}{}
	}
	for range 8 {
		go workerFn()
	}
	for range 8 {
		<-done
	}
}

func TestExitGeoCacheClose(t *testing.T) {
	c := NewExitGeoCache()
	require.NoError(t, c.Close())
	err := c.Set("x", &ExitGeoEntry{})
	require.Error(t, err)
	_, ok := c.Get("x")
	assert.False(t, ok)
}

func TestExitGeoCacheCloseIdempotentAndStopsGoroutine(t *testing.T) {
	c := NewExitGeoCache(ExitCacheConfig{
		CleanWindow: 10 * time.Millisecond,
	})

	// Concurrently call Close() from multiple goroutines to verify race-freedom and idempotency
	const goroutines = 10
	errCh := make(chan error, goroutines)
	closeFn := func() {
		errCh <- c.Close()
	}
	for range goroutines {
		go closeFn()
	}

	for range goroutines {
		err := <-errCh
		require.NoError(t, err)
	}

	// Calling Close again sequentially must be a no-op
	require.NoError(t, c.Close())
	assert.True(t, c.isClosed())

	// Verifying mutations fail cleanly
	err := c.Set("1.1.1.1", &ExitGeoEntry{Country: "US"})
	assert.ErrorIs(t, err, ErrClosed)
}

func TestExitGeoCacheRehydrateFromStruct(t *testing.T) {
	c := NewExitGeoCache()
	defer func() { _ = c.Close() }()
	rec := model.GeoRecord{IP: "1.1.1.1", Country: "AU", LastSeen: time.Now().UTC().Format(time.RFC3339)}
	c.Rehydrate([]model.GeoRecord{rec})
	_, ok := c.Get("1.1.1.1")
	assert.True(t, ok)
}

func TestExitGeoCacheStressConcurrentResizeRehydrate(t *testing.T) {
	c := NewExitGeoCache(ExitCacheConfig{
		TTL:         10 * time.Minute,
		MaxEntries:  2000,
		Shards:      16,
		CleanWindow: 50 * time.Millisecond,
		StaleWaves:  5,
	})
	defer func() { _ = c.Close() }()

	const numWorkers = 50
	duration := 2500 * time.Millisecond
	stopCh := make(chan struct{})

	// Seed some stable entries that should never be lost
	for i := range 100 {
		ip := fmt.Sprintf("10.0.0.%d", i)
		require.NoError(t, c.Set(ip, &ExitGeoEntry{Country: "SE", City: "Stockholm"}))
	}

	var wg sync.WaitGroup

	// Background resizer calling Resize repeatedly across capacities
	wg.Add(1)
	resizerFn := func() {
		defer wg.Done()
		caps := []int{500, 1000, 2500, 1500, 3000, 800}
		idx := 0
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				c.Resize(caps[idx%len(caps)])
				idx++
			}
		}
	}
	go resizerFn()

	// 50 concurrent workers running Get, Set, and Rehydrate
	for w := range numWorkers {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			op := 0
			for {
				select {
				case <-stopCh:
					return
				default:
				}

				switch op % 3 {
				case 0: // Get
					ip := fmt.Sprintf("10.0.0.%d", (wID*17+op)%100)
					c.Get(ip)
				case 1: // Set
					ip := fmt.Sprintf("10.0.0.%d", (wID*31+op)%100)
					_ = c.Set(ip, &ExitGeoEntry{
						Country: "DE",
						City:    "Frankfurt",
					})
				case 2: // Rehydrate
					recs := []*model.GeoRecord{
						{
							IP:            fmt.Sprintf("10.0.0.%d", (wID*7+op)%100),
							Country:       "NL",
							City:          "Amsterdam",
							LastSeen:      time.Now().UTC().Format(time.RFC3339),
							FlagsVerified: true,
						},
					}
					c.Rehydrate(recs)
				}
				op++
			}
		}(w)
	}

	time.Sleep(duration)
	close(stopCh)
	wg.Wait()

	// Verify all seeded entries still exist and are retrievable
	for i := range 100 {
		ip := fmt.Sprintf("10.0.0.%d", i)
		entry, ok := c.Get(ip)
		assert.True(t, ok, "seeded entry for %s must not be lost", ip)
		assert.NotNil(t, entry)
	}
}
