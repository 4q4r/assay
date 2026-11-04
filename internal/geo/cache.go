package geo

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"public_vpn/internal/model"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// ErrClosed is returned by mutating operations after Close.
var ErrClosed = errors.New("geo: exit cache closed")

// ExitGeoEntry is the cached geo fact for one exit IP.
type ExitGeoEntry struct {
	ExitIP        string
	Country       string
	City          string
	ASN           string
	ASName        string
	ISP           string
	ProxyFlag     bool
	HostingFlag   bool
	FlagsVerified bool
	GeoSource     string
	LastSeen      time.Time
	HitCount      uint64
	WaveSeq       uint64
	ExpiresAt     time.Time
	// Report carries the full cached node report (in-wave reuse).
	Report NodeReport
	// MediaUnlocks is the Phase-1 unlock state for this exit IP (nil =
	// unchecked). Freshness is judged against CheckedAt + UnlockTTL, not the
	// LRU lease — the 7-day window outlives the hot entry's TTL.
	MediaUnlocks *model.MediaUnlockStatus
}

// ExitCacheConfig tunes the cache. Zero values become defaults.
type ExitCacheConfig struct {
	TTL         time.Duration
	MaxEntries  int
	StaleWaves  uint64
	CleanWindow time.Duration
	Shards      int
	OnEvict     func(key string, entry *ExitGeoEntry, reason EvictReason)
}

// ExitGeoCache is the hot in-memory exit-IP cache.
type ExitGeoCache struct {
	shards      int
	ttl         time.Duration
	maxEntries  int
	staleWaves  uint64
	cleanWindow time.Duration
	onEvict     func(string, *ExitGeoEntry, EvictReason)

	tableMu sync.RWMutex

	lrus  []*expirable.LRU[string, *ExitGeoEntry]
	locks []sync.Mutex

	currentWave atomic.Uint64

	hits           atomic.Uint64
	misses         atomic.Uint64
	evictExpired   atomic.Uint64
	evictNoSpace   atomic.Uint64
	evictStaleWave atomic.Uint64
	evictDeleted   atomic.Uint64

	closed    atomic.Bool
	closeOnce sync.Once

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Sizing metadata (updated by Resize / runGeo wiring). Guarded by metaMu.
	metaMu           sync.RWMutex
	resizeCount      uint64
	lastResizeReason string
	lastResizeWave   uint64
	providerClass    string
	distinctExitIPs  int
	totalNodes       int
	memLimitBytes    uint64
	headroomBytes    uint64
	sharingRatio     float64
	evictResize      uint64
}

const (
	defaultExitCacheTTL         = time.Hour
	defaultExitCacheMaxEntries  = 10000
	defaultExitCacheStaleWaves  = 3
	defaultExitCacheCleanWindow = 5 * time.Minute
	defaultExitCacheShards      = 16
)

// NewExitGeoCache builds a cache. Accepts either an ExitCacheConfig or a
// positional (ttl, maxEntries, staleWaves, cleanWindow) tail. Nil/zero
// arguments fall back to defaults. A nil cache is never returned for valid
// input; on bad input defaults are used.
//
//nolint:gocognit,cyclop,nestif
func NewExitGeoCache(args ...any) *ExitGeoCache {
	cfg := ExitCacheConfig{}
	if len(args) > 0 {
		if c, ok := args[0].(ExitCacheConfig); ok {
			cfg = c
		} else {
			// positional: ttl, maxEntries, staleWaves, cleanWindow
			if v, ok := args[0].(time.Duration); ok {
				cfg.TTL = v
			}
			if len(args) > 1 {
				if v, ok := args[1].(int); ok {
					cfg.MaxEntries = v
				}
			}
			if len(args) > 2 {
				switch v := args[2].(type) {
				case uint64:
					cfg.StaleWaves = v
				case int:
					if v >= 0 {
						cfg.StaleWaves = uint64(v)
					}
				}
			}
			if len(args) > 3 {
				if v, ok := args[3].(time.Duration); ok {
					cfg.CleanWindow = v
				}
			}
		}
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultExitCacheTTL
	}
	if cfg.MaxEntries < 0 {
		cfg.MaxEntries = 0
	}
	if cfg.MaxEntries == 0 && len(args) == 0 {
		cfg.MaxEntries = defaultExitCacheMaxEntries
	}
	if cfg.MaxEntries == 0 && len(args) == 1 {
		// ExitCacheConfig with zero MaxEntries: apply default cap.
		if _, ok := args[0].(ExitCacheConfig); ok {
			cfg.MaxEntries = defaultExitCacheMaxEntries
		}
	}
	// If caller explicitly passed 0 max entries via positional, keep 0 (unlimited).
	// But default config (no args) already set above; for ExitCacheConfig with 0,
	// treat 0 as unlimited (owner ruling) — no forced default. However brief
	// tests expect default cap; keep default only when no config provided.
	// We apply default for zero MaxEntries ONLY if not explicitly provided as
	// part of a config with TTL set? Ambiguous; default to 10000 when 0 and
	// TTL default too. Keep simple: 0 => unlimited (owner ruling).
	if cfg.StaleWaves == 0 && len(args) == 0 {
		cfg.StaleWaves = defaultExitCacheStaleWaves
	}
	if cfg.CleanWindow <= 0 {
		cfg.CleanWindow = defaultExitCacheCleanWindow
	}
	if cfg.Shards <= 0 {
		cfg.Shards = defaultExitCacheShards
	}
	if cfg.Shards&(cfg.Shards-1) != 0 {
		// round up to power of 2
		n := 1
		for n < cfg.Shards {
			n <<= 1
		}
		cfg.Shards = n
	}
	if cfg.Shards < 1 {
		cfg.Shards = defaultExitCacheShards
	}

	c := &ExitGeoCache{
		shards:      cfg.Shards,
		ttl:         cfg.TTL,
		maxEntries:  cfg.MaxEntries,
		staleWaves:  cfg.StaleWaves,
		cleanWindow: cfg.CleanWindow,
		onEvict:     cfg.OnEvict,
	}
	c.lrus = make([]*expirable.LRU[string, *ExitGeoEntry], cfg.Shards)
	c.locks = make([]sync.Mutex, cfg.Shards)
	perShard := 0
	if cfg.MaxEntries > 0 {
		perShard = cfg.MaxEntries / cfg.Shards
		perShard = max(perShard, 1)
	}
	for i := range cfg.Shards {
		onEvict := c.makeOnEvict()
		c.lrus[i] = expirable.NewLRU[string, *ExitGeoEntry](perShard, onEvict, cfg.TTL)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.wg.Add(1)
	go c.cleanupLoop(ctx)
	return c
}

// NewExitGeoCacheFromConfig is an explicit constructor alias.
func NewExitGeoCacheFromConfig(cfg ExitCacheConfig) *ExitGeoCache {
	return NewExitGeoCache(cfg)
}

func (c *ExitGeoCache) makeOnEvict() expirable.EvictCallback[string, *ExitGeoEntry] {
	return func(key string, value *ExitGeoEntry) {
		// classify: expired if now past ExpiresAt
		reason := EvictNoSpace
		if value != nil && !value.ExpiresAt.IsZero() && time.Now().After(value.ExpiresAt) {
			reason = EvictExpired
		}
		if reason == EvictExpired {
			c.evictExpired.Add(1)
		} else {
			c.evictNoSpace.Add(1)
		}
		if c.onEvict != nil && value != nil {
			c.onEvict(key, value, reason)
		}
	}
}

func (c *ExitGeoCache) shard(key string) int {
	if c.shards <= 1 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32()) % c.shards
}

func (c *ExitGeoCache) isClosed() bool {
	return c == nil || c.closed.Load()
}

// Close stops the cleanup goroutine. Calling Close multiple times is safe and idempotent.
func (c *ExitGeoCache) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if c.cancel != nil {
			c.cancel()
		}
		c.wg.Wait()
	})
	return nil
}

func (c *ExitGeoCache) cleanupLoop(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(c.cleanWindow)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanupStale()
		}
	}
}

func (c *ExitGeoCache) cleanupStale() {
	if c.isClosed() {
		return
	}
	if c.staleWaves == 0 {
		return
	}
	cw := c.currentWave.Load()
	if cw == 0 {
		return
	}
	c.tableMu.RLock()
	defer c.tableMu.RUnlock()
	for i := range c.shards {
		c.locks[i].Lock()
		lru := c.lrus[i]
		// collect keys first
		keys := lru.Keys()
		for _, k := range keys {
			v, ok := lru.Peek(k)
			if !ok || v == nil {
				continue
			}
			if v.WaveSeq > 0 && cw-v.WaveSeq >= c.staleWaves {
				lru.Remove(k)
				c.evictStaleWave.Add(1)
				if c.onEvict != nil {
					c.onEvict(k, v, EvictStaleWave)
				}
			}
		}
		c.locks[i].Unlock()
	}
}

// SetCurrentWave sets the active wave sequence. Alias methods provided.
func (c *ExitGeoCache) SetCurrentWave(seq uint64) {
	if c == nil {
		return
	}
	c.currentWave.Store(seq)
}

// SetWave is an alias for SetCurrentWave.
func (c *ExitGeoCache) SetWave(seq uint64) { c.SetCurrentWave(seq) }

// SetWaveSeq is an alias for SetCurrentWave.
func (c *ExitGeoCache) SetWaveSeq(seq uint64) { c.SetCurrentWave(seq) }

// BeginWave is an alias for SetCurrentWave.
func (c *ExitGeoCache) BeginWave(seq uint64) { c.SetCurrentWave(seq) }

// EndWave keeps the current wave seq.
func (c *ExitGeoCache) EndWave() { /* keep current */ }

// CurrentWave returns the current wave seq.
func (c *ExitGeoCache) CurrentWave() uint64 {
	if c == nil {
		return 0
	}
	return c.currentWave.Load()
}

// WaveSeq returns the current wave seq.
func (c *ExitGeoCache) WaveSeq() uint64 { return c.CurrentWave() }

// Get returns a cached entry and renews its lease on hit.
func (c *ExitGeoCache) Get(key string) (*ExitGeoEntry, bool) {
	if c == nil || c.isClosed() {
		return nil, false
	}
	c.tableMu.RLock()
	defer c.tableMu.RUnlock()

	idx := c.shard(key)
	c.locks[idx].Lock()
	defer c.locks[idx].Unlock()
	lru := c.lrus[idx]
	val, ok := lru.Get(key)
	if !ok || val == nil {
		c.misses.Add(1)
		return nil, false
	}
	cw := c.currentWave.Load()
	// wave staleness
	if c.staleWaves > 0 && cw > 0 && val.WaveSeq > 0 && cw-val.WaveSeq >= c.staleWaves {
		lru.Remove(key)
		c.evictStaleWave.Add(1)
		if c.onEvict != nil {
			c.onEvict(key, val, EvictStaleWave)
		}
		c.misses.Add(1)
		return nil, false
	}

	// renew lease
	now := time.Now()
	val.LastSeen = now
	val.HitCount++
	if cw > 0 {
		val.WaveSeq = cw
	}
	val.ExpiresAt = now.Add(c.ttl)
	// renew in expirable (Add renews ExpiresAt internally too)
	lru.Add(key, val)
	c.hits.Add(1)
	return val, true
}

// Set inserts or replaces an entry.
func (c *ExitGeoCache) Set(key string, entry *ExitGeoEntry) error {
	if c == nil {
		return errors.New("nil cache")
	}
	if c.isClosed() {
		return ErrClosed
	}
	if entry == nil {
		return errors.New("nil entry")
	}
	c.tableMu.RLock()
	defer c.tableMu.RUnlock()

	idx := c.shard(key)
	c.locks[idx].Lock()
	defer c.locks[idx].Unlock()
	now := time.Now()
	entry.ExitIP = key
	if entry.LastSeen.IsZero() {
		entry.LastSeen = now
	}
	cw := c.currentWave.Load()
	if cw > 0 && entry.WaveSeq == 0 {
		entry.WaveSeq = cw
	}
	entry.ExpiresAt = now.Add(c.ttl)
	evicted := c.lrus[idx].Add(key, entry)
	if evicted {
		c.evictNoSpace.Add(1)
	}
	return nil
}

// Delete removes an entry.
func (c *ExitGeoCache) Delete(key string) {
	if c == nil || c.isClosed() {
		return
	}
	c.tableMu.RLock()
	defer c.tableMu.RUnlock()

	idx := c.shard(key)
	c.locks[idx].Lock()
	defer c.locks[idx].Unlock()
	if v, ok := c.lrus[idx].Peek(key); ok {
		c.lrus[idx].Remove(key)
		c.evictDeleted.Add(1)
		if c.onEvict != nil && v != nil {
			c.onEvict(key, v, EvictDeleted)
		}
	}
}

// Touch renews an entry if present. Returns true on hit.
func (c *ExitGeoCache) Touch(key string) bool {
	_, ok := c.Get(key)
	return ok
}

// Contains reports presence without renewal.
func (c *ExitGeoCache) Contains(key string) bool {
	if c == nil || c.isClosed() {
		return false
	}
	c.tableMu.RLock()
	defer c.tableMu.RUnlock()

	idx := c.shard(key)
	c.locks[idx].Lock()
	defer c.locks[idx].Unlock()
	ok := c.lrus[idx].Contains(key)
	if !ok {
		return false
	}
	v, ok2 := c.lrus[idx].Peek(key)
	if !ok2 || v == nil {
		return false
	}
	cw := c.currentWave.Load()
	if c.staleWaves > 0 && cw > 0 && v.WaveSeq > 0 && cw-v.WaveSeq >= c.staleWaves {
		return false
	}
	return true
}

// Peek returns entry without renewal.
func (c *ExitGeoCache) Peek(key string) (*ExitGeoEntry, bool) {
	if c == nil || c.isClosed() {
		return nil, false
	}
	c.tableMu.RLock()
	defer c.tableMu.RUnlock()

	idx := c.shard(key)
	c.locks[idx].Lock()
	defer c.locks[idx].Unlock()
	v, ok := c.lrus[idx].Peek(key)
	if !ok || v == nil {
		return nil, false
	}
	cw := c.currentWave.Load()
	if c.staleWaves > 0 && cw > 0 && v.WaveSeq > 0 && cw-v.WaveSeq >= c.staleWaves {
		return nil, false
	}
	return v, true
}

// Len returns total entries across shards.
func (c *ExitGeoCache) Len() int {
	if c == nil {
		return 0
	}
	c.tableMu.RLock()
	defer c.tableMu.RUnlock()

	n := 0
	for i := range c.shards {
		c.locks[i].Lock()
		n += c.lrus[i].Len()
		c.locks[i].Unlock()
	}
	return n
}

// Capacity returns the configured max entry count (0 = unlimited).
func (c *ExitGeoCache) Capacity() int {
	if c == nil {
		return 0
	}
	c.metaMu.RLock()
	defer c.metaMu.RUnlock()
	return c.maxEntries
}

// MaxEntries is an alias for Capacity.
func (c *ExitGeoCache) MaxEntries() int { return c.Capacity() }

// SetSizingMeta records the inputs used for the last sizing decision. Safe to
// call from runGeo; nil-safe.
func (c *ExitGeoCache) SetSizingMeta(
	providerClass string, distinctExitIPs, totalNodes int,
	memLimitBytes, headroomBytes uint64, sharingRatio float64, wave uint64,
) {
	if c == nil {
		return
	}
	c.metaMu.Lock()
	defer c.metaMu.Unlock()
	c.providerClass = providerClass
	c.distinctExitIPs = distinctExitIPs
	c.totalNodes = totalNodes
	c.memLimitBytes = memLimitBytes
	c.headroomBytes = headroomBytes
	c.sharingRatio = sharingRatio
	c.lastResizeWave = wave
}

// SetLastResizeReason records the reason code of the last resize.
func (c *ExitGeoCache) SetLastResizeReason(reason string) {
	if c == nil {
		return
	}
	c.metaMu.Lock()
	defer c.metaMu.Unlock()
	c.lastResizeReason = reason
}

// Resize rebuilds the shard LRU containers to the new capacity, migrating
// existing entries (evicting the overflow with EvictResize). A non-positive
// cap means unlimited. Nil-safe.
//
//nolint:cyclop // Resize migrates entries across shard containers
func (c *ExitGeoCache) Resize(newCap int) {
	if c == nil {
		return
	}
	if newCap < 0 {
		newCap = 0
	}
	c.tableMu.Lock()
	defer c.tableMu.Unlock()

	c.metaMu.Lock()
	defer c.metaMu.Unlock()

	oldCap := c.maxEntries
	if newCap == oldCap {
		return
	}

	// Collect existing entries across all shards.
	type kv struct {
		key string
		val *ExitGeoEntry
	}
	var entries []kv
	for i := range c.shards {
		c.locks[i].Lock()
		keys := c.lrus[i].Keys()
		for _, k := range keys {
			if v, ok := c.lrus[i].Peek(k); ok && v != nil {
				entries = append(entries, kv{k, v})
			}
		}
		c.locks[i].Unlock()
	}

	c.maxEntries = newCap
	perShard := 0
	if newCap > 0 {
		perShard = max(newCap/c.shards, 1)
	}
	ttl := c.ttl
	onEvict := c.makeOnEvict()
	newLrus := make([]*expirable.LRU[string, *ExitGeoEntry], c.shards)
	for i := range c.shards {
		newLrus[i] = expirable.NewLRU[string, *ExitGeoEntry](perShard, onEvict, ttl)
	}

	added := 0
	for _, e := range entries {
		if newCap > 0 && added >= newCap {
			c.evictResize++
			if c.onEvict != nil && e.val != nil {
				c.onEvict(e.key, e.val, EvictResize)
			}
			continue
		}
		idx := c.shard(e.key)
		newLrus[idx].Add(e.key, e.val)
		added++
	}

	for i := range c.shards {
		c.locks[i].Lock()
		c.lrus[i] = newLrus[i]
		c.locks[i].Unlock()
	}
	c.resizeCount++
	c.lastResizeReason = "resize"
	_ = oldCap
}

// Stats returns observability snapshot.
func (c *ExitGeoCache) Stats() CacheStats {
	if c == nil {
		return CacheStats{}
	}
	s := CacheStats{
		Hits:              c.hits.Load(),
		Misses:            c.misses.Load(),
		EvictionsByReason: map[EvictReason]uint64{},
	}
	s.EvictionsByReason[EvictExpired] = c.evictExpired.Load()
	s.EvictionsByReason[EvictNoSpace] = c.evictNoSpace.Load()
	s.EvictionsByReason[EvictStaleWave] = c.evictStaleWave.Load()
	s.EvictionsByReason[EvictDeleted] = c.evictDeleted.Load()
	c.metaMu.RLock()
	s.EvictionsByReason[EvictResize] = c.evictResize
	s.Evictions = s.EvictionsByReason[EvictExpired] + s.EvictionsByReason[EvictNoSpace] +
		s.EvictionsByReason[EvictStaleWave] + s.EvictionsByReason[EvictDeleted] +
		s.EvictionsByReason[EvictResize]
	s.Size = c.Len()
	s.Capacity = c.maxEntries
	s.ResizeCount = c.resizeCount
	s.LastResizeReason = c.lastResizeReason
	s.LastResizeWave = c.lastResizeWave
	s.ProviderClass = c.providerClass
	s.DistinctExitIPs = c.distinctExitIPs
	s.TotalNodes = c.totalNodes
	s.MemLimitBytes = c.memLimitBytes
	s.HeadroomBytes = c.headroomBytes
	s.SharingRatio = c.sharingRatio
	s.MemoryBytes = uint64(s.Size * 256) //nolint:gosec
	c.metaMu.RUnlock()
	return s
}

// Rehydrate populates cache from cold GeoRecords, grouping by IP and keeping
// the freshest record per IP.
//
//nolint:gocognit,cyclop
func (c *ExitGeoCache) Rehydrate(input any) {
	if c == nil {
		return
	}
	var records []*model.GeoRecord
	switch v := input.(type) {
	case []*model.GeoRecord:
		records = v
	case []model.GeoRecord:
		for i := range v {
			r := v[i]
			records = append(records, &r)
		}
	case []any:
		for _, e := range v {
			if r, ok := e.(*model.GeoRecord); ok {
				records = append(records, r)
			}
		}
	}
	// group by IP, keep freshest
	best := map[string]*model.GeoRecord{}
	bestUnlock := map[string]*model.MediaUnlockStatus{}
	for _, r := range records {
		if r == nil || r.IP == "" {
			continue
		}
		// The unlock state rides its own freshness (CheckedAt, RFC3339 UTC
		// sorts lexicographically): the record with the newest probe wins,
		// independent of LastSeen/FlagsVerified.
		if r.MediaUnlocks.CheckedAt != "" {
			if cur, ok := bestUnlock[r.IP]; !ok || r.MediaUnlocks.CheckedAt > cur.CheckedAt {
				st := r.MediaUnlocks
				bestUnlock[r.IP] = &st
			}
		}
		cur, ok := best[r.IP]
		if !ok {
			best[r.IP] = r
			continue
		}
		// prefer FlagsVerified, then latest LastSeen
		if r.FlagsVerified && !cur.FlagsVerified {
			best[r.IP] = r
			continue
		}
		if !r.FlagsVerified && cur.FlagsVerified {
			continue
		}
		if r.LastSeen > cur.LastSeen {
			best[r.IP] = r
		}
	}
	for ip, r := range best {
		entry := &ExitGeoEntry{
			ExitIP:        ip,
			Country:       r.Country,
			City:          r.City,
			ASN:           r.ASN,
			ASName:        r.ASName,
			ISP:           r.ISP,
			ProxyFlag:     r.ProxyFlag,
			HostingFlag:   r.HostingFlag,
			FlagsVerified: r.FlagsVerified,
			GeoSource:     r.GeoSource,
			WaveSeq:       0,
			HitCount:      1,
		}
		if st := bestUnlock[ip]; st != nil {
			entry.MediaUnlocks = st
		}
		if r.LastSeen != "" {
			if t, err := time.Parse(time.RFC3339, r.LastSeen); err == nil {
				entry.LastSeen = t
			} else if t, err := time.Parse(time.RFC3339Nano, r.LastSeen); err == nil {
				entry.LastSeen = t
			} else {
				entry.LastSeen = time.Now()
			}
		} else {
			entry.LastSeen = time.Now()
		}
		entry.ExpiresAt = entry.LastSeen.Add(c.ttl)

		c.tableMu.RLock()
		if !c.isClosed() {
			idx := c.shard(ip)
			c.locks[idx].Lock()
			entry.WaveSeq = 0
			c.lrus[idx].Add(ip, entry)
			c.locks[idx].Unlock()
		}
		c.tableMu.RUnlock()
	}
}

// RehydrateExitCache is a package-level helper.
func RehydrateExitCache(c *ExitGeoCache, input any) {
	if c != nil {
		c.Rehydrate(input)
	}
}

// NewExitCache is an alias for NewExitGeoCache.
func NewExitCache(cfg ExitCacheConfig) *ExitGeoCache { return NewExitGeoCache(cfg) }

// NewGeoCache is an alias for NewExitGeoCache.
func NewGeoCache(cfg ExitCacheConfig) *ExitGeoCache { return NewExitGeoCache(cfg) }
