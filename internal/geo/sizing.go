package geo

import (
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

// EvictReason is why a cache entry was evicted.
type EvictReason string

const (
	// EvictExpired means TTL elapsed without renewal.
	EvictExpired EvictReason = "expired"
	// EvictNoSpace means size cap exceeded.
	EvictNoSpace EvictReason = "nospace"
	// EvictStaleWave means not seen for too many waves.
	EvictStaleWave EvictReason = "stalewave"
	// EvictDeleted means explicitly deleted.
	EvictDeleted EvictReason = "deleted"
	// EvictResize means evicted during a shrink resize.
	EvictResize EvictReason = "resize"
)

// CapacitySnapshot is the previous-wave capacity state fed to RecomputeCap.
type CapacitySnapshot struct {
	Cap            int
	LastResizeWave uint64
}

// SizingInputs are the live inputs for one wave.
type SizingInputs struct {
	DistinctExitIPs int
	TotalNodes      int
	MemLimitBytes   uint64
	HeapAllocBytes  uint64
	ReserveBytes    uint64
	HardCeiling     int
	CurrentWave     uint64
	ProviderClass   string
}

// MemorySnapshot is the resolved memory state.
type MemorySnapshot struct {
	MemLimitBytes  uint64
	HeapAllocBytes uint64
	HeapSysBytes   uint64
	SysBytes       uint64
}

// CacheStats is the sizing/usage snapshot exposed by the cache.
type CacheStats struct {
	Hits              uint64
	Misses            uint64
	Evictions         uint64
	EvictionsByReason map[EvictReason]uint64
	Size              int
	Capacity          int
	MemoryBytes       uint64
	HitRate           float64
	EvictionRate      float64
	MemoryPressure    float64
	ProviderClass     string
	LastResizeReason  string
	LastResizeWave    uint64
	ResizeCount       uint64
	DistinctExitIPs   int
	TotalNodes        int
	SharingRatio      float64
	MemLimitBytes     uint64
	HeadroomBytes     uint64
}

// SizingEngine computes cache capacity from memory + input + provider class.
type SizingEngine struct {
	PerEntryBytes        int
	MinEntries           int
	MaxEntriesCeiling    int
	GrowThreshold        float64
	ShrinkThreshold      float64
	MemoryPressureGrow   float64
	MemoryPressureShrink float64
	ResizeHysteresis     float64
	GrowthFactorShared   float64
	GrowthFactorMixed    float64
	GrowthFactorDiverse  float64
	ProviderSharedRatio  float64
	ProviderDiverseRatio float64
	MemoryBudgetBytes    uint64
	readMemStats         func(*runtime.MemStats)
	setMemoryLimit       func(int64) int64
}

// NewSizingEngine returns an engine populated with documented defaults.
func NewSizingEngine() *SizingEngine {
	return &SizingEngine{
		PerEntryBytes:        256,
		MinEntries:           256,
		MaxEntriesCeiling:    200000,
		GrowThreshold:        0.70,
		ShrinkThreshold:      0.05,
		MemoryPressureGrow:   0.70,
		MemoryPressureShrink: 0.85,
		ResizeHysteresis:     0.10,
		GrowthFactorShared:   1.0,
		GrowthFactorMixed:    1.2,
		GrowthFactorDiverse:  1.5,
		ProviderSharedRatio:  5.0,
		ProviderDiverseRatio: 2.0,
	}
}

func (e *SizingEngine) perEntryBytes() int {
	if e == nil || e.PerEntryBytes <= 0 {
		return 256
	}
	return e.PerEntryBytes
}

func (e *SizingEngine) minEntries() int {
	if e == nil || e.MinEntries <= 0 {
		return 256
	}
	return e.MinEntries
}

func (e *SizingEngine) maxEntriesCeiling() int {
	if e == nil || e.MaxEntriesCeiling <= 0 {
		return 200000
	}
	return e.MaxEntriesCeiling
}

func (e *SizingEngine) growThreshold() float64 {
	if e == nil || e.GrowThreshold <= 0 {
		return 0.70
	}
	return e.GrowThreshold
}

func (e *SizingEngine) shrinkThreshold() float64 {
	if e == nil {
		return 0.05
	}
	if e.ShrinkThreshold == 0 {
		return 0.05
	}
	return e.ShrinkThreshold
}

func (e *SizingEngine) memoryPressureGrow() float64 {
	if e == nil || e.MemoryPressureGrow <= 0 {
		return 0.70
	}
	return e.MemoryPressureGrow
}

func (e *SizingEngine) memoryPressureShrink() float64 {
	if e == nil || e.MemoryPressureShrink <= 0 {
		return 0.85
	}
	return e.MemoryPressureShrink
}

func (e *SizingEngine) resizeHysteresis() float64 {
	if e == nil {
		return 0.10
	}
	if e.ResizeHysteresis == 0 {
		return 0.10
	}
	return e.ResizeHysteresis
}

func (e *SizingEngine) growthFactorShared() float64 {
	if e == nil || e.GrowthFactorShared <= 0 {
		return 1.0
	}
	return e.GrowthFactorShared
}

func (e *SizingEngine) growthFactorMixed() float64 {
	if e == nil || e.GrowthFactorMixed <= 0 {
		return 1.2
	}
	return e.GrowthFactorMixed
}

func (e *SizingEngine) growthFactorDiverse() float64 {
	if e == nil || e.GrowthFactorDiverse <= 0 {
		return 1.5
	}
	return e.GrowthFactorDiverse
}

func (e *SizingEngine) providerSharedRatio() float64 {
	if e == nil || e.ProviderSharedRatio <= 0 {
		return 5.0
	}
	return e.ProviderSharedRatio
}

func (e *SizingEngine) providerDiverseRatio() float64 {
	if e == nil || e.ProviderDiverseRatio <= 0 {
		return 2.0
	}
	return e.ProviderDiverseRatio
}

// ClassifyProvider infers shared/mixed/diverse from totalNodes/distinctIPs.
func (e *SizingEngine) ClassifyProvider(totalNodes, distinctIPs int) string {
	sharedRatio := e.providerSharedRatio()
	diverseRatio := e.providerDiverseRatio()
	if distinctIPs <= 0 {
		return "mixed"
	}
	ratio := float64(totalNodes) / float64(distinctIPs)
	if ratio >= sharedRatio {
		return "shared"
	}
	if ratio <= diverseRatio {
		return "diverse"
	}
	return "mixed"
}

// ClassifyProvider uses default thresholds.
func ClassifyProvider(totalNodes, distinctIPs int) string {
	return NewSizingEngine().ClassifyProvider(totalNodes, distinctIPs)
}

func (e *SizingEngine) growthFactor(class string) float64 {
	switch class {
	case "shared":
		return e.growthFactorShared()
	case "diverse":
		return e.growthFactorDiverse()
	default:
		return e.growthFactorMixed()
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// RecomputeCap applies the decision ladder and returns (newCap, reason).
//
//nolint:cyclop // decision ladder is inherently branchy
func (e *SizingEngine) RecomputeCap(prev CapacitySnapshot, inputs SizingInputs, metrics CacheStats) (int, string) {
	perEntry := e.perEntryBytes()
	minEntries := e.minEntries()
	maxCeiling := e.maxEntriesCeiling()
	growThresh := e.growThreshold()
	shrinkThresh := e.shrinkThreshold()
	memPressGrow := e.memoryPressureGrow()
	memPressShrink := e.memoryPressureShrink()
	hyst := e.resizeHysteresis()

	reserve := inputs.ReserveBytes
	var headroom uint64
	total := inputs.HeapAllocBytes + reserve
	if inputs.MemLimitBytes >= total {
		headroom = inputs.MemLimitBytes - total
	}
	maxByMemory := int(headroom / uint64(perEntry)) //nolint:gosec
	maxByMemory = clampInt(maxByMemory, minEntries, maxCeiling)
	if inputs.HardCeiling > 0 && inputs.HardCeiling < maxByMemory {
		maxByMemory = inputs.HardCeiling
	}
	if maxByMemory < minEntries {
		maxByMemory = minEntries
	}

	providerClass := inputs.ProviderClass
	if providerClass == "" {
		providerClass = e.ClassifyProvider(inputs.TotalNodes, inputs.DistinctExitIPs)
	}
	gf := e.growthFactor(providerClass)
	minNeeded := int(float64(inputs.DistinctExitIPs) * gf)
	minNeeded = clampInt(minNeeded, minEntries, maxByMemory)

	if maxByMemory < prev.Cap {
		return clampInt(maxByMemory, minEntries, maxByMemory), "memory-ceiling"
	}

	if minNeeded > prev.Cap {
		return clampInt(minNeeded, minEntries, maxByMemory), "input-growth"
	}

	if metrics.HitRate < growThresh &&
		metrics.MemoryPressure < memPressGrow &&
		prev.Cap < int(float64(maxByMemory)*0.9) {
		candidate := min(int(float64(prev.Cap)*1.25), maxByMemory)
		if prev.Cap > 0 && float64(candidate-prev.Cap)/float64(prev.Cap) >= hyst {
			return candidate, "low-hit-rate"
		}
	}

	if metrics.EvictionRate < shrinkThresh &&
		metrics.MemoryPressure < 0.50 &&
		prev.Cap > int(float64(minNeeded)*1.2) {
		candidate := max(int(float64(prev.Cap)*0.85), minNeeded)
		if prev.Cap > 0 && float64(prev.Cap-candidate)/float64(prev.Cap) >= hyst {
			return candidate, "low-eviction"
		}
	}

	if metrics.MemoryPressure > memPressShrink {
		candidate := max(int(float64(prev.Cap)*0.80), minNeeded)
		if prev.Cap > 0 && float64(prev.Cap-candidate)/float64(prev.Cap) >= hyst {
			return candidate, "memory-pressure"
		}
	}

	if inputs.CurrentWave > 0 {
		if prev.LastResizeWave == inputs.CurrentWave-1 ||
			metrics.LastResizeWave == inputs.CurrentWave-1 {
			return prev.Cap, "cooldown"
		}
	}

	return prev.Cap, "hold"
}

// ReuseCap is an alias for RecomputeCap.
func (e *SizingEngine) ReuseCap(prev CapacitySnapshot, inputs SizingInputs, metrics CacheStats) (int, string) {
	return e.RecomputeCap(prev, inputs, metrics)
}

// ComputeCap is an alias for RecomputeCap.
func (e *SizingEngine) ComputeCap(prev CapacitySnapshot, inputs SizingInputs, metrics CacheStats) (int, string) {
	return e.RecomputeCap(prev, inputs, metrics)
}

// Recompute is an alias for RecomputeCap.
func (e *SizingEngine) Recompute(prev CapacitySnapshot, inputs SizingInputs, metrics CacheStats) (int, string) {
	return e.RecomputeCap(prev, inputs, metrics)
}

// RecomputeCap (package-level) uses default engine.
func RecomputeCap(prev CapacitySnapshot, inputs SizingInputs, metrics CacheStats) (int, string) {
	return NewSizingEngine().RecomputeCap(prev, inputs, metrics)
}

// MeasureMemory resolves memory limit via GOMEMLIMIT/cgroup/budget.
func (e *SizingEngine) MeasureMemory() MemorySnapshot {
	var ms runtime.MemStats
	if e != nil && e.readMemStats != nil {
		e.readMemStats(&ms)
	} else {
		runtime.ReadMemStats(&ms)
	}
	var limit int64
	if e != nil && e.setMemoryLimit != nil {
		limit = e.setMemoryLimit(-1)
	} else {
		limit = debug.SetMemoryLimit(-1)
	}
	if limit <= 0 || limit == math.MaxInt64 {
		if cg := readCgroupMemoryLimit(); cg > 0 && cg < (1<<62) {
			limit = int64(cg)
		} else if e != nil && e.MemoryBudgetBytes > 0 {
			limit = int64(e.MemoryBudgetBytes) //nolint:gosec
		} else {
			limit = 512 * 1024 * 1024
		}
	}
	if limit <= 0 {
		limit = 512 * 1024 * 1024
	}
	return MemorySnapshot{
		MemLimitBytes:  uint64(limit),
		HeapAllocBytes: ms.HeapAlloc,
		HeapSysBytes:   ms.HeapSys,
		SysBytes:       ms.Sys,
	}
}

func readCgroupMemoryLimit() uint64 {
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" && s != "max" {
			if v, err := strconv.ParseUint(s, 10, 64); err == nil {
				return v
			}
		}
	}
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		s := strings.TrimSpace(string(data))
		if v, err := strconv.ParseUint(s, 10, 64); err == nil {
			if v < (1 << 62) {
				return v
			}
		}
	}
	return 0
}
