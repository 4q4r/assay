package geo_test

import (
	"testing"

	"public_vpn/internal/geo"
)

func TestClassifyProvider(t *testing.T) {
	e := geo.NewSizingEngine()
	e.MinEntries = 1
	if e.ClassifyProvider(100, 10) != "shared" {
		t.Fatal("shared")
	}
	if e.ClassifyProvider(15, 10) != "diverse" {
		t.Fatal("diverse")
	}
	if e.ClassifyProvider(35, 10) != "mixed" {
		t.Fatal("mixed")
	}
}

func TestInputGrowth(t *testing.T) {
	e := geo.NewSizingEngine()
	e.MinEntries = 1
	in := geo.SizingInputs{DistinctExitIPs: 100, TotalNodes: 150, MemLimitBytes: 1 << 30, CurrentWave: 1}
	prev := geo.CapacitySnapshot{Cap: 50}
	m, r := e.RecomputeCap(prev, in, geo.CacheStats{HitRate: 0.9, MemoryPressure: 0.3})
	if r != "input-growth" || m != 150 {
		t.Fatalf("%d %s", m, r)
	}
}

func TestMemoryCeiling(t *testing.T) {
	e := geo.NewSizingEngine()
	e.MinEntries = 1
	in := geo.SizingInputs{DistinctExitIPs: 10, TotalNodes: 10, MemLimitBytes: 10 * 256, CurrentWave: 1}
	prev := geo.CapacitySnapshot{Cap: 1000}
	_, r := e.RecomputeCap(prev, in, geo.CacheStats{HitRate: 0.9, MemoryPressure: 0.3})
	if r != "memory-ceiling" {
		t.Fatalf("%s", r)
	}
}

func TestLowHitRate(t *testing.T) {
	e := geo.NewSizingEngine()
	e.MinEntries = 1
	in := geo.SizingInputs{DistinctExitIPs: 100, TotalNodes: 300, MemLimitBytes: 100 << 20, CurrentWave: 1}
	prev := geo.CapacitySnapshot{Cap: 120}
	m, r := e.RecomputeCap(prev, in, geo.CacheStats{HitRate: 0.5, MemoryPressure: 0.4})
	if r != "low-hit-rate" || m != 150 {
		t.Fatalf("%d %s", m, r)
	}
}

func TestLowEviction(t *testing.T) {
	e := geo.NewSizingEngine()
	e.MinEntries = 1
	in := geo.SizingInputs{DistinctExitIPs: 10, TotalNodes: 30, MemLimitBytes: 100 << 20, CurrentWave: 1}
	prev := geo.CapacitySnapshot{Cap: 100}
	m, r := e.RecomputeCap(prev, in, geo.CacheStats{HitRate: 0.9, EvictionRate: 0.01, MemoryPressure: 0.3})
	if r != "low-eviction" || m != 85 {
		t.Fatalf("%d %s", m, r)
	}
}

func TestMemoryPressure(t *testing.T) {
	e := geo.NewSizingEngine()
	e.MinEntries = 1
	in := geo.SizingInputs{DistinctExitIPs: 10, TotalNodes: 30, MemLimitBytes: 100 << 20, CurrentWave: 1}
	prev := geo.CapacitySnapshot{Cap: 100}
	m, r := e.RecomputeCap(prev, in, geo.CacheStats{HitRate: 0.9, EvictionRate: 0.5, MemoryPressure: 0.9})
	if r != "memory-pressure" || m != 80 {
		t.Fatalf("%d %s", m, r)
	}
}

func TestCooldown(t *testing.T) {
	e := geo.NewSizingEngine()
	e.MinEntries = 1
	in := geo.SizingInputs{DistinctExitIPs: 10, TotalNodes: 30, MemLimitBytes: 100 << 20, CurrentWave: 5}
	prev := geo.CapacitySnapshot{Cap: 100, LastResizeWave: 4}
	_, r := e.RecomputeCap(prev, in, geo.CacheStats{HitRate: 0.9, EvictionRate: 0.5, MemoryPressure: 0.4})
	if r != "cooldown" {
		t.Fatalf("%s", r)
	}
}

func TestHold(t *testing.T) {
	e := geo.NewSizingEngine()
	e.MinEntries = 1
	in := geo.SizingInputs{DistinctExitIPs: 10, TotalNodes: 30, MemLimitBytes: 100 << 20, CurrentWave: 5}
	prev := geo.CapacitySnapshot{Cap: 100}
	m, r := e.RecomputeCap(prev, in, geo.CacheStats{HitRate: 0.9, EvictionRate: 0.5, MemoryPressure: 0.4})
	if r != "hold" || m != 100 {
		t.Fatalf("%d %s", m, r)
	}
}

func TestHysteresis(t *testing.T) {
	e := geo.NewSizingEngine()
	e.MinEntries = 1
	e.ResizeHysteresis = 0.50
	in := geo.SizingInputs{DistinctExitIPs: 10, TotalNodes: 30, MemLimitBytes: 100 << 20, CurrentWave: 5}
	prev := geo.CapacitySnapshot{Cap: 100}
	_, r := e.RecomputeCap(prev, in, geo.CacheStats{HitRate: 0.9, EvictionRate: 0.5, MemoryPressure: 0.4})
	if r != "hold" {
		t.Fatalf("%s", r)
	}
}

func TestMeasureMemory(t *testing.T) {
	e := geo.NewSizingEngine()
	e.MinEntries = 1
	s := e.MeasureMemory()
	if s.MemLimitBytes == 0 {
		t.Fatal("zero")
	}
}
