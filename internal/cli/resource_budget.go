package cli

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"time"

	"assay/internal/config"
)

// WaveBudgetInfo captures the wave-start resource budget: the effective
// concurrency is the minimum of the RAM, CPU and port budgets (the scarcest
// resource wins).
type WaveBudgetInfo struct {
	RAMBudget   int `json:"ram_budget"`
	CPUBudget   int `json:"cpu_budget"`
	PortBudget  int `json:"port_budget"`
	Concurrency int `json:"concurrency"`
}

// WaveBudget is the scalar convenience form of ComputeWaveBudget.
func WaveBudget(ramBudget, cpuBudget, portBudget int) int {
	return ComputeWaveBudget(ramBudget, cpuBudget, portBudget)
}

// ComputeWaveBudget returns min(ramBudget, cpuBudget, portBudget), never
// below 1.
func ComputeWaveBudget(ramBudget, cpuBudget, portBudget int) int {
	return minInt(ramBudget, cpuBudget, portBudget)
}

// MinBudget is an alias for ComputeWaveBudget.
func MinBudget(ramBudget, cpuBudget, portBudget int) int {
	return ComputeWaveBudget(ramBudget, cpuBudget, portBudget)
}

// MinWaveBudget is an alias for ComputeWaveBudget.
func MinWaveBudget(ramBudget, cpuBudget, portBudget int) int {
	return ComputeWaveBudget(ramBudget, cpuBudget, portBudget)
}

// ComputeWaveBudgetFromConfig derives the RAM/CPU budgets from the config's
// ResourceConfig (auto-detecting when unset) and combines them with the
// supplied port budget. perInstanceRAMMB is the estimated RAM cost of one
// concurrent temp instance; if <=0 a default of 64 MB is used.
func ComputeWaveBudgetFromConfig(cfg *config.Config, portBudget int, perInstanceRAMMB int) WaveBudgetInfo {
	if cfg == nil {
		return WaveBudgetInfo{Concurrency: 1}
	}
	if perInstanceRAMMB <= 0 {
		perInstanceRAMMB = 64
	}
	usableRAM := cfg.Resources.UsableRAMMB()
	ramBudget := usableRAM / perInstanceRAMMB
	ramBudget = max(ramBudget, 1)
	cpuBudget := cfg.Resources.EffectiveCPUCores()
	cpuBudget = max(cpuBudget, 1)
	portBudget = max(portBudget, 1)
	conc := ComputeWaveBudget(ramBudget, cpuBudget, portBudget)
	conc = max(conc, 1)
	return WaveBudgetInfo{
		RAMBudget:   ramBudget,
		CPUBudget:   cpuBudget,
		PortBudget:  portBudget,
		Concurrency: conc,
	}
}

// WaveBudgetForConfig is an alias for ComputeWaveBudgetFromConfig.
func WaveBudgetForConfig(cfg *config.Config, portBudget int, perInstanceRAMMB int) WaveBudgetInfo {
	return ComputeWaveBudgetFromConfig(cfg, portBudget, perInstanceRAMMB)
}

// ComputeConcurrencyBudget is the scalar convenience wrapper.
func ComputeConcurrencyBudget(cfg *config.Config, portBudget int) int {
	wb := ComputeWaveBudgetFromConfig(cfg, portBudget, 64)
	return wb.Concurrency
}

// ResourceBudget is a scalar budget derived from config alone (port budget
// defaults to the CPU budget so RAM/CPU remain the binding constraints).
func ResourceBudget(cfg *config.Config) int {
	if cfg == nil {
		return 1
	}
	return ComputeConcurrencyBudget(cfg, cfg.Resources.EffectiveCPUCores())
}

// MemoryPressure reports whether memory usage exceeds the 85% threshold.
func MemoryPressure(memUsedPct float64) bool {
	return memUsedPct > 85.0
}

// StageStat is one persisted per-stage cost record for inter-wave EMA.
type StageStat struct {
	Stage       string    `json:"stage"`
	CostMs      int64     `json:"cost_ms"`
	Concurrency int       `json:"concurrency"`
	Wave        int       `json:"wave"`
	At          time.Time `json:"at"`
}

// StageStatsPath returns the stage-stats.jsonl path under dataDir.
func StageStatsPath(dataDir string) string {
	return filepath.Join(dataDir, "stage-stats.jsonl")
}

// RecordStageCost is an alias for RecordStageStat.
func RecordStageCost(dataDir string, stat StageStat) error {
	return RecordStageStat(dataDir, stat)
}

// PersistStageStat is an alias for RecordStageStat.
func PersistStageStat(dataDir string, stat StageStat) error {
	return RecordStageStat(dataDir, stat)
}

// RecordStageStat appends one StageStat to stage-stats.jsonl.
func RecordStageStat(dataDir string, stat StageStat) error {
	if stat.At.IsZero() {
		stat.At = time.Now().UTC()
	}
	f, err := os.OpenFile(StageStatsPath(dataDir), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	return enc.Encode(stat)
}

// ReadStageStats reads all StageStat records from stage-stats.jsonl.
func ReadStageStats(dataDir string) ([]StageStat, error) {
	f, err := os.Open(StageStatsPath(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []StageStat
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var st StageStat
		if err := json.Unmarshal(line, &st); err != nil {
			continue
		}
		out = append(out, st)
	}
	return out, sc.Err()
}

// InterWaveEMA is an alias for AdjustBaseConcurrency.
func InterWaveEMA(base int, stats []StageStat) int {
	return AdjustBaseConcurrency(base, stats)
}

// InterWaveAdapt is an alias for AdjustBaseConcurrency.
func InterWaveAdapt(base int, stats []StageStat) int {
	return AdjustBaseConcurrency(base, stats)
}

// AdjustBaseConcurrency adjusts the base concurrency for the next wave using
// the most recent stage stats. High cost -> reduce 25%; low cost -> increase.
func AdjustBaseConcurrency(base int, stats []StageStat) int {
	base = max(base, 1)
	if len(stats) == 0 {
		return base
	}
	last := stats[len(stats)-1]
	if last.CostMs > 5000 {
		return max(int(math.Floor(float64(base)*0.75)), 1)
	}
	if last.CostMs > 0 && last.CostMs < 1000 {
		return max(int(math.Ceil(float64(base)*1.25)), base+1)
	}
	return base
}

// EMAConcurrency smooths base concurrency toward observed via EMA.
func EMAConcurrency(base, observed int, alpha float64) int {
	if alpha <= 0 {
		alpha = 0.3
	}
	v := (1-alpha)*float64(base) + alpha*float64(observed)
	n := int(math.Round(v))
	n = max(n, 1)
	return n
}

func minInt(a, b, c int) int {
	return min(a, b, c)
}
