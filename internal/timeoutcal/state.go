package timeoutcal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var mu sync.Mutex

// path returns the state file path.
func path(dataDir string) string {
	return filepath.Join(dataDir, "timeout-calibration.json")
}

// Load reads the persisted state; a missing file returns the zero state.
func Load(dataDir string) (State, error) {
	mu.Lock()
	defer mu.Unlock()
	return loadLocked(dataDir)
}

func loadLocked(dataDir string) (State, error) {
	b, err := os.ReadFile(path(dataDir))
	if os.IsNotExist(err) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, err
	}
	return st, nil
}

// Save atomically writes the state.
func Save(dataDir string, state State) error {
	mu.Lock()
	defer mu.Unlock()
	return saveLocked(dataDir, state)
}

func saveLocked(dataDir string, state State) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dataDir, "timeout-calibration.json.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(state); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path(dataDir))
}

// Modify atomically loads, mutates, and saves state under mu.
func Modify(dataDir string, fn func(st *State) error) error {
	mu.Lock()
	defer mu.Unlock()
	st, err := loadLocked(dataDir)
	if err != nil {
		return err
	}
	if err := fn(&st); err != nil {
		return err
	}
	return saveLocked(dataDir, st)
}

// Update applies one observation to the persisted state.
func Update(dataDir string, stage string, obs Observation) error {
	return UpdateWithConfig(dataDir, stage, obs, DefaultConfig())
}

// UpdateWithConfig is the configurable variant.
func UpdateWithConfig(dataDir string, stage string, obs Observation, cfg Config) error {
	cfg = cfg.normalize()
	return Modify(dataDir, func(st *State) error {
		ss, err := stageState(st, stage)
		if err != nil {
			return err
		}
		applyObservation(ss, obs, cfg)
		switch stage {
		case "probe":
			st.Probe = *ss
		case "geo":
			st.Geo = *ss
		}
		return nil
	})
}

func stageState(st *State, stage string) (*StageState, error) {
	switch stage {
	case "probe":
		if st.Probe.Regions == nil {
			st.Probe.Regions = map[string]KeyState{}
		}
		if st.Probe.Cities == nil {
			st.Probe.Cities = map[string]KeyState{}
		}
		if st.Probe.Base == 0 {
			st.Probe.Base = 10 * time.Second
		}
		return &st.Probe, nil
	case "geo":
		if st.Geo.Regions == nil {
			st.Geo.Regions = map[string]KeyState{}
		}
		if st.Geo.Cities == nil {
			st.Geo.Cities = map[string]KeyState{}
		}
		if st.Geo.Base == 0 {
			st.Geo.Base = 10 * time.Second
		}
		return &st.Geo, nil
	default:
		return nil, fmt.Errorf("unknown stage %q", stage)
	}
}

func applyObservation(ss *StageState, obs Observation, cfg Config) {
	key := obs.Key
	if key == "" {
		key = "global"
	}
	var local KeyState
	switch {
	case key == "global":
		local = ss.Global
	case stringsContains(key, ":"):
		local = ss.Cities[key]
	default:
		local = ss.Regions[key]
	}
	if local.History == nil {
		local.History = []HistoryEntry{}
	}
	current := local.Current
	if current == 0 {
		current = ss.Base
	}
	newCur := CalibrateWithConfig(cfg, key, obs, current)
	recent := make([]float64, 0, len(local.History))
	for _, h := range local.History {
		recent = append(recent, h.P95Ms)
	}
	recent = append(recent, P95(obs.RTTsMs))
	if len(recent) > cfg.MaxHistory {
		recent = recent[len(recent)-cfg.MaxHistory:]
	}
	k, _ := AdaptiveWindowWithBase(recent, cfg.Alpha)
	local.Current = newCur
	local.EMAP95Ms = P95(obs.RTTsMs)
	local.Rate = 0
	if obs.Total > 0 {
		local.Rate = float64(obs.TimedOut) / float64(obs.Total)
	}
	local.Waves++
	local.HistorySize = k
	local.History = append(local.History, HistoryEntry{At: obs.At, P95Ms: P95(obs.RTTsMs), Rate: local.Rate, N: obs.Total})
	if len(local.History) > k {
		local.History = local.History[len(local.History)-k:]
	}
	switch {
	case key == "global":
		ss.Global = local
	case stringsContains(key, ":"):
		ss.Cities[key] = local
	default:
		ss.Regions[key] = local
	}
}
