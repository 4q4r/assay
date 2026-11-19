package hotapply

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"assay/internal/store"
)

// StateFileName is the hot-apply state file inside the data dir — the
// honest "what did the last activation do" mirror the status core block
// consumes (the T5 supervision parity: a hot activation and a restart are
// both recorded, with the pid transition as the observable proof).
const StateFileName = "hotapply-state.json"

// Apply-mode values for State.Mode.
const (
	// ModeHot: the routing section was hot-applied through the running
	// core's API — the core pid survived the activation.
	ModeHot = "hot"
	// ModeRestart: the full activate path ran — the core was stopped and
	// spawned on the replaced config.
	ModeRestart = "restart"
)

// State is the persisted hot-apply mirror: the mode of the LAST activation
// and the core pid across it. PIDStable is DERIVED at write time
// (PIDBefore > 0 && PIDBefore == PIDAfter — a hot apply observes both pids
// from the pidfile, never presumes), so a reader cannot mistake a
// hand-edited file for an observation.
type State struct {
	Mode      string `json:"mode"`
	PIDBefore int    `json:"pid_before"`
	PIDAfter  int    `json:"pid_after"`
	PIDStable bool   `json:"pid_stable"`
	UpdatedAt string `json:"updated_at"` // RFC3339, UTC
}

// WriteState persists the state atomically (0600 — the store's state-file
// discipline). The derived fields are stamped here: one definition, so a
// call site can never record a stability claim it did not observe.
func WriteState(dataDir string, st *State) error {
	if st.Mode != ModeHot && st.Mode != ModeRestart {
		return fmt.Errorf("hotapply: unknown apply mode %q — state not written", st.Mode)
	}
	st.PIDStable = st.PIDBefore > 0 && st.PIDBefore == st.PIDAfter
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return store.WriteFileAtomic(filepath.Join(dataDir, StateFileName), func(f *os.File) error {
		return json.NewEncoder(f).Encode(st)
	})
}

// ReadState reads the persisted state for the status core block. A missing
// file is the never-activated state (os.ErrNotExist preserved for the
// caller's no-line decision); a corrupt one is an error — the status block
// degrades loud, never fabricates.
func ReadState(dataDir string) (*State, error) {
	path := filepath.Join(dataDir, StateFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &st, nil
}
