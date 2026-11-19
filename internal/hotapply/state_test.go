package hotapply

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStateRoundTripAndPIDStability pins the state mirror's write/read
// contract: the derived fields are stamped at WRITE time (PIDStable from
// the observed pids, UpdatedAt from the clock), a round trip preserves the
// recorded facts, and a reader cannot confuse a hot apply with a restart.
func TestStateRoundTripAndPIDStability(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, WriteState(dir, &State{Mode: ModeHot, PIDBefore: 4242, PIDAfter: 4242}))
	st, err := ReadState(dir)
	require.NoError(t, err)
	assert.Equal(t, ModeHot, st.Mode)
	assert.Equal(t, 4242, st.PIDBefore)
	assert.Equal(t, 4242, st.PIDAfter)
	assert.True(t, st.PIDStable, "equal observed pids are stable")
	assert.NotEmpty(t, st.UpdatedAt, "the write stamps the clock")

	// The same file name is reused: the LAST activation overwrites the
	// mirror (the status block shows what happened LAST).
	require.NoError(t, WriteState(dir, &State{Mode: ModeRestart, PIDBefore: 4242, PIDAfter: 5252}))
	st, err = ReadState(dir)
	require.NoError(t, err)
	assert.Equal(t, ModeRestart, st.Mode)
	assert.False(t, st.PIDStable, "a pid transition is not stable")

	// A first activation has no pidfile on the before-side: pid 0 reads
	// honestly as NOT stable (never a fabricated stability claim).
	require.NoError(t, WriteState(dir, &State{Mode: ModeRestart, PIDBefore: 0, PIDAfter: 5252}))
	st, err = ReadState(dir)
	require.NoError(t, err)
	assert.False(t, st.PIDStable, "no observed before-pid is not stable")
}

// TestStateRefusesUnknownMode pins the write-side validation: an unknown
// mode is refused loud and writes nothing (a hand-built caller cannot
// poison the mirror with a mode the status block would render as data).
func TestStateRefusesUnknownMode(t *testing.T) {
	dir := t.TempDir()
	err := WriteState(dir, &State{Mode: "sneaky", PIDBefore: 1, PIDAfter: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown apply mode")

	_, readErr := ReadState(dir)
	require.ErrorIs(t, readErr, os.ErrNotExist,
		"the refused write left no state file behind")
}

// TestReadStateContract pins the read-side honesty: a missing file is the
// never-activated state (os.ErrNotExist preserved for the caller's no-line
// decision); a corrupt file is an error carrying the path, never a
// half-parsed State.
func TestReadStateContract(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadState(dir)
	require.ErrorIs(t, err, os.ErrNotExist, "a missing file is os.ErrNotExist")

	corrupt := filepath.Join(dir, StateFileName)
	require.NoError(t, os.WriteFile(corrupt, []byte("{not json"), 0o600))
	_, err = ReadState(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), StateFileName, "the corrupt-file error names the path")
}
