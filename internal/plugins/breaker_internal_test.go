package plugins

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Round-7 item 6 — the plugin circuit breaker state machine, owned by the
// registry (the one structure both one-shot waves and the watch daemon
// share; the daemon's registry persists across waves, a one-shot run gets
// a fresh one). Consecutive FAILURE events per plugin; reset on a
// successful run or a file reload (Set = owner touched the file = fresh
// chance); on hitting the limit the plugin is AUTO-DISABLED and excluded
// from subsequent wave snapshots.

func newBreakerPlugin(id string) *Plugin {
	return &Plugin{ID: id, Path: id + ".lua", Code: []byte(`return function() return {} end`)}
}

func TestBreakerDisablesAtLimit(t *testing.T) {
	reg := NewRegistry()
	reg.Set(newBreakerPlugin("flaky"))

	for range 4 {
		disabled := reg.RecordFailure("flaky", 5)
		assert.False(t, disabled, "below the limit: still enabled")
	}
	disabled := reg.RecordFailure("flaky", 5)
	require.True(t, disabled, "the 5th consecutive failure must trip the breaker")
	assert.Contains(t, reg.DisabledPlugins(), "flaky")

	// Disabled plugins are excluded from subsequent wave snapshots.
	for _, p := range reg.Snapshot() {
		assert.NotEqual(t, "flaky", p.ID, "a disabled plugin must not appear in wave snapshots")
	}
}

func TestBreakerSuccessResetsCount(t *testing.T) {
	reg := NewRegistry()
	reg.Set(newBreakerPlugin("wobbly"))

	for range 4 {
		reg.RecordFailure("wobbly", 5)
	}
	require.Equal(t, 4, reg.FailureCount("wobbly"))

	reg.RecordSuccess("wobbly") // a healthy run: fresh slate
	require.Equal(t, 0, reg.FailureCount("wobbly"), "a successful run must reset the counter")

	// The reset is observable: WITHOUT it, the very first post-success
	// failure would reach the tripping count (4+1) and disable. With it,
	// four fresh failures stay below the limit...
	for range 4 {
		disabled := reg.RecordFailure("wobbly", 5)
		assert.False(t, disabled, "post-reset failures start from zero")
	}
	assert.Empty(t, reg.DisabledPlugins())
	// ...and the NEXT consecutive failure is the one that trips.
	assert.True(t, reg.RecordFailure("wobbly", 5),
		"the 5th consecutive failure AFTER the reset trips the breaker")
}

func TestBreakerReloadResetsAndReenables(t *testing.T) {
	reg := NewRegistry()
	reg.Set(newBreakerPlugin("edited"))
	for range 5 {
		reg.RecordFailure("edited", 5)
	}
	require.Contains(t, reg.DisabledPlugins(), "edited")

	// The watchdog reload path: owner touched the file, Compile succeeded,
	// Set upserts — fresh chance, disabled state and counter cleared.
	reg.Set(newBreakerPlugin("edited"))
	assert.Empty(t, reg.DisabledPlugins(), "a file reload re-enables the plugin")
	assert.Equal(t, 0, reg.FailureCount("edited"), "a file reload resets the counter")

	found := false
	for _, p := range reg.Snapshot() {
		if p.ID == "edited" {
			found = true
		}
	}
	assert.True(t, found, "the re-enabled plugin is back in wave snapshots")
}

func TestBreakerUnlimitedNeverDisables(t *testing.T) {
	reg := NewRegistry()
	reg.Set(newBreakerPlugin("steadfast"))

	for range 25 {
		disabled := reg.RecordFailure("steadfast", 0) // 0 = unlimited (breaker off)
		assert.False(t, disabled, "unlimited mode must never disable")
	}
	found := false
	for _, p := range reg.Snapshot() {
		if p.ID == "steadfast" {
			found = true
		}
	}
	assert.True(t, found, "the plugin stays in snapshots under the unlimited breaker")
	assert.Equal(t, 25, reg.FailureCount("steadfast"),
		"the counter still accumulates for observability under the unlimited breaker")
}

func TestBreakerRemoveClearsState(t *testing.T) {
	reg := NewRegistry()
	reg.Set(newBreakerPlugin("gone"))
	for range 5 {
		reg.RecordFailure("gone", 5)
	}
	require.Contains(t, reg.DisabledPlugins(), "gone")

	reg.Remove("gone")
	assert.Empty(t, reg.DisabledPlugins(), "removal clears the breaker state")
}

func TestBreakerDisabledSnapshotStaysDeterministic(t *testing.T) {
	reg := NewRegistry()
	reg.Set(newBreakerPlugin("b"))
	reg.Set(newBreakerPlugin("a"))
	for range 5 {
		reg.RecordFailure("a", 5)
	}
	ids := make([]string, 0, reg.Len())
	for _, p := range reg.Snapshot() {
		ids = append(ids, p.ID)
	}
	assert.Equal(t, []string{"b"}, ids, "snapshot stays id-sorted minus disabled plugins")
}
