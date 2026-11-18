//go:build linux

package platform

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseMemAvailable pins the /proc/meminfo MemAvailable grammar: the
// "MemAvailable:" line's kB value × 1024 = bytes. Every other line is noise
// (MemFree/MemTotal/Cached and friends); a missing or unparseable
// MemAvailable line is a loud error — the gate fail-opens on it, and a
// silent zero would hold every wave forever.
func TestParseMemAvailable(t *testing.T) {
	const fixture = `MemTotal:       16308416 kB
MemFree:         2100308 kB
MemAvailable:    6123456 kB
Buffers:          312004 kB
Cached:          6998172 kB
SwapTotal:       2097148 kB
SwapFree:         707384 kB
`
	got, err := parseMemAvailable(fixture)
	require.NoError(t, err)
	require.Equal(t, uint64(6123456)*1024, got, "MemAvailable kB must scale to bytes")
}

func TestParseMemAvailableErrors(t *testing.T) {
	t.Run("missing line", func(t *testing.T) {
		_, err := parseMemAvailable("MemTotal: 100 kB\nMemFree: 50 kB\n")
		require.Error(t, err)
		require.Contains(t, err.Error(), "MemAvailable", "error must name the field")
	})
	t.Run("garbage value", func(t *testing.T) {
		_, err := parseMemAvailable("MemAvailable:    banana kB\n")
		require.Error(t, err)
	})
	t.Run("empty", func(t *testing.T) {
		_, err := parseMemAvailable("")
		require.Error(t, err)
	})
}

// TestMemAvailableLiveSmoke runs the real /proc read once on linux: the
// value must be non-zero (the kernel always reports one) and the error path
// is exercised by the unit fixtures above.
func TestMemAvailableLiveSmoke(t *testing.T) {
	v, err := MemAvailable()
	require.NoError(t, err)
	require.Positive(t, v)
}
