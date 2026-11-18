//go:build windows

package platform

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// TestMemAvailableLiveSmoke runs the real GlobalMemoryStatusEx call once on
// windows: a healthy host always reports a non-zero available-physical
// figure, and the struct size the API validates is the fixed Win32 ABI size
// (64 bytes — pinned here so a struct drift fails loud on the platform that
// runs the call, not at render time on linux).
func TestMemAvailableLiveSmoke(t *testing.T) {
	require.Equal(t, uint64(64), uint64(unsafe.Sizeof(memoryStatusEx{})))
	v, err := MemAvailable()
	require.NoError(t, err)
	require.Positive(t, v)
}
