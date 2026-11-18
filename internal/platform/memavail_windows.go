//go:build windows

package platform

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// memoryStatusEx mirrors Win32 MEMORYSTATUSEX (fixed ABI layout, winnls.h):
// dwLength must carry the structure size the API validates; ullAvailPhys is
// the bytes of physical memory available to the system right now. x/sys/
// windows does not export the call as of v0.50.0, so the kernel32 proc is
// reached through the documented NewLazySystemDLL path — the same pattern
// x/sys itself uses for calls it does not wrap.
type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

// kernel32GlobalMemoryStatusEx resolves lazily; resolution failure surfaces
// as the returned error (loud), never a panic.
var kernel32GlobalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

// MemAvailable returns GlobalMemoryStatusEx's ullAvailPhys — the bytes of
// physical memory windows reports as available. UNITS: the API reports
// BYTES directly (no scaling — DWORDLONG byte counts). HONEST BOUNDS:
// windows has no linux-style kernel estimate that includes reclaimable
// caches; ullAvailPhys is the OS's own "available physical memory" figure
// (free plus standby-list semantics as windows accounts them) — the
// platform-native truth this gate compares against the floor on windows.
// A failed call is a loud error — the gate fail-opens on read errors, and a
// silent zero would hold every wave forever.
func MemAvailable() (uint64, error) {
	var st memoryStatusEx
	st.length = uint32(unsafe.Sizeof(st))
	r1, _, callErr := kernel32GlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&st)))
	if r1 == 0 {
		if callErr != nil {
			return 0, fmt.Errorf("GlobalMemoryStatusEx: %w", callErr)
		}
		return 0, fmt.Errorf("GlobalMemoryStatusEx: call failed")
	}
	return st.availPhys, nil
}
