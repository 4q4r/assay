//go:build linux

package platform

import (
	"os"

	"golang.org/x/sys/unix"
)

// DropFilePageCache best-effort advises the kernel to drop f's pages from
// the page cache (linux fadvise FADV_DONTNEED — the pre-S0 store.go
// mechanics, byte-identical). Errors are swallowed BY CONTRACT: the hint
// never blocks or fails a write path. darwin/windows have no equivalent
// and get the documented no-op in dropcache_other.go.
func DropFilePageCache(f *os.File) {
	fi, err := f.Stat()
	if err != nil {
		return
	}
	_ = unix.Fadvise(int(f.Fd()), 0, fi.Size(), unix.FADV_DONTNEED)
}
