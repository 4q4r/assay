//go:build !linux

package platform

import "os"

// DropFilePageCache is the documented no-op for platforms without an
// fadvise FADV_DONTNEED equivalent (darwin, windows): the store's
// page-cache hint is a linux-only optimization, and its call-site contract
// is best-effort-hint-never-fails — the absence of the syscall is the
// platform fact, not a swallowed error.
func DropFilePageCache(_ *os.File) {}
