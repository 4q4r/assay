//go:build !linux && !darwin && !windows

package platform

import "errors"

// errMemAvailableUnsupported names the platform fact: the release matrix is
// linux/darwin/windows and no other GOOS carries a host-memory-availability
// reader. The memory gate treats this error as its documented fail-open
// trigger (read failure → proceed ungated, loud), so an exotic platform
// degrades to the pre-gate behavior honestly instead of holding waves on a
// signal it cannot read.
var errMemAvailableUnsupported = errors.New(
	"host memory availability is not implemented on this platform (release matrix: linux, darwin, windows)")

// MemAvailable is the documented unsupported-platform stub.
func MemAvailable() (uint64, error) {
	return 0, errMemAvailableUnsupported
}
