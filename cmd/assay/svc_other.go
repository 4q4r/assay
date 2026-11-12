//go:build !windows

package main

// serviceEntrypoint is the per-GOOS service gate (plan §2.2.1): on
// non-windows builds there is no service machinery at all — the process is
// the plain CLI (handled=false falls through to cobra).
func serviceEntrypoint() (bool, int) {
	return false, 0
}
