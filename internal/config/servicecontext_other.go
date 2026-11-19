//go:build !windows

package config

// detectWindowsServiceContext is trivially false off windows: the guard is
// windows-only by construction (svc.IsWindowsService() has no meaning on
// linux/darwin, whose service contexts carry their own supervision and are
// not this landmine's scope). Interactive and service behavior are
// byte-identical there.
func detectWindowsServiceContext() bool { return false }
