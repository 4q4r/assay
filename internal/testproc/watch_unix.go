//go:build unix

package testproc

import "os"

// parentAlive reports whether the given pid is still this child's parent.
// On unix, orphaning REPARENTS the child (to init, or the nearest
// subreaper): a CHANGED ppid proves the parent died — pure Go, no /proc
// reads, no signals.
func parentAlive(parentAtEntry int) bool {
	return os.Getppid() == parentAtEntry
}
