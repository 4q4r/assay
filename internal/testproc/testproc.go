// Package testproc is TEST-ONLY infrastructure (the termination-audit P2-2
// containment belt): parent-death containment for the re-exec'd fake-core
// serve children. Every fake serve child sits in a blocking Accept loop
// whose ONLY designed exit is the parent's exact-PID teardown — when the
// parent dies hard (SIGKILL of a wedged test binary, a CI timeout,
// ctrl-C), no defer or t.Cleanup ever runs and the serve child survives
// holding its port band (the stray `checker.test` class). WatchParent arms
// the child-side containment: the serve loop calls it at entry and the
// process exits the moment its parent dies.
//
// This package is deliberately imported ONLY from _test.go files; nothing
// in the daemon depends on it. The per-GOOS parent-liveness primitive
// mirrors the internal/core GOOS-split contract (configureChildSpawn):
// watch_unix.go carries the unix mechanism, watch_windows.go the windows
// one.
package testproc

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// parentPollEvery is the orphan-detection cadence: fast enough that a
// leftover child cannot hold a test-band port through a subsequent run,
// slow enough to be invisible in a serve loop.
const parentPollEvery = 500 * time.Millisecond

var (
	once   sync.Once
	stopFn func()
)

// WatchParent arms parent-death containment for the calling (child)
// process: when the parent process dies, the child exits loudly (code 9,
// with a stderr line naming the containment) instead of serving forever as
// an orphan. Returns the stop func — the serve loops never call it (the
// containment is one-shot per fake-mode process); it exists so the armed
// goroutine is never a mystery to a reader. Calling WatchParent twice in
// one process arms once (the second call returns the same stop).
func WatchParent() func() {
	once.Do(func() {
		parentAtEntry := os.Getppid()
		done := make(chan struct{})
		var closeOnce sync.Once
		stopFn = func() { closeOnce.Do(func() { close(done) }) }
		go func() {
			ticker := time.NewTicker(parentPollEvery)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if !parentAlive(parentAtEntry) {
						_, _ = fmt.Fprintf(os.Stderr,
							"testproc: parent pid %d is gone — orphan fake-serve child exiting "+
								"(parent-death containment, termination-audit P2-2)\n", parentAtEntry)
						os.Exit(9)
					}
				}
			}
		}()
	})
	return stopFn
}
