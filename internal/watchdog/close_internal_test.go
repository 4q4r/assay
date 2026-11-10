package watchdog

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWatchdogCloseIsIdempotent pins the round-7 hardening: Close is
// single-shot in spirit but MUST be safe to call twice (double-Close must
// not panic on close-of-closed-channel, and the second call must not
// double-stop the watcher). Pre-fix, a second Close panicked on
// `close(w.stop)`.
func TestWatchdogCloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	_, w, err := start(dir, io.Discard, debounce)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second close must be a no-op, got: %v", err)
	}
}

// TestWatchdogReloadRechecksClosedAfterLock pins the mid-reload window the
// callback-body gate misses: a debounce callback that fired just before
// Close and already passed its own closed check can still be about to run
// reload when Close returns. The guard lives INSIDE reload: it re-checks
// the closed flag after acquiring the mutex, so a reload entered after
// Close's critical section mutates nothing. White-box, deterministic: the
// exact post-Close state is set by hand and reload is invoked directly.
func TestWatchdogReloadRechecksClosedAfterLock(t *testing.T) {
	dir := t.TempDir()
	log := &syncBuffer{}
	reg, w := startAt(t, dir, log)
	path := filepath.Join(dir, "midflight.lua")
	body := `return function() return { assay.node{ raw = "vless://m@h:1" } } end`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Post-Close state (Close already ran): closed armed under the mutex.
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()

	w.reload(path) // the mid-reload callback shape: must be a no-op now

	if _, ok := reg.Get("midflight"); ok {
		t.Fatalf("reload mutated the registry after Close — the reload-internal gate is missing; log: %q", log.String())
	}
	if strings.Contains(log.String(), "plugin midflight loaded") {
		t.Fatalf("reload ran after Close: %q", log.String())
	}
}
