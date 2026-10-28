package watchdog

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"public_vpn/internal/plugins"
)

const debounce = 30 * time.Millisecond

func startTest(t *testing.T) (string, *plugins.Registry) {
	t.Helper()
	dir := t.TempDir()
	reg, w, err := start(dir, io.Discard, debounce)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return dir, reg
}

func startAt(t *testing.T, dir string, log io.Writer) (*plugins.Registry, *Watchdog) {
	t.Helper()
	reg, w, err := start(dir, log, debounce)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return reg, w
}

// syncBuffer is a goroutine-safe log sink: the watchdog goroutine writes it
// while the test goroutine reads.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestWatchdogHotAdd(t *testing.T) {
	dir, reg := startTest(t)
	path := filepath.Join(dir, "new.lua")
	if err := os.WriteFile(path, []byte(`return function()
		return { publicvpn.node{ raw = "vless://a@h:1" } }
	end`), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "hot-added plugin", func() bool {
		p, ok := reg.Get("new")
		return ok && p != nil
	})
}

func TestWatchdogHotModifySwap(t *testing.T) {
	dir, reg := startTest(t)
	path := filepath.Join(dir, "swap.lua")
	body := `return function() return {} end`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "initial load", func() bool {
		_, ok := reg.Get("swap")
		return ok
	})
	body = `return function() return { publicvpn.node{ raw = "vless://b@h:2" } } end`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "swapped version", func() bool {
		p, ok := reg.Get("swap")
		return ok && strings.Contains(string(p.Code), "vless://b@h:2")
	})
}

func TestWatchdogBrokenKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	log := &syncBuffer{}
	reg, _ := startAt(t, dir, log)
	path := filepath.Join(dir, "good.lua")
	good := `return function() return { publicvpn.node{ raw = "vless://g@h:1" } } end`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "good version loaded", func() bool {
		_, ok := reg.Get("good")
		return ok
	})

	if err := os.WriteFile(path, []byte(`return function( broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	brokenSeen := false
	for time.Now().Before(deadline) {
		if strings.Contains(log.String(), "plugin good reload FAILED") {
			brokenSeen = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !brokenSeen {
		t.Fatalf("no loud reload failure logged; log: %q", log.String())
	}
	p, ok := reg.Get("good")
	if !ok || !strings.Contains(string(p.Code), "vless://g@h:1") {
		t.Fatalf("last-good version lost after broken reload: %+v", p)
	}
}

func TestWatchdogRemoveDisables(t *testing.T) {
	dir, reg := startTest(t)
	path := filepath.Join(dir, "gone.lua")
	if err := os.WriteFile(path, []byte(`return function() end`), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "plugin loaded", func() bool {
		_, ok := reg.Get("gone")
		return ok
	})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "plugin disabled by removal", func() bool {
		_, ok := reg.Get("gone")
		return !ok
	})
}

func TestWatchdogVanishViaRename(t *testing.T) {
	dir, reg := startTest(t)
	path := filepath.Join(dir, "moved.lua")
	if err := os.WriteFile(path, []byte(`return function() end`), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "plugin loaded", func() bool {
		_, ok := reg.Get("moved")
		return ok
	})
	if err := os.Rename(path, path+".off"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "plugin disabled by rename", func() bool {
		_, ok := reg.Get("moved")
		return !ok
	})
	_ = os.Remove(path + ".off")
}

func TestWatchdogNonLuaIgnored(t *testing.T) {
	dir, reg := startTest(t)
	for _, name := range []string{"notes.txt", "sub", "x.swp"} {
		full := filepath.Join(dir, name)
		if name == "sub" {
			if err := os.MkdirAll(full, 0o750); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(full, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(3 * debounce)
	if reg.Len() != 0 {
		t.Fatalf("non-lua entries must be ignored, registry: %d", reg.Len())
	}
}

// TestWatchdogNoReloadAfterClose pins the N-2 fix: a debounced AfterFunc
// callback that fires around Close must check the closed flag under the
// mutex and skip the reload. Pre-fix, a callback past its timer fire (Stop()
// can no longer prevent it) proceeded to reload() and mutated the registry
// AFTER Close returned — post-shutdown registry writes. The test sets the
// exact state Close leaves behind (white-box, deterministic) and asserts a
// freshly scheduled callback lands nowhere.
func TestWatchdogNoReloadAfterClose(t *testing.T) {
	dir := t.TempDir()
	log := &syncBuffer{}
	reg, w := startAt(t, dir, log)
	path := filepath.Join(dir, "late.lua")
	body := `return function() return { publicvpn.node{ raw = "vless://l@h:1" } } end`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// The exact post-Close state: closed set under the mutex, pending map
	// drained (Close already ran).
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()

	w.schedule(path)
	time.Sleep(2 * debounce) // the AfterFunc fired; a buggy callback reloaded here

	if _, ok := reg.Get("late"); ok {
		t.Fatalf("plugin loaded AFTER Close — the closed gate is missing; log: %q", log.String())
	}
	if strings.Contains(log.String(), "plugin late loaded") {
		t.Fatalf("reload ran after Close: %q", log.String())
	}
}

// TestWatchdogCloseSetsClosedFlag pins that Close itself arms the gate.
// (Built via start() — no cleanup double-Close: Close is single-shot.)
func TestWatchdogCloseSetsClosedFlag(t *testing.T) {
	dir := t.TempDir()
	_, w, err := start(dir, io.Discard, debounce)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	w.mu.Lock()
	closedBefore := w.closed
	w.mu.Unlock()
	if closedBefore {
		t.Fatal("closed must be false while running")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w.mu.Lock()
	closedAfter := w.closed
	w.mu.Unlock()
	if !closedAfter {
		t.Fatal("Close must set the closed flag")
	}
}

func TestWatchdogConcurrentReloadAndSnapshot(t *testing.T) {
	// -race evidence: watchdog-style Set/Remove on one goroutine while a
	// wave-style reader takes snapshots and runs plugins from them.
	dir, reg := startTest(t)
	path := filepath.Join(dir, "churn.lua")
	if err := os.WriteFile(path, []byte(`return function() end`), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "initial", func() bool { _, ok := reg.Get("churn"); return ok })

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 30 {
			code := `return function() return {} end`
			if i%2 == 0 {
				code = `return function() return { publicvpn.node{ raw = "vless://c@h:9" } } end`
			}
			if err := os.WriteFile(path, []byte(code), 0o600); err != nil {
				return
			}
			time.Sleep(debounce / 2)
		}
	})
	wg.Go(func() {
		for range 100 {
			snap := reg.Snapshot()
			for _, p := range snap {
				if len(p.Code) == 0 {
					t.Error("snapshot exposed an empty plugin")
				}
			}
			time.Sleep(time.Millisecond)
		}
	})
	wg.Wait()
}
