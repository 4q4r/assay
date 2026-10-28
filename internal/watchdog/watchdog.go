// Package watchdog keeps the in-memory plugin registry in sync with the
// plugins dir: add/modify of any .lua recompiles and hot-swaps it (a broken
// file keeps the previous version active — last-good — with a loud error
// naming the Lua failure), and removal disables the source on the fly. A
// new provider is a new .lua file; no Go rebuild, no daemon restart.
package watchdog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"public_vpn/internal/plugins"

	"github.com/fsnotify/fsnotify"
)

// DefaultDebounce coalesces editor write bursts (vim/npm-style tools emit
// several events per save) into one reload per file.
const DefaultDebounce = 250 * time.Millisecond

// Watchdog owns the fsnotify watcher and the debounced reload queue.
type Watchdog struct {
	dir      string
	reg      *plugins.Registry
	log      io.Writer
	debounce time.Duration

	watcher *fsnotify.Watcher
	stop    chan struct{}
	stopped chan struct{}

	mu      sync.Mutex
	closed  bool // Close set: pending debounce callbacks must skip reload
	pending map[string]*time.Timer
}

// Start performs the initial full load (materialize defaults + compile
// everything) and begins watching dir. It returns the registry it keeps
// current until Close: waves snapshot it at their start; the daemon passes
// it to runFetchWith.
func Start(dir string, log io.Writer) (*plugins.Registry, *Watchdog, error) {
	return start(dir, log, DefaultDebounce)
}

func start(dir string, log io.Writer, debounce time.Duration) (*plugins.Registry, *Watchdog, error) {
	if err := plugins.EnsureDefaults(dir); err != nil {
		return nil, nil, err
	}
	reg, err := plugins.LoadDir(dir, log)
	if err != nil {
		return nil, nil, err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, nil, fmt.Errorf("watchdog: create fsnotify watcher: %w", err)
	}
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return nil, nil, fmt.Errorf("watchdog: watch %s: %w", dir, err)
	}
	w := &Watchdog{
		dir:      dir,
		reg:      reg,
		log:      log,
		debounce: debounce,
		watcher:  watcher,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
		pending:  map[string]*time.Timer{},
	}
	go w.loop()
	return reg, w, nil
}

// Close stops the watcher and the reload loop. The registry keeps its last
// state (the daemon is shutting down anyway).
func (w *Watchdog) Close() error {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	close(w.stop)
	<-w.stopped
	w.mu.Lock()
	for _, t := range w.pending {
		t.Stop()
	}
	w.pending = map[string]*time.Timer{}
	w.mu.Unlock()
	return w.watcher.Close()
}

func (w *Watchdog) loop() {
	defer close(w.stopped)
	for {
		select {
		case <-w.stop:
			return
		case ev, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			w.handleEvent(ev)
		case err, ok := <-w.watcher.Errors:
			if ok && err != nil {
				_, _ = fmt.Fprintf(w.log, "WARNING: watchdog error on %s: %v\n", w.dir, err)
			}
		}
	}
}

func (w *Watchdog) handleEvent(ev fsnotify.Event) {
	if !strings.HasSuffix(ev.Name, ".lua") || ev.Has(fsnotify.Chmod) {
		return
	}
	switch {
	case ev.Has(fsnotify.Create) || ev.Has(fsnotify.Write):
		w.schedule(ev.Name)
	case ev.Has(fsnotify.Remove) || ev.Has(fsnotify.Rename):
		w.removeNow(ev.Name)
	}
}

// schedule debounces one path: every event resets the per-file timer; only
// the last event inside the debounce window fires the reload.
func (w *Watchdog) schedule(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if t, ok := w.pending[name]; ok {
		t.Reset(w.debounce)
		return
	}
	w.pending[name] = time.AfterFunc(w.debounce, func() {
		w.mu.Lock()
		delete(w.pending, name)
		closed := w.closed
		w.mu.Unlock()
		if closed {
			// Close won the race: no reload after it. Without this gate a
			// callback already past its timer fire (Stop() cannot prevent
			// it) mutated the registry after Close returned.
			return
		}
		w.reload(name)
	})
}

// reload recompiles one plugin file and hot-swaps it. Semantics:
//   - healthy file  → registry upsert, source active (replaced or added);
//   - broken file   → LOUD error, previous version stays active (last-good);
//   - vanished file → treated as removal (source disabled).
func (w *Watchdog) reload(name string) {
	code, err := os.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		w.removeNow(name)
		return
	}
	if err != nil {
		_, _ = fmt.Fprintf(w.log, "WARNING: plugin %s unreadable — keeping previous version: %v\n",
			filepath.Base(name), err)
		return
	}
	id := plugins.IDFromPath(name)
	p, err := plugins.Compile(id, name, code, w.log)
	if err != nil {
		// Loud, attributed, and the old version keeps serving — a broken
		// edit must never take a healthy source offline.
		_, _ = fmt.Fprintf(w.log, "WARNING: plugin %s reload FAILED — keeping the previous "+
			"version active: %v\n", id, err)
		return
	}
	replaced := w.reg.Set(p)
	if replaced {
		_, _ = fmt.Fprintf(w.log, "plugin %s reloaded — previous version replaced\n", id)
		return
	}
	_, _ = fmt.Fprintf(w.log, "plugin %s loaded — source active (hot-added)\n", id)
}

// Compile re-exports nothing: the load check lives in plugins.Compile (this
// wrapper removed — callers validate via that package directly).

func (w *Watchdog) removeNow(name string) {
	id := plugins.IDFromPath(name)
	if w.reg.Remove(id) {
		_, _ = fmt.Fprintf(w.log, "plugin %s removed — source disabled\n", id)
	}
}
