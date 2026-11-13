// Package watchdog keeps the in-memory plugin registry in sync with the
// plugins dir: add/modify of any .lua recompiles and hot-swaps it (a broken
// file keeps the previous version active — last-good — with a loud error
// naming the Lua failure), and removal disables the source on the fly. A
// new provider is a new .lua file; no Go rebuild, no daemon restart.
//
// Delivery guarantee: fsnotify's inotify and ReadDirectoryChangesW backends
// report dir activity reliably; the kqueue backend (darwin, BSDs) can
// silently lose events for a name (upstream #783), so on those platforms a
// slow reconciliation scan backstops the event stream — same contract,
// per-OS mechanism.
package watchdog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"assay/internal/plugins"

	"github.com/fsnotify/fsnotify"
)

// DefaultDebounce coalesces editor write bursts (vim/npm-style tools emit
// several events per save) into one reload per file.
const DefaultDebounce = 250 * time.Millisecond

// The kqueue backend (darwin + the BSDs) opens one descriptor per watched
// file and re-registers watches while processing directory changes; those
// registrations race file activity and can leave a watch dead — events for
// that name stop arriving entirely for the watcher's lifetime (upstream
// fsnotify #783, open against v1.10.x, plus the spurious Ident=0 kevents
// documented in the backend source). A silently lost event means a plugin
// edit never hot-swaps — exactly the failure the darwin CI leg hit
// (TestWatchdogHotModifySwap: green in cycle 1, timed out in cycle 2 with
// unchanged code). On kqueue platforms the watchdog therefore runs a slow
// reconciliation pass over the plugins dir; inotify and ReadDirectoryChangesW
// deliver reliably, so the extra poller stays off there. Tests flip
// reconcileForced to exercise the mechanism on every OS.
var (
	reconcileForced   = false
	reconcileInterval = time.Second
	reconcileDefault  = func() bool {
		switch runtime.GOOS {
		case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
			return true
		}
		return false
	}()
)

// fileStamp is the reconciliation identity of one plugin file: content
// identity by proxy (size + mtime — good enough to notice an edit; a
// same-size same-mtime write is not a real-world edit pattern).
type fileStamp struct {
	size  int64
	mtime time.Time
}

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
	stamps  map[string]fileStamp // last content identity the reload path saw
	once    sync.Once            // Close teardown runs exactly once (idempotent Close)
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
		stamps:   stampDir(dir),
	}
	// PANIC POLICY (audit P3-9): a panic in this goroutine crashes the whole
	// process loudly — Go semantics — and every deployment transport answers a
	// crash with a restart (systemd Restart=always / launchd KeepAlive / the
	// SCM recovery actions) BY DESIGN. No recover here: a recover could mask a
	// corrupted-state crash-loop the supervisor surfaces honestly.
	go w.loop()
	return reg, w, nil
}

// stampDir snapshots the reconciliation identity of every .lua in dir (the
// state the initial LoadDir just loaded). The reconciler compares against
// this baseline; on kqueue platforms a lost Create/Write event leaves the
// delta invisible to fsnotify but not to this map.
func stampDir(dir string) map[string]fileStamp {
	stamps := map[string]fileStamp{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return stamps
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".lua") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		stamps[filepath.Join(dir, e.Name())] = fileStamp{size: info.Size(), mtime: info.ModTime()}
	}
	return stamps
}

// Close stops the watcher and the reload loop. The registry keeps its last
// state (the daemon is shutting down anyway).
//
// Idempotent (round-7 hardening): a second Close is a no-op returning nil —
// the teardown runs once (sync.Once), so a double-Close can neither panic
// on close-of-closed-channel nor double-stop the watcher.
//
// Mid-reload window, honestly documented: a debounce callback that fired
// just before Close may already be past its own closed check and inside
// reload when Close returns. The guard is the closed flag itself — reload
// re-checks it after acquiring mu, so any reload ENTERED after Close's
// critical section mutates nothing. What remains theoretical: a reload
// that passed its re-check BEFORE Close armed the flag can still be
// mid-Compile (os.ReadFile + Lua compile, ms-scale) when Close returns,
// and its registry write may land marginally after Close returns. Close
// does not wait for such an in-flight reload by design: at daemon shutdown
// the process is exiting anyway, and no reload can BEGIN after Close
// returns.
func (w *Watchdog) Close() error {
	var err error
	w.once.Do(func() {
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
		err = w.watcher.Close()
	})
	return err
}

func (w *Watchdog) loop() {
	defer close(w.stopped)
	var reconcile <-chan time.Time
	if reconcileDefault || reconcileForced {
		t := time.NewTicker(reconcileInterval)
		defer t.Stop()
		reconcile = t.C
	}
	for {
		select {
		case <-w.stop:
			return
		case <-reconcile:
			w.reconcile()
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

// reconcile is the kqueue-platform safety net: scan the plugins dir and
// debounce a reload for every .lua whose content identity moved since the
// reload path last saw it — including files fsnotify never reported (the
// lost-Create case), files whose edit was lost (lost-Write), and files that
// vanished (reload turns their ENOENT into a removal). With events flowing
// normally the scan is a no-op: the stamp is updated by every reload and
// removal, so nothing re-schedules and nothing re-logs.
func (w *Watchdog) reconcile() {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		_, _ = fmt.Fprintf(w.log, "WARNING: watchdog reconcile scan on %s: %v\n", w.dir, err)
		return
	}
	present := map[string]struct{}{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".lua") {
			continue
		}
		name := filepath.Join(w.dir, e.Name())
		present[name] = struct{}{}
		info, err := e.Info()
		if err != nil {
			continue // vanished between ReadDir and stat: the missing-pass handles it
		}
		w.scheduleIfChanged(name, fileStamp{size: info.Size(), mtime: info.ModTime()})
	}
	w.mu.Lock()
	missing := make([]string, 0, len(w.stamps))
	for name := range w.stamps {
		if _, ok := present[name]; !ok {
			missing = append(missing, name)
		}
	}
	w.mu.Unlock()
	for _, name := range missing {
		w.schedule(name) // reload turns ENOENT into a removal
	}
}

// scheduleIfChanged schedules name when stamp differs from the last stamp
// the reload path recorded, then records stamp. Unknown files schedule too
// (never-seen content must load even when the Create event was lost).
func (w *Watchdog) scheduleIfChanged(name string, stamp fileStamp) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	prev, seen := w.stamps[name]
	if seen && prev == stamp {
		return
	}
	w.stamps[name] = stamp
	w.scheduleLocked(name)
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
	w.scheduleLocked(name)
}

// scheduleLocked is the debounce body; mu must already be held (schedule
// takes it, scheduleIfChanged already holds it).
func (w *Watchdog) scheduleLocked(name string) {
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
	// Reload-internal closed gate (round-7): the callback body checks
	// closed before calling reload, but a callback that fired just before
	// Close may still enter here after Close's critical section. Re-check
	// under the mutex so a post-Close entry mutates nothing (the remaining
	// theoretical window — a reload already past THIS check when Close
	// arms the flag — is documented at Close).
	w.mu.Lock()
	closed := w.closed
	w.mu.Unlock()
	if closed {
		return
	}
	code, err := os.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		w.removeNow(name)
		w.mu.Lock()
		delete(w.stamps, name)
		w.mu.Unlock()
		return
	}
	if err != nil {
		_, _ = fmt.Fprintf(w.log, "WARNING: plugin %s unreadable — keeping previous version: %v\n",
			filepath.Base(name), err)
		return
	}
	id := plugins.IDFromPath(name)
	p, err := plugins.Compile(id, name, code, w.log)
	// Record what the reload path saw regardless of compile outcome: a
	// failed compile stamps the broken content too, so the reconciler does
	// not retry the same broken file every tick (the loud error already
	// fired); a later edit moves the stamp and reloads normally.
	if st, serr := os.Stat(name); serr == nil {
		w.mu.Lock()
		w.stamps[name] = fileStamp{size: st.Size(), mtime: st.ModTime()}
		w.mu.Unlock()
	}
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
	w.mu.Lock()
	delete(w.stamps, name)
	w.mu.Unlock()
}
