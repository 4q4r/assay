package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// binaryStabilityDelay is how long verifyBinary waits between two stat
// calls to confirm a partially-written binary has settled. Package-level so
// tests can shorten it; production uses ~2s per the brief.
var binaryStabilityDelay = 2 * time.Second

// elfMagic is the first four bytes of a valid ELF executable.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// verifyBinary confirms that path points at a complete, valid ELF binary:
//   - the file exists and is stat-stable across two reads (size + mtime
//     unchanged across binaryStabilityDelay — partial-write protection);
//   - the first four bytes are the ELF magic \x7fELF.
//
// An optional sidecar "<path>.sha256" is verified when present. Returns
// (true, "") when armed, (false, reason) otherwise. Never panics; logs
// nothing — callers log.
func verifyBinary(path string) (bool, string) {
	st1, err := os.Stat(path)
	if err != nil {
		return false, fmt.Sprintf("stat: %v", err)
	}
	time.Sleep(binaryStabilityDelay)
	st2, err := os.Stat(path)
	if err != nil {
		return false, fmt.Sprintf("stat: %v", err)
	}
	if st1.Size() != st2.Size() {
		return false, fmt.Sprintf("size changed: %d -> %d", st1.Size(), st2.Size())
	}
	if !st1.ModTime().Equal(st2.ModTime()) {
		return false, fmt.Sprintf("mtime changed: %v -> %v", st1.ModTime(), st2.ModTime())
	}
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Sprintf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 4)
	n, err := f.Read(buf)
	if err != nil || n < 4 {
		return false, "short read (not a complete ELF)"
	}
	for i := range elfMagic {
		if buf[i] != elfMagic[i] {
			return false, "not an ELF binary (bad magic)"
		}
	}
	// Optional sha256 sidecar.
	if side, err := os.ReadFile(path + ".sha256"); err == nil {
		want := trimSpace(string(side))
		got, err := sha256File(path)
		if err != nil {
			return false, fmt.Sprintf("sha256: %v", err)
		}
		if want != "" && want != got {
			return false, fmt.Sprintf("sha256 mismatch: %s != %s", got, want)
		}
	}
	return true, ""
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\r' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\r' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func sha256File(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// binarySelfWatcher watches the parent directory of a binary for changes.
type binarySelfWatcher struct {
	dir  string
	base string
	log  io.Writer

	pending *atomic.Bool
	armed   *atomic.Bool

	checkInterval time.Duration
	exePath       string

	baselineSize  int64
	baselineMtime time.Time

	watcher *fsnotify.Watcher
	stop    chan struct{}
	done    chan struct{}
}

func startBinarySelfWatcherWith(
	dir, base string,
	pending, armed *atomic.Bool,
	log io.Writer,
	checkInterval time.Duration,
	exePath string,
) (*binarySelfWatcher, error) {
	if pending == nil {
		var p atomic.Bool
		pending = &p
	}
	if armed == nil {
		var a atomic.Bool
		armed = &a
	}
	if log == nil {
		log = io.Discard
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("self-update: create fsnotify watcher: %w", err)
	}
	if err := w.Add(dir); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("self-update: watch %s: %w", dir, err)
	}
	bw := &binarySelfWatcher{
		dir:           dir,
		base:          base,
		log:           log,
		pending:       pending,
		armed:         armed,
		checkInterval: checkInterval,
		exePath:       exePath,
		watcher:       w,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	go bw.loop()
	if checkInterval > 0 && exePath != "" {
		go bw.statLoop()
	}
	outf(log, "self-update: watching %s (binary %s)\n", dir, base)
	return bw, nil
}

func (bw *binarySelfWatcher) loop() {
	defer close(bw.done)
	for {
		select {
		case <-bw.stop:
			return
		case ev, ok := <-bw.watcher.Events:
			if !ok {
				return
			}
			if filepath.Base(ev.Name) != bw.base {
				continue
			}
			if ev.Has(fsnotify.Chmod) {
				continue
			}
			if ev.Has(fsnotify.Create) || ev.Has(fsnotify.Write) || ev.Has(fsnotify.Rename) || ev.Has(fsnotify.Remove) {
				outf(bw.log, "self-update: binary change detected (%v on %s) — restart pending\n", ev.Op, ev.Name)
				bw.pending.Store(true)
			}
		case err, ok := <-bw.watcher.Errors:
			if ok && err != nil {
				_, _ = fmt.Fprintf(bw.log, "WARNING: self-update watcher error on %s: %v\n", bw.dir, err)
			}
		}
	}
}

func (bw *binarySelfWatcher) statLoop() {
	if bw.checkInterval <= 0 {
		return
	}
	ticker := time.NewTicker(bw.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-bw.stop:
			return
		case <-ticker.C:
			if bw.pending.Load() {
				continue
			}
			st, err := os.Stat(bw.exePath)
			if err != nil {
				continue
			}
			if bw.baselineSize == 0 && bw.baselineMtime.IsZero() {
				bw.baselineSize = st.Size()
				bw.baselineMtime = st.ModTime()
				continue
			}
			if st.Size() != bw.baselineSize || !st.ModTime().Equal(bw.baselineMtime) {
				outf(bw.log, "self-update: stat check detected binary change — restart pending\n")
				bw.pending.Store(true)
			}
		}
	}
}

func (bw *binarySelfWatcher) close() {
	close(bw.stop)
	<-bw.done
	_ = bw.watcher.Close()
}

func (bw *binarySelfWatcher) IsPending() bool {
	if bw == nil || bw.pending == nil {
		return false
	}
	return bw.pending.Load()
}

func (bw *binarySelfWatcher) IsArmed() bool {
	if bw == nil || bw.armed == nil {
		return false
	}
	return bw.armed.Load()
}

// Pending returns the pending flag (exported-ish accessor for tests).
func (bw *binarySelfWatcher) Pending() *atomic.Bool { return bw.pending }

// Armed returns the armed flag.
func (bw *binarySelfWatcher) Armed() *atomic.Bool { return bw.armed }
