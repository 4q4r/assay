//go:build windows

package platform

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// FileLogSink is the windows service-context log sink (plan §2.2.6): a
// service's stdout goes nowhere, so the daemon writes its log stream into
// a plain append-mode file — the launchd StandardOutPath contract's windows
// mirror (<data>/logs/watch.log, §4.2). Appends survive restarts (SCM
// recovery actions restart the service; the log keeps its history, the same
// unrotated-file caveat the plan records for every non-journald platform).
// Writes from the daemon's concurrent goroutines are mutex-serialized: one
// Write call per log line, never interleaved half-lines.
type FileLogSink struct {
	mu   sync.Mutex
	file *os.File
}

var _ io.WriteCloser = (*FileLogSink)(nil)

// NewFileLogSink opens (creating parent directories) the append-mode sink
// at path. An existing log is APPENDED — recovery-action restarts must not
// truncate the history (the launchd StandardOutPath semantics).
func NewFileLogSink(path string) (*FileLogSink, error) {
	if path == "" {
		return nil, errors.New("platform: log sink path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("platform: create log dir %s: %w", filepath.Dir(path), err)
	}
	//nolint:gosec // G304: the path comes from the service context's resolved
	// data dir (the config is the trust root); there is no fixed log path to
	// fall back to.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("platform: open log sink %s: %w", path, err)
	}
	return &FileLogSink{file: f}, nil
}

// Write appends p to the sink (mutex-serialized — the daemon writes from
// several goroutines).
func (s *FileLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Write(p)
}

// Close flushes and closes the sink file.
func (s *FileLogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Close()
}
