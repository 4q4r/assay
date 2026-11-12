//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The windows service log sink pins (§2.2.6): <data>/logs/watch.log is
// created on demand, APPENDS across reopen (SCM recovery-action restarts
// must not truncate the history), and serializes concurrent writes.
func TestFileLogSinkCreatesAndAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "watch.log")

	sink, err := NewFileLogSink(path)
	require.NoError(t, err)
	_, err = sink.Write([]byte("first line\n"))
	require.NoError(t, err)
	require.NoError(t, sink.Close())

	// Reopen: append-mode — the first write survives the restart-shaped
	// reopen and the new line lands after it.
	sink2, err := NewFileLogSink(path)
	require.NoError(t, err)
	_, err = sink2.Write([]byte("second line\n"))
	require.NoError(t, err)
	require.NoError(t, sink2.Close())

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "first line\nsecond line\n", string(got))
}

func TestFileLogSinkConcurrentWritesStayLineAtomic(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewFileLogSink(filepath.Join(dir, "logs", "watch.log"))
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			line := []byte{byte('a' + n), '\n'}
			for range 64 {
				_, err := sink.Write(line)
				if err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	require.NoError(t, sink.Close())
}

func TestFileLogSinkEmptyPathRefuses(t *testing.T) {
	_, err := NewFileLogSink("")
	require.Error(t, err)
}
