package cli

import (
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSelfUpdateFsnotifyDetection(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "assay")
	require.NoError(t, os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F', 1, 2, 3, 4}, 0o755))

	var pending, armed atomic.Bool
	bw, err := startBinarySelfWatcherWith(dir, "assay", &pending, &armed, io.Discard, 0, bin)
	require.NoError(t, err)
	defer bw.close()

	time.Sleep(50 * time.Millisecond)

	require.NoError(t, os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F', 9, 9, 9, 9}, 0o755))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if bw.IsPending() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, bw.IsPending(), "fsnotify must set restartPending on binary write")
}

func TestSelfUpdateStatStabilityPartialWrite(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "assay")
	require.NoError(t, os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F'}, 0o755))

	old := binaryStabilityDelay
	binaryStabilityDelay = 10 * time.Millisecond
	defer func() { binaryStabilityDelay = old }()

	go func() {
		time.Sleep(5 * time.Millisecond)
		_ = os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F', 1}, 0o755)
	}()
	ok, reason := verifyBinary(bin)
	require.False(t, ok, "partial write must not arm: %s", reason)
	require.NotEmpty(t, reason)

	require.NoError(t, os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F', 2, 3}, 0o755))
	time.Sleep(20 * time.Millisecond)
	ok, reason = verifyBinary(bin)
	require.True(t, ok, "stable ELF must arm: %s", reason)
	require.Empty(t, reason)
}

func TestSelfUpdateEscalation(t *testing.T) {
	sched := &waveScheduler{
		out:     io.Discard,
		exePath: "",
	}
	sched.restartPending.Store(true)

	for i := range 3 {
		got := sched.checkSelfUpdate()
		require.False(t, got, "wave %d should not yet restart", i+1)
	}
	got := sched.checkSelfUpdate()
	require.True(t, got, "4th wave must trigger restart")
	require.True(t, sched.restartRequested.Load())
}

func TestSelfUpdateBadMagic(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "assay")
	require.NoError(t, os.WriteFile(bin, []byte("not-elf"), 0o755))

	old := binaryStabilityDelay
	binaryStabilityDelay = 1 * time.Millisecond
	defer func() { binaryStabilityDelay = old }()

	ok, reason := verifyBinary(bin)
	require.False(t, ok)
	require.Contains(t, reason, "bad magic")
}
