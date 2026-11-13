package cli

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"assay/internal/platform"

	"github.com/stretchr/testify/require"
)

// execMagic returns the RUNNING platform's primary exec magic (platform.
// ExecMagics: ELF on linux, Mach-O on darwin, PE on windows). The verifier
// judges the binary by the host's own exec format — a hard-coded ELF magic
// passed only on linux hosts and was rejected as "not a Mach-O binary" on
// the darwin runner (run 43330792666).
func execMagic(extra ...byte) []byte {
	return append(slices.Clone(platform.ExecMagics(runtime.GOOS)[0]), extra...)
}

// kqueueBackend reports whether the running platform uses fsnotify's kqueue
// backend — the one backend that can silently stop delivering events for a
// name (upstream fsnotify #783, open against v1.10.x; the darwin CI leg hit
// exactly that: TestSelfUpdateFsnotifyDetection failed in two consecutive
// cycles with unchanged code, while create-path events arrived fine).
func kqueueBackend() bool {
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		return true
	}
	return false
}

// waitForPending polls the pending flag until the deadline.
func waitForPending(t *testing.T, bw *binarySelfWatcher, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if bw.IsPending() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, bw.IsPending(), what)
}

// TestSelfUpdateFsnotifyDetection pins the fsnotify FAST path: a binary
// write sets restartPending through the event channel alone (no stat
// fallback). That contract is only sound where the fsnotify backend
// delivers reliably; on kqueue platforms the strict pin asserts a channel
// upstream documents as lossy (#783 — events for a name can stop for the
// watcher's lifetime, no deadline fixes it), so there the strict pin is
// skipped with the fallback pin below carrying the detection contract.
func TestSelfUpdateFsnotifyDetection(t *testing.T) {
	if kqueueBackend() {
		t.Skip("kqueue fsnotify delivery is lossy (fsnotify #783); the detection " +
			"contract on this platform is pinned by TestSelfUpdateStatFallbackDetection")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "assay")
	require.NoError(t, os.WriteFile(bin, execMagic(1, 2, 3, 4), 0o755))

	var pending, armed atomic.Bool
	bw, err := startBinarySelfWatcherWith(dir, "assay", &pending, &armed, io.Discard, 0, bin)
	require.NoError(t, err)
	defer bw.close()

	time.Sleep(50 * time.Millisecond)

	require.NoError(t, os.WriteFile(bin, execMagic(9, 9, 9, 9), 0o755))

	waitForPending(t, bw, "fsnotify must set restartPending on binary write")
}

// TestSelfUpdateStatFallbackDetection pins the PRODUCTION detection
// contract on every OS: the stat poller sets restartPending when the binary
// is replaced even with the event stream dead — the darwin/BSD guarantee
// (kqueue can drop the write event entirely, #783). The watch is silenced
// via the public API so the pin cannot be satisfied by inotify on linux;
// it also pins the eager start-time baseline: the write lands before the
// first tick, which the old lazy first-tick baseline absorbed silently
// (the poller made the post-write state its reference and never fired).
func TestSelfUpdateStatFallbackDetection(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "assay")
	require.NoError(t, os.WriteFile(bin, execMagic(1, 2, 3, 4), 0o755))

	var pending, armed atomic.Bool
	// 100ms test-scaled check_interval (production default 30s) — same
	// statLoop mechanism, bounded test wall time.
	bw, err := startBinarySelfWatcherWith(dir, "assay", &pending, &armed, io.Discard, 100*time.Millisecond, bin)
	require.NoError(t, err)
	defer bw.close()

	// Silence the event channel after the watcher is up (and the baseline
	// is captured): from here only the poller can detect anything.
	require.NoError(t, bw.watcher.Remove(dir))

	time.Sleep(50 * time.Millisecond)

	require.NoError(t, os.WriteFile(bin, execMagic(9, 9, 9, 9), 0o755))

	waitForPending(t, bw, "stat fallback must set restartPending on binary write")
}

func TestSelfUpdateStatStabilityPartialWrite(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "assay")
	require.NoError(t, os.WriteFile(bin, execMagic(), 0o755))

	old := binaryStabilityDelay
	binaryStabilityDelay = 10 * time.Millisecond
	defer func() { binaryStabilityDelay = old }()

	go func() {
		time.Sleep(5 * time.Millisecond)
		_ = os.WriteFile(bin, execMagic(1), 0o755)
	}()
	ok, reason := verifyBinary(bin)
	require.False(t, ok, "partial write must not arm: %s", reason)
	require.NotEmpty(t, reason)

	require.NoError(t, os.WriteFile(bin, execMagic(2, 3), 0o755))
	time.Sleep(20 * time.Millisecond)
	ok, reason = verifyBinary(bin)
	require.True(t, ok, "stable exec image must arm: %s", reason)
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

// TestMagicRejectionSkipsOversizedMagic (review P3-2): a magic longer than
// the verifier's exact 4-byte read must be SKIPPED, never slice-panicked —
// the defensive guard keeps a hypothetical future >4-byte ExecMagics entry
// from turning the verifier into a panic. ExecMagics itself documents the
// ≤4-byte table contract.
func TestMagicRejectionSkipsOversizedMagic(t *testing.T) {
	buf := []byte{'M', 'Z', 0x00, 0x01} // the exact 4 bytes verifyBinary reads

	oversized := [][]byte{{'M', 'Z', 'X', 'Y', 'Z', 'W'}}
	require.Equal(t, "not a PE binary (bad magic)",
		magicRejection(buf, oversized, "PE"),
		"an oversized magic cannot match a 4-byte buffer — skip it and keep the rejection")

	mixed := [][]byte{oversized[0], platform.ExecMagic("windows")}
	require.Empty(t, magicRejection(buf, mixed, "PE"),
		"the oversized entry is skipped while the real magic still matches")

	for _, magic := range platform.ExecMagics(runtime.GOOS) {
		require.LessOrEqual(t, len(magic), len(buf),
			"the ExecMagics table must stay within the verifier's 4-byte read")
	}
}

// TestSelfWatcherCloseWaitsStatLoop (termination-audit P3-8): close() may
// only return once BOTH watcher goroutines have exited — the statLoop used
// to be unwaited, so one os.Stat+log iteration could still be in flight
// after close returned. The pin reads the statLoop exit channel directly
// (structural: the channel is the fix; with the pre-fix shape this file
// does not compile, which is the RED).
func TestSelfWatcherCloseWaitsStatLoop(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "assay")
	require.NoError(t, os.WriteFile(bin, []byte("placeholder"), 0o755))
	var pending, armed atomic.Bool
	bw, err := startBinarySelfWatcherWith(dir, "assay", &pending, &armed, io.Discard, time.Hour, bin)
	require.NoError(t, err)
	bw.close() // must return only after loop() AND statLoop() exited
	select {
	case <-bw.statDone:
	default:
		t.Fatal("close() returned with statLoop still running (audit P3-8)")
	}
}

// TestSelfWatcherCloseWithPollerDisabled covers the disabled-poller shape:
// statLoop starts unconditionally and exits immediately; close() must not
// hang waiting on it.
func TestSelfWatcherCloseWithPollerDisabled(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "assay")
	require.NoError(t, os.WriteFile(bin, []byte("placeholder"), 0o755))
	var pending, armed atomic.Bool
	bw, err := startBinarySelfWatcherWith(dir, "assay", &pending, &armed, io.Discard, 0, bin)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { bw.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("close() hung on the disabled-poller statDone")
	}
}
