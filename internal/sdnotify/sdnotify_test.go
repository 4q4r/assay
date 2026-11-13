//go:build unix

package sdnotify_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"assay/internal/sdnotify"

	"github.com/stretchr/testify/require"
)

// notifySockPath hands out the fake NOTIFY_SOCKET path. darwin caps unix
// socket paths at 104 bytes (the kernel sockaddr storage), and the darwin
// runner's /var/folders/... temp root already overflows it — the bind dies
// with "invalid argument" before any datagram flies (run 43330792666). A
// temp-root path that fits stays (unix keeps 108); an overflowing one falls
// back to a short, pid-unique /tmp path.
func notifySockPath(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "notify.sock")
	if len(sock) < 100 {
		return sock
	}
	short := filepath.Join("/tmp", fmt.Sprintf("assay-sdnotify-%d.sock", os.Getpid()))
	t.Cleanup(func() { _ = os.Remove(short) })
	return short
}

// startFakeNotifyListener is the hermetic stand-in for systemd's
// NOTIFY_SOCKET datagram socket: tests read the states the daemon sends.
func startFakeNotifyListener(t *testing.T, sock string) net.PacketConn {
	t.Helper()
	ln, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "unixgram", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// readState reads one datagram with a generous deadline (the hermetic
// receive side).
func readState(t *testing.T, ln net.PacketConn) string {
	t.Helper()
	const within = 2 * time.Second
	require.NoError(t, ln.SetReadDeadline(time.Now().Add(within)))
	buf := make([]byte, 128)
	n, _, err := ln.ReadFrom(buf)
	require.NoError(t, err, "expected a sd_notify datagram within %s", within)
	return string(buf[:n])
}

// TestReadySendsDatagram pins the Type=notify start handshake: READY=1 must
// reach systemd's datagram socket (path namespace) or `systemctl start` on a
// Type=notify unit would hang and fail.
func TestReadySendsDatagram(t *testing.T) {
	sock := notifySockPath(t)
	ln := startFakeNotifyListener(t, sock)
	t.Setenv("NOTIFY_SOCKET", sock)

	require.NoError(t, sdnotify.Ready())
	require.Equal(t, "READY=1", readState(t, ln))
}

// TestReadyWithoutNotifySocketIsNoOp pins the non-systemd contract: no
// NOTIFY_SOCKET → no-op success (a plain `assay watch` run must be
// unaffected; the socket's absence is expected, not an error).
func TestReadyWithoutNotifySocketIsNoOp(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	require.NoError(t, sdnotify.Ready(), "no socket = documented no-op, not an error")
}

// TestWatchdogPingsAtHalfInterval pins the pinger cadence: WATCHDOG=1 fires
// immediately and then every WATCHDOG_USEC/2 (systemd's recommended ping at
// half the deadline), until stopped.
func TestWatchdogPingsAtHalfInterval(t *testing.T) {
	sock := notifySockPath(t)
	ln := startFakeNotifyListener(t, sock)
	t.Setenv("NOTIFY_SOCKET", sock)
	t.Setenv("WATCHDOG_USEC", "1200000") // 1.2s deadline → 600ms pings

	log := &bytes.Buffer{}
	ctx := context.Background()
	stop := sdnotify.Watch(ctx, log)
	defer stop()

	require.Equal(t, "READY=1", readState(t, ln), "Watch sends READY=1 first")
	start := time.Now()
	require.Equal(t, "WATCHDOG=1", readState(t, ln), "the first ping fires immediately")
	require.Equal(t, "WATCHDOG=1", readState(t, ln), "then the cadence holds")
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, 500*time.Millisecond,
		"the second ping must respect the ~600ms interval (got %s)", elapsed)
	require.Less(t, elapsed, 2*time.Second,
		"the second ping must arrive within one extra interval (got %s)", elapsed)
}

// TestWatchdogPingsOverAbstractSocket pins the '@' namespace form of
// NOTIFY_SOCKET (systemd hands out both spellings).
func TestWatchdogPingsOverAbstractSocket(t *testing.T) {
	sock := fmt.Sprintf("@assay-sdnotify-test-%d", time.Now().UnixNano())
	ln := startFakeNotifyListener(t, sock)
	t.Setenv("NOTIFY_SOCKET", sock)
	t.Setenv("WATCHDOG_USEC", "2000000")

	ctx := context.Background()
	stop := sdnotify.Watch(ctx, &bytes.Buffer{})
	defer stop()

	require.Equal(t, "READY=1", readState(t, ln))
	require.Equal(t, "WATCHDOG=1", readState(t, ln))
}

// TestWatchWithoutSystemdIsNoOp pins the daemon's non-systemd run: no
// WATCHDOG_USEC → no pings, stop is safe, and the off-state is logged once.
func TestWatchWithoutSystemdIsNoOp(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	log := &bytes.Buffer{}
	stop := sdnotify.Watch(context.Background(), log)
	require.NotPanics(t, stop, "stop must be safe when the watchdog is off")
	require.Contains(t, log.String(), "off", "the off-state must be visible in the log: %s", log.String())
}
