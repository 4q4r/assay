// Package sdnotify implements the minimal sd_notify(3) protocol slice the
// watch daemon needs: one READY=1 start handshake and periodic WATCHDOG=1
// pings. Hand-rolled on purpose (one UNIX datagram, ~40 lines) — pulling in
// coreos/go-systemd for this would be a new dependency for no capability.
//
// systemd sets NOTIFY_SOCKET for Type=notify services: an absolute path or
// an '@'-prefixed abstract-namespace name (both accepted verbatim — Go's
// net package treats a leading '@' as abstract). WATCHDOG_USEC carries the
// unit's WatchdogSec in microseconds; the pinger fires at half the deadline,
// the cadence systemd recommends. Without those variables the daemon is not
// running under systemd supervision and everything here is a documented
// no-op — a plain `assay watch` run is unaffected.
//
// The hang contract this serves: a wedged daemon stops pinging, systemd
// kills it at WatchdogSec and Restart=always brings it back — the honest
// backstop for hang classes the per-plugin run timeout cannot see.
package sdnotify

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	stateReady    = "READY=1"
	stateWatchdog = "WATCHDOG=1"
)

// Ready sends the Type=notify start handshake. Without NOTIFY_SOCKET this is
// a documented no-op success (not running under systemd).
func Ready() error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	return sendState(sock, stateReady)
}

// Watch starts the watchdog pinger: READY=1 immediately, then WATCHDOG=1
// every WATCHDOG_USEC/2 until stop is called or ctx is done. Returns the
// stop func (always non-nil, safe to call in any state). Ping failures are
// logged LOUD and retried — the daemon is on its way to being killed by
// systemd at the deadline anyway, and silencing them would hide exactly the
// wedge this watchdog exists to catch. With no NOTIFY_SOCKET or no
// WATCHDOG_USEC the pinger stays off (logged once) and stop is a no-op.
func Watch(ctx context.Context, log io.Writer) func() {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		_, _ = fmt.Fprintln(log, "sd_notify: off — NOTIFY_SOCKET unset (not running under systemd supervision)")
		return func() {}
	}
	if err := sendState(sock, stateReady); err != nil {
		_, _ = fmt.Fprintf(log, "WARNING: sd_notify READY=1 failed: %v\n", err)
	}
	interval, ok := watchdogInterval()
	if !ok {
		_, _ = fmt.Fprintln(log,
			"sd_notify: READY=1 sent; watchdog pings off (WATCHDOG_USEC unset — no WatchdogSec in the unit)")
		return func() {}
	}
	_, _ = fmt.Fprintf(log, "sd_notify: READY=1 sent; watchdog pings every %s (WatchdogSec/2)\n", interval)

	pingCtx, cancel := context.WithCancel(ctx)
	go pingLoop(pingCtx, sock, interval, log)
	return cancel
}

// watchdogInterval resolves the ping cadence from WATCHDOG_USEC (systemd's
// WatchdogSec in microseconds): ping at half the deadline. ok=false when the
// variable is absent or unparsable — the unit simply carries no WatchdogSec.
func watchdogInterval() (time.Duration, bool) {
	v := os.Getenv("WATCHDOG_USEC")
	if v == "" {
		return 0, false
	}
	usec, err := strconv.ParseInt(v, 10, 64)
	if err != nil || usec <= 0 {
		return 0, false
	}
	return time.Duration(usec) * time.Microsecond / 2, true
}

// pingLoop fires one ping immediately (systemd starts counting from service
// start) and then keeps the cadence until the context ends.
func pingLoop(ctx context.Context, sock string, interval time.Duration, log io.Writer) {
	sendWatchdog := func() {
		if err := sendState(sock, stateWatchdog); err != nil {
			_, _ = fmt.Fprintf(log, "WARNING: sd_notify watchdog ping failed: %v\n", err)
		}
	}
	sendWatchdog()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendWatchdog()
		}
	}
}

// Stopping sends the STOPPING=1 state to systemd (used for graceful self-restart).
// Without NOTIFY_SOCKET this is a documented no-op success.
func Stopping() error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	return sendState(sock, "STOPPING=1")
}

// sendState delivers one state datagram to the NOTIFY_SOCKET socket.
func sendState(sock, state string) error {
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("connect %s: %w", sock, err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(state)); err != nil {
		return fmt.Errorf("send %q to %s: %w", state, sock, err)
	}
	return nil
}
