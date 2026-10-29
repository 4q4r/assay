package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/render"
)

// SocksInstance is one live temp SOCKS5 endpoint (production: a temp xray;
// tests: an in-process server).
type SocksInstance interface {
	Addr() string
	Close() error
}

// InstanceFactory spawns one instance per node (production: a temp xray with
// the node's rendered outbound).
type InstanceFactory func(ctx context.Context, n *model.Node) (SocksInstance, error)

// Temp-instance geometry: boot gets 10s; a killed child's inherited pipes
// get 5s to release Wait (activate.go M-3 landmine).
const (
	instanceBootBound  = 10 * time.Second
	instanceKillDelay  = 5 * time.Second
	tempOutboundTag    = "check-out"
	instanceLogBuffers = 8 * 1024
)

// Temp-instance PRODUCTION scan band: 18xxx is clear of the live client's
// 10808/10809 inbounds and fox-proxy 9999, and the watch daemon boots its
// own temp instances there on every hourly wave — the daemon and the live
// instances KEEP this band. It is a variable pair solely so TEST SUITES can
// re-pin it to a disjoint band (SetTestPortBand): a full -race suite run
// overlapped by a live daemon wave used to flake boot/ports/env-strip tests,
// each side's bind-test-close window losing against the other's churn.
// Production callers never reassign it — the production scan is unchanged.
var (
	instancePortMin = 18500
	instancePortMax = 18799
)

// SetTestPortBand re-pins the temp-instance port scan band. FOR TEST SUITES
// ONLY (the checker TestMain and the probe boot-smoke TestMain): suite temp
// instances must boot OUTSIDE the production 18xxx band so suite runs and
// live daemon waves never contend for the same ports. Calling it from
// production code is a bug.
func SetTestPortBand(minPort, maxPort int) {
	instancePortMin = minPort
	instancePortMax = maxPort
}

// NewXrayFactory returns the production InstanceFactory: each node gets a
// temporary single-node xray instance (managed binary) — a socks inbound on a
// free 127.0.0.1 18xxx port plus the node's outbound built by the SAME
// render.BuildOutbound the live renderer uses, carrying the SAME hardening
// knobs (one builder, no drift): tcp_max_seg is emitted mandatorily and the
// TLS fingerprint is applied — hardening IS uniform across live and temp.
// Nothing here ever touches the live client, its config, or geo-base.
//
// Exported for the W11 geo stage: the per-node self-report piggybacks on ONE
// such instance per node (the CLI wires this factory into geo.Input.Factory).
func NewXrayFactory(xrayBin, workDir string, knobs render.Config) InstanceFactory {
	return func(ctx context.Context, n *model.Node) (SocksInstance, error) {
		// Zero knobs normalize to the config defaults — a caller passing a
		// bare render.Config must never get an unhardened temp instance.
		// Local copy: the factory runs concurrently and knobs is shared.
		cfg := knobs
		if cfg.TCPMaxSeg == 0 {
			cfg.TCPMaxSeg = config.DefaultTCPMaxSeg
		}
		if cfg.TLSFingerprint == "" {
			cfg.TLSFingerprint = config.DefaultTLSFingerprint
		}
		outbound, _, err := render.BuildOutbound(n, tempOutboundTag, cfg)
		if err != nil {
			return nil, fmt.Errorf("render outbound for temp instance: %w", err)
		}
		return StartTempXray(ctx, xrayBin, workDir, outbound)
	}
}

type xrayInstance struct {
	cmd       *exec.Cmd
	port      int
	dir       string
	waitOnce  sync.Once
	done      chan struct{} // closed by the wait goroutine after Wait returns
	waitErr   error         // valid after <-done (channel close = happens-before)
	closeOnce sync.Once
	closeErr  error
}

func (x *xrayInstance) Addr() string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(x.port)) }

// Close kills the instance by its EXACT captured PID (never name-based — the
// owner runs live processes), reaps it, and removes the temp config dir.
// Idempotent: a second Close is a no-op (the first already waited for the
// reap and cleaned the dir).
func (x *xrayInstance) Close() error {
	x.closeOnce.Do(func() {
		if x.cmd.Process != nil {
			_ = x.cmd.Process.Kill()
		}
		<-x.waitDone() // Wait returns after the kill; WaitDelay bounds lingering pipes
		x.closeErr = os.RemoveAll(x.dir)
	})
	return x.closeErr
}

// waitDone reaps the child exactly once and closes done when Wait returns.
// The completion signal is a channel CLOSE, so it stays observable by every
// waiter forever: readiness and Close each wait on it independently, and
// neither can drain a one-shot value out from under the other (the C1
// landmine — a buffered single-value channel consumed by readiness left
// Close blocked forever and leaked the temp dir).
func (x *xrayInstance) waitDone() <-chan struct{} {
	x.waitOnce.Do(func() {
		x.done = make(chan struct{})
		go func() {
			x.waitErr = x.cmd.Wait()
			close(x.done)
		}()
	})
	return x.done
}

// bootMu serializes the boot window — port handout THROUGH the instance's
// own socks accept — per process. freeInstancePort bind-tests and closes the
// port long before xray binds it, so two concurrent factories could scan the
// same port: the loser's readiness poll would then succeed VIA THE WINNER'S
// socket and its checks would ride the winner's tunnel — silently wrong
// measurements (reviewer-reproduced: a dead-outbound node scoring 200 OK).
// The mutex makes that collision impossible BY CONSTRUCTION rather than by
// luck. Boot is ~100ms per instance; the check phase stays fully parallel.
var bootMu sync.Mutex

// StartTempXray spawns one temporary xray instance: a socks inbound on a free
// 127.0.0.1 18xxx port plus the GIVEN outbound (production callers pass a
// render.BuildOutbound product). The child is killed by its exact captured
// PID on Close; the config dir dies with it. The boot mutex is held from the
// port scan until the instance's OWN socks listener accepts (awaitReadiness)
// — see bootMu.
//
//nolint:ireturn // SocksInstance is the seam: engine and tests stay implementation-agnostic
func StartTempXray(ctx context.Context, xrayBin, workDir string, outbound map[string]any) (SocksInstance, error) {
	if xrayBin == "" {
		return nil, errors.New("xray binary path is empty (activate.xray_bin)")
	}
	bootMu.Lock()
	defer bootMu.Unlock()
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(workDir, "check-")
	if err != nil {
		return nil, err
	}
	port, err := freeInstancePort(ctx)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "socks-in", "listen": "127.0.0.1", "port": port,
			"protocol": "socks", "settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{outbound},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	//nolint:gosec // the binary comes from the owner's config.toml — the config file IS the trust root
	cmd := exec.CommandContext(ctx, xrayBin, "run", "-c", cfgPath)
	// The child must not inherit a proxy environment (L5 hygiene), and Wait
	// must never block forever on inherited pipes (M-3 landmine).
	cmd.Env = dropProxyEnv(os.Environ())
	cmd.WaitDelay = instanceKillDelay
	stderr := &limitedWriter{max: instanceLogBuffers}
	cmd.Stderr = stderr

	inst := &xrayInstance{cmd: cmd, port: port, dir: dir}
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("start %s: %w", xrayBin, err)
	}
	if err := inst.awaitReadiness(ctx, stderr); err != nil {
		_ = inst.Close()
		return nil, err
	}
	return inst, nil
}

// awaitReadiness polls the socks inbound until it accepts (xray binds the
// listener only after the config parses) or the boot bound expires, failing
// fast when the child exits with its captured stderr tail.
func (x *xrayInstance) awaitReadiness(ctx context.Context, stderr *limitedWriter) error {
	deadline := time.After(instanceBootBound)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	dialer := &net.Dialer{Timeout: 400 * time.Millisecond}
	for {
		select {
		case <-x.waitDone(): // child died during boot; waitErr is set (done closed after Wait)
			return fmt.Errorf("xray exited during startup: %w\n%s", x.waitErr, tailStr(stderr.String(), 400))
		case <-ctx.Done():
			return fmt.Errorf("instance boot canceled: %w", ctx.Err())
		case <-deadline:
			return fmt.Errorf("xray socks inbound %s not ready within %s\n%s",
				x.Addr(), instanceBootBound, tailStr(stderr.String(), 400))
		case <-tick.C:
			conn, err := dialer.DialContext(ctx, "tcp", x.Addr())
			if err == nil {
				_ = conn.Close()
				return nil
			}
		}
	}
}

// freeInstancePort hands out a bindable 127.0.0.1 port from the configured
// scan band (production: 18xxx; test suites: the disjoint band pinned via
// SetTestPortBand). The bind test closes before xray binds — the resulting
// boot-to-bind window is exactly why bootMu serializes handout-to-readiness:
// inside one process a second factory cannot even SCAN while an instance is
// booting, so the loser-rides-the-winner's-socket collision cannot happen
// (cross-process contention on this band remains theoretically possible and
// surfaces as a loud boot failure, never as a silent wrong measurement).
func freeInstancePort(ctx context.Context) (int, error) {
	var lc net.ListenConfig
	for p := instancePortMin; p <= instancePortMax; p++ {
		ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return p, nil
	}
	return 0, fmt.Errorf("no free port in [%d,%d] for a temp instance", instancePortMin, instancePortMax)
}

// dropProxyEnv strips ambient proxy variables from a child environment
// (L5: nothing in the check path may silently route through the live client).
func dropProxyEnv(env []string) []string {
	out := env[:0]
	for _, e := range env {
		upper := strings.ToUpper(e)
		if strings.HasPrefix(upper, "HTTP_PROXY=") || strings.HasPrefix(upper, "HTTPS_PROXY=") ||
			strings.HasPrefix(upper, "ALL_PROXY=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

func tailStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// limitedWriter keeps at most max bytes of the child's stderr (diagnostics
// only); it reports full writes so the child never sees short-write errors.
// The mutex is load-bearing: os/exec streams Stderr from its own goroutine
// while awaitReadiness snapshots the buffer for error messages (a data race
// the C2 stress test caught under -race).
type limitedWriter struct {
	mu  sync.Mutex
	buf strings.Builder
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() < w.max {
		rem := w.max - w.buf.Len()
		if len(p) > rem {
			p = p[:rem]
		}
		w.buf.Write(p)
	}
	return len(p), nil
}

// String snapshots the buffered tail safely against the exec copy goroutine.
func (w *limitedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
