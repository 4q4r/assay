package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/geo"
	"public_vpn/internal/model"
	"public_vpn/internal/probe"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Production-scale regression harness for the merged classification pass
// (owner order 2026-11-07 «сразу на чеке»): the wave-58 production incident
// showed an apparent 10x alive-rate collapse on the first wave that ran
// with Options.Classifier set, and the fixture-scale parity pin
// (TestClassifierNilIsProbeOnly, internal/probe) could not see it — its
// classifier stub does zero work (no network, no time) and its population
// was five nodes.
//
// These tests reproduce the production SHAPE: a 1000-node batch of
// slow-but-alive tunnels served by ONE shared socks relay (a batch
// instance's 1000 inbounds share one egress), with the REAL geo.Classifier
// battery wired as the hook, at the production default batch concurrency.
// The invariant under test: probe outcomes with the hook ON are byte-parity
// with the hook OFF — the battery's through-tunnel load must never starve,
// reset, or re-classify a probe verdict.

// scaleRelay is a minimal no-auth SOCKS5 CONNECT relay (the same wire
// contract the probe engine test harness uses): unrouted CONNECTs dial the
// default (battery-fast) upstream, the probe target is pinned to a
// dedicated slow upstream, and concurrent CONNECT load on the shared
// listener is gauged.
type scaleRelay struct {
	ln       net.Listener
	mu       sync.Mutex
	routes   map[string]string // CONNECT host:port -> upstream dial target
	upstream string            // default dial target (unrouted CONNECTs)
	closers  []io.Closer
	wg       sync.WaitGroup

	connects atomic.Int64
	inFlight atomic.Int64
	peakLoad atomic.Int64
}

func newScaleRelay(t *testing.T, defaultUpstream string) *scaleRelay {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	r := &scaleRelay{ln: ln, routes: map[string]string{}, upstream: defaultUpstream}
	r.wg.Add(1)
	go r.serve()
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func (r *scaleRelay) Addr() string { return r.ln.Addr().String() }

func (r *scaleRelay) addRoute(hostport, upstream string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[hostport] = upstream
}

func (r *scaleRelay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.ln.Close()
	for _, c := range r.closers {
		_ = c.Close()
	}
	r.wg.Wait()
	return err
}

func (r *scaleRelay) serve() {
	defer r.wg.Done()
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		r.closers = append(r.closers, conn)
		r.mu.Unlock()
		r.wg.Go(func() {
			r.handle(conn)
		})
	}
}

func (r *scaleRelay) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return
		}
		host = string(name)
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return
	}
	portNum := int(port[0])<<8 | int(port[1])

	r.mu.Lock()
	target := r.routes[net.JoinHostPort(host, strconv.Itoa(portNum))]
	if target == "" {
		target = r.upstream
	}
	r.mu.Unlock()

	up, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", target)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	r.connects.Add(1)
	cur := r.inFlight.Add(1)
	for {
		peak := r.peakLoad.Load()
		if cur <= peak || r.peakLoad.CompareAndSwap(peak, cur) {
			break
		}
	}
	defer r.inFlight.Add(-1)
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	defer func() { _ = up.Close() }()
	go func() { _, _ = io.Copy(up, conn) }()
	_, _ = io.Copy(conn, up)
}

// scaleUpstream builds the double the relay forwards to. slowDelay > 0 makes
// EVERY response take that long — the probe target rides a dedicated slow
// upstream via addRoute, so the probe phase takes real time while the
// classification battery (unrouted targets) stays fast.
func scaleUpstream(t *testing.T, slowDelay time.Duration) *httptest.Server {
	t.Helper()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "generate_204") || strings.Contains(req.URL.Path, "connecttest") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if slowDelay > 0 {
			time.Sleep(slowDelay)
		}
		// The ip-api self-report shape (the ladder's rung 1 and the probe
		// wave's D8 echo both parse this); every other battery endpoint
		// tolerates arbitrary bodies (verdicts land unknown — honest).
		_ = json.NewEncoder(w).Encode(map[string]any{"query": "9.9.9.9", "countryCode": "DE"})
	}))
	t.Cleanup(site.Close)
	return site
}

func scaleNodes(prefix string, n int) []*model.Node {
	nodes := make([]*model.Node, n)
	for i := range nodes {
		nodes[i] = model.NewNode(
			"scale-src", "vless",
			fmt.Sprintf("uuid-scale-%s-%d", prefix, i),
			fmt.Sprintf("%s-%d.example.invalid", prefix, i), 443,
			map[string]string{"security": "tls", "type": "tcp"},
		)
	}
	return nodes
}

// scaleSink is a TCP sink for the battery's raw-TCP channels (DNS-over-TCP,
// STUN): it accepts and closes immediately — the production contract of a
// real resolver/STUN target that answers or resets fast, never holds the
// socket open.
func scaleSink(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close() // immediate close = fast honest channel failure
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return ln.Addr().String()
}

// scaleClassifier builds the REAL battery hook for the scale wave: every
// HTTP endpoint rides the fast upstream, the raw-TCP channels (DNS-over-TCP,
// STUN) ride the sink. It returns the sink's host:port so the caller can
// ROUTE it through the relay (an unrouted relay target would fall through
// to the keep-alive HTTP upstream and hang the deadline-less DNS read).
func scaleClassifier(t *testing.T, fastURL string) (*geo.Classifier, string) {
	t.Helper()
	sinkHostPort := scaleSink(t)
	endpoints := geo.UnlockEndpoints{
		ChatGPCTrace:      fastURL + "/trace",
		ChatGPTCompliance: fastURL + "/compliance",
		NetflixTitleA:     fastURL + "/title/a",
		NetflixTitleB:     fastURL + "/title/b",
		YouTubePremium:    fastURL + "/premium",
		TikTokHome:        fastURL + "/tiktok",
		TikTokExplore:     fastURL + "/explore",
		DisneyDevices:     fastURL + "/devices",
		DisneyAuth:        fastURL + "/token",
		DisneyGraphQL:     fastURL + "/graphql",
		IPInfoWidget:      fastURL + "/widget",
		CFTrace:           fastURL + "/cdn-cgi/trace",
		EchoIPify:         fastURL + "/ipify",
		EchoIPSB:          fastURL + "/ipsb",
		IPAPIContract:     fastURL + "/json",
		AlivePrimary:      fastURL + "/generate_204",
		AliveFallback:     fastURL + "/connecttest.txt",
		// DNS-over-TCP rides the relay to this sink: the sink accepts and
		// closes immediately (the production contract — a real authoritative
		// resolver answers or resets fast; it never holds the socket open),
		// so the channel records its fast, honest non-fatal failure.
		DNSServer:  sinkHostPort,
		DNSName:    "o-o.myaddr.l.google.com",
		STUNServer: sinkHostPort,
	}
	return geo.NewClassifier(geo.ClassifyInput{
		DataDir: t.TempDir(),
		Cfg: config.GeoConfig{
			Timeout:       config.Duration{Duration: 3 * time.Second},
			DoHURL:        fastURL + "/resolve",
			HTTPSURL:      fastURL + "/json",
			ExitIPEchoURL: fastURL + "/echo",
		},
		UserAgent:       "publicvpn-scale-parity/1",
		SelfURL:         fastURL + "/json",
		UnlockEndpoints: &endpoints,
		// The production pacer spaces a node's own requests 100ms apart; the
		// contention mechanism under test is the REQUEST LOAD through the
		// shared instance, not the idle waits, so the sleeps collapse.
		Sleep: func(context.Context, time.Duration) error { return nil },
	}), sinkHostPort
}

type scaleBatchInstance struct{ addrs []string }

func (f *scaleBatchInstance) Addr() string    { return f.addrs[0] }
func (f *scaleBatchInstance) Addrs() []string { return f.addrs }
func (f *scaleBatchInstance) Close() error    { return nil }

// runScaleWave drives one production-shaped wave (slow tunnels, shared
// relay, real classifier hook or none) and returns the outcomes.
// runScaleWave drives one production-shaped wave (slow tunnels, shared
// relay, real classifier hook or none) and returns the outcomes. The batch
// size is the production big-batch default 1000 (the mission's fixture
// shape: a 1000-node batch, plus a 500-node sibling when the node count
// exceeds one batch).
func runScaleWave(
	t *testing.T, nodes []*model.Node, relay *scaleRelay, slowURL, fastURL string, hook bool, threads int,
) ([]store.ProbeResult, time.Duration) {
	t.Helper()
	factory := func(_ context.Context, batch []*model.Node) (probe.BatchSocksInstance, error) {
		addrs := make([]string, len(batch))
		for i := range addrs {
			addrs[i] = relay.Addr()
		}
		return &scaleBatchInstance{addrs: addrs}, nil
	}
	opts := probe.Options{
		Timeout:          3 * time.Second,
		Attempts:         2,
		URL:              slowURL,
		ExitIPURL:        fastURL + "/json",
		SpeedtestTimeout: time.Second,
		TCPPrefilter:     new(bool), // engine fixtures stay deterministic offline (nil = ON)
		Threads:          threads,
		BatchSize:        1000,
		BatchConcurrency: 8, // the production default
	}
	if hook {
		clf, sinkHostPort := scaleClassifier(t, fastURL)
		relay.addRoute(sinkHostPort, sinkHostPort) // DNS/STUN sink rides the relay to the real sink
		opts.Classifier = clf.ClassifyNode
	}
	start := time.Now()
	out, err := probe.RunWithBatchFactory(context.Background(), nodes, nil, factory, opts, "")
	duration := time.Since(start)
	require.NoError(t, err)
	require.Len(t, out, len(nodes))
	return out, duration
}

func scaleParity(t *testing.T, plain, classified []store.ProbeResult) int {
	t.Helper()
	require.Len(t, classified, len(plain))
	alive := 0
	for i := range plain {
		assert.Equal(t, plain[i].Key, classified[i].Key, "outcome order must match")
		assert.Equal(t, plain[i].Alive, classified[i].Alive, "probe alive %d must be byte-parity", i)
		assert.Equal(t, plain[i].Status, classified[i].Status, "probe status %d must be byte-parity", i)
		assert.Equal(t, plain[i].FailureKind, classified[i].FailureKind, "probe failure class %d must be byte-parity", i)
		assert.Equal(t, plain[i].Checks, classified[i].Checks, "probe checks %d must be byte-parity", i)
		if classified[i].Alive {
			alive++
		}
	}
	return alive
}

// TestClassifierScaleParity1000NodeBatch is the production-scale repro of
// the wave-58 collapse hunt: a 1000-node batch of slow-but-alive tunnels
// through ONE shared instance, the real classification battery as the hook,
// at the production batch concurrency. The hook runs AFTER the batch's
// outcome loop (internal/probe runBatchJobOnce), so alive outcomes must be
// byte-parity — the battery cannot retroactively change its own batch's
// verdicts, and its load must not starve anything into a different class.
func TestClassifierScaleParity1000NodeBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("production-scale parity wave — skipped in -short")
	}
	const n = 1000
	slow := scaleUpstream(t, 60*time.Millisecond) // slow-but-alive probe target
	fast := scaleUpstream(t, 0)                   // battery targets answer instantly
	relay := newScaleRelay(t, fast.Listener.Addr().String())
	slowHostPort := strings.TrimPrefix(slow.URL, "http://")
	relay.addRoute(slowHostPort, slowHostPort)

	nodes := scaleNodes("parity", n)
	plain, plainDur := runScaleWave(t, nodes, relay, slow.URL, fast.URL, false, 1)
	relayConnectsBeforeBattery := relay.connects.Load()
	classified, hookDur := runScaleWave(t, nodes, relay, slow.URL, fast.URL, true, 1)

	alive := scaleParity(t, plain, classified)
	require.Equal(t, n, alive, "every slow-but-alive tunnel must pass with the hook ON — a collapse here is the wave-58 repro")
	require.Greater(t, relay.connects.Load(), relayConnectsBeforeBattery,
		"the classification battery must demonstrably ride the same shared relay")
	// The classified wave pays the battery serially after its probe phase;
	// a starvation regression would blow this envelope far past 3x.
	assert.Less(t, hookDur, 3*plainDur,
		"classified wave wall time must stay bounded — hook took %s vs probe-only %s", hookDur, plainDur)
}

// TestClassifierScaleParityCrossBatchOverlap reproduces the production
// concurrency shape the single-batch test cannot: with Threads=2 the FIRST
// batch to finish probing (the 500-node sibling) classifies its alive nodes
// THROUGH the shared instance while the 1000-node batch is STILL probing
// over the SAME relay. The still-probing batch's outcomes must be
// byte-parity — classification load on the shared egress must not starve
// concurrent probes.
func TestClassifierScaleParityCrossBatchOverlap(t *testing.T) {
	if testing.Short() {
		t.Skip("production-scale parity wave — skipped in -short")
	}
	const n = 1500 // 1000-node batch + 500-node sibling at Threads=2
	slow := scaleUpstream(t, 60*time.Millisecond)
	fast := scaleUpstream(t, 0)
	relay := newScaleRelay(t, fast.Listener.Addr().String())
	slowHostPort := strings.TrimPrefix(slow.URL, "http://")
	relay.addRoute(slowHostPort, slowHostPort)

	nodes := scaleNodes("overlap", n)
	plain, plainDur := runScaleWave(t, nodes, relay, slow.URL, fast.URL, false, 2)
	classified, hookDur := runScaleWave(t, nodes, relay, slow.URL, fast.URL, true, 2)

	alive := scaleParity(t, plain, classified)
	require.Equal(t, n, alive, "every tunnel must pass with the hook ON under cross-batch classification load")
	assert.Less(t, hookDur, 3*plainDur,
		"classified wave wall time must stay bounded — hook took %s vs probe-only %s", hookDur, plainDur)
	assert.Greater(t, relay.peakLoad.Load(), int64(8),
		"the shared relay must have carried overlapping battery+probe load")
}
