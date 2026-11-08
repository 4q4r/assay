package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// socksServer is a minimal in-process SOCKS5 CONNECT server (no-auth only —
// exactly what the checker's x/net socks client offers). It lets the engine
// tests drive the PRODUCTION through-tunnel client end to end: the temp
// instance seam hands out this server's address, and it relays CONNECTs to
// the loopback httptest doubles. Same pattern the geo tests use.
type socksServer struct {
	ln      net.Listener
	mu      sync.Mutex
	closers []io.Closer
	routes  map[string]string // requested host:port -> upstream (echo double etc.)
	done    sync.WaitGroup
	// Connects counts completed CONNECT relays (wire evidence the probe rode
	// the tunnel seam, not some ambient path).
	Connects atomic.Int32
}

func newSocksServer(t *testing.T, upstream string) *socksServer {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks test server listen: %v", err)
	}
	s := &socksServer{ln: ln, routes: map[string]string{}}
	s.done.Add(1)
	go s.serve(upstream)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func (s *socksServer) Addr() string { return s.ln.Addr().String() }

// addRoute pins one CONNECT target to a specific upstream (the exit-IP echo
// double rides its own httptest server — the relay must route by target, or
// the echo would hit the probe site and answer unparseable body).
func (s *socksServer) addRoute(hostport, upstream string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[hostport] = upstream
}

func (s *socksServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.ln.Close()
	for _, c := range s.closers {
		_ = c.Close()
	}
	s.done.Wait()
	return err
}

func (s *socksServer) serve(upstream string) {
	defer s.done.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.closers = append(s.closers, conn)
		s.mu.Unlock()
		s.done.Go(func() {
			s.handle(conn, upstream)
		})
	}
}

func (s *socksServer) handle(conn net.Conn, upstream string) {
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

	s.mu.Lock()
	target := s.routes[net.JoinHostPort(host, strconv.Itoa(portNum))]
	if target == "" {
		target = upstream
	}
	s.mu.Unlock()

	up, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", target)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // conn refused
		return
	}
	s.Connects.Add(1)
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	defer func() { _ = up.Close() }()
	// Handle must stay alive until the stream ends — the deferred conn/up
	// closes fire on return (checker's relay: one blocking copy + one twin).
	go func() { _, _ = io.Copy(up, conn) }()
	_, _ = io.Copy(conn, up)
}

// tunnelFactory adapts the socks test server into the engine's factory seam:
// production hands out one temp xray per node; tests hand out the loopback
// socks relay (same SocksInstance contract, no real xray needed).
func tunnelFactory(addr string) Factory {
	return func(_ context.Context, _ *model.Node) (SocksInstance, error) {
		return &staticInstance{addr: addr}, nil
	}
}

type staticInstance struct{ addr string }

func (i *staticInstance) Addr() string { return i.addr }
func (i *staticInstance) Close() error { return nil }

// bootFailFactory always fails: the instance-boot failure path.
func bootFailFactory(err error) Factory {
	return func(_ context.Context, _ *model.Node) (SocksInstance, error) {
		return nil, err
	}
}

func node(t *testing.T, name string) *model.Node {
	t.Helper()
	return model.NewNode("s", "vless", "uuid-"+name, name+".example.com", 443, map[string]string{"security": "tls", "type": "tcp"})
}

// healthySite is the canonical reachable target: small 2xx page, no
// blockpage markers.
func healthySite(t *testing.T) *httptest.Server {
	t.Helper()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK — the tunnel reached the target."))
	}))
	t.Cleanup(site.Close)
	return site
}

// exitIPEcho is the exit-IP double: it answers exactly what the production
// ip-api self-report answers, so the engine's D8 anchor parse is exercised
// against the real response shape.
func exitIPEcho(t *testing.T, ip string) string {
	t.Helper()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"query": ip, "countryCode": "DE"})
	}))
	t.Cleanup(site.Close)
	return site.URL
}

func baseOpts(siteURL, echoURL string) Options {
	// The engine fixtures drive FAKE endpoints (name.example.com) through
	// in-process doubles — they pin probe verdict logic, not reachability,
	// so the wave-1 TCP pre-filter is explicitly OFF here (prefilter tests
	// cover the ON path; engine tests must stay deterministic offline).
	opts := Options{
		Timeout:          5 * time.Second,
		Attempts:         3,
		URL:              siteURL,
		ExitIPURL:        echoURL,
		SpeedtestTimeout: time.Second,
		TCPPrefilter:     prefilterOff(),
	}
	return opts
}

func TestEngineAliveMapping(t *testing.T) {
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	socks.addRoute(strings.TrimPrefix(echoURL, "http://"), strings.TrimPrefix(echoURL, "http://"))
	n := node(t, "alive")

	opts := baseOpts(site.URL, echoURL)
	opts.SpeedtestURL = site.URL // tiny but real sample: bytes/time > 0
	opts.Speedtest = true
	out, err := Run(context.Background(), []*model.Node{n}, tunnelFactory(socks.Addr()), opts, "")
	require.NoError(t, err)
	require.Len(t, out, 1)

	r := out[0]
	assert.Equal(t, n.Key, r.Key)
	assert.True(t, r.Alive, "3/3 success attempts = alive")
	assert.Equal(t, "passed", r.Status)
	assert.Equal(t, "5.6.7.8", r.ExitIP, "exit IP observed through the tunnel (D8)")
	assert.Positive(t, r.SpeedBPS, "speedtest through the same instance")
	assert.Equal(t, 3, r.Checks)
	assert.Equal(t, 3, r.TotalChecks)
	assert.Positive(t, r.RTTMs, "RTT from the tunnel attempt timings")
	assert.Empty(t, r.FailureKind)
	assert.Positive(t, socks.Connects.Load(), "traffic rode the tunnel seam")
}

// C-1 pin (fix round): the PRODUCTION option literal — the field the echo
// ships as left untouched, exactly how internal/cli's probeOptions builds
// Options — must carry the tunnel exit IP on every alive record when the
// echo is reachable. Pre-fix the echo flag was an unexported bool defaulting
// false and never set outside tests: the live wave recorded 0/128 exit IPs
// against a reachable echo (the feature was UNWIRED in production, not
// slow). Hermetic: the echo double rides the loopback socks relay.
func TestProductionWaveCarriesExitIPByDefault(t *testing.T) {
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	socks.addRoute(strings.TrimPrefix(echoURL, "http://"), strings.TrimPrefix(echoURL, "http://"))
	n := node(t, "prod-echo")

	// The production literal: only the fields probeOptions sets — nothing
	// echo-specific — with ONE documented exception: the pre-filter knob is
	// pinned OFF because this fixture's endpoint is fake (name.example.com
	// must never be TCP-dialed); production receives the knob from config
	// (default ON) via probeOptions.
	opts := Options{
		Timeout:      5 * time.Second,
		Attempts:     3,
		URL:          site.URL,
		ExitIPURL:    echoURL,
		TCPPrefilter: prefilterOff(),
	}
	out, err := Run(context.Background(), []*model.Node{n}, tunnelFactory(socks.Addr()), opts, "")
	require.NoError(t, err)
	require.Len(t, out, 1)
	r := out[0]
	require.True(t, r.Alive, "fixture sanity: the node must be alive for the echo to run at all")
	assert.Equal(t, "5.6.7.8", r.ExitIP,
		"an alive record with a reachable echo carries its D8 exit IP — the echo defaults ON in production")
}

// The explicit OFF switch: a caller that sets ExitProbe=false suppresses
// the echo even when it is reachable — the off-switch half of the nil=on
// contract (C-1 fix round).
func TestEngineExitProbeExplicitOff(t *testing.T) {
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	socks.addRoute(strings.TrimPrefix(echoURL, "http://"), strings.TrimPrefix(echoURL, "http://"))
	n := node(t, "echo-off")

	opts := baseOpts(site.URL, echoURL)
	opts.ExitProbe = new(false)
	out, err := Run(context.Background(), []*model.Node{n}, tunnelFactory(socks.Addr()), opts, "")
	require.NoError(t, err)
	require.Len(t, out, 1)
	r := out[0]
	require.True(t, r.Alive, "fixture sanity: alive node, echo reachable")
	assert.Empty(t, r.ExitIP, "an explicit ExitProbe=false suppresses the echo even when reachable")
}

func TestEngineDeadMapping(t *testing.T) {
	site := healthySite(t)
	// Relay to a dead upstream: every CONNECT answers refusal → dial-fail.
	socks := newSocksServer(t, "127.0.0.1:1")
	echoURL := exitIPEcho(t, "5.6.7.8")
	n := node(t, "dead")

	out, err := Run(context.Background(), []*model.Node{n}, tunnelFactory(socks.Addr()),
		baseOpts(site.URL, echoURL), "")
	require.NoError(t, err)
	require.Len(t, out, 1)

	r := out[0]
	assert.False(t, r.Alive)
	assert.Equal(t, "failed", r.Status)
	assert.Equal(t, "dial-fail", r.FailureKind, "the dominant failure class is recorded")
	assert.Empty(t, r.ExitIP, "a dead tunnel yields no exit IP (echo only runs on alive nodes)")
	assert.Equal(t, 0, r.Checks)
	assert.Zero(t, r.RTTMs)
}

func TestEngineBootFailureIsLoud(t *testing.T) {
	n := node(t, "bootfail")
	boom := errors.New("xray exited during startup: boom")
	out, err := Run(context.Background(), []*model.Node{n}, bootFailFactory(boom), Options{Attempts: 3, TCPPrefilter: prefilterOff()}, "")
	require.NoError(t, err, "a boot failure is a per-node outcome, never a wave error")
	require.Len(t, out, 1)
	r := out[0]
	assert.False(t, r.Alive)
	assert.Equal(t, "failed", r.Status)
	assert.Equal(t, "instance-boot", r.FailureKind)
	assert.Contains(t, r.Reason, "boom", "the boot error reaches the probe log")
}

func TestEngineBlockpageIsNotAlive(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("error code: 1020"))
	}))
	t.Cleanup(site.Close)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	n := node(t, "blocked")

	out, err := Run(context.Background(), []*model.Node{n}, tunnelFactory(socks.Addr()),
		baseOpts(site.URL, echoURL), "")
	require.NoError(t, err)
	require.Len(t, out, 1)
	r := out[0]
	assert.False(t, r.Alive, "alive = success class; a blockpage is not success")
	assert.Equal(t, "failed", r.Status)
	assert.Equal(t, "blocked-http", r.FailureKind)
	assert.Contains(t, r.Reason, "403", "the refusal status surfaces in the log")
}

// TestEngineBlockedPageSignature pins the tiny-body classifier path: a 2xx
// answer carrying a blockpage signature classifies blocked-page — success
// status, NOT alive.
func TestEngineBlockedPageSignature(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>Just a moment...</html>"))
	}))
	t.Cleanup(site.Close)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	n := node(t, "cfpage")

	out, err := Run(context.Background(), []*model.Node{n}, tunnelFactory(socks.Addr()),
		baseOpts(site.URL, echoURL), "")
	require.NoError(t, err)
	require.Len(t, out, 1)
	r := out[0]
	assert.False(t, r.Alive, "a blockpage masquerading as 2xx is not success")
	assert.Equal(t, "blocked-page", r.FailureKind)
	assert.Contains(t, r.Reason, "just a moment", "the blockpage signature surfaces in the log")
}

func TestEngineSemiPassed(t *testing.T) {
	var calls atomic.Int32
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1)%2 == 0 {
			// Abrupt reset: the attempt dies at the transport level.
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				if conn != nil {
					_ = conn.Close()
				}
			}
			return
		}
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(site.Close)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	n := node(t, "flaky")

	out, err := Run(context.Background(), []*model.Node{n}, tunnelFactory(socks.Addr()),
		baseOpts(site.URL, echoURL), "")
	require.NoError(t, err)
	require.Len(t, out, 1)
	r := out[0]
	assert.True(t, r.Alive, "a tunnel that serves some attempts is alive")
	assert.Equal(t, "semi-passed", r.Status)
	assert.Positive(t, r.Checks)
	assert.Less(t, r.Checks, r.TotalChecks)
}

func TestEngineSpeedtestOnlyOnAlive(t *testing.T) {
	site := healthySite(t)
	echoURL := exitIPEcho(t, "5.6.7.8")
	aliveSocks := newSocksServer(t, site.Listener.Addr().String())
	aliveNode, deadNode := node(t, "fast"), node(t, "slow")

	opts := baseOpts(site.URL, echoURL)
	opts.Speedtest = true
	opts.SpeedtestURL = site.URL
	// Routing factory: the alive node rides the working relay, the dead node
	// gets a socks endpoint whose upstream refuses (a dead tunnel).
	factory := Factory(func(_ context.Context, n *model.Node) (SocksInstance, error) {
		if n.Key == deadNode.Key {
			return &staticInstance{addr: "127.0.0.1:1"}, nil
		}
		return &staticInstance{addr: aliveSocks.Addr()}, nil
	})
	out, err := Run(context.Background(), []*model.Node{aliveNode, deadNode}, factory, opts, "")
	require.NoError(t, err)
	require.Len(t, out, 2)
	byKey := map[string]store.ProbeResult{out[0].Key: out[0], out[1].Key: out[1]}
	assert.Positive(t, byKey[aliveNode.Key].SpeedBPS, "alive node carries a speed measurement")
	assert.Equal(t, int64(0), byKey[deadNode.Key].SpeedBPS, "a dead tunnel measures nothing")
}

func TestEngineSpeedtestDisabled(t *testing.T) {
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	n := node(t, "nospeed")
	opts := baseOpts(site.URL, echoURL) // Speedtest false
	out, err := Run(context.Background(), []*model.Node{n}, tunnelFactory(socks.Addr()), opts, "")
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, int64(0), out[0].SpeedBPS)
}

func TestEngineDedupLinkBothNodesTakeOutcome(t *testing.T) {
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	a, _ := node(t, "dupa"), node(t, "dupb")
	b := model.NewNode("s", "vless", "uuid-dupa", "dupa.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"}) // identical link to `a`
	b.Key = "other-key"

	out, err := Run(context.Background(), []*model.Node{a, b}, tunnelFactory(socks.Addr()),
		baseOpts(site.URL, echoURL), "")
	require.NoError(t, err)
	require.Len(t, out, 2, "both nodes appear in the wave outcome")
	assert.True(t, out[0].Alive)
	assert.True(t, out[1].Alive, "identical links probe once; both nodes take the outcome")
}

func TestEngineOrderPreserved(t *testing.T) {
	site := healthySite(t)
	echoURL := exitIPEcho(t, "5.6.7.8")
	good := newSocksServer(t, site.Listener.Addr().String())
	nodes := make([]*model.Node, 0, 8)
	for i := range 8 {
		nodes = append(nodes, node(t, fmt.Sprintf("ord%02d", i)))
	}
	out, err := Run(context.Background(), nodes, tunnelFactory(good.Addr()),
		baseOpts(site.URL, echoURL), "")
	require.NoError(t, err)
	require.Len(t, out, len(nodes))
	for i := range nodes {
		assert.Equal(t, nodes[i].Key, out[i].Key, "input order is preserved regardless of completion order")
	}
}

func TestEngineAppendsToProbeLog(t *testing.T) {
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	n := node(t, "logged")
	path := filepath.Join(t.TempDir(), "probe-results.jsonl")

	_, err := Run(context.Background(), []*model.Node{n}, tunnelFactory(socks.Addr()),
		baseOpts(site.URL, echoURL), path)
	require.NoError(t, err)
	latest, err := store.LatestProbeByKey(path)
	require.NoError(t, err)
	require.Contains(t, latest, n.Key)
	assert.True(t, latest[n.Key].Alive)
	assert.WithinDuration(t, time.Now().UTC(), latest[n.Key].CheckedAt, time.Minute)
}

func TestEngineConcurrencyBound(t *testing.T) {
	// A concurrency of 1 must still complete the whole wave (serialization
	// works; no deadlock when workers == 1).
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	nodes := []*model.Node{node(t, "c1"), node(t, "c2"), node(t, "c3")}
	opts := baseOpts(site.URL, echoURL)
	opts.Threads = 1
	out, err := Run(context.Background(), nodes, tunnelFactory(socks.Addr()), opts, "")
	require.NoError(t, err)
	require.Len(t, out, 3)
	for _, r := range out {
		assert.True(t, r.Alive)
	}
}

// --- skip_fresh_within: carried over from the knife era, contract intact. ---

func skipFreshFixture(t *testing.T) ([]*model.Node, map[string]store.ProbeResult) {
	t.Helper()
	freshNode, staleNode := node(t, "freshpass"), node(t, "stalepass")
	now := time.Now().UTC()
	latest := map[string]store.ProbeResult{
		freshNode.Key: {Key: freshNode.Key, Host: freshNode.Host, Alive: true, Status: "passed", CheckedAt: now.Add(-time.Minute)},
		staleNode.Key: {Key: staleNode.Key, Host: staleNode.Host, Alive: true, Status: "passed", CheckedAt: now.Add(-2 * time.Hour)},
	}
	return []*model.Node{freshNode, staleNode}, latest
}

func TestSkipFreshDefaultProbesEverything(t *testing.T) {
	nodes, latest := skipFreshFixture(t)
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	var probed atomic.Int32
	factory := Factory(func(_ context.Context, _ *model.Node) (SocksInstance, error) {
		probed.Add(1)
		return &staticInstance{addr: socks.Addr()}, nil
	})
	out, err := Run(context.Background(), nodes, factory, Options{Latest: latest, TCPPrefilter: prefilterOff()}, "")
	require.NoError(t, err)
	assert.Len(t, out, 2, "window 0 = probe everything (default behavior)")
	assert.Equal(t, int32(2), probed.Load(), "both nodes must be probed")
}

func TestSkipFreshWindowSkipsFreshPassed(t *testing.T) {
	nodes, latest := skipFreshFixture(t)
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	var probed atomic.Int32
	factory := Factory(func(_ context.Context, n *model.Node) (SocksInstance, error) {
		probed.Add(1)
		_ = n
		return &staticInstance{addr: socks.Addr()}, nil
	})
	var logText strings.Builder
	opts := Options{SkipFreshWithin: 30 * time.Minute, Latest: latest, Progress: &logText, TCPPrefilter: prefilterOff()}
	out, err := Run(context.Background(), nodes, factory, opts, "")
	require.NoError(t, err)
	require.Len(t, out, 1, "the skipped node gets NO probe-log entry (its history stays intact)")
	assert.Equal(t, nodes[1].Key, out[0].Key, "only the stale node is probed")
	assert.Equal(t, int32(1), probed.Load())
	assert.Contains(t, logText.String(), "skipping", "the skip must be logged per node")
	assert.Contains(t, logText.String(), nodes[0].Key)
}

func TestSkipFreshIncludesFailedAndSemiPassed(t *testing.T) {
	failedNode, semiNode := node(t, "freshfail"), node(t, "freshsemi")
	now := time.Now().UTC()
	latest := map[string]store.ProbeResult{
		failedNode.Key: {Key: failedNode.Key, Alive: false, Status: "failed", CheckedAt: now.Add(-time.Minute)},
		semiNode.Key:   {Key: semiNode.Key, Alive: true, Status: "semi-passed", CheckedAt: now.Add(-time.Minute)},
	}
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	var probed atomic.Int32
	factory := Factory(func(_ context.Context, _ *model.Node) (SocksInstance, error) {
		probed.Add(1)
		return &staticInstance{addr: socks.Addr()}, nil
	})
	_, err := Run(context.Background(), []*model.Node{failedNode, semiNode}, factory,
		Options{SkipFreshWithin: time.Hour, Latest: latest, TCPPrefilter: prefilterOff()}, "")
	require.NoError(t, err)
	assert.Equal(t, int32(2), probed.Load(), "failed/semi-passed are not `passed` — both must be probed")
}

func TestSkipFreshSkippedNodeKeepsHistory(t *testing.T) {
	nodes, latest := skipFreshFixture(t)
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	path := filepath.Join(t.TempDir(), "p.jsonl")
	factory := Factory(func(_ context.Context, _ *model.Node) (SocksInstance, error) {
		return &staticInstance{addr: socks.Addr()}, nil
	})
	_, err := Run(context.Background(), nodes, factory,
		Options{SkipFreshWithin: 30 * time.Minute, Latest: latest, TCPPrefilter: prefilterOff()}, path)
	require.NoError(t, err)
	got, err := store.LatestProbeByKey(path)
	require.NoError(t, err)
	assert.NotContains(t, got, nodes[0].Key, "a skipped node must not gain a synthetic (dead) record")
	assert.Contains(t, got, nodes[1].Key)
}

// classifyRecorder records the classifier hook's calls and a monotonic
// sequence shared with the fixture instance's Close — the ordering pin
// (classification happens BEFORE the teardown). rtts additionally captures
// the per-node probe RTT the engine hands the hook (the adaptive-timeout
// input).
type classifyRecorder struct {
	mu    sync.Mutex
	calls []string // "key@addr=exitIP"
	rtts  map[string]float64
	seq   int
	close int
}

func (c *classifyRecorder) classifier() ClassifyFunc {
	return func(_ context.Context, n *model.Node, addr string, exitIP string, rttMs float64) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.seq++
		c.calls = append(c.calls, n.Key+"@"+addr+"="+exitIP)
		if c.rtts == nil {
			c.rtts = map[string]float64{}
		}
		c.rtts[n.Key] = rttMs
	}
}

// rttOf returns the probe RTT the hook received for one node's key.
func (c *classifyRecorder) rttOf(key string) (float64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rtt, ok := c.rtts[key]
	return rtt, ok
}

func (c *classifyRecorder) noteClose() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.close = c.seq + 1
	c.seq = c.close
}

func (c *classifyRecorder) got() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func (c *classifyRecorder) classifiedBeforeClose() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls) > 0 && c.seq >= c.close && c.close >= 1
}

// closingBatchInstance sequences its Close against the recorder.
type closingBatchInstance struct {
	fakeBatchInstance

	rec *classifyRecorder
}

func (f *closingBatchInstance) Close() error {
	f.rec.noteClose()
	return f.fakeBatchInstance.Close()
}

// TestClassificationRidesHotBatchInstance pins the merged flow (owner order
// 2026-11-07 «сразу на чеке»): every ALIVE node of a batch is classified
// through the SAME hot instance address its probe just used, BEFORE the
// batch instance is torn down, carrying the probe's D8 exit IP — and the
// classification's own traffic demonstrably rides that same socks port (the
// battery-hits-on-the-wire pin). Dead nodes never reach the classifier.
func TestClassificationRidesHotBatchInstance(t *testing.T) {
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	socks.addRoute(strings.TrimPrefix(echoURL, "http://"), strings.TrimPrefix(echoURL, "http://"))

	aliveA, aliveB, dead := node(t, "alive-a"), node(t, "alive-b"), node(t, "dead-x")
	nodes := []*model.Node{aliveA, aliveB, dead}
	rec := &classifyRecorder{}

	// The batch factory hands every batch node the socks endpoint its probe
	// will use — alive nodes the working relay, the dead node a refusing
	// endpoint (a dead tunnel) — and sequences Close against the recorder.
	factory := func(_ context.Context, batch []*model.Node) (BatchSocksInstance, error) {
		addrs := make([]string, len(batch))
		for i, bn := range batch {
			if bn.Key == dead.Key {
				addrs[i] = "127.0.0.1:1" // dead tunnel: every attempt dial-fails
				continue
			}
			addrs[i] = socks.Addr()
		}
		return &closingBatchInstance{fakeBatchInstance{addrs: addrs}, rec}, nil
	}

	opts := baseOpts(site.URL, echoURL)
	opts.Threads = 1
	opts.BatchSize = 10
	opts.BatchConcurrency = 8
	opts.Attempts = 1
	// ExitProbe stays nil = ON: the D8 anchor rides to the classifier.
	opts.Classifier = rec.classifier()

	out, err := RunWithBatchFactory(context.Background(), nodes, nil, factory, opts, "")
	require.NoError(t, err)
	require.Len(t, out, 3)
	alive, deadCount := 0, 0
	for _, r := range out {
		if r.Alive {
			alive++
			assert.Equal(t, "5.6.7.8", r.ExitIP)
		} else {
			deadCount++
		}
	}
	require.Equal(t, 2, alive, "fixture sanity: two alive nodes")
	require.Equal(t, 1, deadCount, "fixture sanity: the dead node fails")

	calls := rec.got()
	require.Len(t, calls, 2, "exactly the ALIVE nodes are classified — the dead node is not")
	byKey := map[string]string{}
	for _, call := range calls {
		parts := strings.SplitN(call, "@", 2)
		byKey[parts[0]] = parts[1]
	}
	for _, n := range []*model.Node{aliveA, aliveB} {
		got, ok := byKey[n.Key]
		require.True(t, ok, "alive node %s classified", n.Key)
		addrIP := strings.SplitN(got, "=", 2)
		assert.Equal(t, socks.Addr(), addrIP[0],
			"classification rides the SAME hot instance address the probe used")
		assert.Equal(t, "5.6.7.8", addrIP[1], "the classifier carries the probe's D8 exit IP")
	}
	assert.NotContains(t, byKey, dead.Key, "the dead node is never classified")
	assert.True(t, rec.classifiedBeforeClose(),
		"classification happened BEFORE the batch instance teardown")
	assert.Positive(t, socks.Connects.Load(), "probe traffic rode the tunnel seam")
}

// TestClassifierNilIsProbeOnly pins the escape hatch at the engine level: a
// nil Classifier means a probe-only wave — outcomes byte-identical to a
// classified run of the same wave.
func TestClassifierNilIsProbeOnly(t *testing.T) {
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	socks.addRoute(strings.TrimPrefix(echoURL, "http://"), strings.TrimPrefix(echoURL, "http://"))
	nodes := halvingNodes(t, "parity", 5)

	run := func(withClassifier bool) []store.ProbeResult {
		rec := &classifyRecorder{}
		factory := func(_ context.Context, batch []*model.Node) (BatchSocksInstance, error) {
			addrs := make([]string, len(batch))
			for i := range addrs {
				addrs[i] = socks.Addr()
			}
			return &fakeBatchInstance{addrs: addrs}, nil
		}
		opts := baseOpts(site.URL, echoURL)
		opts.Threads = 1
		opts.BatchSize = 10
		opts.BatchConcurrency = 8
		opts.Attempts = 1
		if withClassifier {
			opts.Classifier = rec.classifier()
		}
		out, err := RunWithBatchFactory(context.Background(), nodes, nil, factory, opts, "")
		require.NoError(t, err)
		return out
	}
	plain := run(false)
	classified := run(true)
	require.Len(t, plain, len(classified))
	for i := range plain {
		assert.Equal(t, plain[i].Alive, classified[i].Alive, "probe outcome %d unchanged", i)
		assert.Equal(t, plain[i].Status, classified[i].Status, "probe status %d unchanged", i)
		assert.Equal(t, plain[i].ExitIP, classified[i].ExitIP, "probe exit IP %d unchanged", i)
		assert.Equal(t, plain[i].FailureKind, classified[i].FailureKind, "probe failure class %d unchanged", i)
	}
}

// TestClassifierRunsOnSingleNodeFactoryPath pins the same contract on the
// non-batch path: the hook fires with the single-node instance's address,
// before its teardown.
func TestClassifierRunsOnSingleNodeFactoryPath(t *testing.T) {
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	socks.addRoute(strings.TrimPrefix(echoURL, "http://"), strings.TrimPrefix(echoURL, "http://"))
	n := node(t, "single")
	rec := &classifyRecorder{}

	opts := baseOpts(site.URL, echoURL)
	opts.Attempts = 1
	opts.Classifier = rec.classifier()

	out, err := Run(context.Background(), []*model.Node{n}, tunnelFactory(socks.Addr()), opts, "")
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.True(t, out[0].Alive, "fixture sanity: the node is alive")
	calls := rec.got()
	require.Len(t, calls, 1)
	parts := strings.SplitN(calls[0], "@", 2)
	assert.Equal(t, n.Key, parts[0])
	assert.Equal(t, socks.Addr(), strings.SplitN(parts[1], "=", 2)[0],
		"the single-node path classifies through the SAME hot instance")
	assert.True(t, strings.HasSuffix(parts[1], "=5.6.7.8"), "the exit IP rides along")
}

// TestClassificationSkippedWhenWaveContextDead pins the shutdown contract: a
// canceled wave context skips the classification pass entirely (the
// adaptive layer re-decides the batch; the next wave re-classifies) — no
// battery is started against a dying context.
func TestClassificationSkippedWhenWaveContextDead(t *testing.T) {
	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	echoURL := exitIPEcho(t, "5.6.7.8")
	socks.addRoute(strings.TrimPrefix(echoURL, "http://"), strings.TrimPrefix(echoURL, "http://"))
	nodes := halvingNodes(t, "ctxdead", 3)
	rec := &classifyRecorder{}

	factory := func(_ context.Context, batch []*model.Node) (BatchSocksInstance, error) {
		addrs := make([]string, len(batch))
		for i := range addrs {
			addrs[i] = socks.Addr()
		}
		return &fakeBatchInstance{addrs: addrs}, nil
	}
	opts := baseOpts(site.URL, echoURL)
	opts.Threads = 1
	opts.BatchSize = 10
	opts.BatchConcurrency = 8
	opts.Attempts = 1
	opts.Classifier = rec.classifier()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // dead before the wave starts: every phase skips
	out, err := RunWithBatchFactory(ctx, nodes, nil, factory, opts, "")
	require.NoError(t, err)
	require.Len(t, out, 3)
	assert.Empty(t, rec.got(), "a dead context never starts the classification pass")
}

// TestClassifierCarriesEachNodeOwnProbeRTT pins the adaptive-timeout input
// (owner order 2026-11-08): the engine hands each node its OWN measured
// probe RTT — neither zero nor a sibling's — so the battery can derive the
// per-node timeout from the node the verdict describes. Two alive nodes
// probe targets with different injected delays (30ms vs none) through
// separate socks endpoints; the recorded RTTs must match their own band.
func TestClassifierCarriesEachNodeOwnProbeRTT(t *testing.T) {
	slowSite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(30 * time.Millisecond)
		_, _ = w.Write([]byte("OK — the tunnel reached the target."))
	}))
	t.Cleanup(slowSite.Close)
	fastSite := healthySite(t)
	socksSlow := newSocksServer(t, strings.TrimPrefix(slowSite.URL, "http://"))
	socksFast := newSocksServer(t, strings.TrimPrefix(fastSite.URL, "http://"))

	slow, fast := node(t, "rtt-slow"), node(t, "rtt-fast")
	nodes := []*model.Node{slow, fast}
	rec := &classifyRecorder{}
	factory := func(_ context.Context, batch []*model.Node) (BatchSocksInstance, error) {
		addrs := make([]string, len(batch))
		for i, bn := range batch {
			if bn.Key == slow.Key {
				addrs[i] = socksSlow.Addr()
				continue
			}
			addrs[i] = socksFast.Addr()
		}
		return &fakeBatchInstance{addrs: addrs}, nil
	}
	opts := baseOpts(slowSite.URL, "")
	opts.Threads = 1
	opts.BatchSize = 10
	opts.BatchConcurrency = 8
	opts.Attempts = 1
	// ExitProbe off: this pin is about the RTT input, not the D8 anchor.
	off := false
	opts.ExitProbe = &off
	opts.Classifier = rec.classifier()

	out, err := RunWithBatchFactory(context.Background(), nodes, nil, factory, opts, "")
	require.NoError(t, err)
	require.Len(t, out, 2)
	for _, r := range out {
		require.True(t, r.Alive, "fixture sanity: both nodes alive")
	}

	slowRTT, okSlow := rec.rttOf(slow.Key)
	fastRTT, okFast := rec.rttOf(fast.Key)
	require.True(t, okSlow, "the slow node's classification call is recorded")
	require.True(t, okFast, "the fast node's classification call is recorded")
	assert.GreaterOrEqual(t, slowRTT, 20.0, "the slow node carries its own measured (delayed) probe RTT")
	assert.Less(t, fastRTT, 10.0, "the fast node carries its own (near-instant) probe RTT")
	assert.Greater(t, slowRTT, fastRTT, "each node's RTT is its OWN measurement — never a sibling's, never a shared value")
}
