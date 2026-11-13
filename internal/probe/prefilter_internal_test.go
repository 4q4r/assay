package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"assay/internal/model"
	"assay/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Wave-1 TCP pre-filter tests (owner-approved probe-optimization program).
// Contract under test: the pre-filter decides WHO reaches batching — closed
// endpoints are excluded from the wave with a per-reason drop report, UDP
// transports bypass (a TCP dial says nothing about a UDP transport), each
// unique endpoint dials once and the verdict fans out to every link sharing
// it, and an explicit [probe].tcp_prefilter=false disables the stage with
// zero dials. Probe verdict logic is untouched.

// prefilterOff is the explicit stage-off knob (engine fixtures drive fake
// endpoints that must never be TCP-dialed).
func prefilterOff() *bool {
	v := false
	return &v
}

// countingDialer is the dial-seam double: it records every dial it is asked
// for and answers with the configured failure class (or passes through to a
// real dialer when next is set).
type countingDialer struct {
	mu     sync.Mutex
	dialed []string
	err    error // when non-nil, every dial fails with this error
	block  bool  // when true, dials block until the dial context expires
	next   func(ctx context.Context, network, address string) (net.Conn, error)
}

func (d *countingDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	switch {
	case d.block:
		<-ctx.Done()
		return nil, fmt.Errorf("dial tcp %s: %w", address, ctx.Err())
	case d.err != nil:
		return nil, d.err
	case d.next != nil:
		return d.next(ctx, network, address)
	default:
		var nd net.Dialer
		return nd.DialContext(ctx, network, address)
	}
}

func (d *countingDialer) calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

// refusedEndpoint hands out a loopback host:port that deterministically
// refuses connections (bound, then closed — nothing listens).
// refusedEndpoint returns a loopback endpoint that REFUSES connections: a
// kernel-ephemeral port is bound, closed, and then VERIFIED to refuse. The
// verification is the hermeticity (run 5a5d69b local -race flakes): long-
// lived local services (dev-harness listeners, the live assay daemon's own
// churn) allocate kernel-ephemeral ports through the same bind-:0 window,
// the kernel favors just-freed ports, and an unverified freed port can be
// re-bound by a foreign listener before the pre-filter's dial — which then
// honestly reports the endpoint alive and the fixture's drop expectation
// breaks. A candidate that fails verification (dials connect or time out)
// is discarded and the next one is tried; the product's pre-filter is not
// involved in the choice.
func refusedEndpoint(t *testing.T) (string, int) {
	t.Helper()
	var lc net.ListenConfig
	const maxCandidates = 32
	for range maxCandidates {
		ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		host, portStr, err := net.SplitHostPort(ln.Addr().String())
		require.NoError(t, err)
		require.NoError(t, ln.Close())
		port, err := strconv.Atoi(portStr)
		require.NoError(t, err)
		if dialRefused(host, port) {
			return host, port
		}
	}
	t.Fatalf("no verifiably refused loopback endpoint after %d candidates — local port churn is hostile", maxCandidates)
	return "", 0
}

// dialRefused reports whether dialing host:port reliably refuses: three
// consecutive dial attempts must fail with a non-timeout dial error
// (ECONNREFUSED on loopback). A successful dial means a foreign listener
// owns the port; a timeout is an ambiguous state (a dropped SYN is not a
// refusal) — both disqualify the candidate.
func dialRefused(host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	for range 3 {
		d := net.Dialer{Timeout: 250 * time.Millisecond}
		c, err := d.DialContext(context.Background(), "tcp", addr)
		if err == nil {
			_ = c.Close() // a foreign listener owns the port — not refused
			return false
		}
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return false // a dropped SYN is not a refusal — ambiguous state
		}
	}
	return true
}

// tcpNode builds a plain vless/tcp/tls node with an explicit endpoint.
func tcpNode(name, host string, port int) *model.Node {
	return model.NewNode("pf", "vless", "uuid-"+name, host, port,
		map[string]string{"security": "tls", "type": "tcp"})
}

// jobsOf wraps nodes into the link-unique probe jobs the engine builds.
func jobsOf(nodes []*model.Node) []*probeJob {
	byLink := make(map[string]*probeJob, len(nodes))
	ordered := make([]*probeJob, 0, len(nodes))
	for _, n := range nodes {
		link := n.Link()
		job, dup := byLink[link]
		if dup {
			job.keys = append(job.keys, n.Key)
			continue
		}
		job = &probeJob{link: link, keys: []string{n.Key}, host: n.Host, node: n, order: len(ordered)}
		byLink[link] = job
		ordered = append(ordered, job)
	}
	return ordered
}

func TestEndpointForNode(t *testing.T) {
	tests := []struct {
		name string
		node *model.Node
		want string
	}{
		{"plain host", tcpNode("a", "de.example.com", 443), "de.example.com:443"},
		{"host case normalized for dedup", tcpNode("a", "DE.Example.COM", 443), "de.example.com:443"},
		{"bracketed ipv6 unwrapped (JoinHostPort re-wraps)", tcpNode("a", "[2001:db8::1]", 2053), "[2001:db8::1]:2053"},
		{"empty host bypasses", tcpNode("a", "", 443), ""},
		{"zero port bypasses", tcpNode("a", "de.example.com", 0), ""},
		{"out-of-range port bypasses", tcpNode("a", "de.example.com", 70000), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, endpointForNode(tt.node))
		})
	}
}

func TestIsUDPTransport(t *testing.T) {
	tests := []struct {
		name string
		node *model.Node
		want bool
	}{
		{"hysteria2 scheme bypasses", model.NewNode("pf", "hysteria2", "u", "h.example", 443,
			map[string]string{"security": "tls"}), true},
		{"vless with mkcp transport bypasses", model.NewNode("pf", "vless", "u", "h.example", 443,
			map[string]string{"security": "tls", "type": "kcp"}), true},
		{"vless with quic transport bypasses", model.NewNode("pf", "vless", "u", "h.example", 443,
			map[string]string{"security": "tls", "type": "quic"}), true},
		{"vless tcp does not bypass", tcpNode("a", "h.example", 443), false},
		{"ss tcp does not bypass", model.NewNode("pf", "ss", "pw", "h.example", 443,
			map[string]string{"type": "tcp", "method": "aes-128-gcm"}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isUDPTransport(tt.node))
		})
	}
}

func TestClassifyDialFailure(t *testing.T) {
	_, port := refusedEndpoint(t)
	var dialer net.Dialer
	_, rerr := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.Error(t, rerr, "nothing listens — the dial must refuse")
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"connection refused", rerr, "refused"},
		{"per-dial timeout", fmt.Errorf("dial tcp h:443: %w", context.DeadlineExceeded), "timeout"},
		{"deadline exceeded alias", fmt.Errorf("dial tcp h:443: %w", os.ErrDeadlineExceeded), "timeout"},
		{"dns no such host", &net.DNSError{Err: "no such host", Name: "h.example", IsNotFound: true}, "dns"},
		{"network unreachable", fmt.Errorf("dial tcp 10.255.255.1:443: %w", errors.New("connect: network is unreachable")), "unreachable"},
		{"connection reset", fmt.Errorf("read tcp 1.2.3.4:5678->5.6.7.8:443: %w", errors.New("read: connection reset by peer")), "reset"},
		{"unclassified", errors.New("dial tcp h:443: weird kernel state"), "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, classifyDialFailure(tt.err))
		})
	}
}

// TestTCPPrefilterStage is the table-driven core: one row per stage behavior,
// each pinning who reaches batching and what the drop report counts.
func TestTCPPrefilterStage(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(site.Close)
	aliveHost, alivePortStr, err := net.SplitHostPort(site.Listener.Addr().String())
	require.NoError(t, err)
	alivePort, err := strconv.Atoi(alivePortStr)
	require.NoError(t, err)
	deadHost, deadPort := refusedEndpoint(t)
	hyHost, hyPort := refusedEndpoint(t) // dead if TCP-dialed — the bypass must save it

	newNodes := func() []*model.Node {
		return []*model.Node{
			tcpNode("alive", aliveHost, alivePort),
			tcpNode("dead", deadHost, deadPort),
			model.NewNode("pf", "hysteria2", "uuid-hy", hyHost, hyPort, map[string]string{"security": "tls"}),
		}
	}

	tests := []struct {
		name        string
		dialer      func(*countingDialer) // seam setup (the seam always fronts the real dialer)
		wantDials   int
		wantPassing []string // node names
		wantDead    int
		wantBypass  int
		wantUnique  int
		wantDrops   map[string]int
	}{
		{
			name:        "default ON filters dead, bypasses hysteria2, passes the rest",
			dialer:      nil,
			wantDials:   2, // alive + dead endpoints; the hysteria2 endpoint is never dialed
			wantPassing: []string{"alive", "hy"},
			wantDead:    1,
			wantBypass:  1,
			wantUnique:  2,
			wantDrops:   map[string]int{"refused": 1},
		},
		{
			name:        "explicit true behaves like absent",
			dialer:      nil,
			wantDials:   2,
			wantPassing: []string{"alive", "hy"},
			wantDead:    1,
			wantBypass:  1,
			wantUnique:  2,
			wantDrops:   map[string]int{"refused": 1},
		},
		{
			name:        "dial timeouts count as dead, bypass node untouched",
			dialer:      func(d *countingDialer) { d.block = true },
			wantDials:   2,
			wantPassing: []string{"hy"},
			wantDead:    2,
			wantBypass:  1,
			wantUnique:  2,
			wantDrops:   map[string]int{"timeout": 2},
		},
		{
			name: "dns failure counts as dead",
			dialer: func(d *countingDialer) {
				d.err = &net.DNSError{Err: "no such host", Name: "blocked.example", IsNotFound: true}
			},
			wantDials:   2,
			wantPassing: []string{"hy"},
			wantDead:    2,
			wantBypass:  1,
			wantUnique:  2,
			wantDrops:   map[string]int{"dns": 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes := newNodes()
			seam := &countingDialer{}
			if tt.dialer != nil {
				tt.dialer(seam)
			}
			opts := Options{
				TCPPrefilter:        func() *bool { v := true; return &v }(),
				TCPPrefilterWorkers: 8,
				TCPPrefilterTimeout: time.Second,
				dialer:              seam.dial,
			}
			passing, stats := runTCPPrefilter(context.Background(), jobsOf(nodes), opts)
			assert.Len(t, seam.calls(), tt.wantDials, "dial count")
			// Fixture uuids are "uuid-<name>" — resolve passing jobs back to
			// node names (keys are sha hashes, loopback hosts collide).
			gotNames := make([]string, 0, len(passing))
			for _, j := range passing {
				gotNames = append(gotNames, strings.TrimPrefix(j.node.UUID, "uuid-"))
			}
			assert.ElementsMatch(t, tt.wantPassing, gotNames, "who reaches batching")
			assert.Equal(t, tt.wantDead, stats.linksDead, "filtered-dead links")
			assert.Equal(t, tt.wantBypass, stats.linksBypassed, "bypassed-udp links")
			assert.Equal(t, tt.wantUnique, stats.uniqueEndpoints, "unique endpoints dialed")
			assert.Equal(t, 3, stats.linksTotal, "total links seen")
			assert.Equal(t, tt.wantDrops, stats.drops, "drop-reason breakdown")
			// Order re-normalization contract: surviving jobs carry 0-based
			// indices matching their position in the returned slice.
			for i, j := range passing {
				assert.Equal(t, i, j.order, "surviving jobs must be re-indexed for the outcome slices")
			}
		})
	}
}

func TestTCPPrefilterDropReport(t *testing.T) {
	deadHost, deadPort := refusedEndpoint(t)
	nodes := []*model.Node{
		tcpNode("a", deadHost, deadPort),
		tcpNode("b", deadHost, deadPort), // same endpoint, different link
		model.NewNode("pf", "vless", "uuid-c", strings.ToUpper(deadHost), deadPort,
			map[string]string{"security": "tls", "type": "tcp"}), // case-variant spelling, same endpoint
	}
	seam := &countingDialer{}
	opts := Options{TCPPrefilterWorkers: 4, dialer: seam.dial}
	_, stats := runTCPPrefilter(context.Background(), jobsOf(nodes), opts)

	assert.Len(t, seam.calls(), 1, "one dial per unique endpoint — three links share it")
	assert.Equal(t, 3, stats.linksDead, "every link sharing the endpoint dies together")
	assert.Equal(t, 3, stats.drops["refused"], "drop report counts the reason per link")
	assert.Empty(t, stats.drops["timeout"], "no other reason class fired")
	line := stats.logLine()
	assert.Contains(t, line, "probe pre-filter:")
	assert.Contains(t, line, "1") // unique endpoints
	assert.Contains(t, line, strconv.Itoa(stats.linksDead))
}

func TestTCPPrefilterDedupAliveFansOutPass(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(site.Close)
	host, portStr, err := net.SplitHostPort(site.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	nodes := []*model.Node{
		tcpNode("a", host, port),
		tcpNode("b", host, port),
		tcpNode("c", host, port),
	}
	seam := &countingDialer{} // real-dial passthrough
	opts := Options{TCPPrefilterWorkers: 4, dialer: seam.dial}
	passing, stats := runTCPPrefilter(context.Background(), jobsOf(nodes), opts)
	assert.Len(t, seam.calls(), 1, "one dial for the shared endpoint")
	assert.Len(t, passing, 3, "all three links pass together")
	assert.Equal(t, 3, stats.linksPassed)
	assert.Empty(t, stats.drops, "no drops on an alive endpoint")
}

func TestTCPPrefilterCanceledWaveIsNotAVerdict(t *testing.T) {
	deadHost, deadPort := refusedEndpoint(t)
	nodes := []*model.Node{tcpNode("a", deadHost, deadPort)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	seam := &countingDialer{}
	opts := Options{TCPPrefilterWorkers: 1, dialer: seam.dial}
	passing, stats := runTCPPrefilter(ctx, jobsOf(nodes), opts)
	assert.Len(t, passing, 1, "a canceled wave produces NO dead verdict — the node passes unchecked")
	assert.Zero(t, stats.linksDead, "canceled dials are not verdicts (xray-knife FailCanceled parity)")
	assert.Equal(t, 1, stats.linksUnchecked, "the canceled dial is counted as unchecked")
	assert.Zero(t, stats.linksPassed, "unchecked dials never inflate passed-through")
	assert.Empty(t, stats.drops)
}

// TestTCPPrefilterKnobAtWaveLevel pins the tri-state semantics at the
// RunWithBatchFactory boundary: nil (absent) = ON — the stage runs and dials
// the (dead) endpoint, dropping it before batching; explicit false = the
// stage is skipped ENTIRELY — zero dials, every node reaches the batch
// factory, no stage line printed.
func TestTCPPrefilterKnobAtWaveLevel(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(site.Close)
	socks := newSocksServer(t, site.Listener.Addr().String())
	deadHost, deadPort := refusedEndpoint(t)

	// A real refused dial once — the seam's failure payload (any dial proves
	// the stage ran, and a refused class drops the node).
	var refDialer net.Dialer
	_, refusedErr := refDialer.DialContext(context.Background(), "tcp", net.JoinHostPort(deadHost, strconv.Itoa(deadPort)))
	require.Error(t, refusedErr)

	newDeadNode := func() *model.Node { return tcpNode("dead", deadHost, deadPort) }
	run := func(t *testing.T, knob *bool) (*countingDialer, []string, string) {
		t.Helper()
		node := newDeadNode()
		seam := &countingDialer{err: refusedErr}
		var arrivals []string
		var mu sync.Mutex
		bf := BatchFactory(func(_ context.Context, batch []*model.Node) (BatchSocksInstance, error) {
			mu.Lock()
			for _, n := range batch {
				arrivals = append(arrivals, n.Key)
			}
			mu.Unlock()
			addrs := make([]string, len(batch))
			for i := range addrs {
				addrs[i] = socks.ln.Addr().String()
			}
			return &fakeBatchInstance{addrs: addrs}, nil
		})
		var log strings.Builder
		opts := Options{
			Timeout: 5 * time.Second, Attempts: 1, URL: site.URL, Threads: 1,
			TCPPrefilter: knob, dialer: seam.dial, Progress: &log,
		}
		_, err := RunWithBatchFactory(context.Background(), []*model.Node{node}, nil, bf, opts, "")
		require.NoError(t, err)
		return seam, arrivals, log.String()
	}

	t.Run("absent knob = stage ON (dials happen, dead dropped)", func(t *testing.T) {
		seam, arrivals, progress := run(t, nil)
		assert.Len(t, seam.calls(), 1, "the stage dialed the endpoint")
		assert.Empty(t, arrivals, "the dead endpoint never reaches the batch factory")
		assert.Contains(t, progress, "probe pre-filter:", "the stage line is printed")
	})

	t.Run("explicit false = stage skipped entirely (zero dials)", func(t *testing.T) {
		seam, arrivals, progress := run(t, prefilterOff())
		assert.Empty(t, seam.calls(), "zero dials when the stage is off")
		assert.Len(t, arrivals, 1, "the node reaches the batch factory unchanged")
		assert.NotContains(t, progress, "probe pre-filter:", "no stage line when skipped")
	})

	t.Run("explicit true = stage ON", func(t *testing.T) {
		seam, arrivals, _ := run(t, func() *bool { v := true; return &v }())
		assert.Len(t, seam.calls(), 1)
		assert.Empty(t, arrivals)
	})
}

// fakeBatchInstance hands every node the same live SOCKS5 address (the
// engine's in-process socks server relays to the target site). One address
// per batch node — the engine's address-count guard is part of the contract.
type fakeBatchInstance struct{ addrs []string }

func (f *fakeBatchInstance) Addr() string    { return f.addrs[0] }
func (f *fakeBatchInstance) Addrs() []string { return f.addrs }
func (f *fakeBatchInstance) Close() error    { return nil }

// TestRunWithBatchFactoryTCPPrefilterWave pins the fixture-level integration:
// the pre-filter runs BEFORE batching — dead endpoints never reach the batch
// factory nor the results file (their previous probe history stays untouched
// — no fake writes), alive endpoints and UDP bypasses do.
func TestRunWithBatchFactoryTCPPrefilterWave(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK — the tunnel reached the target."))
	}))
	t.Cleanup(site.Close)
	socks := newSocksServer(t, site.Listener.Addr().String())
	aliveHost, alivePortStr, err := net.SplitHostPort(site.Listener.Addr().String())
	require.NoError(t, err)
	alivePort, err := strconv.Atoi(alivePortStr)
	require.NoError(t, err)
	deadHost, deadPort := refusedEndpoint(t)
	hyHost, hyPort := refusedEndpoint(t)

	alive := tcpNode("alive", aliveHost, alivePort)
	dead := tcpNode("dead", deadHost, deadPort)
	hy := model.NewNode("pf", "hysteria2", "uuid-hy", hyHost, hyPort, map[string]string{"security": "tls"})
	nodes := []*model.Node{dead, alive, hy} // dead first: proves exclusion is by verdict, not order

	var mu sync.Mutex
	var batched []*model.Node
	bf := BatchFactory(func(_ context.Context, batch []*model.Node) (BatchSocksInstance, error) {
		mu.Lock()
		batched = append(batched, batch...)
		mu.Unlock()
		addrs := make([]string, len(batch))
		for i := range addrs {
			addrs[i] = socks.ln.Addr().String()
		}
		return &fakeBatchInstance{addrs: addrs}, nil
	})

	opts := Options{Timeout: 5 * time.Second, Attempts: 1, URL: site.URL, Threads: 2}
	resultsPath := filepath.Join(t.TempDir(), "probe.jsonl")
	results, err := RunWithBatchFactory(context.Background(), nodes, nil, bf, opts, resultsPath)
	require.NoError(t, err)

	mu.Lock()
	batchedKeys := make([]string, len(batched))
	for i, n := range batched {
		batchedKeys[i] = n.Key
	}
	mu.Unlock()
	assert.ElementsMatch(t, []string{alive.Key, hy.Key}, batchedKeys,
		"dead endpoint never reaches the batch factory; hysteria2 arrives despite a dead TCP endpoint")

	require.Len(t, results, 2, "the excluded node produces NO wave record (no fake writes)")
	gotKeys := map[string]bool{}
	for _, r := range results {
		gotKeys[r.Key] = true
	}
	assert.Contains(t, gotKeys, alive.Key)
	assert.Contains(t, gotKeys, hy.Key)
	assert.NotContains(t, gotKeys, dead.Key)
	for _, r := range results {
		if r.Key == alive.Key {
			assert.True(t, r.Alive, "alive node probed through the batch instance")
		}
	}

	stored, err := store.ReadProbeResults(resultsPath)
	require.NoError(t, err)
	assert.Len(t, stored, 2, "the probe log carries exactly the probed nodes")
	for _, r := range stored {
		assert.NotEqual(t, dead.Key, r.Key, "no probe-log write for the pre-filtered node")
	}
}

func TestPrefilterStatsLogLine(t *testing.T) {
	s := prefilterStats{
		linksTotal: 100, uniqueEndpoints: 80, linksDead: 15, linksBypassed: 5, linksPassed: 77,
		linksUnchecked: 3,
		drops:          map[string]int{"refused": 12, "timeout": 3},
	}
	line := s.logLine()
	assert.Contains(t, line, "unique-endpoints 80")
	assert.Contains(t, line, "links 100")
	assert.Contains(t, line, "filtered-dead 15")
	assert.Contains(t, line, "bypassed-udp 5")
	assert.Contains(t, line, "passed-through 77")
	assert.Contains(t, line, "unchecked 3")
	assert.Contains(t, line, "refused:12")
	assert.Contains(t, line, "timeout:3")
}
