package geo

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"

	"github.com/stretchr/testify/require"
)

// The classification battery's raw-TCP channels (DNS-over-TCP, STUN) dial
// through the tunnel; a target that accepts and then never answers wedges
// the deadline-less framed read forever. In the merged flow the probe batch
// lifecycle WAITS on every battery (classifyAliveNodes), so one wedged
// battery would stall the whole batch — the budget converts that into the
// honesty contract's outcome (skip the node; the next wave re-classifies).
// The external-package harness (socks_test.go) is package geo_test, so this
// file carries its own minimal relay.

// budgetBlackhole accepts connections and never speaks: no socks greeting
// answer, no DNS frame, no close — the silent-blackhole shape.
func budgetBlackhole(t *testing.T) string {
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
			t.Cleanup(func() { _ = conn.Close() }) // drain at teardown only
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return ln.Addr().String()
}

// budgetRelay is the minimal no-auth SOCKS5 CONNECT relay with per-target
// routes: the battery's tunnel-alive gate must reach a REAL 204 server (or
// the dead-tunnel fast-path skips the DNS channel entirely and the wedge is
// never reached), while the DNS-over-TCP target lands in the blackhole.
type budgetRelay struct {
	ln      net.Listener
	routes  map[string]string
	closers []io.Closer
	mu      sync.Mutex
	wg      sync.WaitGroup
}

func newBudgetRelay(t *testing.T, routes map[string]string) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	r := &budgetRelay{ln: ln, routes: routes}
	r.wg.Add(1)
	go r.serve()
	t.Cleanup(func() { _ = r.Close() })
	return ln.Addr().String()
}

func (r *budgetRelay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.ln.Close()
	for _, c := range r.closers {
		_ = c.Close()
	}
	r.wg.Wait()
	return err
}

func (r *budgetRelay) serve() {
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

func (r *budgetRelay) handle(conn net.Conn) {
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
	target := net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1])))
	r.mu.Lock()
	up, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", r.routes[target])
	r.mu.Unlock()
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = up.Close() }()
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	go func() { _, _ = io.Copy(up, conn) }()
	_, _ = io.Copy(conn, up)
}

// TestClassifyNodeReturnsBoundedUnderBlackholedBatteryChannel pins the
// merged flow's stall-safety: a battery channel that silently blackholes
// (accepts the tunnel dial, answers nothing — the deadline-less framed DNS
// read wedges) must not hang ClassifyNode past the node budget. The node
// budget is the ONLY bound: the production wave context is deadline-less,
// so nothing else converts the wedge into a return.
func TestClassifyNodeReturnsBoundedUnderBlackholedBatteryChannel(t *testing.T) {
	blackhole := budgetBlackhole(t)
	alive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent) // the tunnel-alive gate's 204
	}))
	t.Cleanup(alive.Close)
	relay := newBudgetRelay(t, map[string]string{
		strings.TrimPrefix(alive.URL, "http://"): strings.TrimPrefix(alive.URL, "http://"),
		blackhole:                                blackhole,
	})
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"query": "9.9.9.9"})
	}))
	t.Cleanup(site.Close)

	in := ClassifyInput{
		DataDir: t.TempDir(),
		Cfg: config.GeoConfig{
			Timeout:  config.Duration{Duration: 300 * time.Millisecond},
			DoHURL:   "http://127.0.0.1:1/resolve",
			HTTPSURL: "http://127.0.0.1:1/json",
		},
		UserAgent: "budget-test/1",
		SelfURL:   site.URL + "/json", // ladder rung 1 succeeds — the battery still runs
	}
	// Every battery channel dead-except the DNS-over-TCP target, which is
	// the blackhole through the relay: the wedge the budget must survive.
	in.UnlockEndpoints = &UnlockEndpoints{
		ChatGPCTrace:      strings.Repeat("x", 0) + "http://127.0.0.1:1/trace",
		ChatGPTCompliance: "http://127.0.0.1:1/compliance",
		NetflixTitleA:     "http://127.0.0.1:1/na",
		NetflixTitleB:     "http://127.0.0.1:1/nb",
		YouTubePremium:    "http://127.0.0.1:1/yt",
		TikTokHome:        "http://127.0.0.1:1/th",
		TikTokExplore:     "http://127.0.0.1:1/te",
		DisneyDevices:     "http://127.0.0.1:1/dd",
		DisneyAuth:        "http://127.0.0.1:1/da",
		DisneyGraphQL:     "http://127.0.0.1:1/dg",
		IPInfoWidget:      "http://127.0.0.1:1/iw",
		CFTrace:           "http://127.0.0.1:1/cf",
		EchoIPify:         "http://127.0.0.1:1/ify",
		EchoIPSB:          "http://127.0.0.1:1/isb",
		IPAPIContract:     "http://127.0.0.1:1/ipapi",
		AlivePrimary:      alive.URL + "/generate_204",
		AliveFallback:     "http://127.0.0.1:1/af",
		DNSServer:         blackhole,
		DNSName:           "o-o.myaddr.l.google.com",
	}
	clf := NewClassifier(in)

	old := classifyNodeBudget
	classifyNodeBudget = 2 * time.Second
	defer func() { classifyNodeBudget = old }()

	n := model.NewNode("s", "vless", "u-budget", "budget.example.com", 443, map[string]string{"security": "tls", "type": "tcp"})
	done := make(chan struct{})
	go func() {
		clf.ClassifyNode(context.Background(), n, relay, "1.2.3.4")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		t.Fatalf("ClassifyNode hung past the %s node budget — the merged batch lifecycle would stall on this node", classifyNodeBudget)
	}
}
