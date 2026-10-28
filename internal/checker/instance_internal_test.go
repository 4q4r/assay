package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	"public_vpn/internal/model"
	"public_vpn/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checkFakeEnv* name the knobs of the hermetic fake-xray helper: the test
// process re-executes ITSELF (os.Args[0]) as the "xray binary" under a mode
// env var — no external binary, no network beyond loopback httptest servers.
const (
	checkFakeModeEnv      = "CHECKFAKE_MODE"
	checkFakeDelayEnv     = "CHECKFAKE_BIND_DELAY_MS"
	checkFakeDeadDelayEnv = "CHECKFAKE_DEAD_DELAY_MS" // delayed bind for configs carrying the dead marker
	checkFakeEnvOutEnv    = "CHECKFAKE_ENV_OUT"
	checkFakeSiteEnv      = "CHECKFAKE_SITE_ADDR"
	checkFakeDeadMarkEnv  = "CHECKFAKE_DEAD_MARKER"

	checkFakeModeExit  = "exit"  // exit(1) instantly during boot (C1 geometry)
	checkFakeModeServe = "serve" // bind the config's socks port, serve socks5
)

// TestMain doubles as the fake-xray entrypoint: when the test binary is
// re-executed by StartTempXray with CHECKFAKE_MODE set, it plays xray and
// NEVER runs the tests.
func TestMain(m *testing.M) {
	switch os.Getenv(checkFakeModeEnv) {
	case checkFakeModeExit:
		os.Exit(1)
	case checkFakeModeServe:
		runCheckFakeServe()
		return // killed by the exact-PID Close; never fall through to tests
	}
	os.Exit(m.Run())
}

// runCheckFakeServe mimics the boot xray does: read the given config, (after
// an optional delay — the real binary takes ~100ms to bind) bind the socks
// inbound port and serve a minimal RFC 1928 CONNECT loop until killed. The
// egress behavior comes from the rendered config itself: a config containing
// CHECKFAKE_DEAD_MARKER simulates a dead outbound (every CONNECT is refused
// with reply 0x05), everything else forwards to the upstream test servers.
func runCheckFakeServe() {
	cfgPath := ""
	for i, a := range os.Args {
		if a == "-c" && i+1 < len(os.Args) {
			cfgPath = os.Args[i+1]
		}
	}
	if cfgPath == "" {
		os.Exit(2)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		os.Exit(2)
	}
	if out := os.Getenv(checkFakeEnvOutEnv); out != "" {
		_ = os.WriteFile(out, []byte(strings.Join(os.Environ(), "\n")), 0o600)
	}
	var cfg struct {
		Inbounds []struct {
			Port int `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || len(cfg.Inbounds) == 0 {
		os.Exit(2)
	}
	containsDead := os.Getenv(checkFakeDeadMarkEnv) != "" && strings.Contains(string(raw), os.Getenv(checkFakeDeadMarkEnv))
	delayEnv := checkFakeDelayEnv
	if containsDead && os.Getenv(checkFakeDeadDelayEnv) != "" {
		delayEnv = checkFakeDeadDelayEnv // per-instance bind delays: healthy binds FIRST, deterministically
	}
	if d := os.Getenv(delayEnv); d != "" {
		if ms, err := strconv.Atoi(d); err == nil && ms > 0 {
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Inbounds[0].Port)))
	if err != nil {
		os.Exit(1) // bind collision: die like a real xray would
	}
	dead := containsDead
	site := os.Getenv(checkFakeSiteEnv)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { _ = serveFakeSocks(conn, dead, site) }()
	}
}

// serveFakeSocks handles one socks5 client: greeting (no auth), CONNECT,
// then either a refusal (dead outbound) or a forward to the mapped target.
func serveFakeSocks(conn net.Conn, dead bool, site string) error {
	defer func() { _ = conn.Close() }()
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return err
	}
	var host string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return err
		}
		host = string(name)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	default:
		return fmt.Errorf("atyp %d unsupported", req[3])
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return err
	}
	if dead { // dead outbound: the socks inbound answers, egress refuses
		_, err := conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1])))
	if ip := net.ParseIP(host); ip == nil && site != "" {
		target = site // fake hostname → the httptest site behind the fake exit
	}
	upstream, err := (&net.Dialer{}).Dial("tcp", target)
	if err != nil {
		_, werr := conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if werr != nil {
			return werr
		}
		return err
	}
	defer func() { _ = upstream.Close() }()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	return nil
}

// fakeBin returns the re-executable "xray binary" for the given fake mode.
// t.Setenv propagates the mode to the child via the inherited environment.
func fakeBin(t *testing.T, mode string) string {
	t.Helper()
	t.Setenv(checkFakeModeEnv, mode)
	return os.Args[0]
}

func freedomOutbound() map[string]any {
	return map[string]any{"protocol": "freedom", "tag": tempOutboundTag}
}

// C1: a child that dies during boot must surface as a LOUD, BOUNDED error —
// never a hang — and Close must reap it and remove the temp config dir.
// Regression pin for the drained one-shot wait channel: awaitReadiness'
// death branch used to consume the single buffered value, leaving Close
// blocked on the same channel forever (external timeout needed, check-*
// dirs leaked — reviewer-reproduced 2/2 with xray_bin=/bin/true).
func TestStartTempXrayBootDeathTerminatesBoundedly(t *testing.T) {
	workDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	inst, err := StartTempXray(ctx, fakeBin(t, checkFakeModeExit), workDir, freedomOutbound())
	elapsed := time.Since(start)

	require.Error(t, err, "an instantly-exiting fake xray must fail the boot loudly")
	assert.Nil(t, inst)
	assert.Contains(t, err.Error(), "exited during startup", "the death must carry its cause")
	assert.Less(t, elapsed, 5*time.Second, "boot death must terminate within a bound, not hang")

	entries, rerr := os.ReadDir(workDir)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "a failed boot must leave ZERO temp config dirs")
}

// C2 invariant pin (direct): two concurrent boots must never be handed the
// same port. Pre-fix, the loser's port scan landed inside the winner's
// boot-to-bind window and BOTH instances claimed one port — the loser's
// readiness poll then succeeded VIA THE WINNER'S socket. The delayed fake
// bind keeps that window open deterministically.
func TestConcurrentBootPortsDistinct(t *testing.T) {
	workDir := t.TempDir()
	t.Setenv(checkFakeDelayEnv, "150")
	bin := fakeBin(t, checkFakeModeServe)

	const n = 2
	addrs := make([]string, n)
	errs := make([]error, n)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate
			inst, err := StartTempXray(context.Background(), bin, workDir, freedomOutbound())
			errs[i] = err
			if inst != nil {
				addrs[i] = inst.Addr()
				_ = inst.Close()
			}
		}(i)
	}
	close(gate)
	wg.Wait()
	for i := range n {
		require.NoError(t, errs[i], "instance %d must boot", i)
	}
	assert.NotEqual(t, addrs[0], addrs[1],
		"two concurrent instances must never share a socks port (wrong measurements)")

	entries, rerr := os.ReadDir(workDir)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "every instance must clean its temp dir on Close")
}

// C2 invariant pin (engine-level, reviewer's repro): with a dead-outbound
// node booted concurrently with a healthy one, the dead node can NEVER
// report ok>0 — its attempts must ride its OWN (refusing) instance, never
// the winner's tunnel. Six rounds, deterministic by construction (the boot
// mutex makes the collision impossible rather than improbable).
func TestEngineDeadNodeNeverScoresOKUnderConcurrency(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("<html>real page content ", 300))) // > tinyBodyLimit
	}))
	defer site.Close()
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Answer":[{"name":"site.example","type":1,"TTL":300,"data":"10.1.2.3"}]}`))
	}))
	defer doh.Close()
	siteAddr := strings.TrimPrefix(site.URL, "http://")
	// Every spawned child must enter the fake-xray path, never the test suite.
	t.Setenv(checkFakeModeEnv, checkFakeModeServe)
	// Deterministic pre-fix geometry: the healthy fake binds at 100ms, the
	// dead one at 400ms — the dead instance's port scan lands INSIDE the
	// winner's boot-to-bind window (the reviewer's repro), so any ok>0 on
	// the dead row is proof its attempts rode the winner's tunnel.
	t.Setenv(checkFakeDelayEnv, "100")
	t.Setenv(checkFakeDeadDelayEnv, "400")
	t.Setenv(checkFakeSiteEnv, siteAddr)
	t.Setenv(checkFakeDeadMarkEnv, "dead.example.com")

	workDir := t.TempDir()
	ctx := context.Background()
	for round := 1; round <= 6; round++ {
		nodes := []*model.Node{
			model.NewNode("test", "vless", "uuid-1", "alive.example.com", 443, map[string]string{"type": "ws", "path": "/p"}),
			model.NewNode("test", "vless", "uuid-2", "dead.example.com", 443, map[string]string{"type": "ws", "path": "/p"}),
		}
		records := []*model.GeoRecord{
			{
				Tag: "pool-ok-01", Source: "test", Scheme: "vless", Host: "alive.example.com", Port: 443,
				Country: "NL", City: "Amsterdam", ASN: "AS9000", ISP: "Test ISP",
				LastProbe: "2026-10-27T00:00:00Z", Alive: true, RTTMs: 50,
			},
			{
				Tag: "pool-dead-01", Source: "test", Scheme: "vless", Host: "dead.example.com", Port: 443,
				Country: "DE", City: "Frankfurt", ASN: "AS9001", ISP: "Test ISP",
				LastProbe: "2026-10-27T00:00:00Z", Alive: true, RTTMs: 60,
			},
		}
		cfgDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "geo-base.jsonl"), geoJSONL(t, records), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "filtered.jsonl"), nodesJSONL(t, nodes), 0o600))

		rep, err := Run(ctx, Options{
			Targets:          []string{httpTargetURL(t, site)},
			Attempts:         1,
			Timeout:          5 * time.Second,
			Concurrency:      2,
			XrayBin:          os.Args[0], // the PRODUCTION factory path, no override
			GeoBasePath:      filepath.Join(cfgDir, "geo-base.jsonl"),
			ProbeResultsPath: filepath.Join(cfgDir, "probe-results.jsonl"),
			NodesPath:        filepath.Join(cfgDir, "filtered.jsonl"),
			GeoTTL:           24 * time.Hour,
			WorkDir:          workDir,
			dohOverride:      doh.URL + "/resolve",
		})
		require.NoError(t, err, "round %d", round)
		require.Len(t, rep.Targets, 1)
		var okRow, deadRow *NodeResult
		for _, r := range rep.Targets[0].Rows {
			switch r.Tag {
			case "pool-ok-01":
				okRow = r
			case "pool-dead-01":
				deadRow = r
			}
		}
		require.NotNil(t, okRow, "round %d", round)
		require.NotNil(t, deadRow, "round %d", round)
		assert.False(t, deadRow.InstanceFailed, "round %d: the dead node must BOOT (its socks works)", round)
		assert.Equal(t, 1, deadRow.Total, "round %d", round)
		assert.Equal(t, 0, deadRow.OK,
			"round %d: a dead-outbound node can NEVER report ok>0 — scoring means its attempts rode another instance's tunnel", round)
		assert.Equal(t, 1, okRow.OK, "round %d: healthy control node must serve (fixture sanity)", round)
	}

	entries, rerr := os.ReadDir(workDir)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "every temp config dir must be cleaned after the run")
}

// I1b: the child environment must carry NONE of the six proxy variables —
// ambient proxy inheritance would silently route check traffic through the
// live client (L5).
func TestStartTempXrayStripsProxyEnv(t *testing.T) {
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(v, "http://127.0.0.1:10809")
	}
	dump := filepath.Join(t.TempDir(), "child-env.txt")
	t.Setenv(checkFakeEnvOutEnv, dump)
	workDir := t.TempDir()

	inst, err := StartTempXray(context.Background(), fakeBin(t, checkFakeModeServe), workDir, freedomOutbound())
	require.NoError(t, err)
	require.NotNil(t, inst)
	childEnv, rerr := os.ReadFile(dump)
	require.NoError(t, rerr, "the fake must dump the child env")
	require.NoError(t, inst.Close())

	for _, v := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY="} {
		assert.NotContains(t, string(childEnv), v,
			"proxy variable %s must be stripped from the child env (L5)", strings.TrimSuffix(v, "="))
	}
	entries, rerr := os.ReadDir(workDir)
	require.NoError(t, rerr)
	assert.Empty(t, entries)
}

// I1c: the port scan must skip occupied ports — a foreign listener on a
// port (any process, not just our fakes) forces the next candidate — and
// fail loud when the whole range is exhausted.
func TestFreeInstancePortSkipsOccupiedAndFailsLoud(t *testing.T) {
	ctx := context.Background()

	// The scan starts at the bottom of the range when that port is actually
	// free (skipped under a foreign holder — the skip assertions pin the rest).
	if ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(instancePortMin))); err == nil {
		require.NoError(t, ln.Close())
		first, ferr := freeInstancePort(ctx)
		require.NoError(t, ferr)
		assert.Equal(t, instancePortMin, first, "a free range hands out its lowest port")
	}

	// Occupy the first two range ports (foreign holders count too).
	occupied := map[int]bool{}
	var listeners []net.Listener
	for p := instancePortMin; p < instancePortMin+2; p++ {
		if ln, lerr := (&net.ListenConfig{}).Listen(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p))); lerr == nil {
			listeners = append(listeners, ln)
			occupied[p] = true
		}
	}
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	next, err := freeInstancePort(ctx)
	require.NoError(t, err)
	assert.NotContains(t, occupied, next, "occupied ports must be skipped, never handed out")
	assert.GreaterOrEqual(t, next, instancePortMin)
	assert.LessOrEqual(t, next, instancePortMax)
	handCheck, herr := (&net.ListenConfig{}).Listen(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(next)))
	require.NoError(t, herr, "a handed-out port must actually be bindable")
	listeners = append(listeners, handCheck) // stays occupied through the exhaustion step

	// Exhaust the rest of the range: the scan must fail loud, not stall.
	// Foreign-held ports (anything already bound outside this test) count as
	// occupied too — the invariant under test is "no bindable port ⇒ loud
	// error", whatever holds the port.
	for p := next + 1; p <= instancePortMax; p++ {
		if ln, lerr := (&net.ListenConfig{}).Listen(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p))); lerr == nil {
			listeners = append(listeners, ln)
		}
	}
	_, err = freeInstancePort(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no free port")
}

// M2 test lands with the M2 implementation (newXrayFactory knobs) — see the
// fix commit; its RED is the build failure against the old 2-arg signature.

// M2: temp outbounds carry the SAME hardening as the live renderer —
// tcp_max_seg is emitted mandatorily and the TLS fingerprint is applied.
// Zero knobs normalize to the config defaults (an unhardened temp instance
// must be unconstructible).
func TestTempOutboundCarriesHardeningKnobs(t *testing.T) {
	cases := []struct {
		name      string
		knobs     render.Config
		wantSeg   int
		wantPrint string
	}{
		{"zero knobs normalize to defaults", render.Config{}, 1440, "firefox"},
		{"explicit knobs pass through", render.Config{TCPMaxSeg: 1234, TLSFingerprint: "chrome"}, 1234, "chrome"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workDir := t.TempDir()
			node := model.NewNode("test", "vless", "uuid-1", "tls.example.com", 443, map[string]string{
				"type": "ws", "path": "/p", "security": "tls", "sni": "tls.example.com",
			})
			inst, err := newXrayFactory(fakeBin(t, checkFakeModeServe), workDir, tc.knobs)(context.Background(), node)
			require.NoError(t, err)
			raw, rerr := os.ReadFile(filepath.Join(inst.(*xrayInstance).dir, "config.json"))
			require.NoError(t, rerr)
			require.NoError(t, inst.Close())

			var cfg struct {
				Outbounds []struct {
					StreamSettings struct {
						Sockopt map[string]any `json:"sockopt"`
						TLS     map[string]any `json:"tlsSettings"`
					} `json:"streamSettings"`
				} `json:"outbounds"`
			}
			require.NoError(t, json.Unmarshal(raw, &cfg))
			require.Len(t, cfg.Outbounds, 1)
			seg, ok := cfg.Outbounds[0].StreamSettings.Sockopt["tcpMaxSeg"].(float64)
			require.True(t, ok, "tcpMaxSeg must be emitted mandatorily")
			assert.InDelta(t, float64(tc.wantSeg), seg, 0.0001, "tcp_max_seg must ride the temp outbound")
			fingerprint, ok := cfg.Outbounds[0].StreamSettings.TLS["fingerprint"].(string)
			require.True(t, ok, "tls fingerprint must be applied")
			assert.Equal(t, tc.wantPrint, fingerprint, "tls fingerprint must ride the temp outbound")
		})
	}
}

// --- tiny JSONL helpers for the engine-level C2 fixture (store-free) ---

func geoJSONL(t *testing.T, records []*model.GeoRecord) []byte {
	t.Helper()
	var b strings.Builder
	for _, r := range records {
		raw, err := json.Marshal(r)
		require.NoError(t, err)
		b.Write(raw)
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func nodesJSONL(t *testing.T, nodes []*model.Node) []byte {
	t.Helper()
	var b strings.Builder
	for _, n := range nodes {
		raw, err := json.Marshal(n)
		require.NoError(t, err)
		b.Write(raw)
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// httpTargetURL renders an http:// target whose HOST is a fake name (the
// socks5h remote-DNS pin) and whose PORT is the site's.
func httpTargetURL(t *testing.T, site *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(site.URL, "http://"))
	require.NoError(t, err)
	return "http://site.example:" + port
}
