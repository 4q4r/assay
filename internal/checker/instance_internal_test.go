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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"assay/internal/model"
	"assay/internal/render"

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

	checkFakeModeExit       = "exit"        // exit(1) instantly during boot (C1 geometry)
	checkFakeModeExitStderr = "exit_stderr" // exit(1) with stderr message
	checkFakeModeServe      = "serve"       // bind the config's socks port, serve socks5
)

// TestMain doubles as the fake-xray entrypoint: when the test binary is
// re-executed by StartTempXray with CHECKFAKE_MODE set, it plays xray and
// NEVER runs the tests.
func TestMain(m *testing.M) {
	switch os.Getenv(checkFakeModeEnv) {
	case checkFakeModeExit:
		os.Exit(1)
	case checkFakeModeExitStderr:
		_, _ = fmt.Fprintln(os.Stderr, "FATAL: custom diagnostic message from fake xray on stderr")
		os.Exit(1)
	case checkFakeModeServe:
		runCheckFakeServe()
		return // killed by the exact-PID Close; never fall through to tests
	}
	// The suite's temp instances boot OUTSIDE the production 18xxx band —
	// the live watch daemon churns that band hourly and a full -race run
	// used to flake against it (live-ops fix; see testPortBand below).
	SetTestPortBand(testPortBandMin, testPortBandMax)
	os.Exit(m.Run())
}

// testPortBand is the suite's DISJOINT temp-instance scan band — the twin of
// the production 18500-18799 (same 300-port width), below the kernel
// ephemeral range (32768-60999 on this box, so the kernel never auto-assigns
// these ports to unrelated sockets) and verified clear of every listener.
// The production watch daemon boots its own temp instances into 18xxx on
// every hourly wave; sharing the band made full -race runs flake against
// that live churn (boot/ports/env-strip tests lost the boot race, and a
// daemon boot could equally lose against a test). The PRODUCTION band stays
// untouched — this is the suite-side construction only.
const (
	testPortBandMin = 28500
	testPortBandMax = 28799
)

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

// TestStartTempXrayBatchBootDeathCapturesStderr verifies that when a batch
// xray instance exits with error during startup, its stderr output is captured
// and present in the returned error message.
func TestStartTempXrayBatchBootDeathCapturesStderr(t *testing.T) {
	workDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	outbounds := []map[string]any{
		freedomOutbound(),
		freedomOutbound(),
	}

	inst, err := StartTempXrayBatch(ctx, fakeBin(t, checkFakeModeExitStderr), workDir, outbounds)
	require.Error(t, err, "exiting fake xray batch must return error")
	assert.Nil(t, inst)
	assert.Contains(t, err.Error(), "FATAL: custom diagnostic message from fake xray on stderr",
		"batch startup error must contain stderr output")

	entries, rerr := os.ReadDir(workDir)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "failed batch boot must clean temp config dir")
}

// TestBatchXrayInstanceConcurrentCloseAndCancel verifies that concurrent Close()
// and context cancellation during/after startup does not race, double-close,
// panic on closed channels, or leak temp directories under -race.
func TestBatchXrayInstanceConcurrentCloseAndCancel(t *testing.T) {
	workDir := t.TempDir()
	t.Setenv(checkFakeDelayEnv, "50")
	bin := fakeBin(t, checkFakeModeServe)

	for range 5 {
		ctx, cancel := context.WithCancel(context.Background())
		outbounds := []map[string]any{
			freedomOutbound(),
			freedomOutbound(),
		}

		inst, err := StartTempXrayBatch(ctx, bin, workDir, outbounds)
		if err != nil {
			cancel()
			continue
		}

		// Fire concurrent Close() calls and context cancellation
		const workers = 10
		var wg sync.WaitGroup
		wg.Add(workers + 1)

		go func() {
			defer wg.Done()
			cancel()
		}()

		for range workers {
			go func() {
				defer wg.Done()
				_ = inst.Close()
			}()
		}

		wg.Wait()
		cancel()
	}

	entries, rerr := os.ReadDir(workDir)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "all batch temp directories must be cleaned up without leaks")
}

// C2 invariant pin (direct): two concurrent boots must never be handed the
// same port. Pre-fix, the loser's port scan landed inside the winner's
// boot-to-bind window and BOTH instances claimed one port — the loser's
// readiness poll then succeeded VIA THE WINNER'S socket. The delayed fake
// bind keeps that window open deterministically.
//
// LIFETIME BARRIER: both instances stay OPEN until every boot has finished —
// the Close calls run only after the port assertion. Recording the addr and
// closing inside the boot goroutine let one instance's Close free its port
// before the sibling's scan ran (legal for SEQUENTIAL lifetimes — the
// allocator may re-issue a closed port), and the windows CI scheduler chose
// exactly that order, failing the assertion with two identical addrs. With
// the barrier, the ports must differ while BOTH instances are live: the
// second scan runs inside the first instance's live-bind window, which is
// precisely the geometry the boot mutex and the used-set must make safe.
func TestConcurrentBootPortsDistinct(t *testing.T) {
	workDir := t.TempDir()
	t.Setenv(checkFakeDelayEnv, "150")
	bin := fakeBin(t, checkFakeModeServe)

	const n = 2
	addrs := make([]string, n)
	insts := make([]SocksInstance, n)
	errs := make([]error, n)
	gate := make(chan struct{})
	var booted sync.WaitGroup
	booted.Add(n)
	for i := range n {
		go func(i int) {
			<-gate
			inst, err := StartTempXray(context.Background(), bin, workDir, freedomOutbound())
			errs[i] = err
			insts[i] = inst
			if inst != nil {
				addrs[i] = inst.Addr()
			}
			booted.Done()
		}(i)
	}
	close(gate)
	booted.Wait()
	for i := range n {
		require.NoError(t, errs[i], "instance %d must boot", i)
		require.NotNil(t, insts[i], "instance %d must boot", i)
	}
	assert.NotEqual(t, addrs[0], addrs[1],
		"two concurrent instances must never share a socks port (wrong measurements)")

	for i := range n {
		require.NoError(t, insts[i].Close(), "instance %d must close cleanly", i)
	}
	entries, rerr := os.ReadDir(workDir)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "every instance must clean its temp dir on Close")
}

// TestTempInstanceCloseReapWaitIsBounded (termination-audit P1): Close's
// reap wait must be BOUNDED — a temp child that accepted the kill but never
// completes exec.Wait (the D-state class) previously wedged the checker
// wave teardown on one unreapable instance, exactly like the manager's
// session-child stop. The simulation mirrors the manager test
// (TestStopSessionChildReapWaitIsBounded in internal/core): a real child
// plus a pre-armed reap channel that never closes — the exact observable
// of the unreapable class. The production bound (5s) is shortened through
// the instanceReapBound seam so the proof runs in milliseconds.
func TestTempInstanceCloseReapWaitIsBounded(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.list=.*")
	require.NoError(t, cmd.Start())
	// The instance's reaper is bypassed (fake done below) — the cleanup
	// kills and reaps the child.
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	origBound := instanceReapBound
	instanceReapBound = 200 * time.Millisecond
	t.Cleanup(func() { instanceReapBound = origBound })

	inst := &xrayInstance{cmd: cmd, port: testPortBandMin + 1, dir: t.TempDir()}
	inst.done = make(chan struct{}) // never closed — the unreapable state
	inst.waitOnce.Do(func() {})     // consume the once: waitDone() returns the fake channel

	closed := make(chan error, 1)
	start := time.Now()
	go func() { closed <- inst.Close() }()
	select {
	case err := <-closed:
		require.Error(t, err, "a child the kill could not reap is NOT a clean close")
		require.Contains(t, err.Error(), strconv.Itoa(cmd.Process.Pid), "the error names the exact pid")
		require.Contains(t, err.Error(), "not reaped", "the error says what did not happen")
		require.Contains(t, err.Error(), "kill -KILL", "the error carries the exact manual escalation")
		require.Less(t, time.Since(start), 5*time.Second, "the bound returned well within the watchdog")
	case <-time.After(10 * time.Second):
		t.Fatalf("Close() hung past %s on the reap wait — the temp-instance close is UNBOUNDED (audit P1)",
			time.Since(start).Round(time.Second))
	}
}

// TestBatchInstanceCloseReapWaitIsBounded is the batch twin of
// TestTempInstanceCloseReapWaitIsBounded: the batch Close's reap wait is
// bounded by the same seam (audit P1 names both legs, instance.go Close
// and batchXrayInstance.Close).
func TestBatchInstanceCloseReapWaitIsBounded(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.list=.*")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	origBound := instanceReapBound
	instanceReapBound = 200 * time.Millisecond
	t.Cleanup(func() { instanceReapBound = origBound })

	inst := &batchXrayInstance{cmd: cmd, ports: []int{testPortBandMin + 2}, dir: t.TempDir()}
	inst.done = make(chan struct{}) // never closed — the unreapable state
	inst.waitOnce.Do(func() {})

	closed := make(chan error, 1)
	start := time.Now()
	go func() { closed <- inst.Close() }()
	select {
	case err := <-closed:
		require.Error(t, err, "a child the kill could not reap is NOT a clean close")
		require.Contains(t, err.Error(), strconv.Itoa(cmd.Process.Pid), "the error names the exact pid")
		require.Contains(t, err.Error(), "not reaped", "the error says what did not happen")
		require.Less(t, time.Since(start), 5*time.Second, "the bound returned well within the watchdog")
	case <-time.After(10 * time.Second):
		t.Fatalf("batch Close() hung past %s on the reap wait — the close is UNBOUNDED (audit P1)",
			time.Since(start).Round(time.Second))
	}
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

	// One full round (I-4 restructure): fresh nodes/config/tmpdir per round
	// so a retry never reuses a possibly-poisoned workspace.
	runRound := func(round int) (*NodeResult, *NodeResult) {
		var okRow, deadRow *NodeResult
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
			Targets:  []string{httpTargetURL(t, site)},
			Attempts: 1,
			// 30s: the full -race suite saturates the box (packages run
			// concurrently) and the W14 boot-smoke adds real xray boots to
			// that load — a 5s attempt deadline flaked the healthy-control
			// sanity under that peak. Success is milliseconds; the larger
			// deadline only buys headroom under saturation.
			Timeout:          30 * time.Second,
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
		return okRow, deadRow
	}

	for round := 1; round <= 6; round++ {
		okRow, deadRow := runRound(round)
		// THE INVARIANT — single-shot strict on EVERY round result (I-4
		// discipline): a dead node reporting ok>0 fails the test IMMEDIATELY
		// and is NEVER retried; a retry would mask the exact
		// cross-contamination race this test hunts.
		require.Equal(t, 0, deadRow.OK,
			"round %d: a dead-outbound node can NEVER report ok>0 — scoring means its attempts rode another instance's tunnel", round)
		// Fixture sanity (both instances boot; the control serves) — the
		// load-flaky half: under full -race package-pair load either the
		// dead boot can fail (round 5, witnessed live pre-I4) or the
		// control's single attempt can starve (1-in-3). A degenerate round
		// exercises nothing. Retry the round up to 3 times, for the SANITY
		// ONLY; the invariant above keeps its single-shot semantics on the
		// original round and on any retry. The dead-node OK==0 invariant is
		// checked on EVERY attempt (including retries) — only the boot/total/
		// control-ok sanity is retried.
		for sanityRetry := 0; sanityRetry < 3 && (deadRow.InstanceFailed || deadRow.Total != 1 || okRow.OK != 1); sanityRetry++ {
			t.Logf("round %d: fixture sanity failed under suite load (dead boot failed=%v, total=%d, control ok=%d) — retrying (sanity only, attempt %d)",
				round, deadRow.InstanceFailed, deadRow.Total, okRow.OK, sanityRetry+1)
			okRow, deadRow = runRound(round)
			require.Equal(t, 0, deadRow.OK,
				"round %d (sanity retry %d): the dead-node invariant holds on the retry too", round, sanityRetry+1)
		}
		require.False(t, deadRow.InstanceFailed,
			"round %d: the dead node must BOOT — failing all retries is real breakage", round)
		require.Equal(t, 1, deadRow.Total, "round %d", round)
		require.Equal(t, 1, okRow.OK,
			"round %d: the healthy control failed all retries under load — real fixture breakage, not a flake", round)
	}

	entries, rerr := os.ReadDir(workDir)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "every temp config dir must be cleaned after the run")
}

// I1b: the child environment must carry NONE of the six canonical proxy
// variables as whole entries — ambient proxy inheritance would silently route
// check traffic through the live client (L5). The guard matches per-line
// exact prefixes, never substrings: ambient harness variables such as
// ZCODE_HTTP_PROXY legitimately contain the substring "HTTP_PROXY=" and are
// inherited by the child on purpose (Go's proxy stack reads only the
// canonical six).
func TestStartTempXrayStripsProxyEnv(t *testing.T) {
	names := []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}
	for _, v := range names {
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

	// Whole-entry guard: no dumped line may begin with "NAME=" for any of the
	// six names — per-line prefixes mirror dropProxyEnv's per-entry prefix
	// semantics, while a substring scan would false-positive on ambient
	// ZCODE_HTTP_PROXY-style variables.
	lines := strings.Split(string(childEnv), "\n")
	for _, name := range names {
		prefix := name + "="
		for _, line := range lines {
			assert.False(t, strings.HasPrefix(line, prefix),
				"proxy variable %s must be stripped from the child env as a whole entry (L5), found %q", name, line)
		}
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
		first, ferr := freeInstancePort(ctx, nil)
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

	next, err := freeInstancePort(ctx, nil)
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
	_, err = freeInstancePort(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no free port")
}

// TestFreeInstancePortNeverReissuesWithinABatch pins the batch-allocation
// contract: two consecutive scans for ONE batch must never return the same
// port. The bind-probe closes each candidate before returning, so an
// unconditioned second scan re-finds the just-released port free and a
// 2-outbound batch rendered TWO inbounds on ONE port — real xray dies on the
// second bind (EADDRINUSE) and every multi-outbound batch failed during
// startup (diag-proved on the flaking boot-death test: every failing boot
// carried ports=[P P]).
func TestFreeInstancePortNeverReissuesWithinABatch(t *testing.T) {
	ctx := context.Background()
	used := map[int]struct{}{}

	first, ferr := freeInstancePort(ctx, used)
	require.NoError(t, ferr)
	used[first] = struct{}{}

	second, serr := freeInstancePort(ctx, used)
	require.NoError(t, serr)
	assert.NotEqual(t, first, second,
		"consecutive allocations for one batch must hand out distinct ports — "+
			"a duplicate inbound port kills the real core at bind time")
	used[second] = struct{}{}

	third, terr := freeInstancePort(ctx, used)
	require.NoError(t, terr)
	assert.NotEqual(t, first, third)
	assert.NotEqual(t, second, third, "the used-set excludes every port the batch already claimed")
}

// The suite constructs temp instances ONLY inside the disjoint test band —
// the production 18xxx band belongs to the live daemon (live-ops fix: suite
// runs and daemon waves must never contend for the same ports).
func TestSuiteInstancesUseDisjointPortBand(t *testing.T) {
	// Disjoint from the PRODUCTION band (18500-18799) by construction —
	// pinned against the literals because the package vars now carry the
	// test band inside this binary.
	require.Greater(t, testPortBandMin, 18799, "the test band must sit entirely above the production 18xxx band")

	inst, err := StartTempXray(context.Background(), fakeBin(t, checkFakeModeServe), t.TempDir(), freedomOutbound())
	require.NoError(t, err)
	defer func() { _ = inst.Close() }()

	_, portStr, perr := net.SplitHostPort(inst.Addr())
	require.NoError(t, perr)
	port, aerr := strconv.Atoi(portStr)
	require.NoError(t, aerr)
	assert.GreaterOrEqual(t, port, testPortBandMin,
		"suite instances must boot inside the disjoint test band, never the production 18xxx band")
	assert.LessOrEqual(t, port, testPortBandMax,
		"suite instances must boot inside the disjoint test band, never the production 18xxx band")
}

// M2 test lands with the M2 implementation (NewXrayFactory knobs) — see the
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
			inst, err := NewXrayFactory(fakeBin(t, checkFakeModeServe), workDir, tc.knobs)(context.Background(), node)
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
