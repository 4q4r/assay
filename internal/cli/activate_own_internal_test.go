package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"assay/internal/checker"
	"assay/internal/config"
	"assay/internal/core"
	"assay/internal/model"
	"assay/internal/plugins"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Hermetic fake-core helper for the cli-level own-activation tests — the
// test process re-executes ITSELF (os.Args[0]) as the "xray binary" under
// the ASSAY_CLI_COREFAKE env var (the internal/core manager test pattern).
// No real xray, no downloads, no network beyond loopback binds.
//
// Behavior is discriminated the way the real binary sees it:
//   - argv containing "-test" plays the `xray run -test` gate
//     (validate-and-exit; exit 1 only when the config carries the gate-fail
//     marker);
//   - anything else plays the long-lived `xray run` child: bind the config's
//     FIRST inbound port and serve a socks5 loop that refuses every CONNECT
//     (the dead-outbound health-failure class). Deliberately ALWAYS-dead at
//     the cli level: a live forward would carry the manager's health fetch
//     (defaultHealthURL) out to the real internet — the refusal keeps the
//     post-activation health deterministic and hermetic, and T2's own suite
//     already covers the healthy-leg machinery with a loopback server.
const (
	cliFakeModeEnv   = "ASSAY_CLI_COREFAKE"
	cliFakeModeServe = "serve"
	cliFakeGateFail  = "CLI_COREFAKE_GATE_FAIL"
	// cliFakeVersionEnv overrides the fake's `version` banner (the status
	// core block reads the same banner contract xrayupdate.CurrentVersion
	// parses).
	cliFakeVersionEnv = "ASSAY_CLI_COREFAKE_VERSION"
)

// TestMain doubles as the fake-core entrypoint: when the test binary is
// re-executed with ASSAY_CLI_COREFAKE=serve, it plays xray and NEVER runs
// the tests.
func TestMain(m *testing.M) {
	if os.Getenv(cliFakeModeEnv) == cliFakeModeServe {
		runCliFakeCore()
		return // killed by the manager's exact-PID Stop; never runs the tests
	}
	os.Exit(m.Run())
}

// runCliFakeCore walks argv exactly like the real core sees it: `version`
// prints the banner (no -c, no ports — the internal/core fake's contract),
// `-test` somewhere in argv = the gate; otherwise the long-lived serve
// child.
func runCliFakeCore() {
	for _, a := range os.Args {
		if a == "version" {
			ver := os.Getenv(cliFakeVersionEnv)
			if ver == "" {
				ver = "26.9.9"
			}
			_, _ = fmt.Fprintf(os.Stdout, "Xray %s (CLIFAKE, Penetrates Everything.) Custom Build\n", ver)
			os.Exit(0)
		}
	}
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
	for _, a := range os.Args {
		if a == "-test" {
			if strings.Contains(string(raw), cliFakeGateFail) {
				_, _ = fmt.Fprintln(os.Stderr, "CLIFAKE: gate refused — "+cliFakeGateFail)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	cliFakeServe(raw)
}

// cliFakeServe binds the config's first inbound port (a bind collision dies
// exit 1 like a real xray) and serves a socks5 loop until killed. Every
// CONNECT is refused with reply 0x05 (connection refused) — the always-dead
// outbound class described above.
func cliFakeServe(raw []byte) {
	var cfg struct {
		Inbounds []struct {
			Port int `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || len(cfg.Inbounds) == 0 {
		os.Exit(2)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Inbounds[0].Port)))
	if err != nil {
		os.Exit(1)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { _ = cliFakeSocksConn(conn) }()
	}
}

// cliFakeSocksConn handles one socks5 client: greeting (no auth), then a
// refusal for every CONNECT (dead outbound).
func cliFakeSocksConn(conn net.Conn) error {
	defer func() { _ = conn.Close() }()
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("bad greeting version %#x", head[0])
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return err
	}
	if req[1] != 0x01 { // only CONNECT is expected; skip addr for others
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil
	}
	// Drain the CONNECT address per ATYP, then refuse (reply 0x05).
	switch req[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
			return err
		}
	case 0x04:
		if _, err := io.ReadFull(conn, make([]byte, 18)); err != nil {
			return err
		}
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, make([]byte, int(l[0])+2)); err != nil {
			return err
		}
	}
	_, err := conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// cliFakeBinary puts the test process into fake-core mode (inherited by
// every re-exec child) and returns the binary path to configure as the
// core binary.
func cliFakeBinary(t *testing.T) string {
	t.Helper()
	t.Setenv(cliFakeModeEnv, cliFakeModeServe)
	return os.Args[0]
}

// Core test port allocation — every package's fixed TEST ports are mutually
// disjoint: production temp instances churn 18xxx (the live watch daemon's
// band), THIS package allocates 21800-21999 (21800 + 2n), internal/core's
// fake cores own 22900-22999 (download/AutoUpdate fixtures 22900-2292x,
// manager fake cores 22940-22980), the checker suite owns 28500-28799, and
// kernel ephemerals sit above that.
//
// Flake-protocol refinement (T6 fix round; T7 fix round 1 completed the
// separation): internal/core's fixed test ports ORIGINALLY sat inside this
// band (the nine AutoUpdate ports at 21900-21914, and — found by the T7
// review — the manager fake cores at 21810-21896), so `go test`'s parallel
// package execution let long-lived fake cores collide with
// concurrently-running cli fixtures drawn by this allocator. All core-suite
// ports now live in the disjoint 22900-22999 band; the earlier flake
// attributions for cli-package port failures to intra-cli cross-process
// contention (instance.go freeInstancePort) are valid ONLY for failures
// where the failing port user was inside the parallel band itself — which,
// with the allocation above, no other package's fixed ports are.
var cliCoreTestPortSeq atomic.Int32

func nextCoreTestPort() int {
	return 21800 + int(cliCoreTestPortSeq.Add(1))*2
}

// syncBuffer is a mutex-guarded log sink: the manager's spawn/reaper
// goroutines (child stdio forwarding) write concurrently with the test's
// assertions.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ownFixture is the own-activation scenario: a temp data dir, the fake core
// binary as [core].xray_bin, a POISONED legacy [activate].xray_bin (proving
// every gate/fleet resolves CoreXrayBin — the S1 single-knob contract), and
// the test-band ports. The out sink is the mutex-guarded buffer: the T5
// transient-spawn tests drop a manager whose child keeps streaming stdio
// into it after the stage returned.
type ownFixture struct {
	cfg *config.Config
	p   paths
	log *syncBuffer
	out *syncBuffer
	cmd *cobra.Command
}

func newOwnFixture(t *testing.T) *ownFixture {
	t.Helper()
	dir := t.TempDir()
	port := nextCoreTestPort()
	cfg := &config.Config{
		DataDir: dir,
		// Backups land in the FIXED <data>/backups (S4: the backup-dir knob
		// is retired — the C1/D8 rollback glob reads exactly this dir).
		Core: config.CoreConfig{
			// AutoUpdate: true mirrors the LOADED-config default (Load
			// pre-seeds it before decode); a hand-built zero value would
			// read as the explicit-off master switch.
			AutoUpdate: true,
			XrayBin:    cliFakeBinary(t),
			SocksPort:  port,
			HTTPPort:   port + 1,
			Loglevel:   "warning",
		},
	}
	log := &syncBuffer{}
	out := &syncBuffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	return &ownFixture{cfg: cfg, p: newPaths(cfg), log: log, out: out, cmd: cmd}
}

// ownLiveBytes writes one generation of the live core config (the fake
// binds the first inbound port = the fixture's socks port).
func ownLiveBytes(port int, gen string) []byte {
	return []byte(fmt.Sprintf(
		`{"marker":%q,"inbounds":[{"tag":"in","listen":"127.0.0.1","port":%d,"protocol":"socks"}]}`,
		gen, port))
}

// writeOwnLive writes the live.json generation to disk.
func (f *ownFixture) writeOwnLive(t *testing.T, gen string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(ownLivePath(f.p)), 0o750))
	require.NoError(t, os.WriteFile(ownLivePath(f.p), ownLiveBytes(f.cfg.Core.SocksPort, gen), 0o600))
}

// writeOwnCandidate writes one generation of the activation candidate (the
// artifact the render leg produces for a non-empty selection).
func (f *ownFixture) writeOwnCandidate(t *testing.T, gen string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(ownCandidatePath(f.p)), 0o750))
	require.NoError(t, os.WriteFile(ownCandidatePath(f.p), ownLiveBytes(f.cfg.Core.SocksPort, gen), 0o600))
}

// ownManager creates the manager over the fixture's data dir with the
// shared log sink (the daemon-style long-lived holder the wave wiring
// injects; a one-shot stage would create its own transient one).
func (f *ownFixture) ownManager(t *testing.T) *core.Manager {
	t.Helper()
	mgr, err := core.NewManager(f.cfg.Core, f.p.dataDir, f.log)
	require.NoError(t, err)
	return mgr
}

// coreServing polls whether something accepts on the fixture's socks port.
func coreServing(port int) bool {
	conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).
		Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// TestBackupDirIsFixedD8RollbackSource pins the whole-branch review WB-I-2
// closure: the activate stage's backup dir is the FIXED <data>/backups —
// exactly the dir the core manager's D8 rollback globs
// (config.json.bak-<ts>) — with no knob able to move it. The backup-dir
// knob is retired (S4, parse-and-warn): a movable backup dir would leave
// the rollback staring at an empty/stale dir while the remedy silently
// dies.
func TestBackupDirIsFixedD8RollbackSource(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir}
	p := newPaths(cfg)
	require.Equal(t, filepath.Join(dir, "backups"), p.backupDir,
		"the backup writer must use the fixed <data>/backups — the D8 rollback source (manager.go backupDir)")
}

// TestActivateOwnWritesBackupsAndRestarts is the activate-stage contract
// pin (brief test 1): activate with a real selection goes -test gate
// (resolved from [core].xray_bin, NOT the poisoned legacy knob) →
// <data>/backups/config.json.bak-<ts> backup of the PRE-activation live
// config (C1) → live.json replaced with the candidate → the core restarted
// through the manager → the post-activation health check runs and feeds the
// strike counter (C3: strikes only post-activation).
func TestActivateOwnWritesBackupsAndRestarts(t *testing.T) {
	f := newOwnFixture(t)
	f.writeOwnLive(t, "gen-0")
	f.writeOwnCandidate(t, "gen-candidate")

	// Daemon-style manager already running the OLD live config — the way
	// the watch daemon's wave wiring holds it across waves. Stopped at
	// cleanup: a leaked fake core would hold the test-band port and collide
	// with the next `go test` invocation.
	mgr := f.ownManager(t)
	t.Cleanup(func() { _ = mgr.Stop() })
	require.NoError(t, mgr.EnsureRunning(context.Background()))
	require.True(t, mgr.Alive(), "the old core must be running before the activation")

	require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr))

	// C1: the backup exists under the exact T2 glob name, holding the
	// PRE-activation live config (the rollback restore source).
	matches, err := filepath.Glob(filepath.Join(f.p.backupDir, "config.json.bak-*"))
	require.NoError(t, err)
	require.Len(t, matches, 1, "exactly one dated backup created")
	raw, err := os.ReadFile(matches[0])
	require.NoError(t, err)
	assert.Equal(t, string(ownLiveBytes(f.cfg.Core.SocksPort, "gen-0")), string(raw),
		"the backup holds the pre-activation live config")

	// live.json replaced with the candidate.
	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.Equal(t, string(ownLiveBytes(f.cfg.Core.SocksPort, "gen-candidate")), string(live))

	// The core was restarted through the manager: stop+start lines, and the
	// socks inbound serves again on the NEW config.
	require.Eventually(t, func() bool { return coreServing(f.cfg.Core.SocksPort) },
		5*time.Second, 50*time.Millisecond, "the restarted core must serve the socks inbound")
	logs := f.log.String()
	assert.Contains(t, logs, "core: stopped pid", "Restart's stop leg ran")
	assert.Contains(t, logs, "core: spawned pid", "Restart's start leg ran")

	// Post-activation health ran and was recorded (C3): the always-dead
	// fake refuses the fetch leg, so strike 1 of K lands in the log.
	assert.Contains(t, logs, "core: health failure 1/", "the post-activation health fed the strike counter")
}

// TestOneShotActivateRefusesUnderFlock is the S3 singleton pin (brief
// test 2): with a daemon-style lock held on the data dir, the one-shot
// activate returns the loud refusal — the EXACT brief message — and does
// not touch the live config or spawn anything.
func TestOneShotActivateRefusesUnderFlock(t *testing.T) {
	f := newOwnFixture(t)
	f.writeOwnLive(t, "gen-0")
	f.writeOwnCandidate(t, "gen-candidate")

	// The daemon-style holder: a live manager keeps the flock for its
	// lifetime (the kernel releases it only at process death) — its mere
	// existence is the "daemon holds the core" state.
	_ = f.ownManager(t)

	// The one-shot entry (nil manager = the stage creates its own transient
	// one, which must refuse).
	err := runActivateStage(f.cmd, f.cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(),
		"the daemon owns the core — restart the unit or use watch",
		"the exact loud refusal text is pinned")

	// Nothing happened: live config untouched, no core spawned (the socks
	// port stays refused — the holder spawned nothing and neither did the
	// refused one-shot).
	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.Equal(t, string(ownLiveBytes(f.cfg.Core.SocksPort, "gen-0")), string(live))
	assert.False(t, coreServing(f.cfg.Core.SocksPort), "no core was spawned by the refused one-shot")
}

// TestWatchBootstrapsCoreAtStart is the S2 pin (brief test 3): a watch
// start on a fresh data dir writes the D7 bootstrap live config
// (catch-all → block, fail-closed), spawns the core, and only THEN sends
// READY=1; no strike is fed during the bootstrap (C3); SIGTERM stops the
// core (the C4 explicit-Stop shutdown contract).
func TestWatchBootstrapsCoreAtStart(t *testing.T) {
	dir := t.TempDir()
	port := nextCoreTestPort()
	cfg := &config.Config{
		DataDir: dir,
		Plugins: config.PluginsConfig{Dir: filepath.Join(dir, "plugins")},
		Core: config.CoreConfig{
			// AutoUpdate: true mirrors the LOADED-config default (Load
			// pre-seeds it before decode); a hand-built zero value would
			// read as the explicit-off master switch.
			AutoUpdate: true,
			XrayBin:    cliFakeBinary(t),
			SocksPort:  port,
			HTTPPort:   port + 1,
			Loglevel:   "warning",
		},
	}

	sigs := make(chan os.Signal, 1)
	sdStarted := make(chan struct{})
	var coreAtReady atomic.Bool
	dep := watchDeps{
		startWatchdog: func(string, io.Writer) (*plugins.Registry, io.Closer, error) {
			return plugins.NewRegistry(), fakeCloser{}, nil
		},
		signals: sigs,
		now:     time.Now,
		after: func(time.Duration) <-chan time.Time {
			return make(chan time.Time) // never fires — only the signal ends it
		},
		sdNotify: func(io.Writer) func() {
			// THE S2 ordering proof: at READY time the bootstrap core must
			// already be reachable on the socks inbound.
			coreAtReady.Store(coreServing(port))
			close(sdStarted)
			return func() {}
		},
	}
	out := &syncWriter{}
	done := make(chan error, 1)
	go func() { done <- runWatch(out, cfg, dep) }()

	select {
	case <-sdStarted:
	case <-time.After(15 * time.Second):
		t.Fatalf("daemon never reached READY: %s", out.String())
	}
	assert.True(t, coreAtReady.Load(), "the bootstrap core must be running BEFORE READY=1 (S2)")

	// The bootstrap artifact: D7 fail-closed posture, base inbounds.
	livePath := filepath.Join(dir, "rendered", "live.json")
	raw, err := os.ReadFile(livePath)
	require.NoError(t, err, "the bootstrap live config must exist")
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	catch := ownCatchAllTag(t, m)
	assert.Equal(t, "block", catch, "bootstrap catch-all routes to block (D7/A4)")
	for _, tag := range []string{"in", "in-http"} {
		assert.NotNil(t, ownInboundByTag(t, m, tag), "base inbound %s rendered", tag)
	}
	assert.Contains(t, out.String(), "bootstrap", "the bootstrap write is loud")

	// C3: the bootstrap never fed a strike (no post-activation health check
	// runs for the fail-closed posture — the fetch leg would fail BY DESIGN).
	assert.NotContains(t, out.String(), "health failure",
		"bootstrap strikes are NOT fed (C3)")

	// SIGTERM shutdown: the manager stops the core explicitly (C4).
	sigs <- syscall.SIGTERM
	select {
	case err := <-done:
		require.NoError(t, err, "graceful shutdown exits nil")
	case <-time.After(10 * time.Second):
		t.Fatalf("daemon did not shut down on SIGTERM: %s", out.String())
	}
	require.Eventually(t, func() bool { return !coreServing(port) },
		5*time.Second, 50*time.Millisecond, "the core must be stopped by the SIGTERM shutdown")
	_, statErr := os.Stat(filepath.Join(dir, "core.pid"))
	assert.True(t, os.IsNotExist(statErr), "the pidfile is cleaned up on stop")
	assert.Contains(t, out.String(), "watch: clean shutdown")
}

// ownCatchAllTag returns the catch-all routing rule's outboundTag.
func ownCatchAllTag(t *testing.T, m map[string]any) any {
	t.Helper()
	routing, ok := m["routing"].(map[string]any)
	require.True(t, ok, "routing block present")
	rules, ok := routing["rules"].([]any)
	require.True(t, ok, "routing rules present")
	require.NotEmpty(t, rules, "at least one routing rule")
	last, ok := rules[len(rules)-1].(map[string]any)
	require.True(t, ok)
	return last["outboundTag"]
}

// ownInboundByTag finds an inbound by tag (nil when absent).
func ownInboundByTag(t *testing.T, m map[string]any, tag string) map[string]any {
	t.Helper()
	raw, ok := m["inbounds"].([]any)
	require.True(t, ok, "inbounds array present")
	for _, inb := range raw {
		if im, isMap := inb.(map[string]any); isMap && im["tag"] == tag {
			return im
		}
	}
	return nil
}

// TestStrikeCounterFeedsRollback is the D8 wiring pin (brief test 4): three
// failed post-activation healths ACROSS activates on ONE manager (the
// daemon's long-lived strike state) fire the rollback through the manager —
// the newest config.json.bak-<ts> restored over live.json and the core
// restarted on it.
func TestStrikeCounterFeedsRollback(t *testing.T) {
	f := newOwnFixture(t)
	gens := []string{"gen-0", "gen-2", "gen-3", "gen-4"}
	f.writeOwnLive(t, gens[0])
	f.writeOwnCandidate(t, gens[1])

	mgr := f.ownManager(t)
	t.Cleanup(func() { _ = mgr.Stop() }) // no leaked fake cores across invocations
	require.NoError(t, mgr.EnsureRunning(context.Background()))

	// Three activates, each with a fresh distinct candidate generation.
	for i := 1; i <= 3; i++ {
		if i > 1 {
			f.writeOwnCandidate(t, gens[i])
		}
		require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr), "activate %d", i)
	}

	logs := f.log.String()
	assert.Contains(t, logs, "core: health failure 3/3", "the third consecutive failure struck out")
	assert.Contains(t, logs, "ROLLBACK", "the D8 rollback fired via the manager")

	// The rollback restored the NEWEST backup (gen-3 — the pre-third-activate
	// state), NOT the oldest (gen-0) and NOT the just-failed candidate.
	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.Equal(t, string(ownLiveBytes(f.cfg.Core.SocksPort, "gen-3")), string(live),
		"the newest backup (pre-third-activate state) was restored over live.json")

	// The core came back on the restored config.
	require.Eventually(t, func() bool { return coreServing(f.cfg.Core.SocksPort) },
		5*time.Second, 50*time.Millisecond, "the core runs after the rollback restart")
}

// cliMkSelected is the cli-local node fixture (the render tests'
// mkSelected shape): one REALITY vless node wired into a real selection.
func cliMkSelected(t *testing.T, tag, cc, city, host string, port int) (*model.Node, model.SelectedNode) {
	t.Helper()
	params := map[string]string{
		"type": "tcp", "security": "reality", "sni": "donor.example",
		"pbk": "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M", "sid": "b1",
	}
	n := model.NewNode("s", "vless", "pool-uuid-1", host, port, params)
	return n, model.SelectedNode{Tag: tag, Key: n.Key, Country: cc, City: city, RTTMs: 100, Checks: 3, Total: 3}
}

// cliBootMarkerBinary plants a boot-marker wrapper at path: executing the
// wrapper appends its OWN path ($0) to the marker file and then execs the
// COREFAKE test double (the mode env rides the inherited environment), so a
// fleet that boots the wrapper both SERVES socks AND proves — by the
// marker's content — exactly WHICH binary path was exec'd. The fixture
// assertion this enables is the hermeticity proof for the S1 fleet pin: the
// marker must name the injected fixture path and never the machine's real
// xray.
func cliBootMarkerBinary(t *testing.T, path, marker string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	script := "#!/bin/sh\nprintf '%s\\n' \"$0\" >> " + strconv.Quote(marker) +
		"\nexec " + strconv.Quote(cliFakeBinary(t)) + " \"$@\"\n"
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
}

// readBootMarker reads the boot marker, empty when nothing booted yet.
func readBootMarker(t *testing.T, marker string) []string {
	t.Helper()
	raw, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// TestProbeAndCheckFleetsResolveCoreBin is the S1 pin (brief test 5, T5b
// resolution order): with the resolution SEAMS armed (the machine's real
// ~/.local/bin/xray and /usr/bin/xray are invisible), a clean data dir, and
// the fake wrapper at the injected DEFAULT location (~/.local/bin/xray —
// the user-local install target), both probe fleets (single + batch) and
// the check fleet resolve and BOOT that exact binary — proven by the boot
// marker naming the injected path, never /usr/bin/xray. The bind-existing
// leg is pinned the same way for a fake planted at the injected system
// path. The test is hermetic on an xray-less machine: only fixture paths
// exist on the scan list.
func TestProbeAndCheckFleetsResolveCoreBin(t *testing.T) {
	newSeams := func(t *testing.T) (string, string, *config.Config) {
		t.Helper()
		userLocal, system := injectCoreBinSeams(t)
		port := nextCoreTestPort()
		cfg := &config.Config{
			DataDir: t.TempDir(),
			Core: config.CoreConfig{
				// Empty override: the owner-ruling resolution decides (the
				// S1 contract under test).
				SocksPort: port,
				HTTPPort:  port + 1,
			},
		}
		p := newPaths(cfg)
		require.NoError(t, os.MkdirAll(p.workDir, 0o750))
		t.Cleanup(func() { _ = os.RemoveAll(p.workDir) })
		return userLocal, system, cfg
	}

	runFleets := func(t *testing.T, cfg *config.Config, wantBin string, marker string) {
		t.Helper()
		p := newPaths(cfg)
		node, _ := cliMkSelected(t, "pool-de-01", "de", "Berlin", "a.example.com", 2053)
		ctx := context.Background()

		// Probe BATCH fleet (pipeline.go batch factory — StartTempXrayBatch).
		batchFactory := newProbeBatchFactory(cfg, p)
		batchInst, err := batchFactory(ctx, []*model.Node{node})
		require.NoError(t, err, "the batch fleet must boot the resolved fake binary")
		require.Len(t, batchInst.Addrs(), 1)
		require.NoError(t, batchInst.Close())

		// Probe SINGLE fleet (pipeline.go factory — checker.NewXrayFactory).
		probeFactory := newProbeFactory(cfg, p)
		singleInst, err := probeFactory(ctx, node)
		require.NoError(t, err, "the single fleet must boot the resolved fake binary")
		require.NoError(t, singleInst.Close())

		// Check fleet: the cli Options resolution + a real boot through the
		// SAME factory machinery the check stage runs.
		opts := newCheckOptions(cfg, p, []string{"https://example.com"}, checkFlags{})
		assert.Equal(t, wantBin, opts.XrayBin,
			"the check fleet resolves the S1 resolution, not a machine-dependent path")
		checkFactory := checker.NewXrayFactory(opts.XrayBin, p.workDir, opts.Render)
		checkInst, err := checkFactory(ctx, node)
		require.NoError(t, err, "the check fleet must boot the resolved fake binary")
		require.NoError(t, checkInst.Close())

		// The FIXTURE-ASSERTION hermeticity proof: every boot exec'd the
		// injected path (the wrapper recorded $0) and NOTHING booted the
		// machine's real xray.
		boots := readBootMarker(t, marker)
		// Exactly ONE boot per fleet — batch, single, check — each the
		// injected wrapper. A fleet that exec'd anything else (e.g. the
		// machine's real xray via a stale resolution) would drop a marker
		// line and fail this exact count.
		require.Len(t, boots, 3,
			"exactly one boot per fleet (batch, single, check), all the injected wrapper")
		for _, booted := range boots {
			assert.Equal(t, wantBin, booted,
				"the fleet exec'd the injected fixture path — never any machine binary")
		}
		assert.NotContains(t, boots, "/usr/bin/xray",
			"the machine's real system xray must never be booted by this test")
	}

	t.Run("fake at the default (user-local) location resolves and boots", func(t *testing.T) {
		userLocal, _, cfg := newSeams(t)
		marker := filepath.Join(t.TempDir(), "boot-marker")
		cliBootMarkerBinary(t, userLocal, marker)
		runFleets(t, cfg, userLocal, marker)
	})

	t.Run("fake at the injected system path binds first-match", func(t *testing.T) {
		_, system, cfg := newSeams(t)
		marker := filepath.Join(t.TempDir(), "boot-marker")
		cliBootMarkerBinary(t, system, marker)
		runFleets(t, cfg, system, marker)
	})
}

// TestDaemonCoreExecSurfaceIsPinned extends the W13 pinning story to the
// NEW exec surface (the brief's guard mandate): every production file that
// spawns a child process is pinned EXACTLY. The systemctl executors stay
// the two allowlist files (restart's own guard); everything else is the
// xray-family child surface: the -test gate, the temp-instance fleets, the
// core manager spawn/kill/rollback-gate, the stats poll, and the updater's
// staged gate. A new exec site must widen this pin deliberately.
func TestDaemonCoreExecSurfaceIsPinned(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "exec.Command") {
			offenders = append(offenders, filepath.ToSlash(strings.TrimPrefix(path, root+string(os.PathSeparator))))
		}
		return nil
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"internal/install/install.go",       // systemctl allowlist executor (its own guard)
		"internal/install/launchd.go",       // launchctl allowlist executor (S1, its own guard)
		"internal/install/runit.go",         // sv allowlist executor (S3, its own guard)
		"internal/install/openrc.go",        // rc-update/rc-service + rc-status probe (S3, its own guard)
		"internal/install/s6.go",            // s6-svc/s6-svscanctl/s6-svstat executor (S3, its own guard)
		"internal/install/cron.go",          // crontab allowlist executor (S3, its own guard)
		"internal/activate/activate.go",     // the -test gate child (WaitDelay-safe)
		"internal/checker/instance.go",      // probe/check temp-instance fleets
		"internal/core/manager.go",          // core spawn/kill (the daemon's own child)
		"internal/core/rollback.go",         // rollback -test gate child
		"internal/stats/stats.go",           // xray api statsquery poll
		"internal/xrayupdate/xrayupdate.go", // staged-gate updater
	}, offenders, "the daemon's complete child-process surface changed — widen this pin deliberately, never silently")
}

// cliCorePortRefused polls until the socks port stops answering (the
// external-kill helper for the revive tests).
func cliCorePortRefused(t *testing.T, port int) {
	t.Helper()
	require.Eventually(t, func() bool { return !coreServing(port) },
		5*time.Second, 50*time.Millisecond, "the killed core must stop serving")
}

// cliPIDFromPidFile reads <data>/core.pid and returns its pid.
func cliPIDFromPidFile(t *testing.T, dataDir string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dataDir, "core.pid"))
	require.NoError(t, err, "the pidfile must exist")
	pid, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, perr)
	require.Positive(t, pid)
	return pid
}

// TestActivateNoCandidateKeepsRunningCoreOnLastGood (T4-I-1, shape a): the
// candidate-missing activate (empty selection) must NOT be a dead no-op —
// the core keeps running on the last-good live config (D7), the keep-last-
// good line is loud, and the no-op activation feeds NO strike (C3).
func TestActivateNoCandidateKeepsRunningCoreOnLastGood(t *testing.T) {
	f := newOwnFixture(t)
	f.writeOwnLive(t, "gen-last-good")
	mgr := f.ownManager(t)
	t.Cleanup(func() { _ = mgr.Stop() })
	require.NoError(t, mgr.EnsureRunning(context.Background()))
	require.True(t, coreServing(f.cfg.Core.SocksPort))

	// No candidate file at all — the empty-selection wave shape.
	require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr))

	assert.True(t, coreServing(f.cfg.Core.SocksPort),
		"the running core must keep running across the candidate-missing activate")
	assert.Contains(t, f.out.String(), "last-good",
		"the D7 keep-last-good posture must be loud in the no-candidate branch")
	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.Equal(t, string(ownLiveBytes(f.cfg.Core.SocksPort, "gen-last-good")), string(live),
		"the last-good live config is untouched")
	assert.NotContains(t, f.log.String(), "health failure",
		"the no-op activation must feed NO strike (C3: strikes are post-activation only)")
}

// TestActivateNoCandidateRevivesDeadCoreOnLastGood (T4-I-1, shape b): the
// daemon restarted after a manual kill, the pool is still empty — the
// candidate-missing activate must REVIVE the core on the last-good artifact
// (the waves-retry contract holds for the empty-pool shape too), with no
// strike fed for the revival.
func TestActivateNoCandidateRevivesDeadCoreOnLastGood(t *testing.T) {
	f := newOwnFixture(t)
	f.writeOwnLive(t, "gen-last-good")
	mgr := f.ownManager(t)
	t.Cleanup(func() { _ = mgr.Stop() })
	require.NoError(t, mgr.EnsureRunning(context.Background()))

	// The daemon restarted after a manual kill: the child is dead, the
	// last-good live config is still on disk.
	pid := cliPIDFromPidFile(t, f.p.dataDir)
	require.NoError(t, syscall.Kill(pid, syscall.SIGKILL))
	cliCorePortRefused(t, f.cfg.Core.SocksPort)

	require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr))

	require.Eventually(t, func() bool { return coreServing(f.cfg.Core.SocksPort) },
		5*time.Second, 50*time.Millisecond,
		"the candidate-missing activate must revive the core on the last-good artifact (T4-I-1)")
	assert.NotContains(t, f.log.String(), "health failure",
		"the revival feeds NO strike (C3)")
	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.Equal(t, string(ownLiveBytes(f.cfg.Core.SocksPort, "gen-last-good")), string(live),
		"the revival runs on the untouched last-good live config")
}

// TestOneShotActivateTransientCoreOutlivesStage (T4-I-2): the daemon-less
// one-shot activate completes a REAL activation through its own transient
// manager — gate, C1 backup, live replace, transient spawn, post-activation
// health — and the spawned child OUTLIVES the stage (A2: the process exit /
// manager drop kills nothing; the pidfile is left for the next daemon to
// adopt).
func TestOneShotActivateTransientCoreOutlivesStage(t *testing.T) {
	f := newOwnFixture(t)
	f.writeOwnLive(t, "gen-0")
	f.writeOwnCandidate(t, "gen-candidate")

	// No manager held anywhere — the daemon-less shape (the flock is free).
	require.NoError(t, runActivateStage(f.cmd, f.cfg))

	out := f.out.String()
	assert.Contains(t, out, "activation complete", "the one-shot activation completed")
	assert.Contains(t, out, "health failure 1/",
		"the full post-activation sequence ran (the fake is always-dead — strike 1 lands)")

	// C1: the dated backup of the pre-activation live config exists.
	matches, err := filepath.Glob(filepath.Join(f.p.backupDir, "config.json.bak-*"))
	require.NoError(t, err)
	require.Len(t, matches, 1, "exactly one dated backup from the one-shot activation")

	// A2 detach: the child survives the stage's returned-and-dropped manager.
	pid := cliPIDFromPidFile(t, f.p.dataDir)
	require.NoError(t, syscall.Kill(pid, 0),
		"the transient spawn must still be alive after runActivateStage returned")
	require.Eventually(t, func() bool { return coreServing(f.cfg.Core.SocksPort) },
		5*time.Second, 50*time.Millisecond,
		"the child keeps serving the socks inbound after the stage's manager is gone (A2)")
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
}

// TestOneShotFirstActivationCreatesNoBackup pins the first-activation branch
// the T4 review called out (pipeline.go Backup: liveErr == nil): with NO
// prior live config there is nothing to back up — the candidate becomes the
// first live config and the transient core comes up on it.
func TestOneShotFirstActivationCreatesNoBackup(t *testing.T) {
	f := newOwnFixture(t)
	f.writeOwnCandidate(t, "gen-first")

	require.NoError(t, runActivateStage(f.cmd, f.cfg))

	matches, err := filepath.Glob(filepath.Join(f.p.backupDir, "config.json.bak-*"))
	require.NoError(t, err)
	assert.Empty(t, matches, "the very first activation has no pre-state to back up")
	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.Equal(t, string(ownLiveBytes(f.cfg.Core.SocksPort, "gen-first")), string(live),
		"the candidate became the first live config")

	pid := cliPIDFromPidFile(t, f.p.dataDir)
	require.Eventually(t, func() bool { return coreServing(f.cfg.Core.SocksPort) },
		5*time.Second, 50*time.Millisecond, "the transient core serves the first live config")
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
}

// TestBootstrapCoreRetriesWithBackoff (bootstrap-degradation closure): the
// daemon's bootstrap EnsureRunning failure retries with a doubling backoff
// before degrading, every failed attempt is loud, and the LAST error
// surfaces to the caller (which prints the loud non-fatal WARNING).
func TestBootstrapCoreRetriesWithBackoff(t *testing.T) {
	out := &strings.Builder{}
	attempts := 0
	var waits []time.Duration
	ensure := func(context.Context) error {
		attempts++
		if attempts < 3 {
			return fmt.Errorf("boom %d", attempts)
		}
		return nil
	}
	err := bootstrapCoreWithRetries(out, ensure, 3, func(d time.Duration) { waits = append(waits, d) })
	require.NoError(t, err)
	assert.Equal(t, 3, attempts, "the successful third attempt must run")
	assert.Equal(t, []time.Duration{time.Second, 2 * time.Second}, waits,
		"the backoff doubles between attempts (bounded by the attempt count)")
	assert.Contains(t, out.String(), "attempt 1/3", "every failed attempt is loud")
	assert.Contains(t, out.String(), "attempt 2/3")
}

// TestBootstrapCoreRetriesExhaustsLoud: all attempts fail — the last error
// is returned (the caller degrades to the loud non-fatal WARNING) and every
// attempt left a loud line.
func TestBootstrapCoreRetriesExhaustsLoud(t *testing.T) {
	out := &strings.Builder{}
	attempts := 0
	ensure := func(context.Context) error {
		attempts++
		return fmt.Errorf("boom %d", attempts)
	}
	err := bootstrapCoreWithRetries(out, ensure, 3, func(time.Duration) {})
	require.Error(t, err)
	assert.Equal(t, 3, attempts, "exactly N attempts run — no unbounded retry")
	assert.Contains(t, err.Error(), "boom 3", "the LAST attempt's error surfaces")
	assert.Contains(t, out.String(), "attempt 3/3", "the final failed attempt is loud")
}
