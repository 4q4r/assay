package cli

// Portable shared test helpers for the cli package. S4 extracted these from
// build-tagged suite files (activate_own_internal_test.go is `//go:build
// unix`, install_cmd_internal_test.go is `//go:build linux`) so the
// darwin/windows CI legs compile and run the portable suites that consume
// them (maintain, watch, install_winsvc, install_launchd, ...). Everything
// here is OS-portable: loopback TCP, temp dirs, and os.Args[0] re-exec —
// no unix syscalls, no shell-script fixtures, no file-mode pins.

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
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/core"
	"assay/internal/testproc"

	"github.com/spf13/cobra"
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
	// Parent-death containment (termination-audit P2-2): see the checker
	// fake's identical belt — a hard-killed parent must not leave a serve
	// child holding the test band.
	testproc.WatchParent()
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
// manager fake cores 22940-22980), the checker suite owns 28500-28799, the
// probe boot smoke owns 29500-29799 (split from the checker band: two
// concurrent test binaries must not share a boot band — the smoke's real
// xray bind answered a checker death-test's readiness dial), and kernel
// ephemerals sit above that.
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

// fakeCtl records systemctl invocations — the CLI-level seam twin of the
// install package's fake executor. Tests never execute systemd.
type fakeCtl struct {
	calls [][]string
}

func (f *fakeCtl) Systemctl(args ...string) error {
	f.calls = append(f.calls, args)
	return nil
}

func writeWaveConfig(t *testing.T, dir string, refresh, speedtest time.Duration) string {
	t.Helper()
	// Hermetic session probe (install/uninstall check for a user session).
	run := filepath.Join(dir, "run")
	require.NoError(t, os.MkdirAll(filepath.Join(run, "systemd"), 0o755))
	t.Setenv("XDG_RUNTIME_DIR", run)
	cfgPath := filepath.Join(dir, "config.toml")
	refreshSpan := (config.Duration{Duration: refresh}).String()
	speedSpan := (config.Duration{Duration: speedtest}).String()
	body := fmt.Sprintf(`
data_dir = %q

[maintain]
refresh_interval = %q
speedtest_interval = %q
`, filepath.Join(dir, "data"), refreshSpan, speedSpan)
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	return cfgPath
}

// mustLoad loads a config or fails the test — the suites' shared loader.
func mustLoad(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.Load(path)
	require.NoError(t, err)
	return cfg
}

// newTestRoot builds a fresh root command (each call gets its own flag
// state).
func newTestRoot() *cobra.Command { return New() }
