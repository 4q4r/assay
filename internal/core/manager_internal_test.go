//go:build unix

package core

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
	"syscall"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/testproc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Hermetic fake-core helper — the test process re-executes ITSELF
// (os.Args[0]) as the "xray binary" under the COREFAKE_MODE env var (the
// checker instance_internal_test.go pattern). No real xray, no network
// beyond loopback. Behavior is discriminated the way the real binary sees
// it: argv containing "-test" plays the `xray run -test` gate
// (validate-and-exit), anything else plays the long-lived `xray run` child
// that binds the config's socks inbound and serves RFC 1928 CONNECTs.
const (
	coreFakeModeEnv   = "COREFAKE_MODE"
	coreFakeModeServe = "serve"

	// fakeDeadMarker rides inside a fixture config's comment field: the
	// serving child then REFUSES every CONNECT (reply 0x05) — the "core is
	// up, its outbound is dead" health-failure class that feeds the strikes.
	fakeDeadMarker = "COREFAKE_DEAD_OUTBOUND"
	// fakeGateFailMarker rides inside a backup fixture: the `-test` gate
	// child then exits 1 — the rollback-refusal class (test gate fails).
	fakeGateFailMarker = "COREFAKE_GATE_FAIL"
)

// TestMain doubles as the fake-core entrypoint: when the test binary is
// re-executed with COREFAKE_MODE set, it plays xray and NEVER runs the tests.
// It also doubles as the cross-process lock holder (CORELOCK_HELPER, the M-5
// test): takes the singleton flock in the given data dir, signals via the
// marker file, and blocks until killed.
func TestMain(m *testing.M) {
	if dir := os.Getenv("CORELOCK_HELPER"); dir != "" {
		runCoreLockHelper(dir)
		return // killed by the parent; never falls through to the tests
	}
	if os.Getenv(coreFakeModeEnv) == coreFakeModeServe {
		runFakeCore()
		return // killed by exact-PID Stop; never falls through to the tests
	}
	os.Exit(m.Run())
}

// runCoreLockHelper takes the singleton flock (NewManager) and blocks.
func runCoreLockHelper(dataDir string) {
	// Parent-death containment (termination-audit P2-2): this helper holds
	// the singleton flock and blocks until killed — a dead parent must
	// never leave the lock held forever (a leaked flock wedges every later
	// manager on that data dir).
	testproc.WatchParent()
	port, err := strconv.Atoi(os.Getenv("CORELOCK_HELPER_PORT"))
	if err != nil || port <= 0 {
		os.Exit(2)
	}
	m, err := NewManager(config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dataDir, io.Discard)
	if err != nil {
		os.Exit(3)
	}
	_ = m
	marker := os.Getenv("CORELOCK_HELPER_MARKER")
	if marker == "" {
		os.Exit(2)
	}
	if err := os.WriteFile(marker, []byte("locked\n"), 0o600); err != nil {
		os.Exit(4)
	}
	time.Sleep(10 * time.Minute) // the parent kills us; blocks without deadlocking the runtime
}

// runFakeCore mimics the xray invocation shapes the manager and the
// managed-core download path use: `version` (banner for the version
// readers; COREFAKE_VERSION overrides the reported version), `run -test
// -c <path>` (gate: validate-and-exit by config content) and `run -c
// <path>` (long-lived child: bind the socks inbound, serve, sleep until
// killed — the brief's "fake binary sleeps").
func runFakeCore() {
	for _, a := range os.Args {
		if a == "version" {
			ver := os.Getenv("COREFAKE_VERSION")
			if ver == "" {
				ver = "26.9.9"
			}
			_, _ = fmt.Fprintf(os.Stdout, "Xray %s (COREFAKE, Penetrates Everything.) Custom Build\n", ver)
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
			if strings.Contains(string(raw), fakeGateFailMarker) {
				_, _ = fmt.Fprintln(os.Stderr, "COREFAKE: gate refused — "+fakeGateFailMarker)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	fakeServe(raw)
}

// fakeServe binds the config's first inbound port (bind collision dies like
// a real xray) and serves a minimal socks5 loop until killed. A config
// carrying fakeDeadMarker refuses every CONNECT; anything else forwards to
// the dialed target.
func fakeServe(raw []byte) {
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
		os.Exit(1) // bind collision: die like a real xray would
	}
	dead := strings.Contains(string(raw), fakeDeadMarker)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { _ = fakeSocksConn(conn, dead) }()
	}
}

// fakeSocksConn handles one socks5 client: greeting (no auth), CONNECT,
// then either a refusal (dead outbound) or a forward to the mapped target
// (same shape as the checker's fake).
func fakeSocksConn(conn net.Conn, dead bool) error {
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

// fakeBin returns the re-executable "xray binary". t.Setenv propagates the
// mode to the child via the inherited environment.
func fakeBin(t *testing.T) string {
	t.Helper()
	t.Setenv(coreFakeModeEnv, coreFakeModeServe)
	return os.Args[0]
}

// syncBuffer is a mutex-guarded log sink: os/exec streams the child's
// stdout/stderr from its own goroutine into the manager's tee writer, which
// forwards into this buffer — an unguarded bytes.Buffer would be a data race
// under -race (the checker C2 landmine class).
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

// fakeCoreConfigJSON renders a minimal xray-shaped config the fake binary
// parses: one socks inbound on port plus a comment carrying the fixture's
// marker (fake behavior discriminator AND byte-distinctive content for the
// restore-equality assertions).
func fakeCoreConfigJSON(t *testing.T, port int, marker string) []byte {
	t.Helper()
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "socks-in", "listen": "127.0.0.1", "port": port,
			"protocol": "socks", "settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
		"comment":   marker,
	}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	return raw
}

// writeLiveFixture writes <data>/rendered/live.json (Task 3 generates it;
// T2 tests write fixtures manually per the brief).
func writeLiveFixture(t *testing.T, dataDir string, port int, marker string) {
	t.Helper()
	path := filepath.Join(dataDir, "rendered", "live.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, fakeCoreConfigJSON(t, port, marker), 0o600))
}

// writeBackupFixture writes <data>/backups/config.json.bak-<ts> (the
// activate stage writes these from Task 4 on; T2 prepares them manually).
func writeBackupFixture(t *testing.T, dataDir string, port int, ts, marker string) string {
	t.Helper()
	dir := filepath.Join(dataDir, "backups")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	path := filepath.Join(dir, "config.json.bak-"+ts)
	require.NoError(t, os.WriteFile(path, fakeCoreConfigJSON(t, port, marker), 0o600))
	return path
}

// newTestManager builds a manager over the fake binary and registers full
// cleanup (child stopped, flock released) so no test leaks a process or a
// lock into its neighbors.
func newTestManager(t *testing.T, cfg config.CoreConfig, dataDir string, log io.Writer) *Manager {
	t.Helper()
	cfg.XrayBin = fakeBin(t)
	m, err := NewManager(cfg, dataDir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)
	return m
}

// newManagedTestManager builds a manager in the USER-LOCAL layout (empty
// [core].xray_bin, the fake binary at the injected ~/.local/bin/xray, no
// system xray on the injected standard paths) — the shape the
// download/AutoUpdate tests exercise (S5 inertness keys on the override
// being ABSENT). The user-local dir and the standard-path list are
// seam-injected here so no manager in this suite can ever scan the real
// $HOME/.local or /usr trees.
func newManagedTestManager(t *testing.T, cfg config.CoreConfig, dataDir string, log io.Writer) *Manager {
	t.Helper()
	require.Empty(t, cfg.XrayBin, "the managed-layout helper takes an empty override")
	userLocal, _ := withResolutionSeams(t)
	fake := fakeBin(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(userLocal), 0o750))
	// Idempotent: subtests may share the data dir fixture.
	_ = os.Remove(userLocal)
	require.NoError(t, os.Symlink(fake, userLocal))
	m, err := NewManager(cfg, dataDir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)
	return m
}

// waitPortRefused polls until the socks port stops answering (a killed
// listener is gone at reap time; the loop only absorbs scheduler jitter).
func waitPortRefused(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).
			Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("socks 127.0.0.1:%d still answering after Stop", port)
}

// TestManagerSpawnsAndKillsFakeCore (brief test 1): the fake binary sleeps;
// EnsureRunning brings the socks inbound up, the pidfile records a live
// process, Stop kills it by the exact PID and reaps — the port is gone and
// the pidfile with it.
func TestManagerSpawnsAndKillsFakeCore(t *testing.T) {
	dataDir := t.TempDir()
	const port = 22940
	writeLiveFixture(t, dataDir, port, "spawn-test")

	log := &syncBuffer{}
	m := newTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dataDir, log)

	require.NoError(t, m.EnsureRunning(context.Background()))

	// The socks inbound listens and the pidfile names a live process.
	require.NoError(t, waitPortAccepted(port), "EnsureRunning must leave the socks port listening")
	pid := readPIDFileForTest(t, filepath.Join(dataDir, "core.pid"))
	require.NoError(t, syscall.Kill(pid, 0), "the pidfile must name a live process")
	assert.True(t, m.Alive(), "Alive() must be true with a live child")
	require.Contains(t, log.String(), "core: spawned pid", "the spawn must log loud")

	require.NoError(t, m.Stop())

	waitPortRefused(t, port)
	_, err := os.Stat(filepath.Join(dataDir, "core.pid"))
	assert.True(t, os.IsNotExist(err), "Stop must remove the pidfile")
	assert.False(t, m.Alive(), "Alive() must be false after Stop")
	assert.False(t, PIDAlive(pid), "the child process must be gone")
	require.Contains(t, log.String(), "core: stopped pid", "the stop must log loud")

	// Idempotence: a second Stop is a no-op, not an error.
	require.NoError(t, m.Stop())
}

// TestSingletonLockRefusesSecondManager (brief test 2): the flock at
// <data>/core.lock is a one-shot singleton — a second manager on the same
// data dir fails with ErrDaemonHoldsCore, and the refusal must not disturb
// the first manager (which keeps working).
func TestSingletonLockRefusesSecondManager(t *testing.T) {
	dataDir := t.TempDir()
	const port = 22944
	writeLiveFixture(t, dataDir, port, "singleton-test")

	log := &syncBuffer{}
	m1 := newTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dataDir, log)

	cfg := config.CoreConfig{SocksPort: port, RollbackStrikes: 3}
	cfg.XrayBin = os.Args[0]
	m2, err := NewManager(cfg, dataDir, &syncBuffer{})
	require.Error(t, err, "a second manager on the same data dir must refuse")
	assert.Nil(t, m2)
	require.ErrorIs(t, err, ErrDaemonHoldsCore)
	require.Contains(t, err.Error(), "core.lock", "the refusal must name the lock")

	// The refusal leaves the first holder untouched.
	require.NoError(t, m1.EnsureRunning(context.Background()))
	require.NoError(t, waitPortAccepted(port))
}

// TestStrikesTriggerRollback (brief test 3): a dead-outbound core fails
// health three times with rollback_strikes=3; the third strike restores the
// newest backup into live.json, restarts the core on it (which then passes
// health), and logs the loud D8 line naming the rollback.
func TestStrikesTriggerRollback(t *testing.T) {
	dataDir := t.TempDir()
	const port = 22948
	writeLiveFixture(t, dataDir, port, fakeDeadMarker)
	bakPath := writeBackupFixture(t, dataDir, port, "20260101-000000", "restored-from-backup")

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer site.Close()

	log := &syncBuffer{}
	m := newTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dataDir, log)
	m.healthURL = site.URL
	require.NoError(t, m.EnsureRunning(context.Background()))

	ctx := context.Background()
	for strike := 1; strike <= 3; strike++ {
		err := m.Healthy(ctx)
		require.Error(t, err, "the dead-outbound core must fail health (strike %d)", strike)
		rolledBack := m.RecordHealth(err)
		if strike < 3 {
			assert.False(t, rolledBack, "strike %d must not roll back yet", strike)
		} else {
			require.True(t, rolledBack, "strike 3 must trigger the D8 rollback")
		}
	}

	// The backup content is now live.json's content (byte-identical restore).
	restored, rerr := os.ReadFile(filepath.Join(dataDir, "rendered", "live.json"))
	require.NoError(t, rerr)
	backup, berr := os.ReadFile(bakPath)
	require.NoError(t, berr)
	assert.Equal(t, string(backup), string(restored), "rollback must restore the backup byte-identically")

	// The core was restarted ON the restored config: it is healthy now.
	require.NoError(t, m.Healthy(ctx), "the restarted core must serve the restored config")

	logs := log.String()
	require.Contains(t, logs, "ROLLBACK", "the loud D8 line must name the rollback")
	require.Contains(t, logs, bakPath, "the loud D8 line must name the restored backup")

	// The persisted mirror (T7): the rollback record is disk truth — it
	// survives in the state file the status core block reads, alongside the
	// post-rollback strike reset.
	h, herr := ReadHealthState(dataDir)
	require.NoError(t, herr)
	require.NotNil(t, h, "the mirror must exist after health transitions")
	assert.Equal(t, 0, h.Strikes, "the post-rollback strike reset persists")
	assert.Contains(t, h.LastRollbackBackup, "config.json.bak-",
		"the rollback record names the restored backup")
	assert.False(t, h.LastRollbackAt.IsZero(), "the rollback timestamp persists")
}

// TestRecordHealthPersistsStrikeState (T7): every RecordHealth transition
// persists the D8 mirror the status core block reads cross-process —
// failures increment under the K clamp, a healthy check resets, and a
// fresh manager RESETS the file (the streak lives in the process that
// counts it; the mirror must never outlive its truth).
func TestRecordHealthPersistsStrikeState(t *testing.T) {
	dataDir := t.TempDir()
	const port = 22952
	writeLiveFixture(t, dataDir, port, fakeDeadMarker)

	m := newTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dataDir, &syncBuffer{})
	require.NoError(t, m.EnsureRunning(context.Background()))

	// NewManager reset the mirror.
	h, herr := ReadHealthState(dataDir)
	require.NoError(t, herr)
	require.NotNil(t, h, "NewManager resets the mirror into existence")
	assert.Equal(t, 0, h.Strikes)

	// One failed transition: the mirror carries the strike and the error.
	err := m.Healthy(context.Background())
	require.Error(t, err, "the dead-outbound core must fail health")
	assert.False(t, m.RecordHealth(err))
	h, herr = ReadHealthState(dataDir)
	require.NoError(t, herr)
	require.NotNil(t, h)
	assert.Equal(t, 1, h.Strikes)
	assert.False(t, h.LastHealthy)
	assert.Equal(t, err.Error(), h.LastError)

	// A healthy transition resets the mirror (the counter's own reset,
	// mirrored).
	assert.False(t, m.RecordHealth(nil))
	h, herr = ReadHealthState(dataDir)
	require.NoError(t, herr)
	require.NotNil(t, h)
	assert.Equal(t, 0, h.Strikes)
	assert.True(t, h.LastHealthy)
	assert.Empty(t, h.LastError)
}

// TestStrikesResetOnHealthy (brief test 4): a healthy check resets the
// strike counter — after two failures, a healthy record, and two more
// failures the counter stands at 2/3 (no rollback); only the third
// consecutive failure rolls back.
func TestStrikesResetOnHealthy(t *testing.T) {
	dataDir := t.TempDir()
	const port = 22956
	writeLiveFixture(t, dataDir, port, fakeDeadMarker)
	bakPath := writeBackupFixture(t, dataDir, port, "20260101-000000", "restored-after-reset")

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer site.Close()

	m := newTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dataDir, &syncBuffer{})
	m.healthURL = site.URL
	require.NoError(t, m.EnsureRunning(context.Background()))

	ctx := context.Background()
	// Strikes 1, 2.
	for i := 1; i <= 2; i++ {
		err := m.Healthy(ctx)
		require.Error(t, err, "the dead-outbound core must fail health (pre-reset strike %d)", i)
		assert.False(t, m.RecordHealth(err), "pre-reset strike %d must not roll back", i)
	}
	// A healthy record resets the counter.
	assert.False(t, m.RecordHealth(nil), "a healthy record never rolls back")
	// Strikes 1, 2 again — the reset is proven by what does NOT happen:
	// without it, the second failure here would already be strike 3.
	for i := 1; i <= 2; i++ {
		err := m.Healthy(ctx)
		require.Error(t, err, "the dead-outbound core must fail health (post-reset strike %d)", i)
		assert.False(t, m.RecordHealth(err), "post-reset strike %d must not roll back", i)
	}
	// The third CONSECUTIVE failure rolls back.
	err := m.Healthy(ctx)
	require.Error(t, err)
	require.True(t, m.RecordHealth(err), "the third consecutive failure must roll back")

	restored, rerr := os.ReadFile(filepath.Join(dataDir, "rendered", "live.json"))
	require.NoError(t, rerr)
	backup, berr := os.ReadFile(bakPath)
	require.NoError(t, berr)
	assert.Equal(t, string(backup), string(restored), "rollback must restore the backup byte-identically")
}

// TestRollbackRunsTestGate (brief test 5): a newest backup that fails the
// `-test` gate refuses the rollback loud — the previous live config stays on
// disk, the core keeps running on it, and the refusal names the failed
// backup.
func TestRollbackRunsTestGate(t *testing.T) {
	dataDir := t.TempDir()
	const port = 22960
	writeLiveFixture(t, dataDir, port, fakeDeadMarker)
	bakPath := writeBackupFixture(t, dataDir, port, "20260101-000000", fakeGateFailMarker)

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer site.Close()

	log := &syncBuffer{}
	m := newTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dataDir, log)
	m.healthURL = site.URL
	require.NoError(t, m.EnsureRunning(context.Background()))

	ctx := context.Background()
	for strike := 1; strike <= 3; strike++ {
		err := m.Healthy(ctx)
		require.Error(t, err, "the dead-outbound core must fail health (strike %d)", strike)
		assert.False(t, m.RecordHealth(err),
			"strike %d: a backup that fails -test must refuse the rollback", strike)
	}

	// Previous state kept: live.json untouched, core still running.
	live, rerr := os.ReadFile(filepath.Join(dataDir, "rendered", "live.json"))
	require.NoError(t, rerr)
	assert.Contains(t, string(live), fakeDeadMarker,
		"the refused rollback must keep the previous live config")
	assert.True(t, m.Alive(), "the refused rollback must keep the core running")
	require.NoError(t, waitPortAccepted(port))

	logs := log.String()
	require.Contains(t, logs, "rollback refused", "the refusal must be loud")
	require.Contains(t, logs, bakPath, "the refusal must name the failed backup")
}

// TestManagerBinResolutionMatchesCoreXrayBin pins the S1 single-knob mirror:
// NewManager receives CoreConfig + dataDir (not the whole Config), so it
// resolves the managed default and the explicit override ITSELF — that
// resolution must match config.CoreXrayBin byte-for-byte and never drift.
func TestManagerBinResolutionMatchesCoreXrayBin(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(config.CoreConfig{}, dir, &syncBuffer{})
	require.NoError(t, err)
	t.Cleanup(m.release)
	want := (&config.Config{DataDir: dir}).CoreXrayBin()
	assert.Equal(t, want, m.bin, "the managed default must mirror CoreXrayBin")

	dir2 := t.TempDir()
	m2, err := NewManager(config.CoreConfig{XrayBin: "/usr/local/bin/xray"}, dir2, &syncBuffer{})
	require.NoError(t, err)
	t.Cleanup(m2.release)
	assert.Equal(t, "/usr/local/bin/xray", m2.bin, "an explicit override must win")
	assert.Equal(t, (&config.Config{Core: config.CoreConfig{XrayBin: "/usr/local/bin/xray"}}).CoreXrayBin(), m2.bin)
}

// TestTailWriterForwardsFullWriteTruncatesTailOnly pins the I-1 fix (review
// round 1): a write larger than the tail bound must reach the forwarded
// sink COMPLETE — S7 allows no byte to be dropped from the journal stream —
// while the retained diagnostics view stays bounded, keeping the LAST bytes
// (boot-death diagnostics want the child's dying words).
func TestTailWriterForwardsFullWriteTruncatesTailOnly(t *testing.T) {
	log := &syncBuffer{}
	const limit = 32
	w := newTailWriter(log, limit)

	payload := strings.Repeat("J", 200)
	n, err := w.Write([]byte(payload))
	require.NoError(t, err)
	require.Equal(t, len(payload), n, "the forwarded write must report the full length")
	require.Equal(t, payload, log.String(),
		"the forwarded stream must carry every byte — truncating it would silently lose journal chunks")
	assert.Equal(t, strings.Repeat("J", limit), w.String(), "the retained view is bounded")

	// Across writes the view keeps sliding to the tail; the forwarded
	// stream only ever accumulates.
	second := strings.Repeat("K", 16)
	_, werr := w.Write([]byte(second))
	require.NoError(t, werr)
	assert.Equal(t, payload+second, log.String(), "every forwarded byte accumulates")
	assert.Equal(t, strings.Repeat("J", limit-len(second))+second, w.String(),
		"the retained view keeps the last %d bytes", limit)
}

// readPIDFileForTest reads the pidfile and returns its integer content.
func readPIDFileForTest(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "the pidfile must exist")
	pid, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, perr, "the pidfile must carry a decimal pid")
	require.Positive(t, pid)
	return pid
}

// waitPortAccepted polls until the socks port accepts a TCP connection.
func waitPortAccepted(port int) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).
			Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("socks 127.0.0.1:%d never accepted", port)
}

// startZombieProcess spawns a child that exits (becoming a zombie — alive to
// kill(0), immune to SIGKILL, never reaped by this manager) and returns a
// reaper for cleanup. Skips on hosts without /proc.
type zombieProcess struct {
	cmd *exec.Cmd
	pid int
}

func (z *zombieProcess) reap() {
	_, _ = z.cmd.Process.Wait()
}

func startZombieProcess(t *testing.T) *zombieProcess {
	t.Helper()
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc — the zombie liveness probe is Linux-specific")
	}
	cmd := exec.CommandContext(context.Background(), "/bin/true")
	require.NoError(t, cmd.Start())
	z := &zombieProcess{cmd: cmd, pid: cmd.Process.Pid}
	t.Cleanup(z.reap)
	// Wait until the child is actually a zombie (exited, unreaped): only
	// then is kill(0) guaranteed to succeed while SIGKILL does nothing.
	require.Eventually(t, func() bool {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", z.pid))
		if err != nil {
			return false
		}
		// state sits after the last ')' field.
		idx := strings.LastIndex(string(raw), ")")
		return idx > 0 && idx+2 < len(raw) && raw[idx+2] == 'Z'
	}, 5*time.Second, 20*time.Millisecond, "the child must become a zombie for the test")
	return z
}

// TestAdoptedStopLogsPostPollTruth (T2 review M-2): Stop of an ADOPTED pid
// logs the POST-poll liveness truth — a pid that survived the SIGKILL poll
// (zombie/D-state class) is reported as still alive, never as a clean stop.
func TestAdoptedStopLogsPostPollTruth(t *testing.T) {
	z := startZombieProcess(t)

	origPoll := adoptedStopPoll
	adoptedStopPoll = 300 * time.Millisecond
	t.Cleanup(func() { adoptedStopPoll = origPoll })

	dataDir := t.TempDir()
	log := &syncBuffer{}
	m := newTestManager(t, config.CoreConfig{SocksPort: 22964, RollbackStrikes: 3}, dataDir, log)
	// White-box: put the manager straight into the adopted state under test
	// (adoption itself is T2-tested; the stop-leg truth is the M-2 subject).
	m.adoptedPID = z.pid

	require.NoError(t, m.Stop())
	require.Contains(t, log.String(), "still alive",
		"Stop must log the post-poll liveness truth for a pid the SIGKILL could not reap (T2 M-2)")
	assert.NotContains(t, log.String(), "stopped adopted pid",
		"the clean-stop line would be a lie for an unreapable pid")
}

// TestAdoptedStopTreatsGonePidAsClean: Stop of an ADOPTED pid that is
// already fully gone (exited AND reaped — unix kill(0) reads ESRCH) is a
// CLEAN stop: no error, the clean-stop line, the stale pidfile cleared.
// This is the benign adopted-core-died-between-adoption-and-Stop race the
// review P2-1 fix must preserve on unix while extending the ignore to the
// windows ErrProcessGone sentinel (compile-pinned in internal/platform's
// process_windows_test.go — the windows transport cannot run on linux).
func TestAdoptedStopTreatsGonePidAsClean(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc — pid-gone probing is Linux-specific")
	}
	cmd := exec.CommandContext(context.Background(), "/bin/true")
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	_, _ = cmd.Process.Wait() // fully reap: unlike the zombie fixture, the pid is now GONE
	require.Eventually(t, func() bool {
		return syscall.Kill(pid, 0) != nil // ESRCH — the pid is fully gone
	}, 5*time.Second, 20*time.Millisecond, "the child must be fully reaped for the test")

	dataDir := t.TempDir()
	log := &syncBuffer{}
	m := newTestManager(t, config.CoreConfig{SocksPort: 22974, RollbackStrikes: 3}, dataDir, log)
	// White-box adopted state, mirroring A2 adoption of a core that died
	// between the previous daemon's exit and this Stop.
	m.adoptedPID = pid
	require.NoError(t, m.writePIDFile(pid))

	require.NoError(t, m.Stop(), "a gone adopted pid is a benign race — the stop must be clean")
	require.Contains(t, log.String(), fmt.Sprintf("stopped adopted pid %d", pid),
		"a gone pid must be treated as a clean stop (the unix ESRCH contract)")
	require.NotContains(t, log.String(), "still alive",
		"a gone pid must never be reported as a surviving stop")
	require.NoFileExists(t, filepath.Join(dataDir, PIDFileName),
		"the clean-stop path must clear the stale pidfile")
}

// TestStopSessionChildReapWaitIsBounded (termination-audit P1): the
// session-child stop's reap wait must be BOUNDED — a child that accepted
// the kill but never completes exec.Wait (the D-state class: hung FUSE/NFS
// I/O, stuck driver) previously left Stop() waiting on the reaper channel
// forever, and with it the daemon's finishGraceful, the darwin miss-path
// goroutine, and every checker teardown.
//
// The simulation is white-box and honest: a REAL child process is spawned
// (its state is irrelevant — kill(2) succeeds against a live or zombie pid
// either way) and the manager's reap signal is pre-armed with a channel
// that NEVER closes. "Kill accepted + Wait never returned" is the exact
// observable of an unreapable child; a real fixture that ignores signals
// cannot reproduce the hang (SIGKILL kills it, the reap completes — the
// linux ladder has no graceful stage to ignore). The production bound
// (5s) is shortened through the adoptedStopPoll seam (the T2 review M-2
// precedent) so this proof runs in milliseconds, not minutes.
func TestStopSessionChildReapWaitIsBounded(t *testing.T) {
	// The child: the test binary listing its tests — exits immediately,
	// hermetically, no external binary. It is never reaped by the manager
	// (the reaper is bypassed below); the cleanup kills and reaps it.
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.list=.*")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	origPoll := adoptedStopPoll
	adoptedStopPoll = 300 * time.Millisecond
	t.Cleanup(func() { adoptedStopPoll = origPoll })

	m := newTestManager(t, config.CoreConfig{SocksPort: 22978, RollbackStrikes: 3}, t.TempDir(), &syncBuffer{})
	// White-box: install the child handle and pre-arm the reap signal with
	// a channel that never closes — the unreapable-child state.
	m.mu.Lock()
	m.cmd = cmd
	m.done = make(chan struct{}) // never closed
	m.waitOnce.Do(func() {})     // consume the once: waitDone() returns the fake channel
	m.mu.Unlock()

	stopped := make(chan error, 1)
	start := time.Now()
	go func() { stopped <- m.Stop() }()
	select {
	case err := <-stopped:
		require.Error(t, err, "a child the kill could not reap is NOT a clean stop")
		require.Contains(t, err.Error(), strconv.Itoa(cmd.Process.Pid), "the error names the exact pid")
		require.Contains(t, err.Error(), "not reaped", "the error says what did not happen")
		require.Contains(t, err.Error(), "D-state", "the error carries the audit vocabulary (the adopted-path precedent)")
		require.Contains(t, err.Error(), "kill -KILL", "the error carries the exact manual escalation")
		require.Less(t, time.Since(start), 5*time.Second, "the bound returned well within the watchdog")
	case <-time.After(10 * time.Second):
		t.Fatalf("Stop() hung past %s on the reap wait — the session-child stop is UNBOUNDED (audit P1)",
			time.Since(start).Round(time.Second))
	}
}

// TestSingletonLockRefusedCrossProcess (T2 review M-5): the flock refusal is
// kernel-guaranteed ACROSS PROCESSES — a helper process holding the lock
// makes a manager in THIS process refuse with ErrDaemonHoldsCore.
func TestSingletonLockRefusedCrossProcess(t *testing.T) {
	dataDir := t.TempDir()
	const port = 22968
	marker := filepath.Join(dataDir, "lock-helper-ready")

	cmd := exec.CommandContext(context.Background(), os.Args[0])
	cmd.Env = append(os.Environ(),
		"CORELOCK_HELPER="+dataDir,
		"CORELOCK_HELPER_MARKER="+marker,
		"CORELOCK_HELPER_PORT="+strconv.Itoa(port),
	)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	})

	// The helper holds the lock once its marker file lands.
	require.Eventually(t, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}, 10*time.Second, 20*time.Millisecond, "the helper process must take the singleton lock")

	_, err := NewManager(config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dataDir, &syncBuffer{})
	require.ErrorIs(t, err, ErrDaemonHoldsCore,
		"the lock held by ANOTHER PROCESS must refuse this manager too")
	require.Contains(t, err.Error(), "core.lock", "the refusal names the lock file")
}

// TestStrikeDisplayClampsAtStrikeCap (T2 review M-1): a REFUSED rollback
// keeps attempting on every further failure — and the failure line's display
// clamps at K, so a refused streak logs "2/2" forever, never "3/2, 4/2…".
func TestStrikeDisplayClampsAtStrikeCap(t *testing.T) {
	dataDir := t.TempDir()
	const port = 22972
	writeLiveFixture(t, dataDir, port, fakeDeadMarker) // NO backups: every rollback refuses

	log := &syncBuffer{}
	m := newTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 2}, dataDir, log)
	require.NoError(t, m.EnsureRunning(context.Background()))

	ctx := context.Background()
	for i := range 4 {
		err := m.Healthy(ctx)
		require.Error(t, err, "the dead-outbound core must fail health (strike %d)", i+1)
		assert.False(t, m.RecordHealth(err), "no backups exist — the rollback must refuse")
	}

	logs := log.String()
	require.Contains(t, logs, "rollback refused", "the refused streak keeps attempting, loud")
	require.Contains(t, logs, "health failure 2/2", "the display reports the streak at K")
	assert.NotContains(t, logs, "3/2", "the display must clamp at K — no 3/2 line (T2 M-1)")
	assert.NotContains(t, logs, "4/2", "the display must clamp at K — no 4/2 line")
}

// TestSuperviseRevivesKilledChildWithoutStrikes (G1 crash supervision):
// between waves the manager supervises the child — an EXTERNAL kill (a
// crash, non-Stop exit) is detected, logged loud, and revived after a
// bounded backoff, twice in a row. The supervision restarts feed NO D8
// strikes (strikes are activation-health-driven only, C3).
func TestSuperviseRevivesKilledChildWithoutStrikes(t *testing.T) {
	dataDir := t.TempDir()
	const port = 22976
	writeLiveFixture(t, dataDir, port, "supervise-test")

	origStart, origCap := crashBackoffStart, crashBackoffCap
	crashBackoffStart, crashBackoffCap = 5*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { crashBackoffStart, crashBackoffCap = origStart, origCap })

	log := &syncBuffer{}
	m := newTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dataDir, log)

	stop := make(chan struct{})
	m.Supervise(stop)
	t.Cleanup(func() { close(stop) })

	require.NoError(t, m.EnsureRunning(context.Background()))
	pid := readPIDFileForTest(t, filepath.Join(dataDir, "core.pid"))

	for i := range 2 {
		require.NoError(t, syscall.Kill(pid, syscall.SIGKILL), "external kill, iteration %d", i)

		// The supervisor revives: a NEW pid appears in the pidfile AND the
		// socks inbound serves again.
		var revived int
		require.Eventually(t, func() bool {
			raw, err := os.ReadFile(filepath.Join(dataDir, "core.pid"))
			if err != nil {
				return false
			}
			n, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
			if perr != nil || n <= 0 || n == pid {
				return false
			}
			conn, derr := (&net.Dialer{Timeout: 200 * time.Millisecond}).
				Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if derr != nil {
				return false
			}
			_ = conn.Close()
			revived = n
			return true
		}, 5*time.Second, 50*time.Millisecond,
			"the supervisor must revive the killed child (iteration %d)", i)
		pid = revived
	}

	logs := log.String()
	require.Contains(t, logs, "crash supervision", "the crash is loud (a non-Stop exit)")
	assert.NotContains(t, logs, "ROLLBACK",
		"crash restarts must NOT feed the D8 strike counter (C3: strikes are activation-health-driven)")
	assert.NotContains(t, logs, "health failure",
		"the supervision path runs no health check and feeds no strike")
}

// TestNewManagerPreservesRollbackRecordAcrossRestarts (T7 fix round 1, I-1):
// a daemon restart resets the D8 STREAK (it lives in the counting process)
// but must NOT clobber the rollback record — the restore really happened on
// disk, and the status core block's whole purpose is cross-process
// observation of exactly that history. NewManager is therefore
// create-if-absent with a streak-only reset, never an unconditional wipe.
func TestNewManagerPreservesRollbackRecordAcrossRestarts(t *testing.T) {
	dataDir := t.TempDir()
	const port = 22980

	// A previous daemon session left: a live streak, a last-check stamp, and
	// a rollback record (the D8 restore ran before it died).
	checked := time.Now().Add(-time.Hour)
	rolled := time.Now().Add(-30 * time.Minute)
	require.NoError(t, writeHealthStateFile(dataDir, &HealthState{
		Strikes:            2,
		LastCheckAt:        checked,
		LastHealthy:        false,
		LastError:          "socks unreachable",
		LastRollbackAt:     rolled,
		LastRollbackBackup: "config.json.bak-20261111-120000",
	}))

	// The daemon restarts: a fresh manager takes the lock.
	m := newTestManager(t, config.CoreConfig{SocksPort: port}, dataDir, &syncBuffer{})
	_ = m

	h, herr := ReadHealthState(dataDir)
	require.NoError(t, herr)
	require.NotNil(t, h, "the mirror must exist after the restart")
	assert.Equal(t, 0, h.Strikes, "the streak resets with the counting process")
	assert.Empty(t, h.LastError, "the streak's last error resets with it")
	assert.False(t, h.LastHealthy, "no health check has run under the new process")
	assert.True(t, checked.Equal(h.LastCheckAt), "the last-check stamp is history and survives")
	assert.Equal(t, "config.json.bak-20261111-120000", h.LastRollbackBackup,
		"the rollback record is disk truth — it survives daemon restarts")
	assert.True(t, rolled.Equal(h.LastRollbackAt), "the rollback timestamp survives")
}
