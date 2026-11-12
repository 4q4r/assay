//go:build unix

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"assay/internal/config"
	"assay/internal/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statusCoreConfig loads a minimal config for the own-core status tests:
// the data dir is the fixture dir, [core].socks_port points at the fake
// core's inbound (the manager's health leg dials it), and the strike cap
// is the D8 default.
func statusCoreConfig(t *testing.T, dir string, socksPort int) *config.Config {
	t.Helper()
	cfgPath := filepath.Join(dir, "config.toml")
	body := fmt.Sprintf(`
data_dir = %q

[core]
socks_port = %d
rollback_strikes = 3
`, filepath.Join(dir, "data"), socksPort)
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	return mustLoad(t, cfgPath)
}

// statusCoreLiveConfig writes the own live config the fake core runs on:
// socks first (the fake binds the FIRST inbound), http second, and the
// reserved stats/API dokodemo-door inbound — the shape RenderOwnConfig
// emits on EVERY real run (ensureAPIStats is unconditional; the T7 review's
// I-2 fixture gap hid exactly this row, which is why api-in was once
// mis-classified as a per-country inbound).
func statusCoreLiveConfig(t *testing.T, dataDir string, socksPort, httpPort int) {
	t.Helper()
	live := fmt.Sprintf(`{"inbounds":[
		{"tag":"in","listen":"127.0.0.1","port":%d,"protocol":"socks"},
		{"tag":"in-http","listen":"127.0.0.1","port":%d,"protocol":"http"},
		{"tag":"api-in","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door"}
	]}`, socksPort, httpPort, nextCoreTestPort())
	require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "rendered"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "rendered", "live.json"),
		[]byte(live), 0o600))
}

// TestStatusCoreBlockRunning (plan T7 test 1): with a fake core actually
// running through the manager, the block renders the honest observables —
// PID, version, uptime, the live config's inbounds, and the D8 strike
// count persisted by RecordHealth.
func TestStatusCoreBlockRunning(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	socksPort, httpPort := nextCoreTestPort(), nextCoreTestPort()
	statusCoreLiveConfig(t, dataDir, socksPort, httpPort)
	cfg := statusCoreConfig(t, dir, socksPort)
	cfg.Core.XrayBin = cliFakeBinary(t) // the version banner is the fake's

	mgr, err := core.NewManager(cfg.Core, dataDir, &strings.Builder{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop() })
	require.NoError(t, mgr.EnsureRunning(context.Background()))

	// Two failed post-activation health checks feed the D8 counter (the
	// fake's dead-outbound refusal makes Healthy fail for real).
	require.Error(t, mgr.Healthy(context.Background()))
	require.False(t, mgr.RecordHealth(errors.New("fake outbound dead")))
	require.Error(t, mgr.Healthy(context.Background()))
	require.False(t, mgr.RecordHealth(errors.New("fake outbound dead")))

	cs := collectCoreState(newPaths(cfg), cfg)
	require.NotNil(t, cs)

	var b strings.Builder
	printCoreStatus(&b, cs, false)
	out := b.String()

	assert.Contains(t, out, "own core", "the section header renders")
	assert.Contains(t, out, "running (pid ", "the alive state names the PID")
	assert.Contains(t, out, strconv.Itoa(pidFromPidfile(t, dataDir)), "the pidfile's PID renders")
	assert.Contains(t, out, "up ", "uptime renders")
	assert.Contains(t, out, "26.9.9", "the `xray version` banner parses (the fake's banner)")
	assert.Contains(t, out, "socks 127.0.0.1:"+strconv.Itoa(socksPort), "the socks inbound renders")
	assert.Contains(t, out, "http 127.0.0.1:"+strconv.Itoa(httpPort), "the http inbound renders")
	// I-2 (T7 fix round): the api inbound is on every real render — it must
	// read as its own explicit entry, NEVER as a per-country count.
	assert.Contains(t, out, "api 127.0.0.1:", "the reserved api inbound renders as its own entry")
	assert.NotContains(t, out, "per-country: api-in",
		"the api inbound is not a per-country inbound (the default config renders none)")
	assert.Contains(t, out, "strikes 2/3", "the persisted D8 strike count renders")
	assert.Contains(t, out, "last check failed: fake outbound dead", "the last health error renders")
}

// TestStatusCoreBlockNotRunning (plan T7 test 1, honest degraded half): no
// manager ever ran → the block says so; a stale pidfile (dead PID) is named
// as stale, never rendered as running; a missing managed binary degrades
// the version line instead of crashing the section.
func TestStatusCoreBlockNotRunning(t *testing.T) {
	injectCoreBinSeams(t) // the resolved path must be a fixture, never the machine's real binaries
	dir := t.TempDir()
	cfg := statusCoreConfig(t, dir, nextCoreTestPort())

	var b strings.Builder
	printCoreStatus(&b, collectCoreState(newPaths(cfg), cfg), false)
	out := b.String()
	assert.Contains(t, out, "not running", "the empty data dir degrades honestly")
	assert.Contains(t, out, "has not started the core", "the not-running reason is named")

	// A stale pidfile: the PID is written but the process is long gone.
	staleDir := filepath.Join(dir, "stale")
	require.NoError(t, os.MkdirAll(staleDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(staleDir, "core.pid"),
		[]byte(strconv.Itoa(deadPID())), 0o600))
	cfgStale := statusCoreConfig(t, dir, nextCoreTestPort())
	cfgStale.DataDir = staleDir
	b.Reset()
	printCoreStatus(&b, collectCoreState(newPaths(cfgStale), cfgStale), false)
	assert.Contains(t, b.String(), "not running", "a dead pidfile pid is not rendered as running")
	assert.Contains(t, b.String(), "stale", "the stale pidfile is named as such")

	// Version honesty: with no managed binary and no override the version
	// line names the missing artifact instead of crashing or fabricating.
	require.NoError(t, os.MkdirAll(filepath.Join(staleDir, "rendered"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(staleDir, "rendered", "live.json"), []byte("{}"), 0o600))
	b.Reset()
	printCoreStatus(&b, collectCoreState(newPaths(cfgStale), cfgStale), false)
	assert.Contains(t, b.String(), "no core binary at the resolved path",
		"the missing core binary degrades the version line")
}

// TestStatusCoreBlockRollbackState pins the rollback half of the strike
// state: after a real D8 rollback through the manager the block names the
// restored backup (cross-process, from the persisted state).
func TestStatusCoreBlockRollbackState(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	socksPort := nextCoreTestPort()
	statusCoreLiveConfig(t, dataDir, socksPort, nextCoreTestPort())
	cfg := statusCoreConfig(t, dir, socksPort)
	cfg.Core.XrayBin = cliFakeBinary(t)

	// The newest backup carries the gate-fail marker → the D8 rollback is
	// REFUSED (the -test gate fails), which is still a persisted rollback
	// ATTEMPT on the refused streak — the refused state renders honestly.
	mgr, err := core.NewManager(cfg.Core, dataDir, &strings.Builder{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop() })
	require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "backups"), 0o750))
	bak := filepath.Join(dataDir, "backups", "config.json.bak-20261111-000000")
	require.NoError(t, os.WriteFile(bak, []byte("COREFAKE_GATE_FAIL_NOT_USED_HERE"), 0o600))
	for range 3 {
		require.Error(t, mgr.Healthy(context.Background()))
		require.False(t, mgr.RecordHealth(errors.New("fake outbound dead")))
	}

	cs := collectCoreState(newPaths(cfg), cfg)
	var b strings.Builder
	printCoreStatus(&b, cs, false)
	assert.Contains(t, b.String(), "strikes 3/3", "the refused streak clamps at K (T2 review M-1)")
}

// pidFromPidfile reads the pidfile the manager wrote (test convenience).
func pidFromPidfile(t *testing.T, dataDir string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dataDir, "core.pid"))
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	return pid
}

// deadPID returns a PID that is provably not alive on this machine: the
// test spawns a short-lived process, waits for it, and uses its PID (the
// kernel will not hand it back as a running process within the test).
func deadPID() int {
	cmd := exec.CommandContext(context.Background(), "true")
	_ = cmd.Run()
	return cmd.Process.Pid
}

// injectCoreBinSeams points the core-binary resolution seams (the
// owner-ruling user-local dir and the standard-path list) at fixture dirs,
// so the status tests never depend on the machine's real ~/.local/bin/xray
// or /usr/bin/xray. Returns the (absent unless planted) user-local and
// canonical system binary paths.
func injectCoreBinSeams(t *testing.T) (string, string) {
	t.Helper()
	userBin := filepath.Join(t.TempDir(), "local-bin")
	sysDir := t.TempDir()
	origDir, origPaths := config.UserLocalBinDir, config.DefaultSystemXrayPaths
	config.UserLocalBinDir = func() string { return userBin }
	config.DefaultSystemXrayPaths = []string{filepath.Join(sysDir, "xray")}
	t.Cleanup(func() {
		config.UserLocalBinDir = origDir
		config.DefaultSystemXrayPaths = origPaths
	})
	return filepath.Join(userBin, "xray"), filepath.Join(sysDir, "xray")
}

// statusFixtureBinary plants a stand-in "xray" answering `version` with the
// given version banner.
func statusFixtureBinary(t *testing.T, path, ver string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path,
		[]byte("#!/bin/sh\necho \"Xray "+ver+" (status fixture, Penetrates Nothing.)\"\nexit 0\n"),
		0o755))
}

// TestStatusCoreBlockSourceProvenance pins the owner-ruling addition: the
// core block renders the resolution provenance (binary_source/binary_path)
// from the persisted core-state.json, with the floor-warning state for a
// below-floor binding — non-blocking by contract.
func TestStatusCoreBlockSourceProvenance(t *testing.T) {
	dir := t.TempDir()
	userLocal, system := injectCoreBinSeams(t)

	render := func(t *testing.T, cfg *config.Config) string {
		t.Helper()
		var b strings.Builder
		printCoreStatus(&b, collectCoreState(newPaths(cfg), cfg), false)
		return b.String()
	}

	t.Run("system-preexisting renders with the non-blocking floor warning", func(t *testing.T) {
		dataDir := filepath.Join(dir, "data-sys")
		socksPort := nextCoreTestPort()
		statusCoreLiveConfig(t, dataDir, socksPort, nextCoreTestPort())
		statusFixtureBinary(t, system, "26.3.27")

		cfg := statusCoreConfig(t, dir, socksPort)
		cfg.DataDir = dataDir
		// The install-time resolution binds the pre-existing system core and
		// records the provenance (below floor — the binding proceeds).
		require.NoError(t, core.EnsureCoreBinary(context.Background(), config.CoreConfig{}, dataDir, io.Discard))

		out := render(t, cfg)
		assert.Contains(t, out, "source:  system-preexisting ("+system+")", "the bound source and path render")
		assert.Contains(t, out, "BELOW the observatory-safe floor "+core.VersionFloor(),
			"the floor warning renders for the below-floor binding")
		assert.Contains(t, out, "non-blocking", "the floor warning states its non-blocking contract")
		assert.Contains(t, out, "auto-update inert", "the system binding names the inert auto-update")
	})

	t.Run("user-local renders as assay-owned and updatable", func(t *testing.T) {
		dataDir := filepath.Join(dir, "data-user")
		socksPort := nextCoreTestPort()
		statusCoreLiveConfig(t, dataDir, socksPort, nextCoreTestPort())
		statusFixtureBinary(t, userLocal, "26.10.31")

		cfg := statusCoreConfig(t, dir, socksPort)
		cfg.DataDir = dataDir
		require.NoError(t, core.EnsureCoreBinary(context.Background(), config.CoreConfig{}, dataDir, io.Discard))

		out := render(t, cfg)
		assert.Contains(t, out, "source:  user-local ("+userLocal+")", "the user-local source and path render")
		assert.Contains(t, out, "auto-update keeps it current", "the updatable contract renders")
		assert.NotContains(t, out, "BELOW the observatory-safe floor",
			"no floor warning for an above-floor binding")
	})

	t.Run("override renders inert", func(t *testing.T) {
		dataDir := filepath.Join(dir, "data-override")
		socksPort := nextCoreTestPort()
		statusCoreLiveConfig(t, dataDir, socksPort, nextCoreTestPort())

		cfg := statusCoreConfig(t, dir, socksPort)
		cfg.DataDir = dataDir
		cfg.Core.XrayBin = "/opt/foreign/xray"
		require.NoError(t, core.EnsureCoreBinary(context.Background(), cfg.Core, dataDir, io.Discard))

		out := render(t, cfg)
		assert.Contains(t, out, "source:  override (/opt/foreign/xray)", "the override source renders")
		assert.Contains(t, out, "auto-update inert", "the override inertness renders")
	})
}
