package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/plugins"
	"assay/internal/selfwatchdog"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The windows service transport pins (plan §2.2.2/§2.2.3/§2.2.5/§2.2.6 +
// ADDENDUM §1). The svc.Handler state machine itself is windows-tagged
// (cmd/assay/svc_windows_test.go — CI leg); these tests pin the GOOS-neutral
// seam it drives: the serviceHooks stop transport (§2.2.3 — ONE graceful-stop
// seam, two feeds), the wired handshake (§2.2.2 — Running right after
// wiring), the service watchDeps assembly (ADDENDUM §1 — the self-watchdog
// transport with the SCM recovery note), and the §2.2.5 fail-closed refusal.

// serviceTestConfig builds the daemon config the service tests run under:
// the fake serve-mode core binary (hermetic bootstrap spawn) on a test-band
// port, plugins under the temp data dir — the TestRunWatchGracefulShutdown
// geometry.
func serviceTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	corePort := nextCoreTestPort()
	return &config.Config{
		DataDir: dir,
		Plugins: config.PluginsConfig{Dir: filepath.Join(dir, "plugins")},
		Core: config.CoreConfig{
			XrayBin:   cliFakeBinary(t),
			SocksPort: corePort,
			HTTPPort:  corePort + 1,
			Loglevel:  "warning",
		},
	}
}

// TestServiceStopRequestMirrorsSignal pins §2.2.3: the svc.Stop transport
// lands in the SAME graceful-stop seam the unix signals feed — requestStop
// → scheduler unwinds → explicit core stop → clean shutdown, exit nil. The
// log carries the windows reason line (the transport is named, never
// silent); the "clean shutdown" line is byte-identical with the SIGTERM
// path.
func TestServiceStopRequestMirrorsSignal(t *testing.T) {
	cfg := serviceTestConfig(t)
	wired := make(chan struct{})
	stopRequest := make(chan struct{})
	sdStarted := make(chan struct{})
	dep := watchDeps{
		startWatchdog: func(string, io.Writer) (*plugins.Registry, io.Closer, error) {
			return plugins.NewRegistry(), fakeCloser{}, nil
		},
		signals: make(chan os.Signal, 1), // never fired — the service feed ends it
		now:     time.Now,
		after: func(time.Duration) <-chan time.Time {
			return make(chan time.Time) // never fires
		},
		sdNotify: func(io.Writer) func() {
			close(sdStarted)
			return func() {}
		},
		serviceHooks: &serviceWiring{Wired: wired, StopRequest: stopRequest},
	}
	out := &syncWriter{}
	done := make(chan error, 1)
	go func() { done <- runWatch(out, cfg, dep) }()

	// The wired handshake (§2.2.2): the daemon reports readiness to the svc
	// handler right after wiring — bounded so a wedged wiring fails the test.
	select {
	case <-wired:
	case <-time.After(15 * time.Second):
		t.Fatalf("wired never closed — the daemon never finished wiring: %s", out.String())
	}
	select {
	case <-sdStarted:
	default:
		t.Fatal("wired must close only after the full wiring (sd_notify handshake included)")
	}
	// The daemon is still running — the handshake is NOT the shutdown.
	select {
	case err := <-done:
		t.Fatalf("runWatch returned before the stop request: %v", err)
	default:
	}

	close(stopRequest)
	select {
	case err := <-done:
		require.NoError(t, err, "the service stop exits nil — the same seam SIGTERM uses")
	case <-time.After(15 * time.Second):
		t.Fatalf("daemon did not shut down on the service stop request: %s", out.String())
	}
	assert.Contains(t, out.String(), "watch: windows service stop")
	assert.Contains(t, out.String(), "watch: clean shutdown")
}

// TestServiceHooksNilOnUnixShape pins that the production unix deps carry
// no service hooks — the select case stays inert (nil channel, never
// ready) and linux behavior is byte-identical (§2.2.3).
func TestServiceHooksNilOnUnixShape(t *testing.T) {
	dep := defaultWatchDeps()
	assert.Nil(t, dep.serviceHooks, "the production unix deps carry no service hooks")
}

// TestNewServiceWatchDepsPins pins the service-context deps assembly
// (ADDENDUM §1): the self-watchdog transport is ACTIVE (the service context
// IS the transport context — clean self-exit → SCM recovery actions
// restart), and the restart note names the mechanism.
func TestNewServiceWatchDepsPins(t *testing.T) {
	wired := make(chan struct{})
	stopRequest := make(chan struct{})
	deps := newServiceWatchDeps(wired, stopRequest)
	require.NotNil(t, deps.serviceHooks)
	require.NotNil(t, deps.serviceHooks.Wired)
	require.NotNil(t, deps.serviceHooks.StopRequest)

	require.NotNil(t, deps.selfWatch, "the service transport must be wired")
	beat, stop, active := deps.selfWatch(io.Discard, selfwatchdog.Threshold, func() {})
	assert.True(t, active, "the service context activates the self-watchdog transport (ADDENDUM §1)")
	stop()
	_ = beat

	assert.Contains(t, deps.restartNote, "SCM recovery actions")
}

// TestServiceDefaultDirRefusalPins pins the §2.2.5 fail-closed refusal: a
// service-context default resolution whose data dir lands under the SYSTEM
// profile refuses with the loud message naming BOTH fixes; on linux (and
// for a real user dir on windows) there is no refusal.
func TestServiceDefaultDirRefusalPins(t *testing.T) {
	sysDir := `C:\Windows\system32\config\systemprofile\AppData\Local\assay`
	msg := serviceDefaultDirRefusal("windows", sysDir)
	require.NotEmpty(t, msg, "the system-profile data dir must refuse")
	assert.Contains(t, msg, sysDir)
	assert.Contains(t, msg, "assay install")
	assert.Contains(t, msg, "-c")

	assert.Empty(t, serviceDefaultDirRefusal("windows", `C:\Users\u\AppData\Local\assay`))
	assert.Empty(t, serviceDefaultDirRefusal("linux", sysDir), "no SYSTEM profile on linux — check cannot apply")
}

// TestServiceLogSinkRefusesOutsideWindows pins the sink GOOS split: the
// file log sink is a windows service-context feature (§2.2.6 — service
// stdout goes nowhere; darwin has launchd redirects, linux journald). The
// non-windows build refuses loudly rather than silently succeeding.
func TestServiceLogSinkRefusesOutsideWindows(t *testing.T) {
	_, err := serviceLogSink(t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "windows")
}

// TestServiceSelfWatchActive pins that the production serviceSelfWatch
// transport activates the supervisor — the service context always runs the
// internal heartbeat (ADDENDUM §1: internal heartbeat → clean self-exit →
// SCM recovery actions restart).
func TestServiceSelfWatchActive(t *testing.T) {
	out := &syncWriter{}
	beat, stop, active := serviceSelfWatch(out, selfwatchdog.Threshold, func() {})
	require.True(t, active)
	require.NotNil(t, beat)
	require.NotNil(t, stop)
	stop()
}

// TestParseServiceArgsPins the handler's arg contract (the SCM delivers
// the registered arguments after the service name; x/sys windows/svc
// service.go): `watch [-c <abs>]` and nothing else.
func TestParseServiceArgsPins(t *testing.T) {
	cfg, err := ParseServiceArgs([]string{"assay", "watch", "-c", `C:\x\config.toml`})
	require.NoError(t, err)
	assert.Equal(t, `C:\x\config.toml`, cfg)

	cfg, err = ParseServiceArgs([]string{"assay", "watch", "--config", `C:\y\config.toml`})
	require.NoError(t, err)
	assert.Equal(t, `C:\y\config.toml`, cfg)

	cfg, err = ParseServiceArgs([]string{"assay", "watch"})
	require.NoError(t, err)
	assert.Empty(t, cfg, "no -c → the §2.2.5 refusal applies downstream, not here")

	for _, args := range [][]string{
		{"assay", "maintain"},
		{"other", "watch"},
		{"assay"},
		{"assay", "watch", "-c"},
		{"assay", "watch", "-c", "a", "b"},
		{"assay", "watch", "extra"},
	} {
		_, err := ParseServiceArgs(args)
		require.Error(t, err, "args %v must refuse", args)
	}
}
