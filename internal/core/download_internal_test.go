package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"assay/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCoreReleaseServer is the hermetic release double for the managed-core
// download tests: the API base rides the releaseAPIBase seam, the asset name
// matches the platform table entry for THIS test host (linux/amd64 — the
// suite runs on the pinned platform), and every request is counted so the
// hermeticity and the "no download happened" assertions are positive.
// binSource's CONTENT becomes the zip's `xray` entry (a shell script for the
// pure download tests; the COREFAKE test binary itself for the swap+restart
// test, which must serve socks after the swap). dgstOverride replaces the
// published SHA2-256 line (the corrupted-checksum fixture).
func fakeCoreReleaseServer(t *testing.T, tag, binSource, dgstOverride string, extraFiles map[string][]byte) (*httptest.Server, *int) {
	t.Helper()

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	if binSource != "" {
		raw, err := os.ReadFile(binSource)
		require.NoError(t, err)
		w, err := zw.Create("xray")
		require.NoError(t, err)
		_, err = w.Write(raw)
		require.NoError(t, err)
	}
	for name, content := range extraFiles {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	asset := zipBuf.Bytes()
	sum := sha256Sum(asset)
	if dgstOverride != "" {
		sum = dgstOverride
	}

	assetName := "Xray-linux-64.zip"
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skipf("the release fixture pins the linux/amd64 asset name (host: %s/%s)", runtime.GOOS, runtime.GOARCH)
	}

	var mu sync.Mutex
	hits := 0
	count := func() {
		mu.Lock()
		hits++
		mu.Unlock()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/XTLS/Xray-core/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		count()
		_, _ = fmt.Fprintf(w,
			`{"tag_name":%q,"assets":[{"name":%q,"browser_download_url":"http://%s/ASSET"}]}`,
			tag, assetName, r.Host)
	})
	mux.HandleFunc("/ASSET", func(w http.ResponseWriter, _ *http.Request) {
		count()
		_, _ = w.Write(asset)
	})
	mux.HandleFunc("/ASSET.dgst", func(w http.ResponseWriter, _ *http.Request) {
		count()
		_, _ = fmt.Fprintf(w, "MD5= x\nSHA1= x\nSHA2-256= %s\nSHA2-512= x\n", sum)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func sha256Sum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func releaseHits(hits *int) int { return *hits }

// writeUpdateStateFixture writes the auto-update state file (the due/not-due
// lever for the interval tests).
func writeUpdateStateFixture(t *testing.T, dataDir string, last time.Time) {
	t.Helper()
	raw, err := json.Marshal(coreUpdateState{LastCheck: last.UTC()})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, coreUpdateStateName), raw, 0o600))
}

// fakeBinVersion pins the version the COREFAKE banner reports for this test.
func fakeBinVersion(t *testing.T, ver string) {
	t.Helper()
	t.Setenv("COREFAKE_VERSION", ver)
}

func withReleaseAPIBase(t *testing.T, url string) {
	t.Helper()
	orig := releaseAPIBase
	releaseAPIBase = url
	t.Cleanup(func() { releaseAPIBase = orig })
}

func withVersionFloor(t *testing.T, floor string) {
	t.Helper()
	orig := coreVersionFloor
	coreVersionFloor = floor
	t.Cleanup(func() { coreVersionFloor = orig })
}

// shellCoreScript is a stand-in "xray binary" for the pure download tests:
// it passes the staged `-test` gate (exit 0) and answers `version` with a
// parsable banner.
const shellCoreScript = "#!/bin/sh\necho \"Xray 1.0.0 fixture-banner\"\nexit 0\n"

// TestEnsureCoreDownloadsVerifiesAndInstalls (plan test 1): a clean data dir
// gets the latest release asset downloaded, sha256-verified against the
// release checksum file, and installed ATOMICALLY to <data>/bin/xray with
// the assets materialized in <data>/share/xray (the C2 contract). A wrong
// checksum refuses LOUD and leaves NO file behind.
func TestEnsureCoreDownloadsVerifiesAndInstalls(t *testing.T) {
	t.Run("wrong checksum refuses loud, installs nothing", func(t *testing.T) {
		dir := t.TempDir()
		srv, hits := fakeCoreReleaseServer(t, "v26.10.31", "", "deadbeef", nil)
		withReleaseAPIBase(t, srv.URL)

		log := &bytes.Buffer{}
		err := EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log)
		require.Error(t, err, "a checksum mismatch must refuse")
		assert.Contains(t, err.Error(), "verification FAILED", "the refusal names the verification")
		_, statErr := os.Stat(filepath.Join(dir, "bin", "xray"))
		assert.True(t, os.IsNotExist(statErr), "no binary was installed by the refused download")
		_, statErr = os.Stat(filepath.Join(dir, "share", "xray"))
		assert.True(t, os.IsNotExist(statErr), "no assets were materialized by the refused download")
		assert.Positive(t, releaseHits(hits), "the refusal happened AFTER a real fetch (the test is not vacuous)")
	})

	t.Run("correct checksum installs atomically with assets", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(t.TempDir(), "core-script")
		require.NoError(t, os.WriteFile(script, []byte(shellCoreScript), 0o755))
		srv, hits := fakeCoreReleaseServer(t, "v26.10.31", script, "", map[string][]byte{
			"geoip.dat":   []byte("GEOIP-FIXTURE"),
			"geosite.dat": []byte("GEOSITE-FIXTURE"),
		})
		withReleaseAPIBase(t, srv.URL)

		log := &bytes.Buffer{}
		require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log))

		bin, err := os.ReadFile(filepath.Join(dir, "bin", "xray"))
		require.NoError(t, err, "the managed binary is installed at <data>/bin/xray")
		assert.Equal(t, shellCoreScript, string(bin), "the installed binary is the verified payload")
		st, err := os.Stat(filepath.Join(dir, "bin", "xray"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o755), st.Mode().Perm(), "the core binary is executable")

		for name, want := range map[string]string{
			"geoip.dat":   "GEOIP-FIXTURE",
			"geosite.dat": "GEOSITE-FIXTURE",
		} {
			raw, err := os.ReadFile(filepath.Join(dir, "share", "xray", name))
			require.NoError(t, err, "asset %s materialized in <data>/share/xray (C2)", name)
			assert.Equal(t, want, string(raw))
		}
		logs := log.String()
		assert.Contains(t, logs, "v26.10.31", "the installed version is loud")
		assert.Contains(t, logs, "sha256", "the verification is loud")
		assert.Positive(t, releaseHits(hits), "a real download happened")
	})

	t.Run("below-floor latest refuses loud", func(t *testing.T) {
		dir := t.TempDir()
		srv, _ := fakeCoreReleaseServer(t, "v26.3.27", "", "", nil)
		withReleaseAPIBase(t, srv.URL)
		withVersionFloor(t, "26.9.9")

		log := &bytes.Buffer{}
		err := EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log)
		require.Error(t, err, "a below-floor release must refuse")
		assert.Contains(t, err.Error(), "version floor")
		_, statErr := os.Stat(filepath.Join(dir, "bin", "xray"))
		assert.True(t, os.IsNotExist(statErr), "nothing was installed below the floor")
	})
}

// TestEnsureCoreNoopWhenOverriddenOrPresent (plan test 2): EnsureCoreBinary
// is a NO-OP when [core].xray_bin is overridden (ONE loud INFO per S5) or
// when the managed binary already exists — neither case touches the network.
func TestEnsureCoreNoopWhenOverriddenOrPresent(t *testing.T) {
	t.Run("overridden binary is inert with one loud INFO", func(t *testing.T) {
		dir := t.TempDir()
		srv, hits := fakeCoreReleaseServer(t, "v26.10.31", "", "", nil)
		withReleaseAPIBase(t, srv.URL)

		log := &bytes.Buffer{}
		require.NoError(t, EnsureCoreBinary(context.Background(),
			config.CoreConfig{XrayBin: "/usr/bin/xray"}, dir, log))

		assert.Zero(t, releaseHits(hits), "an overridden binary never touches the network")
		assert.Contains(t, log.String(), "inert", "the S5 INFO is loud")
		_, statErr := os.Stat(filepath.Join(dir, "bin", "xray"))
		assert.True(t, os.IsNotExist(statErr), "no managed binary is installed for an override")
	})

	t.Run("existing managed binary is a no-op", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "bin"), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "bin", "xray"), []byte("#!/bin/sh\nexit 0\n"), 0o755))
		srv, hits := fakeCoreReleaseServer(t, "v26.10.31", "", "", nil)
		withReleaseAPIBase(t, srv.URL)

		log := &bytes.Buffer{}
		require.NoError(t, EnsureCoreBinary(context.Background(), config.CoreConfig{}, dir, log))
		assert.Zero(t, releaseHits(hits), "an existing managed binary downloads nothing")
		assert.Contains(t, log.String(), "present", "the presence is reported loud")
	})
}

// TestAutoUpdateInertWhenOverridden (plan test 3): the manager's auto-update
// is INERT for an overridden binary — and the S5 INFO line lands exactly
// ONCE across repeated calls (one-time loud INFO, not per-wave noise).
// The fixed ports below live in internal/core's OWN test band (22900-22999,
// disjoint from cli's 21800-21999): go test runs packages in PARALLEL, and
// internal/cli's seq allocator grows through 21800-21999 in every full run
// — sharing that band produced deterministic bind collisions under
// cross-package concurrency (the fake core exits 1 at bind, the wave fails
// with "child exited during startup"). Sub-allocation inside the band: the
// download/AutoUpdate fixtures use 22900-2292x, the manager fake cores
// 22940-22980 (see manager_internal_test.go) — one package, sequential
// tests, disjoint sub-ranges kept for triage clarity.
func TestAutoUpdateInertWhenOverridden(t *testing.T) {
	dir := t.TempDir()
	srv, hits := fakeCoreReleaseServer(t, "v26.10.31", "", "", nil)
	withReleaseAPIBase(t, srv.URL)

	log := &syncBuffer{}
	m := newTestManager(t, config.CoreConfig{XrayBin: "/usr/bin/xray", SocksPort: 22900}, dir, log)

	ctx := context.Background()
	require.NoError(t, m.AutoUpdate(ctx, config.CoreConfig{XrayBin: "/usr/bin/xray"}))
	require.NoError(t, m.AutoUpdate(ctx, config.CoreConfig{XrayBin: "/usr/bin/xray"}))

	assert.Zero(t, releaseHits(hits), "the inert path never touches the network")
	assert.Equal(t, 1, strings.Count(log.String(), "inert"),
		"the S5 INFO is ONE-TIME loud, not per-call noise")
}

// TestAutoUpdateRespectsVersionFloor (plan test 6): the latest release being
// below the observatory-safe floor is refused loud — no download, no swap,
// the installed binary untouched.
func TestAutoUpdateRespectsVersionFloor(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(t.TempDir(), "core-script")
	require.NoError(t, os.WriteFile(script, []byte(shellCoreScript), 0o755))

	srv, hits := fakeCoreReleaseServer(t, "v26.10.31", script, "", nil)
	withReleaseAPIBase(t, srv.URL)
	withVersionFloor(t, "99.0.0")

	log := &syncBuffer{}
	m := newManagedTestManager(t, config.CoreConfig{SocksPort: 22902}, dir, log)
	err := m.AutoUpdate(context.Background(), config.CoreConfig{UpdateInterval: config.Duration{Duration: time.Hour}})
	require.Error(t, err, "a below-floor latest must refuse")
	assert.Contains(t, err.Error(), "version floor")
	assert.Zero(t, releaseHits(hits)-1, "no asset download happens below the floor (only the release check)")
	st, rerr := os.Lstat(filepath.Join(dir, "bin", "xray"))
	require.NoError(t, rerr)
	assert.NotZero(t, st.Mode()&os.ModeSymlink,
		"the planted binary is untouched (still the symlink — no swap happened below the floor)")
}

// TestAutoUpdateRespectsUpdateInterval: a fresh check inside update_interval
// is skipped with zero network; an elapsed interval proceeds with the full
// download+swap.
func TestAutoUpdateRespectsUpdateInterval(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(t.TempDir(), "core-script")
	require.NoError(t, os.WriteFile(script, []byte(shellCoreScript), 0o755))

	srv, hits := fakeCoreReleaseServer(t, "v26.10.31", script, "", nil)
	withReleaseAPIBase(t, srv.URL)

	cfg := config.CoreConfig{UpdateInterval: config.Duration{Duration: 24 * time.Hour}}

	t.Run("fresh check inside the interval is skipped", func(t *testing.T) {
		writeUpdateStateFixture(t, dir, time.Now().Add(-1*time.Hour))
		log := &syncBuffer{}
		m := newManagedTestManager(t, config.CoreConfig{SocksPort: 22904}, dir, log)
		require.NoError(t, m.AutoUpdate(context.Background(), cfg))
		assert.Zero(t, releaseHits(hits), "the interval gate short-circuits before any network")
		assert.Contains(t, log.String(), "skipped", "the skip is loud")
	})

	t.Run("elapsed interval proceeds with download and swap", func(t *testing.T) {
		writeUpdateStateFixture(t, dir, time.Now().Add(-25*time.Hour))
		log := &syncBuffer{}
		m := newManagedTestManager(t, config.CoreConfig{SocksPort: 22906}, dir, log)
		require.NoError(t, m.AutoUpdate(context.Background(), cfg))
		assert.GreaterOrEqual(t, releaseHits(hits), 3, "release check + asset + checksum fetched")
		assert.Contains(t, log.String(), "v26.10.31", "the update is loud")

		// The state file is fresh: a follow-up check inside the interval skips.
		raw, err := os.ReadFile(filepath.Join(dir, coreUpdateStateName))
		require.NoError(t, err)
		var state coreUpdateState
		require.NoError(t, json.Unmarshal(raw, &state))
		assert.Less(t, time.Since(state.LastCheck), time.Minute, "the check timestamp persisted")
	})
}

// TestAutoUpdateDownloadsSwapsAndRestarts pins the update contract's second
// half: a running core is swapped to the verified staged binary and
// RESTARTED onto it (staged swap + core restart per the brief) — the socks
// inbound serves again after the swap, and the swap is logged loud.
func TestAutoUpdateDownloadsSwapsAndRestarts(t *testing.T) {
	dir := t.TempDir()
	const port = 22908
	writeLiveFixture(t, dir, port, "autoupdate-swap")
	fakeBinVersion(t, "26.9.9") // the CURRENT core reports the old version

	srv, hits := fakeCoreReleaseServer(t, "v26.10.31", os.Args[0], "", nil) // the payload is the COREFAKE binary
	withReleaseAPIBase(t, srv.URL)

	log := &syncBuffer{}
	m := newManagedTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dir, log)
	require.NoError(t, m.EnsureRunning(context.Background()))
	pid := readPIDFileForTest(t, filepath.Join(dir, "core.pid"))

	require.NoError(t, m.AutoUpdate(context.Background(),
		config.CoreConfig{UpdateInterval: config.Duration{Duration: 24 * time.Hour}}))

	logs := log.String()
	assert.Contains(t, logs, "updated", "the swap is loud")
	assert.Contains(t, logs, "core: stopped pid", "the running core was stopped for the swap restart")
	assert.Contains(t, logs, "core: spawned pid", "the core came back ON the new binary")
	require.NoError(t, waitPortAccepted(port), "the restarted core serves the socks inbound")
	newPID := readPIDFileForTest(t, filepath.Join(dir, "core.pid"))
	assert.NotEqual(t, pid, newPID, "a NEW child process runs the new binary")
	assert.GreaterOrEqual(t, releaseHits(hits), 3, "a real download happened")
}

// TestAutoUpdateInstallsWhenBinaryMissing: with no managed binary at all,
// the auto-update path IS the recovery path — it installs the latest
// release (no restart: nothing was running) and the next EnsureRunning
// boots the core.
func TestAutoUpdateInstallsWhenBinaryMissing(t *testing.T) {
	dir := t.TempDir()
	const port = 22910
	writeLiveFixture(t, dir, port, "autoupdate-install")
	script := filepath.Join(t.TempDir(), "core-script")
	require.NoError(t, os.WriteFile(script, []byte(shellCoreScript), 0o755))

	srv, _ := fakeCoreReleaseServer(t, "v26.10.31", script, "", nil)
	withReleaseAPIBase(t, srv.URL)

	log := &syncBuffer{}
	// A managed manager with NO binary placed: the auto-update path IS the
	// recovery path (the helper would plant the fake — build it by hand).
	m, err := NewManager(config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)
	require.NoError(t, m.AutoUpdate(context.Background(),
		config.CoreConfig{UpdateInterval: config.Duration{Duration: 24 * time.Hour}}))

	logs := log.String()
	assert.Contains(t, logs, "installed at", "the fresh install is loud")
	assert.NotContains(t, logs, "core: stopped pid", "nothing was running — no restart leg")
	_, statErr := os.Stat(filepath.Join(dir, "bin", "xray"))
	require.NoError(t, statErr, "the managed binary exists after the auto-update install")
}

// bootDeathCoreScript passes the staged `-test` gate (exit 0) but DIES as a
// `run` child (exit 1 — the bind-collision class): the swap succeeds, the
// Restart leg fails loud (the M-1 fixture).
const bootDeathCoreScript = "#!/bin/sh\ncase \" $* \" in *\" -test \"*) exit 0;; esac\nexit 1\n"

// TestAutoUpdateRestartFailureDoesNotAdvanceState (fix M-1): a failed
// RESTART (binary swapped, boot death) must NOT advance the update-check
// state — the running core kept the OLD binary, so a later due check must
// re-attempt the restart leg instead of skipping forever as "already at
// latest".
func TestAutoUpdateRestartFailureDoesNotAdvanceState(t *testing.T) {
	dir := t.TempDir()
	const port = 22912
	writeLiveFixture(t, dir, port, "restart-fail")
	fakeBinVersion(t, "26.9.9")

	script := filepath.Join(t.TempDir(), "boot-death-core")
	require.NoError(t, os.WriteFile(script, []byte(bootDeathCoreScript), 0o755))
	srv, _ := fakeCoreReleaseServer(t, "v26.10.31", script, "", nil)
	withReleaseAPIBase(t, srv.URL)

	log := &syncBuffer{}
	m := newManagedTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dir, log)
	require.NoError(t, m.EnsureRunning(context.Background()))

	cfg := config.CoreConfig{UpdateInterval: config.Duration{Duration: 24 * time.Hour}}
	err := m.AutoUpdate(context.Background(), cfg)
	require.Error(t, err, "the boot-death swap must fail the restart leg")
	assert.Contains(t, err.Error(), "restart failed")

	_, statErr := os.Stat(filepath.Join(dir, coreUpdateStateName))
	assert.True(t, os.IsNotExist(statErr),
		"the check state must NOT advance on a failed restart (fix M-1)")

	// The restart-pending marker is WRITTEN on the failed restart (the T6
	// disposition of the M-1 residual): the "already at latest" early-return
	// would otherwise defeat every re-attempt once the install landed.
	assert.FileExists(t, filepath.Join(dir, coreRestartPendingName),
		"the failed restart plants the pending marker")

	// The next AutoUpdate call runs the PENDING leg BEFORE the interval
	// gate — local work only, no API traffic — and re-attempts the restart.
	// The boot-death binary fails to boot again (loud WARNING), the marker
	// STAYS (the leg is still unhealed), and no interval skip fires.
	_ = m.AutoUpdate(context.Background(), cfg)
	assert.Contains(t, log.String(), "restart-pending leg could not start",
		"the pending leg re-attempted the restart on the next wave (the M-1 residual fix; the boot-death binary fails the boot again)")
	assert.NotContains(t, log.String(), "auto-update skipped",
		"no interval skip may fire while the restart leg is unhealed")
	assert.FileExists(t, filepath.Join(dir, coreRestartPendingName),
		"the marker stays while the restart leg is unhealed")
}

// TestAutoUpdatePendingRestartReattemptsDespiteSameVersion pins the exact
// residual the marker closes: binary installed (version pair matches → the
// "already at latest" early-return), restart had failed once, marker present
// → the next wave re-attempts ONLY the restart leg and CLEARS the marker on
// success — a healthy system never restarts again from the same-version
// branch (the marker is the only trigger there).
func TestAutoUpdatePendingRestartReattemptsDespiteSameVersion(t *testing.T) {
	dir := t.TempDir()
	const port = 22913
	writeLiveFixture(t, dir, port, "pending-restart")
	fakeBinVersion(t, "26.10.31") // the INSTALLED version: the early-return fires

	// Hermetic release surface: the "latest" release equals the installed
	// version, so the same-version branch is exactly the state under test.
	script := filepath.Join(t.TempDir(), "ok-core")
	require.NoError(t, os.WriteFile(script, []byte(shellCoreScript), 0o755))
	srv, _ := fakeCoreReleaseServer(t, "v26.10.31", script, "", nil)
	withReleaseAPIBase(t, srv.URL)

	log := &syncBuffer{}
	m := newManagedTestManager(t, config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dir, log)
	require.NoError(t, m.EnsureRunning(context.Background()))

	// Simulate the previous wave's failed restart: the marker is on disk,
	// the running core predates it.
	require.NoError(t, os.WriteFile(filepath.Join(dir, coreRestartPendingName), []byte("v26.10.31"), 0o600))

	cfg := config.CoreConfig{UpdateInterval: config.Duration{Duration: 24 * time.Hour}}
	require.NoError(t, m.AutoUpdate(context.Background(), cfg),
		"the pending restart leg succeeds on a healthy core")
	assert.Contains(t, log.String(), "pending restart leg completed",
		"the pending leg restarted the running core onto the current binary")
	assert.NoFileExists(t, filepath.Join(dir, coreRestartPendingName),
		"success clears the marker — a healthy system must not restart again")

	// A further wave hits the early-return WITHOUT any restart (the marker
	// is gone): no new "pending restart" lines may land.
	before := strings.Count(log.String(), "pending restart leg completed")
	require.NoError(t, m.AutoUpdate(context.Background(), cfg))
	assert.Equal(t, before, strings.Count(log.String(), "pending restart leg completed"),
		"without the marker the same-version branch is a pure no-op")
}

// TestAutoUpdateFailsFastOnUnreadableCurrentBinaryBeforeNetwork pins the
// current-version-first ordering (the M-2 hermeticity enabler): a core
// binary that cannot answer `version` fails the update leg LOCALLY — zero
// network hits — instead of fetching the release first.
func TestAutoUpdateFailsFastOnUnreadableCurrentBinaryBeforeNetwork(t *testing.T) {
	dir := t.TempDir()
	const port = 22914
	writeLiveFixture(t, dir, port, "fail-fast")

	srv, hits := fakeCoreReleaseServer(t, "v26.10.31", "", "", nil)
	withReleaseAPIBase(t, srv.URL)

	// The managed binary cannot answer `version` (exit 1 on every argv).
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "bin"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bin", "xray"), []byte("#!/bin/sh\nexit 1\n"), 0o755))

	log := &syncBuffer{}
	// Managed layout by hand: the broken script sits AT the managed default
	// <data>/bin/xray (no override).
	m, err := NewManager(config.CoreConfig{SocksPort: port, RollbackStrikes: 3}, dir, log)
	require.NoError(t, err)
	t.Cleanup(m.release)

	cerr := m.AutoUpdate(context.Background(),
		config.CoreConfig{UpdateInterval: config.Duration{Duration: 24 * time.Hour}})
	require.Error(t, cerr, "an unreadable current binary must fail the update leg")
	assert.Contains(t, cerr.Error(), "could not read the current version")
	assert.Zero(t, releaseHits(hits),
		"the failure must land BEFORE any network (current-version reads first)")
}
