package xrayupdate

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeXray is the scripted "xray" binary the tests stage inside release
// zips and install as the current target: it answers `version` with a
// chosen banner and accepts `run -test` (exit 0) — or fails when the marker
// is set (the -test gate failure path). The version banner defaults to a
// parsable one so the post-replace validation (I-2) passes on the happy
// path.
const fakeXraySh = `#!/bin/sh
case "$1" in
  version)
    echo "${XRAY_FAKE_VERSION_BANNER:-Xray 26.10.21 (fake, validates)}"
    exit 0 ;;
  run)
    if [ "$XRAY_FAKE_TEST_FAILS" = "1" ]; then
      echo "fake core: rejected" >&2
      exit 1
    fi
    exit 0 ;;
esac
exit 1
`

// fakeXrayBadVersionSh is the post-replace-validation-failure double: the
// binary runs and passes -test, but `version` prints no parsable banner —
// the installed artifact is broken from the pipeline's point of view and
// must be rolled back.
const fakeXrayBadVersionSh = `#!/bin/sh
case "$1" in
  version)
    echo "definitely not a version banner"
    exit 0 ;;
  run)
    exit 0 ;;
esac
exit 1
`

// fakeXrayZip builds the release asset: a zip whose entries mirror the real
// Xray-linux-64.zip layout (binary + dat files). The script variant selects
// the fake's behavior (default vs bad-version).
func fakeXrayZipScript(t *testing.T, script string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, entry := range []struct{ name, body string }{
		{"xray", script},
		{"geoip.dat", "fake-geoip"},
		{"geosite.dat", "fake-geosite"},
	} {
		w, err := zw.Create(entry.name)
		require.NoError(t, err)
		_, err = w.Write([]byte(entry.body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func fakeXrayZip(t *testing.T, _ string) []byte {
	t.Helper()
	return fakeXrayZipScript(t, fakeXraySh)
}

const dgstLine = "MD5= deadbeef\nSHA1= deadbeef\nSHA2-256= %s\nSHA2-512= deadbeef\n"

// sha256Hex is the test-side digest helper (the production verifier's algorithm).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// releaseServer is the fake GitHub release surface: /releases/latest JSON
// plus the asset + .dgst downloads. checksum overrides the real digest so
// the mismatch path is testable.
func releaseServer(t *testing.T, tag string, assetBody []byte, checksum string) *httptest.Server {
	t.Helper()
	sha := sha256Hex(assetBody)
	if checksum != "" {
		sha = checksum
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/XTLS/Xray-core/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"tag_name":"`+tag+`","assets":[{"name":"Xray-linux-64.zip","browser_download_url":"http://%s/ASSET"}]}`,
			r.Host)
	})
	mux.HandleFunc("/ASSET", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(assetBody)
	})
	mux.HandleFunc("/ASSET.dgst", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Replace(dgstLine, "%s", sha, 1)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// installFakeXray stages a CURRENT "xray" at path (a runnable script whose
// version banner is the given version).
func installFakeXray(t *testing.T, path, banner string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\necho \""+banner+"\"\nexit 0\n"), 0o755))
}

func baseOpts(t *testing.T, api string) Options {
	t.Helper()
	return Options{
		APIBase:    api,
		Stdin:      strings.NewReader("y\n"),
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
		StagingDir: filepath.Join(t.TempDir(), "staged"),
		Now:        func() time.Time { return time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC) },
	}
}

// --- platform asset mapping ---

func TestAssetForPlatform(t *testing.T) {
	for _, tc := range []struct {
		goos, arch, arm, want string
	}{
		{"linux", "amd64", "", "Xray-linux-64.zip"},
		{"linux", "386", "", "Xray-linux-32.zip"},
		{"linux", "arm64", "", "Xray-linux-arm64-v8a.zip"},
		{"linux", "arm", "7", "Xray-linux-arm32-v7a.zip"},
		{"linux", "arm", "6", "Xray-linux-arm32-v6.zip"},
		{"linux", "arm", "5", "Xray-linux-arm32-v5.zip"},
		{"darwin", "amd64", "", "Xray-macos-64.zip"},
		{"darwin", "arm64", "", "Xray-macos-arm64-v8a.zip"},
		{"windows", "amd64", "", "Xray-windows-64.zip"},
		{"freebsd", "amd64", "", "Xray-freebsd-64.zip"},
		{"plan9", "amd64", "", ""},
	} {
		got := assetForPlatform(tc.goos, tc.arch, tc.arm)
		if tc.want == "" {
			assert.Empty(t, got, "%s/%s must be unsupported (loud, not guessed)", tc.goos, tc.arch)
		} else {
			assert.Equal(t, tc.want, got, "%s/%s/%s", tc.goos, tc.arch, tc.arm)
		}
	}
}

func TestParseVersionBanner(t *testing.T) {
	out := "Xray 26.3.27 (Xray, Penetrates Everything.) Custom (go1.24 linux/amd64)\nCommand line: ..."
	assert.Equal(t, "26.3.27", parseVersionBanner(out))
	assert.Empty(t, parseVersionBanner("garbage with no version"))
}

// --- --check mode ---

func TestCheckModeReportsVersions(t *testing.T) {
	asset := fakeXrayZip(t, "26.10.21")
	srv := releaseServer(t, "v26.10.21", asset, "")
	target := filepath.Join(t.TempDir(), "bin", "xray")
	installFakeXray(t, target, "Xray 26.3.27 (Xray, Penetrates Everything.)")

	opts := baseOpts(t, srv.URL)
	opts.CheckOnly = true
	opts.TargetPath = target
	res, err := Run(opts)
	require.NoError(t, err)
	assert.Equal(t, "v26.10.21", res.LatestVersion, "the latest tag resolves dynamically (verbatim)")
	assert.Equal(t, "26.3.27", res.CurrentVersion, "the current version parses from the banner (unprefixed)")
	assert.False(t, res.Updated, "--check never touches the target")

	out := opts.Stdout.(*bytes.Buffer).String()
	assert.Contains(t, out, "26.10.21")
	assert.Contains(t, out, "26.3.27")
	assert.Contains(t, out, "update available", "an outdated binary is called out plainly")
}

// --- full update happy path ---

func TestFullUpdateHappyPath(t *testing.T) {
	asset := fakeXrayZip(t, "26.10.21")
	srv := releaseServer(t, "v26.10.21", asset, "")
	target := filepath.Join(t.TempDir(), "bin", "xray")
	installFakeXray(t, target, "Xray 26.3.27 (Xray, Penetrates Everything.)")

	opts := baseOpts(t, srv.URL)
	opts.TargetPath = target
	opts.AssumeYes = true
	res, err := Run(opts)
	require.NoError(t, err)
	assert.True(t, res.Updated)
	assert.Equal(t, "26.3.27", res.CurrentVersion)
	assert.Equal(t, "v26.10.21", res.LatestVersion)

	// The target now IS the new binary, runnable, versioned fresh.
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(got), "XRAY_FAKE_VERSION_BANNER", "the new binary replaced the old")
	fi, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "the installed binary stays executable")

	// A date-stamped backup of the old binary exists next to the target.
	backup := res.BackupPath
	require.NotEmpty(t, backup, "a date-stamped backup of the old binary is recorded")
	b, err := os.ReadFile(backup)
	require.NoError(t, err)
	assert.Contains(t, string(b), "26.3.27", "the backup carries the OLD binary")
	assert.Contains(t, filepath.Base(backup), "bak-", "activate-convention .bak-<ts> naming")

	// No half-states: the target dir holds exactly target + backup.
	entries, err := os.ReadDir(filepath.Dir(target))
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.ElementsMatch(t, []string{"xray", filepath.Base(backup)}, names,
		"atomic replace leaves exactly the new binary + its backup (no temp files)")
}

// --- checksum verification ---

func TestChecksumMismatchFailsLoudAndLeavesTargetUntouched(t *testing.T) {
	asset := fakeXrayZip(t, "26.10.21")
	srv := releaseServer(t, "v26.10.21", asset, "0000000000000000000000000000000000000000000000000000000000000000")
	target := filepath.Join(t.TempDir(), "bin", "xray")
	installFakeXray(t, target, "Xray 26.3.27")
	before, err := os.ReadFile(target)
	require.NoError(t, err)

	opts := baseOpts(t, srv.URL)
	opts.TargetPath = target
	opts.AssumeYes = true
	_, err = Run(opts)
	require.Error(t, err, "a checksum mismatch must fail loud")
	assert.Contains(t, err.Error(), "sha256", "the failure names the verification")
	assert.Contains(t, err.Error(), "26.10.21", "the release under question is named")

	after, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, before, after, "the target is NEVER touched on a failed verification")
}

// --- -test gate on the staged binary ---

func TestStagedBinaryFailingTestGateAbortsReplace(t *testing.T) {
	asset := fakeXrayZip(t, "26.10.21")
	srv := releaseServer(t, "v26.10.21", asset, "")
	target := filepath.Join(t.TempDir(), "bin", "xray")
	installFakeXray(t, target, "Xray 26.3.27")
	before, err := os.ReadFile(target)
	require.NoError(t, err)

	opts := baseOpts(t, srv.URL)
	opts.TargetPath = target
	opts.AssumeYes = true
	opts.TestFailsEnv = []string{"XRAY_FAKE_TEST_FAILS=1"}
	_, err = Run(opts)
	require.Error(t, err, "a staged binary that fails `xray run -test` must abort the update")
	assert.Contains(t, err.Error(), "-test")

	after, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a failed -test gate never replaces the target")
}

// I-2 pin (fix round): a failed POST-REPLACE validation must roll the
// backup back over the target (same-directory rename) and error loud
// naming the rollback — a broken install must never be the resting state.
func TestPostReplaceValidationFailureRollsBackToBackup(t *testing.T) {
	asset := fakeXrayZipScript(t, fakeXrayBadVersionSh)
	srv := releaseServer(t, "v26.10.21", asset, "")
	target := filepath.Join(t.TempDir(), "bin", "xray")
	installFakeXray(t, target, "Xray 26.3.27 (Xray, Penetrates Everything.)")
	before, err := os.ReadFile(target)
	require.NoError(t, err)

	opts := baseOpts(t, srv.URL)
	opts.TargetPath = target
	opts.AssumeYes = true
	res, err := Run(opts)
	require.Error(t, err, "a replaced binary that fails validation must not stand")
	assert.Contains(t, strings.ToLower(err.Error()), "rolled back", "the error names the rollback loudly")
	assert.False(t, res.Updated, "a rolled-back run is NOT an update")

	after, rerr := os.ReadFile(target)
	require.NoError(t, rerr)
	assert.Equal(t, before, after, "the backup content is back at the target")
	assert.NoFileExists(t, target+".bak-20261029-120000",
		"the backup was renamed back over the target — no stray backup file remains")
	assert.FileExists(t, res.StagedBinary, "the staged binary survives for inspection")
}

// --- unwritable target: loud refusal, never half-applied (S5 managed-only —
// the sudo stage-and-instruct path died with the external mode) ---

func TestUnwritableTargetRefusesLoudWithoutPrivilegedCommands(t *testing.T) {
	asset := fakeXrayZip(t, "26.10.21")
	srv := releaseServer(t, "v26.10.21", asset, "")
	rootDir := t.TempDir()
	require.NoError(t, os.Chmod(rootDir, 0o555)) // root-owned-directory simulation
	t.Cleanup(func() { _ = os.Chmod(rootDir, 0o750) })
	target := filepath.Join(rootDir, "xray")

	opts := baseOpts(t, srv.URL)
	opts.TargetPath = target
	opts.AssumeYes = true
	res, err := Run(opts)
	require.Error(t, err, "an unwritable target must fail loud, exit-path material for the owner")
	assert.Contains(t, err.Error(), "not writable", "the refusal names the directory")
	assert.Contains(t, err.Error(), "[core].xray_bin", "the refusal names the knob")
	_, err = os.Stat(res.StagedBinary)
	require.NoError(t, err, "the staged binary SURVIVES for the owner to re-point and retry")
	_, err = os.Stat(target)
	require.True(t, os.IsNotExist(err), "nothing was half-applied to the unwritable target")
}

// I-1 pin (fix round), re-pointed to the loud refusal: an unwritable target
// with an EXISTING binary must still refuse at the writability probe BEFORE
// the backup — pre-fix the backup copy ran first and died with a generic
// "backup … permission denied" naming nothing actionable.
func TestUnwritableTargetWithExistingBinaryRefusesBeforeBackup(t *testing.T) {
	asset := fakeXrayZip(t, "26.10.21")
	srv := releaseServer(t, "v26.10.21", asset, "")
	rootDir := t.TempDir()
	target := filepath.Join(rootDir, "xray")
	installFakeXray(t, target, "Xray 26.3.27")
	require.NoError(t, os.Chmod(rootDir, 0o555)) // root-owned-directory simulation (after the fixture binary is in place)
	t.Cleanup(func() { _ = os.Chmod(rootDir, 0o750) })
	before, err := os.ReadFile(target)
	require.NoError(t, err)

	opts := baseOpts(t, srv.URL)
	opts.TargetPath = target
	opts.AssumeYes = true
	res, err := Run(opts)
	require.Error(t, err, "an unwritable target must fail loud, exit-path material for the owner")
	assert.Contains(t, err.Error(), "not writable", "the refusal names the directory")
	assert.FileExists(t, res.StagedBinary, "the staged binary survives for inspection")

	after, rerr := os.ReadFile(target)
	require.NoError(t, rerr)
	assert.Equal(t, before, after, "nothing was half-applied to the unwritable target")
	assert.NoFileExists(t, target+".bak-20261029-120000",
		"no user-level backup may appear for a target the user cannot write")
	_, err = os.Stat(res.StagedBinary)
	require.NoError(t, err, "the staged binary SURVIVES for the owner to install manually")
}

// --- confirmation discipline ---

func TestNonTTYWithoutYesRefuses(t *testing.T) {
	asset := fakeXrayZip(t, "26.10.21")
	srv := releaseServer(t, "v26.10.21", asset, "")
	target := filepath.Join(t.TempDir(), "bin", "xray")
	installFakeXray(t, target, "Xray 26.3.27")

	opts := baseOpts(t, srv.URL)
	opts.TargetPath = target
	opts.Stdin = strings.NewReader("") // non-TTY, empty input
	_, err := Run(opts)
	require.Error(t, err, "non-interactive update without --yes must refuse")
	assert.Contains(t, err.Error(), "--yes")
}

func TestTTYConfirmationDeclinedAborts(t *testing.T) {
	asset := fakeXrayZip(t, "26.10.21")
	srv := releaseServer(t, "v26.10.21", asset, "")
	target := filepath.Join(t.TempDir(), "bin", "xray")
	installFakeXray(t, target, "Xray 26.3.27")
	before, err := os.ReadFile(target)
	require.NoError(t, err)

	opts := baseOpts(t, srv.URL)
	opts.TargetPath = target
	opts.Stdin = strings.NewReader("n\n")
	_, err = Run(opts)
	require.NoError(t, err, "a declined confirmation is a clean no-op, not an error")
	assert.False(t, opts.AssumeYes)
	after, rerr := os.ReadFile(target)
	require.NoError(t, rerr)
	assert.Equal(t, before, after, "a declined update touches nothing")
}

// --- already up to date ---

func TestUpToDateShortCircuits(t *testing.T) {
	asset := fakeXrayZip(t, "26.3.27")
	srv := releaseServer(t, "v26.3.27", asset, "")
	target := filepath.Join(t.TempDir(), "bin", "xray")
	installFakeXray(t, target, "Xray 26.3.27 (Xray, Penetrates Everything.)")

	opts := baseOpts(t, srv.URL)
	opts.TargetPath = target
	opts.AssumeYes = true
	res, err := Run(opts)
	require.NoError(t, err)
	assert.False(t, res.Updated, "same version = no update")
	assert.Empty(t, res.BackupPath)
}

// --- missing target binary ---

func TestMissingTargetBinaryInstallsFresh(t *testing.T) {
	asset := fakeXrayZip(t, "26.10.21")
	srv := releaseServer(t, "v26.10.21", asset, "")
	target := filepath.Join(t.TempDir(), "bin", "xray") // never installed

	opts := baseOpts(t, srv.URL)
	opts.TargetPath = target
	opts.AssumeYes = true
	res, err := Run(opts)
	require.NoError(t, err, "a fresh install (no current binary) is a valid update path")
	assert.True(t, res.Updated)
	assert.Empty(t, res.BackupPath, "nothing to back up")
	assert.Empty(t, res.CurrentVersion, "no current version reported")

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(got), "XRAY_FAKE_VERSION_BANNER")
}
