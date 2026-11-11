package cli

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeReleaseServer is the release double for the CLI-level test: the API
// base rides the [fetch].api_base mirror knob (W14: one mirror surface).
func fakeReleaseServer(t *testing.T, tag string) *httptest.Server {
	t.Helper()
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, err := zw.Create("xray")
	require.NoError(t, err)
	_, err = w.Write([]byte("#!/bin/sh\necho \"fake-xray-bin\"\nexit 0\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	asset := zipBuf.Bytes()
	sum := sha256.Sum256(asset)
	sha := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/XTLS/Xray-core/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w,
			`{"tag_name":"`+tag+`","assets":[{"name":"Xray-linux-64.zip","browser_download_url":"http://%s/ASSET"}]}`, r.Host)
	})
	mux.HandleFunc("/ASSET", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(asset)
	})
	mux.HandleFunc("/ASSET.dgst", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "MD5= x\nSHA1= x\nSHA2-256= %s\nSHA2-512= x\n", sha)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestXrayUpdateCommandCheckMode drives the REAL command through the cobra
// seam against the fake release surface: --check reports the version pair,
// touches nothing.
func TestXrayUpdateCommandCheckMode(t *testing.T) {
	srv := fakeReleaseServer(t, "v26.10.21")
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin", "xray")
	require.NoError(t, os.MkdirAll(filepath.Dir(bin), 0o750))
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\necho \"Xray 26.3.27 test-banner\"\nexit 0\n"), 0o755))

	cfgBody := fmt.Sprintf("data_dir = %q\n[fetch]\napi_base = %q\n[core]\nxray_bin = %q\n",
		filepath.Join(dir, "data"), srv.URL, bin)
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgBody), 0o600))

	out := &bytes.Buffer{}
	root := New()
	root.SetOut(out)
	root.SetArgs([]string{"--config", cfgPath, "xray-update", "--check"})
	err := root.Execute()
	require.NoError(t, err)
	text := out.String()
	assert.Contains(t, text, "v26.10.21")
	assert.Contains(t, text, "26.3.27")
	assert.Contains(t, text, "update available")
}

// TestXrayUpdateCommandUnwritableTargetExitLoud pins the CLI contract (S5
// managed-only): a root-owned target FAILS the command (exit 1 through the
// cobra error path) with the loud refusal on stderr — never a silent
// half-apply, never privileged commands.
func TestXrayUpdateCommandUnwritableTargetExitLoud(t *testing.T) {
	srv := fakeReleaseServer(t, "v26.10.21")
	dir := t.TempDir()
	rootDir := filepath.Join(dir, "root-owned-bin")
	require.NoError(t, os.MkdirAll(rootDir, 0o555)) // unwritable simulation
	t.Cleanup(func() { _ = os.Chmod(rootDir, 0o750) })
	bin := filepath.Join(rootDir, "xray")

	cfgBody := fmt.Sprintf("data_dir = %q\n[fetch]\napi_base = %q\n[core]\nxray_bin = %q\n",
		filepath.Join(dir, "data"), srv.URL, bin)
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgBody), 0o600))

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	root := New()
	root.SetOut(out)
	root.SetErr(errOut)
	root.SetIn(strings.NewReader("y\n"))
	root.SetArgs([]string{"--config", cfgPath, "xray-update", "--yes"})
	err := root.Execute()
	require.Error(t, err, "unwritable target must fail the command (exit 1)")
	assert.Contains(t, err.Error(), "not writable", "the refusal names the directory")
	assert.Contains(t, err.Error(), "[core].xray_bin", "the refusal names the knob")
	assert.NotContains(t, errOut.String(), "sudo", "no privileged commands exist anymore (managed-only)")
	_, statErr := os.Stat(bin)
	assert.True(t, os.IsNotExist(statErr), "nothing was applied to the unwritable target")
}
