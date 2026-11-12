//go:build unix

package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
// The index carries an asset for EVERY release-matrix host arch (linux
// amd64/arm64/386/arm7 — production picks its own by runtime.GOARCH), each
// with a distinct body; a single-arch index passes on amd64 and breaks the
// command tests on other runners (the arm CI gate failure).
func fakeReleaseServer(t *testing.T, tag string) *httptest.Server {
	t.Helper()
	// Mirrors internal/xrayupdate's platformAssets entries for the release
	// host matrix; the map is unexported and its names are pinned by
	// TestAssetForPlatform + TestReleaseFixtureServesFullReleaseMatrix.
	archAssets := []struct{ name, mark string }{
		{"Xray-linux-64.zip", "amd64"},
		{"Xray-linux-arm64-v8a.zip", "arm64"},
		{"Xray-linux-32.zip", "386"},
		{"Xray-linux-arm32-v7a.zip", "arm7"},
	}
	type served struct {
		body []byte
		sha  string
	}
	assets := make(map[string]served, len(archAssets))
	var idx bytes.Buffer
	idx.WriteString(`{"tag_name":"` + tag + `","assets":[`)
	for i, a := range archAssets {
		var zipBuf bytes.Buffer
		zw := zip.NewWriter(&zipBuf)
		w, err := zw.Create("xray")
		require.NoError(t, err)
		_, err = w.Write([]byte("#!/bin/sh\necho \"fake-xray-bin\"\nexit 0\n"))
		require.NoError(t, err)
		w, err = zw.Create("fixture-arch-" + a.mark)
		require.NoError(t, err)
		_, err = w.Write([]byte(a.mark))
		require.NoError(t, err)
		require.NoError(t, zw.Close())
		sum := sha256.Sum256(zipBuf.Bytes())
		assets[a.name] = served{body: zipBuf.Bytes(), sha: hex.EncodeToString(sum[:])}
		if i > 0 {
			idx.WriteString(",")
		}
		_, _ = fmt.Fprintf(&idx, `{"name":%q,"browser_download_url":"http://HOST/ASSET/%s"}`, a.name, a.name)
	}
	idx.WriteString("]}")
	index := idx.Bytes()

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/XTLS/Xray-core/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.ReplaceAll(index, []byte("http://HOST/"), []byte("http://"+r.Host+"/")))
	})
	mux.HandleFunc("/ASSET/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/ASSET/")
		if base, isDgst := strings.CutSuffix(name, ".dgst"); isDgst {
			a, ok := assets[base]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = fmt.Fprintf(w, "MD5= x\nSHA1= x\nSHA2-256= %s\nSHA2-512= x\n", a.sha)
			return
		}
		a, ok := assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(a.body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// httpGetBody fetches url with a context-carrying request and returns the
// body of a 200 response (test-side helper, fail-loud on every leg).
func httpGetBody(t *testing.T, url string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s must serve 200", url)
	return body
}

// TestFakeReleaseServerServesFullReleaseMatrix pins the CLI fixture against
// single-arch regression: the fake release index must carry an asset for
// every host arch the release matrix (.goreleaser.yaml: linux
// amd64/arm64/386/arm7) can run on, with pairwise-distinct bodies so the
// per-arch checksum paths stay meaningful. Production (xrayupdate) resolves
// the asset by runtime.GOARCH — a single-arch index passes on amd64 and
// breaks the command tests on other runners (the arm CI gate failure).
func TestFakeReleaseServerServesFullReleaseMatrix(t *testing.T) {
	srv := fakeReleaseServer(t, "v26.10.21")

	var idx struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	require.NoError(t, json.Unmarshal(httpGetBody(t, srv.URL+"/repos/XTLS/Xray-core/releases/latest"), &idx))
	require.Equal(t, "v26.10.21", idx.TagName)

	// Mirrors internal/xrayupdate's platformAssets entries for the release
	// host matrix; the map itself is unexported and its names are pinned by
	// TestAssetForPlatform + TestReleaseFixtureServesFullReleaseMatrix.
	want := map[string]string{
		"Xray-linux-64.zip":        "amd64",
		"Xray-linux-arm64-v8a.zip": "arm64",
		"Xray-linux-32.zip":        "386",
		"Xray-linux-arm32-v7a.zip": "arm7",
	}
	require.Len(t, idx.Assets, len(want),
		"the fake index carries exactly the release-matrix assets")
	bodies := make(map[string]string, len(idx.Assets))
	names := make([]string, 0, len(idx.Assets))
	for _, a := range idx.Assets {
		body := httpGetBody(t, a.URL)
		owner, dup := bodies[string(body)]
		require.False(t, dup,
			"assets %s and %s share one body — the per-arch paths would be indistinguishable",
			owner, a.Name)
		bodies[string(body)] = a.Name
		names = append(names, a.Name)
	}
	for name, arch := range want {
		require.Contains(t, names, name,
			"the fixture index must ship the linux/%s asset %q — production asks for it on that host", arch, name)
	}
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
