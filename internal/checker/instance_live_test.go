//go:build live

// Live temp-instance integration (explicit guard): run with
//
//	env -u http_proxy -u https_proxy go test -tags live ./internal/checker/
//
// Exercises the REAL xray temp-instance lifecycle end-to-end — config write,
// spawn, socks readiness, traffic through the tunnel, exact-PID teardown —
// with a FREEDOM outbound (no external node is dialed; the live client is
// never involved).
package checker_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"assay/internal/checker"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

func TestLiveXrayTempInstanceEndToEnd(t *testing.T) {
	bin := "/usr/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("xray binary not present at %s", bin)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("hello from the freedom outbound ", 64)))
	}))
	defer site.Close()

	workDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	inst, err := checker.StartTempXray(ctx, bin, workDir, map[string]any{
		"protocol": "freedom",
		"tag":      "check-out",
	})
	require.NoError(t, err)
	defer func() { _ = inst.Close() }()

	dialer, err := proxy.SOCKS5("tcp", inst.Addr(), nil, proxy.Direct)
	require.NoError(t, err)
	client := &http.Client{
		Transport: &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext, Proxy: nil},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(site.URL)
	require.NoError(t, err, "GET through the temp instance must succeed")
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "freedom outbound")

	require.NoError(t, inst.Close())
}
