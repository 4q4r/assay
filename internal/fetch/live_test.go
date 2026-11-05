//go:build live

// Live fetch integration (explicit guard): run with
//
//	env -u http_proxy -u https_proxy go test -tags live ./internal/fetch/
//
// Hits the real GitHub API + raw hosts. Off by default — the default suite is
// hermetic (httptest mocks).
package fetch_test

import (
	"context"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/fetch"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLiveDiscoverRadikalManifest(t *testing.T) {
	cl := fetch.NewClient(fetch.ClientConfig{Timeout: 30 * time.Second, Retries: 2})
	src := config.Source{
		Repo:      "0xRadikal/Free-v2ray-Configs",
		Discovery: "manifest",
		Manifest:  "index.json",
		Include:   []string{"secure/configs.txt"},
	}
	got, err := cl.Discover(context.Background(), src)
	require.NoError(t, err)
	assert.Equal(t, []string{"secure/configs.txt"}, got)
}
