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

func TestLiveFetchEpodoniosVless(t *testing.T) {
	cl := fetch.NewClient(fetch.ClientConfig{Timeout: 60 * time.Second, Retries: 2, Concurrency: 2})
	src := config.Source{
		Repo:      "Epodonios/v2ray-configs",
		Discovery: "github-contents",
		Include:   []string{"Splitted-By-Protocol/vless.txt"},
	}
	files, err := cl.Source(context.Background(), "epodonios", src)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Greater(t, len(files[0].Body), 1000, "the vless split file carries real content")
}
