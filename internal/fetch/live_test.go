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

	"assay/internal/config"
	"assay/internal/fetch"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLiveDiscoverExampleManifest(t *testing.T) {
	cl := fetch.NewClient(fetch.ClientConfig{Timeout: 30 * time.Second, Retries: 2})
	// Placeholder repo: swap in your own manifest-discovery source to smoke
	// the live path against a real upstream.
	src := config.Source{
		Repo:      "your-name/your-lists",
		Discovery: "manifest",
		Manifest:  "index.json",
		Include:   []string{"secure/configs.txt"},
	}
	got, err := cl.Discover(context.Background(), src)
	require.NoError(t, err)
	assert.Equal(t, []string{"secure/configs.txt"}, got)
}
