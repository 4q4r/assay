//go:build live

// Live W20 integration (explicit guard): run with
//
//	env -u http_proxy -u https_proxy go test -tags live -run TestLiveW20 ./internal/plugins/
//
// Hits the real upstreams of the remaining W20 sources (public data;
// owner-named). Off by default — the default suite is hermetic (the fixture
// twins live in w20_internal_test.go). barry-far has been GitHub
// ToS-blocked before (403): a loud github_files failure for that plugin is
// the designed tolerated outcome, not a test failure.
package plugins

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"assay/internal/fetch"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLiveW20Plugins(t *testing.T) {
	eng := NewEngine(fetch.ClientConfig{Timeout: 60 * time.Second, Retries: 2}, io.Discard)
	for _, id := range []string{
		"hidashimora", "kort0881", "au1rxx", "barryfar", "mehdirzfx",
	} {
		code, ok := defaultSources()[id+".lua"]
		require.True(t, ok, "embedded default %s.lua missing", id)
		t.Run(id, func(t *testing.T) {
			nodes, err := eng.Run(context.Background(), &Plugin{ID: id, Path: id + ".lua", Code: code})
			if err != nil {
				msg := err.Error()
				// Upstream-unavailable classes stay loud-but-tolerated:
				// github_files failures (404/403-ToS/tree issues) and
				// raw HTTP status failures. Contract violations (sandbox,
				// shape, type errors) still fail the test.
				require.True(t,
					strings.Contains(msg, "github_files") ||
						strings.Contains(msg, "404") ||
						strings.Contains(msg, "403") ||
						strings.Contains(msg, "no files matched") ||
						strings.Contains(msg, "HTTP "),
					"%s: unexpected (non-upstream) plugin failure: %v", id, err)
				t.Logf("live %s: upstream unavailable (loud, non-fatal by design): %v", id, err)
				return
			}
			var links int
			for _, n := range nodes {
				if strings.Contains(n.Raw, "://") {
					links++
				}
			}
			t.Logf("live %s: %d nodes (%d link-shaped)", id, len(nodes), links)
			assert.Greater(t, len(nodes), 0, "%s must discover candidates from the live source", id)
		})
	}
}
