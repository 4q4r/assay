//go:build live

// Live default-plugin sweep (explicit guard): run with
//
//	env -u http_proxy -u https_proxy go test -tags live ./internal/plugins/
//
// Runs EVERY embedded default against its real configured source — a fresh
// clone embeds exactly the tracked sample template, and a tree carrying
// additional untracked plugins in the same dir embeds those too (embed
// reads disk). Live reality: upstreams die without notice — loud
// per-plugin failure and wave continuation is the designed behavior. The
// assertion therefore accepts BOTH healthy outcomes: candidates
// discovered, OR a loud upstream/transport failure (DNS lookup, HTTP
// status, github_files 404/403/tree issues, plugin-attributed fetch
// errors). Contract violations (sandbox, shape, type errors) still fail.
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

func TestLiveDefaultPlugins(t *testing.T) {
	eng := NewEngine(fetch.ClientConfig{Timeout: 60 * time.Second, Retries: 2}, io.Discard)
	require.NotEmpty(t, defaultSources(), "the go:embed glob must match at least the tracked sample template")
	for name, code := range defaultSources() {
		id := IDFromPath(name)
		t.Run(id, func(t *testing.T) {
			nodes, err := eng.Run(context.Background(), &Plugin{ID: id, Path: name, Code: code})
			if err != nil {
				msg := err.Error()
				// Upstream-unavailable classes stay loud-but-tolerated:
				// github_files failures (404/403-ToS/tree issues), raw
				// HTTP status failures, and transport failures (DNS
				// lookup, refusal, timeout, plugin fetch guards — the
				// tracked sample template's placeholder URL lands here
				// by design). Contract violations (sandbox, shape, type
				// errors) still fail the test.
				require.True(t,
					strings.Contains(msg, "github_files") ||
						strings.Contains(msg, "404") ||
						strings.Contains(msg, "403") ||
						strings.Contains(msg, "no files matched") ||
						strings.Contains(msg, "HTTP ") ||
						strings.Contains(msg, "lookup") ||
						strings.Contains(msg, "connection refused") ||
						strings.Contains(msg, "timeout") ||
						strings.Contains(msg, "fetch failed"),
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
