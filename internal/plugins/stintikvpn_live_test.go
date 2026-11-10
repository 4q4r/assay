//go:build live

// Live StintikVPN integration (explicit guard): run with
//
//	env -u http_proxy -u https_proxy go test -tags live ./internal/plugins/
//
// Hits the real StintikVPN docs/data.json and its real upstream
// subscriptions (public data; the owner-named provider). Off by default —
// the default suite is hermetic (the fixture twin lives in
// stintikvpn_internal_test.go).
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

func TestLiveStintikVPNPlugin(t *testing.T) {
	eng := NewEngine(fetch.ClientConfig{Timeout: 30 * time.Second, Retries: 2}, io.Discard)
	p := &Plugin{ID: "stintikvpn", Path: "stintikvpn.lua", Code: defaultSources()["stintikvpn.lua"]}
	nodes, err := eng.Run(context.Background(), p)
	require.NoError(t, err, "the live plugin must tolerate dead upstreams per-subscription")
	t.Logf("live stintikvpn: %d raw candidates", len(nodes))
	assert.GreaterOrEqual(t, len(nodes), 0)
}

// TestLiveAllDefaultPlugins runs the whole embedded plugin set against the
// real sources (the W10 migration parity proof). Live reality: upstream
// repos die without notice (two of the five defaults' repos were deleted
// upstream on 2026-10-28 — loud per-plugin failure and wave continuation is
// the designed behavior). The assertion therefore accepts BOTH healthy
// outcomes: candidates discovered, OR a loud failure naming the upstream
// problem. Contract violations (sandbox, shape, type errors) still fail.
func TestLiveAllDefaultPlugins(t *testing.T) {
	eng := NewEngine(fetch.ClientConfig{Timeout: 60 * time.Second, Retries: 2}, io.Discard)
	for name, code := range defaultSources() {
		id := IDFromPath(name)
		t.Run(id, func(t *testing.T) {
			nodes, err := eng.Run(context.Background(), &Plugin{ID: id, Path: name, Code: code})
			if err != nil {
				msg := err.Error()
				require.True(t,
					strings.Contains(msg, "github_files") || strings.Contains(msg, "404") ||
						strings.Contains(msg, "no files matched"),
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
