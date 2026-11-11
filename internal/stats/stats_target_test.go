package stats_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"assay/internal/stats"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W7 item 9 seams: the stats stage classifies its failures (INFO / WARNING /
// LOUD). The INFO arm must detect the two first-run shapes WITHOUT exec'ing
// xray: a target config lacking the rendered api/stats shape (we render
// it, so we can read it back), and a loopback endpoint that refuses
// connections (the service was never restarted after activation).

// apiShapedTarget is the shape ensureAPIStats + ensureStatsAndPolicy render
// into the target; TargetHasAPI must recognize it.
func apiShapedTarget(t *testing.T, dir string, port int) string {
	t.Helper()
	body := `{
  "api": {"tag": "api", "services": ["StatsService"]},
  "inbounds": [
    {"tag": "socks-in", "port": 10808, "protocol": "socks"},
    {"tag": "api-in", "listen": "127.0.0.1", "port": ` + strconv.Itoa(port) + `, "protocol": "dokodemo-door"}
  ],
  "stats": {},
  "policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}}
}`
	path := filepath.Join(dir, "target-with-api.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestTargetHasAPI(t *testing.T) {
	dir := t.TempDir()

	t.Run("rendered shape recognized", func(t *testing.T) {
		path := apiShapedTarget(t, dir, 15490)
		has, err := stats.TargetHasAPI(path, 15490)
		require.NoError(t, err)
		assert.True(t, has, "the rendered api/stats shape must be recognized")
	})

	t.Run("port mismatch is not our shape", func(t *testing.T) {
		path := apiShapedTarget(t, dir, 15490)
		has, err := stats.TargetHasAPI(path, 15491)
		require.NoError(t, err)
		assert.False(t, has, "an api-in on a different port is not the shape this stage polls")
	})

	t.Run("plain config lacks the shape", func(t *testing.T) {
		path := filepath.Join(dir, "target-plain.json")
		require.NoError(t, os.WriteFile(path, []byte(`{"inbounds": [], "outbounds": []}`), 0o600))
		has, err := stats.TargetHasAPI(path, 15490)
		require.NoError(t, err)
		assert.False(t, has, "a config without the api block lacks the shape")
	})

	t.Run("missing target lacks the shape", func(t *testing.T) {
		has, err := stats.TargetHasAPI(filepath.Join(dir, "never-activated.json"), 15490)
		require.NoError(t, err, "a target that does not exist yet is the first run, not an error")
		assert.False(t, has)
	})

	t.Run("unreadable target is an error", func(t *testing.T) {
		path := filepath.Join(dir, "its-a-dir.json")
		require.NoError(t, os.MkdirAll(path, 0o750))
		_, err := stats.TargetHasAPI(path, 15490)
		require.Error(t, err, "an unreadable target cannot be reasoned about — must not silently read as lacking the shape")
	})
}

func TestEndpointReachable(t *testing.T) {
	t.Run("bound listener is reachable", func(t *testing.T) {
		var lc net.ListenConfig
		ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close() //nolint:errcheck // test listener
		assert.True(t, stats.EndpointReachable(context.Background(), ln.Addr().String()))
	})

	t.Run("closed port refuses", func(t *testing.T) {
		var lc net.ListenConfig
		ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := ln.Addr().String()
		require.NoError(t, ln.Close(), "close to produce a guaranteed-refused loopback port")
		assert.False(t, stats.EndpointReachable(context.Background(), addr),
			"connection refused = the service is not listening (first run before restart)")
	})
}
