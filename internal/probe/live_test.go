//go:build live

// Live probe integration (explicit guard): run with
//
//	env -u http_proxy -u https_proxy go test -tags live ./internal/probe/
//
// Exercises the REAL xray-knife binary end-to-end. The probe target is a
// TEST-NET-1 address (RFC 5737, never routable) so the wave is fast and
// touches no real node — it verifies flag wiring and JSONL parsing against
// the actual CLI, which is exactly the drift-sensitive surface.
package probe_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/model"
	"public_vpn/internal/probe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLiveKnifeDeadLink(t *testing.T) {
	bin := "/home/whoami/.local/bin/xray-knife"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("xray-knife not installed at %s", bin)
	}
	workDir := t.TempDir()
	runner := &probe.KnifeRunner{BinPath: bin}
	dead := model.NewNode("live", "vless", "3f2f6c9e-dead-4bad-8f00-deadbeef0000", "192.0.2.1", 1,
		map[string]string{"type": "tcp", "security": "tls", "sni": "example.com"})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	results, err := probe.Run(ctx, []*model.Node{dead}, runner, probe.Options{
		Timeout: 3 * time.Second,
		Threads: 1,
		URL:     "https://cloudflare.com/cdn-cgi/trace",
		DBPath:  filepath.Join(workDir, "knife.db"),
		WorkDir: workDir,
	}, "")
	require.NoError(t, err, "the real CLI must accept our flags and answer in JSONL")
	require.Len(t, results, 1)
	assert.False(t, results[0].Alive, "TEST-NET target is never alive")
	assert.Empty(t, results[0].ExitIP)
	assert.NotEmpty(t, results[0].Status, "real CLI reported status")
	assert.WithinDuration(t, time.Now().UTC(), results[0].CheckedAt, time.Minute)
}
