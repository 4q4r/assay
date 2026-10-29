//go:build live

// Live probe integration (explicit guard): run with
//
//	env -u http_proxy -u https_proxy go test -tags live ./internal/probe/
//
// Exercises the REAL probe engine end-to-end: real temp single-node xray
// instances (the checker factory), real through-tunnel HTTP attempts, real
// classification. TEST-NET targets keep the dead-link test deterministic;
// the hysteria2 smoke probes REAL pool nodes when the pool carries any
// (skip-with-log when none) — the round-7 owner ruling 14b: the smoke is
// part of the test loop, and hysteria2 coverage is uniform like every other
// protocol (W14: the knife-era "does the prober even support hysteria2"
// question is dead — the real core is the prober).
package probe_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/checker"
	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/probe"
	"public_vpn/internal/render"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func liveXrayBin(t *testing.T) string {
	t.Helper()
	bin := "/usr/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("xray binary not present at %s", bin)
	}
	return bin
}

// TestLiveProbeDeadLink drives the REAL engine (factory + attempts + store
// mapping) against a TEST-NET-1 dead node: never alive, honest failure
// class, the wave completes clean.
func TestLiveProbeDeadLink(t *testing.T) {
	bin := liveXrayBin(t)
	workDir := t.TempDir()
	factory := checker.NewXrayFactory(bin, workDir, render.Config{})
	probeFactory := probe.Factory(func(ctx context.Context, n *model.Node) (probe.SocksInstance, error) {
		return factory(ctx, n)
	})
	dead := model.NewNode("live", "vless", "3f2f6c9e-dead-4bad-8f00-deadbeef0000", "192.0.2.1", 1,
		map[string]string{"type": "tcp", "security": "tls", "sni": "example.com"})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	results, err := probe.Run(ctx, []*model.Node{dead}, probeFactory, probe.Options{
		Timeout:  3 * time.Second,
		Threads:  1,
		Attempts: 2,
		URL:      "https://cloudflare.com/cdn-cgi/trace",
	}, "")
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	assert.False(t, r.Alive, "TEST-NET target is never alive")
	assert.Equal(t, "failed", r.Status)
	assert.NotEmpty(t, r.FailureKind, "real engine reported the failure class")
	assert.WithinDuration(t, time.Now().UTC(), r.CheckedAt, time.Minute)
}

// TestLiveProbeRealPoolHysteria2 probes REAL hysteria2 nodes from the live
// pool when it carries any (skip-with-log when none): render → boot →
// through-tunnel attempt, with per-attempt stats logged for the wave report.
func TestLiveProbeRealPoolHysteria2(t *testing.T) {
	bin := liveXrayBin(t)
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	resolved, err := config.Resolve("", home, "")
	if err != nil {
		t.Skipf("no live config resolution (home/cwd): %v", err)
	}
	dataDir := config.ExpandHome(resolved.Config.DataDir)
	nodes, err := store.ReadNodes(filepath.Join(dataDir, "filtered.jsonl"))
	if err != nil {
		t.Skipf("no live filtered pool at %s: %v", dataDir, err)
	}
	var hy []*model.Node
	protocols := map[string]int{}
	for _, n := range nodes {
		protocols[n.Scheme]++
		if n.Scheme == "hysteria2" {
			hy = append(hy, n)
		}
	}
	t.Logf("live pool: %d nodes, protocol coverage %v", len(nodes), protocols)
	if len(hy) == 0 {
		t.Skip("live pool carries no hysteria2 nodes — boot-level smoke (in-suite) covers the family; skip-with-log per the W14 contract")
	}

	// A handful of real hysteria2 nodes: boot → attempts → verdicts.
	if len(hy) > 3 {
		hy = hy[:3]
	}
	factory := checker.NewXrayFactory(bin, t.TempDir(), render.Config{
		TCPMaxSeg:      resolved.Config.Render.TCPMaxSeg,
		TLSFingerprint: resolved.Config.Render.TLSFingerprint,
	})
	probeFactory := probe.Factory(func(ctx context.Context, n *model.Node) (probe.SocksInstance, error) {
		return factory(ctx, n)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	results, err := probe.Run(ctx, hy, probeFactory, probe.Options{
		Timeout:  8 * time.Second,
		Threads:  2,
		Attempts: 2,
		URL:      "https://cloudflare.com/cdn-cgi/trace",
	}, "")
	require.NoError(t, err, "real hysteria2 probe must complete, boot failures included")
	for _, r := range results {
		t.Logf("hysteria2 %s: alive=%v status=%s checks=%d/%d failure=%s rtt=%.0fms reason=%q",
			r.Key[:12], r.Alive, r.Status, r.Checks, r.TotalChecks, r.FailureKind, r.RTTMs, truncate(r.Reason, 80))
		assert.NotEmpty(t, r.Status, "every attempt wave carries a verdict")
		assert.LessOrEqual(t, r.TotalChecks, 2)
	}
	// No live-pool liveness assertion: public hysteria2 nodes churn; the
	// contract is CLEAN CLASSIFICATION, not alive counts.
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
