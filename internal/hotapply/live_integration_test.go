package hotapply

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Live temp-instance integration (the T2 DoD; binary-gated skip per the
// repo guard pattern — render_test.go:515): boots a REAL xray core with the
// api inbound enabled (services: StatsService+RoutingService+HandlerService)
// and exercises the full client surface against it — Reachable, ListRules
// key casing (the §1.2 UNVERIFIED-verbatim item), ReplaceRouting (no
// -append, full replace), the balancer rebuild (rules AND balancers ride the
// same AddRule), the R1 torn-state reality (a payload referencing a missing
// balancer fails AFTER the wipe — the healing reload restores), and the REAL
// stderr vocabulary behind ProbeFailureKind.
//
// Every present binary in the dialect matrix runs; absent ones skip. The
// pinned pair: /usr/bin/xray (26.3.27, the plan's primary) and
// ~/.local/bin/xray (26.11.9, the managed current).

func coreBinaryMatrix(t *testing.T) []string {
	t.Helper()
	bins := []string{"/usr/bin/xray", filepath.Join(homeDir(), ".local", "bin", "xray")}
	var present []string
	for _, bin := range bins {
		if _, err := os.Stat(bin); err == nil {
			present = append(present, bin)
		}
	}
	if len(present) == 0 {
		t.Skipf("no xray binary present at the pinned paths (%v)", bins)
	}
	return present
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "/root"
	}
	return h
}

// limitedBuffer keeps the last N bytes of the child's stderr for failure
// diagnostics (the same discipline as the checker's limitedWriter).
type limitedBuffer struct {
	buf []byte
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.max == 0 {
		b.max = 8192
	}
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *limitedBuffer) tail() string { return string(b.buf) }

// tempAPIInstance boots xray with an api inbound on a free loopback port and
// the given routing section. The returned stop kills the exact child.
type tempAPIInstance struct {
	port     int
	cfgPath  string
	pid      int
	stopOnce func()
}

func bootTempAPIInstance(t *testing.T, bin string, services []string, routing map[string]any) *tempAPIInstance {
	t.Helper()

	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close()) // hand the port to xray (sequential boots; the checker's bootMu scope is per-process)

	dir := t.TempDir()
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"api": map[string]any{
			"tag":      "api",
			"services": services,
		},
		"inbounds": []any{map[string]any{
			"tag": "api-in", "listen": "127.0.0.1", "port": port,
			"protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"},
		}},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		// leastLoad balancers depend on the observatory app — the same
		// co-rendering discipline the real render follows (balancers and
		// observatory always come as a pair).
		"observatory": map[string]any{
			"subjectSelector":   []any{"direct"},
			"probeInterval":     "1m0s",
			"enableConcurrency": true,
		},
		"routing": routing,
	}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	cfgPath := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))

	ctx := context.Background()
	cmd := exec.CommandContext(ctx, bin, "run", "-c", cfgPath)
	cmd.Env = os.Environ()
	coreStderr := &limitedBuffer{}
	cmd.Stderr = coreStderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("core (%s) stderr tail:\n%s", bin, coreStderr.tail())
		}
	})

	inst := &tempAPIInstance{port: port, cfgPath: cfgPath, pid: cmd.Process.Pid}
	inst.stopOnce = func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
	t.Cleanup(inst.stopOnce)

	// Wait for the API inbound to answer (the boot window; a config the core
	// rejects kills the child — surface the exit loudly instead of polling a
	// dead port forever).
	deadline := time.Now().Add(15 * time.Second)
	for {
		dialer := net.Dialer{Timeout: 250 * time.Millisecond}
		conn, derr := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if derr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			inst.stopOnce()
			t.Fatalf("%s: api inbound never came up on port %d (config rejected?)", bin, port)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return inst
}

func apiRouting(rules []any, balancers []any) map[string]any {
	r := map[string]any{"rules": rules}
	if balancers != nil {
		r["balancers"] = balancers
	}
	return r
}

func apiRule() map[string]any {
	return map[string]any{"type": "field", "inboundTag": []any{"api-in"}, "outboundTag": "api"}
}

func catchAllDirect() map[string]any {
	return map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "direct"}
}

func allServices() []string {
	return []string{"StatsService", "RoutingService", "HandlerService"}
}

func assertSamePid(t *testing.T, inst *tempAPIInstance, stage string) {
	t.Helper()
	// The pid is captured from the same Process handle — the load-bearing
	// assertion is that the child NEVER exited and was re-spawned (a hot
	// apply must not restart the core). Read /proc for the honest check.
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", inst.pid))
	require.NoErrorf(t, err, "%s: the core process must stay alive (no restart) — pid %d gone", stage, inst.pid)
	assert.Contains(t, string(raw), "xray", "%s: the live pid still is the core", stage)
}

func TestLiveHotApplyClientRoundTrip(t *testing.T) {
	for _, bin := range coreBinaryMatrix(t) {
		t.Run(bin, func(t *testing.T) {
			baseRouting := apiRouting(
				[]any{apiRule(), catchAllDirect()},
				[]any{map[string]any{"tag": "test-bal", "selector": []any{"direct"}, "strategy": map[string]any{"type": "leastLoad"}}},
			)
			inst := bootTempAPIInstance(t, bin, allServices(), baseRouting)
			client := NewClient(bin, inst.port)
			ctx := context.Background()

			// 1. Reachable BEFORE any mutation (the plan's probe).
			require.NoError(t, client.Reachable(ctx), "the api inbound with RoutingService answers lsrules")

			// 2. The initial routing table: api rule + catch-all, untagged.
			entries, err := client.ListRules(ctx)
			require.NoError(t, err)
			require.Len(t, entries, 2, "api rule + catch-all")
			assert.Equal(t, "api", entries[0].OutboundTag, "lsrules JSON key casing pinned live (tag = outbound tag)")

			// 3. ReplaceRouting: api rule + a balancer rule + catch-all — the
			// full routing section (balancers included) rides ONE AddRule.
			good := map[string]any{"routing": apiRouting(
				[]any{
					apiRule(),
					map[string]any{
						"type": "field", "ruleTag": "pool-route-0",
						"domain": []any{"domain:nvidia.com"}, "balancerTag": "test-bal",
					},
					catchAllDirect(),
				},
				[]any{map[string]any{"tag": "test-bal", "selector": []any{"direct"}, "strategy": map[string]any{"type": "leastLoad"}}},
			)}
			payload, cleanup, err := WritePayloadFile(good)
			t.Cleanup(cleanup)
			require.NoError(t, err)
			require.NoError(t, client.ReplaceRouting(ctx, payload), "adrules without -append replaces the routing section")

			// 4. Verify: count + the expected ruleTag present (VerifyApplied).
			entries, err = client.ListRules(ctx)
			require.NoError(t, err)
			require.NoError(t, VerifyApplied(entries, []string{"pool-route-0"}, 3),
				"the hot-applied rule is live on the running core")
			assertSamePid(t, inst, "after hot-apply")

			// 5. Revert to the original routing — the rule is gone.
			orig := map[string]any{"routing": baseRouting}
			origPayload, origCleanup, err := WritePayloadFile(orig)
			t.Cleanup(origCleanup)
			require.NoError(t, err)
			require.NoError(t, client.ReplaceRouting(ctx, origPayload))
			entries, err = client.ListRules(ctx)
			require.NoError(t, err)
			require.NoError(t, VerifyApplied(entries, nil, 2), "the revert restores the original rule set")
			assertSamePid(t, inst, "after revert")
		})
	}
}

// The R1 torn-state reality, live (observed 2026-11-13): a payload whose
// rule references an undefined balancer fails the AddRule build AFTER the
// wipe — and the POST-FAILURE behavior is version-dependent:
//   - managed 26.11.9: the core keeps answering — the healing reload
//     re-applies the last-good routing and verifies (the plan's remedy 8a).
//   - 26.3.27: the process LIVES but the gRPC API stops answering (the
//     healing reload times out at the dial) — only the restart path heals,
//     which is exactly the plan's remedy 8b (the CLI's loud fallback).
//
// The test branches on the OBSERVED post-torn state and pins the D7 contract
// of each branch: answers → healing MUST succeed and verify; silent → the
// healing attempt MUST fail loud (never fake success).

func TestLiveTornStateRecovery(t *testing.T) {
	for _, bin := range coreBinaryMatrix(t) {
		t.Run(bin, func(t *testing.T) {
			baseRouting := apiRouting(
				[]any{apiRule(), catchAllDirect()},
				[]any{map[string]any{"tag": "test-bal", "selector": []any{"direct"}, "strategy": map[string]any{"type": "leastLoad"}}},
			)
			inst := bootTempAPIInstance(t, bin, allServices(), baseRouting)
			client := NewClient(bin, inst.port)
			ctx := context.Background()

			good := map[string]any{"routing": apiRouting(
				[]any{
					apiRule(),
					map[string]any{
						"type": "field", "ruleTag": "pool-route-0",
						"domain": []any{"domain:nvidia.com"}, "balancerTag": "test-bal",
					},
					catchAllDirect(),
				},
				[]any{map[string]any{"tag": "test-bal", "selector": []any{"direct"}, "strategy": map[string]any{"type": "leastLoad"}}},
			)}
			payload, cleanup, err := WritePayloadFile(good)
			t.Cleanup(cleanup)
			require.NoError(t, err)

			torn := map[string]any{"routing": apiRouting(
				[]any{
					apiRule(),
					map[string]any{
						"type": "field", "ruleTag": "pool-route-0",
						"domain": []any{"domain:nvidia.com"}, "balancerTag": "ghost-bal",
					},
					catchAllDirect(),
				},
				nil,
			)}
			tornPayload, tornCleanup, err := WritePayloadFile(torn)
			t.Cleanup(tornCleanup)
			require.NoError(t, err)

			// The torn apply fails loud, naming the missing balancer.
			tornErr := client.ReplaceRouting(ctx, tornPayload)
			require.Error(t, tornErr, "a rule referencing an undefined balancer fails the rebuild")
			assert.Contains(t, tornErr.Error(), "ghost-bal", "the core names the missing balancer")

			// The observed post-torn state decides the pinned branch.
			entries, probeErr := client.ListRules(ctx)
			switch {
			case probeErr == nil:
				// The core kept answering (26.11.9 observed): the healing
				// reload re-applies the last-good routing and verifies.
				require.NoError(t, client.ReplaceRouting(ctx, payload), "the healing reload re-applies the last-good routing")
				entries, err = client.ListRules(ctx)
				require.NoError(t, err)
				require.NoError(t, VerifyApplied(entries, []string{"pool-route-0"}, 3), "the healed routing verifies")
				assertSamePid(t, inst, "after healing reload")

			case ProbeFailureKind(probeErr) == CoreDown:
				// The API went silent after the torn rebuild (26.3.27
				// observed): the healing reload is impossible — the loud
				// failure IS the contract, the restart path is the remedy
				// (the CLI's fallback prints the exact restart command).
				healErr := client.ReplaceRouting(ctx, payload)
				require.Error(t, healErr, "a wedged API cannot heal — fail loud, never fake success")
				t.Logf("core went silent after the torn rebuild (healing dial: %v) — the restart fallback is the remedy", healErr)

			default:
				t.Fatalf("unexpected post-torn probe failure: %v", probeErr)
			}
			_ = entries
		})
	}
}

// The probe failure classes against the REAL core CLI errors: core-down
// (nothing dials) and service-missing (a core booted with the PRE-T1
// services list runs, but RoutingService is not registered).

func TestLiveProbeFailureClasses(t *testing.T) {
	for _, bin := range coreBinaryMatrix(t) {
		t.Run(bin+"/core-down", func(t *testing.T) {
			// A port nothing listens on.
			var lc net.ListenConfig
			l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)
			deadPort := l.Addr().(*net.TCPAddr).Port
			require.NoError(t, l.Close())

			client := NewClient(bin, deadPort)
			err = client.Reachable(context.Background())
			require.Error(t, err, "core down is a first-class apply input")
			assert.Equal(t, CoreDown, ProbeFailureKind(err), "real dial failure classifies as CoreDown; got: %v", err)
		})
		t.Run(bin+"/service-missing", func(t *testing.T) {
			inst := bootTempAPIInstance(t, bin, []string{"StatsService"}, apiRouting([]any{apiRule(), catchAllDirect()}, nil))
			client := NewClient(bin, inst.port)

			err := client.Reachable(context.Background())
			require.Error(t, err, "a pre-T1 services list must fail the probe loud")
			assert.Equal(t, ServiceMissing, ProbeFailureKind(err), "real unknown-service classifies as ServiceMissing; got: %v", err)
			assert.Contains(t, err.Error(), "unknown service", "the gRPC Unimplemented vocabulary")
		})
	}
}
