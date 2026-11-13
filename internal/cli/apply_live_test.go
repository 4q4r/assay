package cli

// The `assay apply` LIVE e2e (plan T4 DoD, binary-gated skip per the repo
// guard pattern): a REAL xray core boots from the rendered live.json (api
// inbound enabled, socks serving), and the FULL production runApply path —
// real render leg, real -test gate, real API client exec, real activate.Run
// persistence, NO seam injections — hot-applies a pool route delta: the rule
// goes live on the running core, live.json converges, and the core pid never
// changes. A second apply reverts the route. Both pinned binaries run when
// present (26.3.27 primary; ~/.local/bin/xray managed current).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/render"
	"assay/internal/store"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func applyLiveBinaries(t *testing.T) []string {
	t.Helper()
	bins := []string{"/usr/bin/xray", filepath.Join(homeDirForApply(), ".local", "bin", "xray")}
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

func homeDirForApply() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "/root"
	}
	return h
}

func TestLiveApplyEndToEndAddsAndRevertsRule(t *testing.T) {
	for _, bin := range applyLiveBinaries(t) {
		t.Run(bin, func(t *testing.T) {
			dir := t.TempDir()
			socksPort := nextCoreTestPort()
			cfg := &config.Config{
				DataDir: dir,
				Core: config.CoreConfig{
					AutoUpdate: true,
					XrayBin:    bin, // the REAL binary: gate, client exec and boot all ride S1
					SocksPort:  socksPort,
					HTTPPort:   socksPort + 1,
					APIPort:    socksPort + 2,
					Loglevel:   "warning",
				},
			}
			cfg.Render.PoolRoutes = []config.PoolRoute{
				{Balancer: "pool_all", Domains: []string{"domain:nyaa.si"}},
			}
			p := newPaths(cfg)

			// Seed the store: one reality node selected → the render emits
			// pool_us + pool_all balancers, the pool outbound, observatory.
			n := model.NewNode("s", "vless", "00000000-0000-0000-0000-000000000001", "Us1.Example.com", 443,
				map[string]string{
					"security": "reality", "type": "tcp",
					"pbk": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "sid": "AA",
				})
			raw, err := json.Marshal(n)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(p.filtered, raw, 0o600))
			sel := &model.Selection{Nodes: []model.SelectedNode{
				{Tag: "pool-us-01", Key: n.Key, Country: "us"},
			}}
			require.NoError(t, store.WriteSelection(p.selection, sel))

			// live.json = the CURRENT render WITHOUT the nvidia route (the
			// core boots from it — disk truth and running state agree).
			liveBytes, _, err := renderBytesForApply(cfg, p, sel, n,
				[]config.PoolRoute{{Balancer: "pool_all", Domains: []string{"domain:nyaa.si"}}})
			require.NoError(t, err)
			require.NoError(t, os.MkdirAll(filepath.Dir(ownLivePath(p)), 0o750))
			require.NoError(t, os.WriteFile(ownLivePath(p), liveBytes, 0o600))

			// Boot the REAL core from the live config; the API inbound comes
			// up with the three services (the enablement already happened —
			// the T1 render's services list is in the live bytes).
			ctx := context.Background()
			cmd := exec.CommandContext(ctx, bin, "run", "-c", ownLivePath(p))
			cmd.Env = os.Environ()
			require.NoError(t, cmd.Start())
			corePID := cmd.Process.Pid
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
			})
			waitForApplyAPI(t, cfg.Core.APIPort)

			out := &syncBuffer{}
			cobraCmd := &cobra.Command{}
			cobraCmd.SetOut(out)

			// APPLY #1: add the nvidia route (the owner's case) — the FULL
			// production path, no seam injections.
			cfg.Render.PoolRoutes = append(cfg.Render.PoolRoutes,
				config.PoolRoute{Balancer: "pool_all", Domains: []string{"domain:nvidia.com"}})
			require.NoError(t, runApply(cobraCmd, cfg, false))

			// The rule is LIVE on the running core (verification already ran
			// inside runApply; re-query through the real binary for the pin).
			client := newApplyClient(cfg)
			entries, err := client.ListRules(ctx)
			require.NoError(t, err)
			var tags []string
			for _, e := range entries {
				if e.RuleTag != "" {
					tags = append(tags, e.RuleTag)
				}
			}
			assert.Contains(t, tags, "pool-route-0")
			assert.Contains(t, tags, "pool-route-1", "the hot-applied nvidia rule is live")

			// live.json converged (disk truth) and carries the rule.
			liveAfter, err := os.ReadFile(ownLivePath(p))
			require.NoError(t, err)
			assert.Contains(t, string(liveAfter), "domain:nvidia.com", "the applied render is persisted")

			// The core NEVER restarted.
			assertCoreAlive(t, corePID, "after hot apply")
			assert.True(t, coreServing(socksPort), "the socks inbound still serves (no outage)")

			// APPLY #2: revert the route — the running rule set regresses.
			cfg.Render.PoolRoutes = []config.PoolRoute{
				{Balancer: "pool_all", Domains: []string{"domain:nyaa.si"}},
			}
			require.NoError(t, runApply(cobraCmd, cfg, false))
			entries, err = client.ListRules(ctx)
			require.NoError(t, err)
			for _, e := range entries {
				assert.NotEqual(t, "pool-route-1", e.RuleTag, "the reverted rule is gone from the running core")
			}
			liveAfter, err = os.ReadFile(ownLivePath(p))
			require.NoError(t, err)
			assert.NotContains(t, string(liveAfter), "domain:nvidia.com", "the revert persisted")
			assertCoreAlive(t, corePID, "after revert")

			// The journal lines are loud.
			assert.Contains(t, out.String(), "hot-applied routing")
		})
	}
}

// renderBytesForApply renders through the REAL renderer (the same call the
// render stage makes) without touching the store — the boot/live artifact.
func renderBytesForApply(
	cfg *config.Config, _ paths, sel *model.Selection, n *model.Node, routes []config.PoolRoute,
) ([]byte, []string, error) {
	byKey := map[string]*model.Node{n.Key: n}
	return render.RenderOwnConfig(sel, cfg.Core, toRenderRoutes(routes), byKey, nil, ownRenderKnobs(cfg))
}

func assertCoreAlive(t *testing.T, pid int, stage string) {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	require.NoErrorf(t, err, "%s: the core process must stay alive (no restart) — pid %d gone", stage, pid)
	assert.Contains(t, string(raw), "xray", "%s: the live pid still is the core", stage)
}

func waitForApplyAPI(t *testing.T, port int) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(15 * time.Second)
	for {
		conn, err := (&net.Dialer{Timeout: 250 * time.Millisecond}).Dial("tcp", addr)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the temp core's api inbound never came up on %s", addr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
