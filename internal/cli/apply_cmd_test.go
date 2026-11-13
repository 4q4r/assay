package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"assay/internal/config"
	"assay/internal/hotapply"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The `assay apply` unit battery (plan T4, Order B flow of §3). Every test
// runs the REAL runApply against file fixtures through the injected seams:
// the render leg (pre-written candidate), the API client (recorded executor),
// the apply lock, and the restart fallback — the production wiring of each
// seam is what the live e2e exercises.

// applyFixture is the own-config scenario plus an API port and FULL
// live/candidate configs (routing sections with ruleTags — the T1 render
// shape the classifier and verifier consume).
type applyFixture struct {
	*ownFixture

	live     map[string]any
	cand     map[string]any
	fallback *recordedFallback
}

func newApplyFixture(t *testing.T) *applyFixture {
	t.Helper()
	f := &applyFixture{ownFixture: newOwnFixture(t)}
	f.cfg.Core.APIPort = 15491

	f.live = applyConfig(t, f.cfg.Core.SocksPort)
	// Candidate = live + one hot routing delta (the owner's nvidia case).
	f.cand = cloneJSON(t, f.live)
	f.cand["routing"].(map[string]any)["rules"] = append(
		f.cand["routing"].(map[string]any)["rules"].([]any),
		map[string]any{
			"type": "field", "ruleTag": "pool-route-1",
			"domain": []any{"domain:nvidia.com"}, "outboundTag": "direct",
		},
	)
	f.writeJSON(t, ownLivePath(f.p), f.live)
	f.writeJSON(t, ownCandidatePath(f.p), f.cand)

	// The render-leg seam: the candidate above IS the render product (the
	// leg itself is covered by the render tests and the live e2e).
	restoreRenderLeg(t, func(*cobra.Command, *config.Config) error { return nil })

	// The restart-fallback seam: recorded — unit tests script its outcome.
	f.fallback = &recordedFallback{}
	old := restartFallback
	restartFallback = f.fallback.run
	t.Cleanup(func() { restartFallback = old })
	return f
}

// applyConfig builds a full own-config shape: log/inbounds (socks + api-in)/
// outbounds (direct + block)/routing (api rule + one pool rule + catch-all)
// /api services. No balancers — a balancerTag rule would need the
// observatory app; the classifier/verifier contracts under test do not
// depend on it (the live e2e renders the real balancer tree).
func applyConfig(t *testing.T, socksPort int) map[string]any {
	t.Helper()
	return map[string]any{
		"marker": "live",
		"log":    map[string]any{"loglevel": "warning", "access": "none"},
		"inbounds": []any{
			map[string]any{"tag": "in", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks"},
			map[string]any{
				"tag": "api-in", "listen": "127.0.0.1", "port": 15491, "protocol": "dokodemo-door",
				"settings": map[string]any{"address": "127.0.0.1"},
			},
		},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"type": "field", "inboundTag": []any{"api-in"}, "outboundTag": "api"},
			map[string]any{
				"type": "field", "ruleTag": "pool-route-0",
				"domain": []any{"domain:nyaa.si"}, "outboundTag": "direct",
			},
			map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "block"},
		}},
		"api": map[string]any{"tag": "api", "services": []any{"StatsService", "RoutingService", "HandlerService"}},
	}
}

func cloneJSON(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func (f *applyFixture) writeJSON(t *testing.T, path string, m map[string]any) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

func (f *applyFixture) liveBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	return raw
}

// recordedClient is the fake API client's recorded executor with scripted
// behaviors per verb.
type recordedClient struct {
	argvs   [][]string
	lsrules func() ([]byte, error)
	adrules func() error
}

func (r *recordedClient) Run(_ context.Context, argv []string, _ []byte) ([]byte, error) {
	r.argvs = append(r.argvs, argv)
	for _, a := range argv {
		if a == "adrules" {
			if r.adrules != nil {
				return nil, r.adrules()
			}
			return []byte("{}"), nil
		}
	}
	if r.lsrules != nil {
		return r.lsrules()
	}
	return []byte(`{"rules":[]}`), nil
}

func (r *recordedClient) adrulesCalls() int {
	n := 0
	for _, argv := range r.argvs {
		for _, a := range argv {
			if a == "adrules" {
				n++
			}
		}
	}
	return n
}

func (r *recordedClient) hasAPIcalls() bool { return len(r.argvs) > 0 }

// lsrulesItems marshals (tag, ruleTag) pairs exactly like the core's
// ListRuleResponse (proto3 zero values omitted — untagged rules carry only
// the outbound tag, balancer rules only the ruleTag; pinned live in the
// hotapply suite).
func lsrulesItems(t *testing.T, pairs ...[2]string) []byte {
	t.Helper()
	type item struct {
		Tag     string `json:"tag,omitempty"`
		RuleTag string `json:"ruleTag,omitempty"`
	}
	resp := struct {
		Rules []item `json:"rules"`
	}{}
	for _, p := range pairs {
		resp.Rules = append(resp.Rules, item{Tag: p[0], RuleTag: p[1]})
	}
	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	return raw
}

func installClient(t *testing.T, rec *recordedClient) {
	t.Helper()
	setApplyClient(t, func(cfg *config.Config) *hotapply.Client {
		return hotapply.NewClientWithRunner(coreXrayBin(cfg), cfg.Core.APIPort, rec)
	})
}

// --- the seams themselves ---

func setApplyClient(t *testing.T, fn func(*config.Config) *hotapply.Client) {
	t.Helper()
	old := newApplyClient
	newApplyClient = fn
	t.Cleanup(func() { newApplyClient = old })
}

func restoreRenderLeg(t *testing.T, fn func(*cobra.Command, *config.Config) error) {
	t.Helper()
	old := renderLeg
	renderLeg = fn
	t.Cleanup(func() { renderLeg = old })
}

type recordedFallback struct {
	calls int
	fn    func(*cobra.Command, *config.Config) error
}

func (r *recordedFallback) run(cmd *cobra.Command, cfg *config.Config) error {
	r.calls++
	if r.fn != nil {
		return r.fn(cmd, cfg)
	}
	return nil
}

func runApplyForTest(t *testing.T, f *applyFixture, dryRun bool) error {
	t.Helper()
	return runApply(f.cmd, f.cfg, dryRun)
}

// --- the battery ---

func TestApplyHotPathAppliesVerifiesAndPersists(t *testing.T) {
	f := newApplyFixture(t)
	rec := &recordedClient{lsrules: func() ([]byte, error) {
		// The POST-apply state: live's rules + the new pool-route-1.
		return lsrulesItems(t,
			[2]string{"api", ""}, [2]string{"", "pool-route-0"},
			[2]string{"", "pool-route-1"}, [2]string{"block", ""},
		), nil
	}}
	installClient(t, rec)

	require.NoError(t, runApplyForTest(t, f, false))

	// The adrules exec: exactly one call, argv pinned (no -append, ONE file).
	require.Equal(t, 1, rec.adrulesCalls(), "one ReplaceRouting exec")
	argv := rec.argvs[0]
	for _, a := range argv {
		assert.NotEqual(t, "-append", a, "R5: never -append (dead behind the catch-all)")
		assert.NotEqual(t, "--append", a, "R5: never --append")
	}
	require.Greater(t, indexOf(argv, "--server"), -1)
	assert.Equal(t, fmt.Sprintf("127.0.0.1:%d", f.cfg.Core.APIPort), argv[indexOf(argv, "--server")+1],
		"the server address is the rendered api inbound")

	// Order B: disk truth converges after hot success — live.json now holds
	// the candidate routing (the wave's next render is a clean no-op).
	live := f.liveBytes(t)
	var liveMap map[string]any
	require.NoError(t, json.Unmarshal(live, &liveMap))
	assert.Equal(t, f.cand["routing"], liveMap["routing"],
		"reconciliation: the applied routing is persisted to live.json (disk truth)")

	// The journal line is loud and one-line.
	assert.Contains(t, f.out.String(), "hot-applied routing", "the one-line journal entry")
	assert.Contains(t, f.out.String(), "no core restart")
	assert.Equal(t, 0, f.fallback.calls, "a clean hot path never touches the restart fallback")
}

func TestApplyDryRunPrintsClassificationAndStops(t *testing.T) {
	f := newApplyFixture(t)
	rec := &recordedClient{}
	installClient(t, rec)

	liveBefore := f.liveBytes(t)
	require.NoError(t, runApplyForTest(t, f, true))

	assert.Contains(t, f.out.String(), "HOT-CAPABLE", "the classification is printed")
	assert.Contains(t, f.out.String(), "routing", "the changed surface is named")
	assert.False(t, rec.hasAPIcalls(), "dry-run makes NO API call")
	assert.Equal(t, liveBefore, f.liveBytes(t), "dry-run never mutates the live config")
}

func TestApplyNotHotCapableFailsLoudNamingSections(t *testing.T) {
	f := newApplyFixture(t)
	// An outbound-set delta (R8): the candidate swaps a pool node.
	f.cand["outbounds"] = []any{
		map[string]any{"tag": "direct", "protocol": "freedom"},
		map[string]any{"tag": "pool-us-02", "protocol": "vless"},
	}
	f.writeJSON(t, ownCandidatePath(f.p), f.cand)
	rec := &recordedClient{}
	installClient(t, rec)

	liveBefore := f.liveBytes(t)
	err := runApplyForTest(t, f, false)

	require.Error(t, err, "a restart-only delta is refused loud — never partially applied")
	assert.Contains(t, err.Error(), "outbounds", "the blocking section is named")
	assert.Contains(t, err.Error(), "assay activate", "the exact restart-path command is printed")
	assert.False(t, rec.hasAPIcalls(), "no API call happened — nothing was mutated")
	assert.Equal(t, liveBefore, f.liveBytes(t), "live.json untouched")
}

func TestApplyCoreDownIsFirstClassLoudInput(t *testing.T) {
	f := newApplyFixture(t)
	rec := &recordedClient{lsrules: func() ([]byte, error) {
		return nil, errors.New("exec /usr/bin/xray api lsrules: exit 1\nfailed to dial 127.0.0.1:15491")
	}}
	installClient(t, rec)

	liveBefore := f.liveBytes(t)
	err := runApplyForTest(t, f, false)

	require.Error(t, err, "core down is a first-class apply input")
	assert.Contains(t, err.Error(), "127.0.0.1:15491", "the API address is named")
	assert.Contains(t, err.Error(), "systemctl --user start assay-watch.service", "the exact start command")
	assert.Contains(t, err.Error(), "assay activate", "the daemon-less alternative")
	assert.Equal(t, liveBefore, f.liveBytes(t), "nothing was mutated")
	assert.Equal(t, 0, f.fallback.calls, "core-down does NOT trigger a spawn — the daemon owns the core")
}

func TestApplyServiceMissingNamesEnablementRestart(t *testing.T) {
	f := newApplyFixture(t)
	rec := &recordedClient{lsrules: func() ([]byte, error) {
		return nil, errors.New("failed to list rules: rpc error: code = Unimplemented desc = " +
			"unknown service xray.app.router.command.RoutingService")
	}}
	installClient(t, rec)

	err := runApplyForTest(t, f, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RoutingService", "the missing service is named")
	assert.Contains(t, err.Error(), "enablement", "the one-time enablement restart is explained")
}

func TestApplyLockHeldFailsLoud(t *testing.T) {
	f := newApplyFixture(t)
	rec := &recordedClient{}
	installClient(t, rec)
	old := acquireApplyLock
	acquireApplyLock = func(string) (func(), error) {
		return nil, errors.New("apply: another apply is already in flight")
	}
	t.Cleanup(func() { acquireApplyLock = old })

	err := runApplyForTest(t, f, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "another apply is already in flight")
	assert.False(t, rec.hasAPIcalls(), "a serialized-out apply never reaches the API")
}

func TestApplyGateFailureIsLoudRefusal(t *testing.T) {
	f := newApplyFixture(t)
	rec := &recordedClient{}
	installClient(t, rec)
	// The fake-core gate refuses when the config carries the marker. The
	// marker goes INSIDE a routing rule (not a top-level field) so the pair
	// stays hot-capable and the GATE is what fails.
	candRaw, err := json.Marshal(f.cand)
	require.NoError(t, err)
	poisoned := strings.Replace(string(candRaw),
		`"domain":["domain:nvidia.com"]`, `"domain":["domain:nvidia.com `+cliFakeGateFail+`"]`, 1)
	require.NoError(t, os.WriteFile(ownCandidatePath(f.p), []byte(poisoned), 0o600))

	err = runApplyForTest(t, f, false)
	require.Error(t, err, "a gate-failing candidate never reaches the API")
	assert.Contains(t, err.Error(), "gate failed", "today's loud refusal text")
	assert.False(t, rec.hasAPIcalls(), "no API call happened")
}

func TestApplyHealingReloadRestoresLastGoodOnApplyFailure(t *testing.T) {
	f := newApplyFixture(t)
	applyAttempts := 0
	rec := &recordedClient{
		adrules: func() error {
			applyAttempts++
			if applyAttempts == 1 {
				return errors.New("AddRule rejected: exit 1\napp/router: balancer pool_all not found")
			}
			return nil // the healing reload succeeds
		},
		lsrules: func() ([]byte, error) {
			// After the healing reload, the LIVE rule set is back.
			return lsrulesItems(t,
				[2]string{"api", ""}, [2]string{"", "pool-route-0"}, [2]string{"block", ""},
			), nil
		},
	}
	installClient(t, rec)

	liveBefore := f.liveBytes(t)
	err := runApplyForTest(t, f, false)

	require.Error(t, err, "the apply itself failed — loud, exit non-zero")
	assert.Contains(t, err.Error(), "restored", "the healing outcome is loud")
	assert.GreaterOrEqual(t, rec.adrulesCalls(), 2, "the healing reload ran with the last-good payload")
	assert.Equal(t, liveBefore, f.liveBytes(t), "a failed apply NEVER persists — disk truth stays last-good")
	assert.Equal(t, 0, f.fallback.calls, "a healed failure does NOT restart")
}

func TestApplyHealingFailureFallsBackToRestart(t *testing.T) {
	f := newApplyFixture(t)
	rec := &recordedClient{adrules: func() error {
		return errors.New("AddRule rejected: exit 1\napp/router: balancer pool_all not found")
	}}
	installClient(t, rec)
	f.fallback.fn = func(*cobra.Command, *config.Config) error { return nil }

	err := runApplyForTest(t, f, false)
	require.NoError(t, err, "the restart fallback completed the activation")
	assert.Equal(t, 1, f.fallback.calls, "the full activate path ran exactly once")
	assert.Contains(t, f.out.String(), "falling back to the full activate path", "the fallback outcome is loud")
}

func TestApplyHealingFailureDaemonHeldPrintsConvergenceGuarantee(t *testing.T) {
	f := newApplyFixture(t)
	rec := &recordedClient{adrules: func() error {
		return errors.New("AddRule rejected: exit 1\napp/router: balancer pool_all not found")
	}}
	installClient(t, rec)
	f.fallback.fn = func(*cobra.Command, *config.Config) error {
		return errors.New("apply: hot-apply failed and healing failed; the daemon owns the core — " +
			"the restart path is not reachable from here\n" +
			"  the running core may serve degraded routing until the next wave converges it (or restart the unit — " +
			"it waits for the stage boundary, W17):\n" +
			"  `systemctl --user restart assay-watch.service`")
	}

	err := runApplyForTest(t, f, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "systemctl --user restart assay-watch.service", "the exact restart command")
	assert.Contains(t, err.Error(), "next wave converges it", "the convergence guarantee is stated")
	assert.Contains(t, err.Error(), "W17", "the stage-boundary wait is disclosed")
}

// TestApplyReconciliationDiskTruthSurvives pins the §3 reconciliation axiom
// end-to-end at the artifact level: after a successful hot apply the disk
// pair converges (candidate==live), so the wave's own re-render is a clean
// no-op — no restart, no divergence store, the wave IS the reconciler.
func TestApplyReconciliationDiskTruthSurvives(t *testing.T) {
	f := newApplyFixture(t)
	installClient(t, &recordedClient{lsrules: func() ([]byte, error) {
		return lsrulesItems(t,
			[2]string{"api", ""}, [2]string{"", "pool-route-0"},
			[2]string{"", "pool-route-1"}, [2]string{"block", ""},
		), nil
	}})

	require.NoError(t, runApplyForTest(t, f, false))

	liveRaw, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	candRaw, err := os.ReadFile(ownCandidatePath(f.p))
	require.NoError(t, err)
	var liveMap, candMap map[string]any
	require.NoError(t, json.Unmarshal(liveRaw, &liveMap))
	require.NoError(t, json.Unmarshal(candRaw, &candMap))
	d := hotapply.Classify(liveMap, candMap)
	assert.True(t, d.HotCapable && !d.RoutingChanged,
		"after the applied render is persisted, live and candidate agree — the next wave is a no-op")
}

// TestApplyRestartFallbackDaemonHeldMessage pins the production fallback's
// daemon-held branch: a real held flock (a live manager) makes the transient
// acquisition refuse, and the convergence-guarantee text with the EXACT
// commands reaches the operator — no spawn ever happens.
func TestApplyRestartFallbackDaemonHeldMessage(t *testing.T) {
	f := newApplyFixture(t)
	holder := f.ownManager(t)
	t.Cleanup(holder.Release) // the lock handle must not outlive the test

	err := runApplyRestartFallback(f.cmd, f.cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "systemctl --user restart assay-watch.service")
	assert.Contains(t, err.Error(), "next wave converges it")
}

func indexOf(argv []string, s string) int {
	for i, a := range argv {
		if a == s {
			return i
		}
	}
	return -1
}
