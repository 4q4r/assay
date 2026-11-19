//go:build unix

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"assay/internal/config"
	"assay/internal/core"
	"assay/internal/hotapply"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The T5 wave hot path (the 2026-11-13 hot-apply plan, in-daemon leg): the
// activate stage diff-classifies live.json vs candidate.json — a
// routing-only delta hot-applies through the running core's own API client
// (the V1 `assay apply` machinery) with the core pid UNCHANGED, and every
// other shape takes the existing full activate path. The battery pins the
// plan contracts: hot-path choice on a routing-only diff, full path on a
// mixed diff, the loud fallback on any hot-apply failure (mutation-proven),
// the disk-truth reconciliation (live.json converges so the next wave is a
// clean no-op), and the status core block's hot-apply state. The client is
// a recorded seam double (the V1 pattern): no test here speaks the xray
// api dialect for real — the production client wiring is proven by the
// apply-CLI battery against the same hotapply.Client.

// hotApplyConfigBytes renders a full own-config generation: everything is
// constant except the pool route's ruleTag (the routing-only delta the hot
// path exists for) and the outbound tag (the mixed-diff knob). The fake
// core binds the FIRST inbound port, so the socks port rides first.
func hotApplyConfigBytes(port int, routeTag, outTag string) []byte {
	return []byte(fmt.Sprintf(`{
  "inbounds": [
    {"tag": "in", "listen": "127.0.0.1", "port": %d, "protocol": "socks"}
  ],
  "outbounds": [
    {"tag": %q, "protocol": "freedom"}
  ],
  "routing": {
    "balancers": [{"tag": "pool", "selector": ["pool-"]}],
    "rules": [
      {"inboundTag": ["in"], "balancerTag": "pool", "ruleTag": %q},
      {"network": "tcp,udp", "outboundTag": "direct"}
    ]
  }
}`, port, outTag, routeTag))
}

// writeHotApplyPair writes the routing-only-delta pair the hot path
// consumes: live pools pool-route-1, candidate pools pool-route-2; candOut
// varies the candidate's outbound tag (the mixed-diff knob).
func writeHotApplyPair(t *testing.T, f *ownFixture, candOut string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(ownLivePath(f.p)), 0o750))
	require.NoError(t, os.WriteFile(ownLivePath(f.p),
		hotApplyConfigBytes(f.cfg.Core.SocksPort, "pool-route-1", "direct"), 0o600))
	require.NoError(t, os.WriteFile(ownCandidatePath(f.p),
		hotApplyConfigBytes(f.cfg.Core.SocksPort, "pool-route-2", candOut), 0o600))
}

// mustParseConfig parses a rendered generation into the map shape the
// classifier and the payload builders consume.
func mustParseConfig(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	return doc
}

// rulesForVerification synthesizes the lsrules snapshot that satisfies
// hotapply.VerifyApplied for a rendered routing section: exactly the
// expected rule count, every expected ruleTag present.
func rulesForVerification(t *testing.T, doc map[string]any) []hotapply.RuleEntry {
	t.Helper()
	routing, ok := doc["routing"].(map[string]any)
	require.True(t, ok, "fixture doc has a routing section")
	tags, count, err := hotapply.ExpectedFromRouting(routing)
	require.NoError(t, err)
	entries := make([]hotapply.RuleEntry, 0, count)
	for i := range count {
		e := hotapply.RuleEntry{OutboundTag: fmt.Sprintf("out-%d", i)}
		if i < len(tags) {
			e.RuleTag = tags[i]
		}
		entries = append(entries, e)
	}
	return entries
}

// recordedHotClient is the wave hot path's client seam double: every verb
// is recorded (adrules payloads captured byte-exact), errors are scripted
// PER VERB (the probe's script must not leak into the replace's) and
// lsrules snapshots as a FIFO queue. The verb contract mirrors
// hotapply.Client — the production wiring is exercised in the apply-CLI
// battery, this double only proves the wave's orchestration.
type recordedHotClient struct {
	mu            sync.Mutex
	verbs         []string
	payloads      [][]byte
	reachableErr  error
	replaceErrs   []error
	listRulesErrs []error
	ruleQueue     [][]hotapply.RuleEntry
}

func (c *recordedHotClient) record(verb string, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verbs = append(c.verbs, verb)
	if payload != nil {
		c.payloads = append(c.payloads, payload)
	}
}

func (c *recordedHotClient) popReplaceErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.replaceErrs) == 0 {
		return nil
	}
	err := c.replaceErrs[0]
	c.replaceErrs = c.replaceErrs[1:]
	return err
}

func (c *recordedHotClient) popListRulesErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.listRulesErrs) == 0 {
		return nil
	}
	err := c.listRulesErrs[0]
	c.listRulesErrs = c.listRulesErrs[1:]
	return err
}

func (c *recordedHotClient) nextRules() []hotapply.RuleEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.ruleQueue) == 0 {
		return nil
	}
	rules := c.ruleQueue[0]
	c.ruleQueue = c.ruleQueue[1:]
	return rules
}

// Reachable records the probe; a scripted error plays the core-down /
// service-missing classes verbatim (the same substrings the real exec
// runner produces and ProbeFailureKind classifies).
func (c *recordedHotClient) Reachable(_ context.Context) error {
	c.record("reachable", nil)
	return c.reachableErr
}

// ReplaceRouting records the adrules verb WITH the payload bytes (the
// mutation-proven fallback pins read which routing section each call
// carried).
func (c *recordedHotClient) ReplaceRouting(_ context.Context, payloadPath string) error {
	raw, rerr := os.ReadFile(payloadPath)
	if rerr != nil {
		c.record("adrules-unreadable", nil)
		return rerr
	}
	c.record("adrules", raw)
	return c.popReplaceErr()
}

// ListRules records the query and returns the next scripted snapshot.
func (c *recordedHotClient) ListRules(_ context.Context) ([]hotapply.RuleEntry, error) {
	c.record("lsrules", nil)
	if err := c.popListRulesErr(); err != nil {
		return nil, err
	}
	return c.nextRules(), nil
}

func (c *recordedHotClient) snapshot() ([]string, [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.verbs...), append([][]byte(nil), c.payloads...)
}

// hotDialError renders the exec-runner failure text for a class: the exact
// substrings ProbeFailureKind maps to CoreDown / ServiceMissing.
func hotDialError(kind hotapply.FailureKind) error {
	const execTail = "exec xray api lsrules: exit status 1\n"
	switch kind {
	case hotapply.CoreDown:
		return errors.New(execTail + "failed to dial 127.0.0.1:1: connect: connection refused")
	case hotapply.ServiceMissing:
		return errors.New(execTail + "unknown service xray.app.router.command.RoutingService")
	case hotapply.FailureOther:
		return errors.New(execTail + "boom")
	default:
		return errors.New(execTail + "boom")
	}
}

// hotTestManager starts the daemon-style manager over the fixture (the
// fake core runs the live config's socks inbound) and stops it at cleanup.
func hotTestManager(t *testing.T, f *ownFixture) *core.Manager {
	t.Helper()
	mgr := f.ownManager(t)
	t.Cleanup(func() { _ = mgr.Stop(); mgr.Release() })
	require.NoError(t, mgr.EnsureRunning(context.Background()))
	require.True(t, mgr.Alive(), "the old core must be running before the stage")
	return mgr
}

// hotPathOnly swaps the wave hot path's client seam for the recorded double.
func hotPathOnly(t *testing.T, client *recordedHotClient) {
	t.Helper()
	prev := newWaveHotClient
	newWaveHotClient = func(*config.Config) hotApplyClient { return client }
	t.Cleanup(func() { newWaveHotClient = prev })
}

// TestWaveHotAppliesRoutingOnlyDeltaWithoutRestart is the headline T5 pin:
// a routing-only delta hot-applies through the client — exactly one probe,
// one adrules replace carrying the CANDIDATE routing, one verification
// query — with the core pid unchanged (no restart legs at all), the
// applied render persisted to live.json (disk truth converges), the
// pre-hot live config backed up (the D8 source survives the hot path), the
// hot state recorded for the status block, and a re-run of the SAME pair a
// clean no-op (the wave re-render steady state).
func TestWaveHotAppliesRoutingOnlyDeltaWithoutRestart(t *testing.T) {
	f := newOwnFixture(t)
	f.cfg.Core.APIPort = f.cfg.Core.SocksPort + 4
	writeHotApplyPair(t, f, "direct")
	mgr := hotTestManager(t, f)
	pidBefore := readCorePID(f.p.dataDir)
	require.Positive(t, pidBefore)
	logsBefore := f.log.String()

	client := &recordedHotClient{
		ruleQueue: [][]hotapply.RuleEntry{
			rulesForVerification(t, mustParseConfig(t, hotApplyConfigBytes(f.cfg.Core.SocksPort, "pool-route-2", "direct"))),
		},
	}
	hotPathOnly(t, client)

	require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr))

	verbs, payloads := client.snapshot()
	require.Equal(t, []string{"reachable", "adrules", "lsrules"}, verbs,
		"the hot path probes once, replaces once, verifies once — nothing else")
	require.Len(t, payloads, 1)
	payload := string(payloads[0])
	assert.Contains(t, payload, "pool-route-2", "the replace carries the candidate routing")
	assert.NotContains(t, payload, "pool-route-1", "the replace is the FULL routing section, not an append")

	// Disk-truth reconciliation: live.json converged to the applied render.
	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	cand, err := os.ReadFile(ownCandidatePath(f.p))
	require.NoError(t, err)
	assert.Equal(t, string(cand), string(live),
		"the hot path persists the applied render — the next wave re-render is a clean no-op")

	// The pre-hot live config is backed up under the fixed D8 name.
	matches, err := filepath.Glob(filepath.Join(f.p.backupDir, "config.json.bak-*"))
	require.NoError(t, err)
	require.Len(t, matches, 1, "exactly one dated backup (the pre-hot live config)")
	raw, err := os.ReadFile(matches[0])
	require.NoError(t, err)
	assert.Contains(t, string(raw), "pool-route-1", "the backup holds the PRE-hot live config")

	// pid stability: no restart legs ran DURING the stage (the manager's
	// EnsureRunning spawn predates it — assert on the stage's log delta),
	// the pidfile pid is unchanged and the core still serves.
	logs := strings.TrimPrefix(f.log.String(), logsBefore)
	assert.NotContains(t, logs, "core: stopped pid", "no Restart stop leg on the hot path")
	assert.NotContains(t, logs, "core: spawned pid", "no Restart start leg on the hot path")
	pidAfter := readCorePID(f.p.dataDir)
	assert.Equal(t, pidBefore, pidAfter, "the core pid is unchanged across the hot activation")
	assert.True(t, mgr.Alive(), "the core stays alive")
	assert.True(t, coreServing(f.cfg.Core.SocksPort), "the socks inbound still serves")

	// The journal names the hot application loud.
	assert.Contains(t, f.out.String(), "no core restart", "the hot-apply chip is loud")

	// The status state: last activation HOT, pid stable.
	st, err := hotapply.ReadState(f.p.dataDir)
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Equal(t, hotapply.ModeHot, st.Mode)
	assert.Equal(t, pidBefore, st.PIDBefore)
	assert.Equal(t, pidBefore, st.PIDAfter)
	assert.True(t, st.PIDStable)

	// The re-run on the converged pair is the byte-identical no-op: the
	// client is untouched and no second backup appears.
	require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr))
	verbs, _ = client.snapshot()
	assert.Equal(t, []string{"reachable", "adrules", "lsrules"}, verbs,
		"the converged wave never touches the API again")
	matches, err = filepath.Glob(filepath.Join(f.p.backupDir, "config.json.bak-*"))
	require.NoError(t, err)
	assert.Len(t, matches, 1, "the no-op re-run creates no backup")
	assert.Contains(t, f.out.String(), "no changes — the live core config already matches")
}

// TestWaveMixedDiffTakesFullRestartPath pins the fail-closed half: a delta
// that touches ANY section outside routing is NOT hot — the client is
// never invoked (a partial apply is structurally impossible) and the
// existing full activate path runs unchanged (backup → replace → restart →
// health → strike), recording the RESTART state for the status block.
func TestWaveMixedDiffTakesFullRestartPath(t *testing.T) {
	f := newOwnFixture(t)
	f.cfg.Core.APIPort = f.cfg.Core.SocksPort + 4
	writeHotApplyPair(t, f, "direct-v2")
	mgr := hotTestManager(t, f)

	client := &recordedHotClient{}
	hotPathOnly(t, client)

	require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr))

	verbs, payloads := client.snapshot()
	assert.Empty(t, verbs, "a mixed diff never touches the core API")
	assert.Empty(t, payloads)

	// The full path mutations: backup of the pre-activation live, live.json
	// replaced from the candidate, core restarted, post-activation health
	// fed the strike counter.
	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.Contains(t, string(live), "direct-v2", "the full path replaced live.json from the candidate")
	logs := f.log.String()
	assert.Contains(t, logs, "core: stopped pid", "the Restart stop leg ran")
	assert.Contains(t, logs, "core: spawned pid", "the Restart start leg ran")
	assert.Contains(t, logs, "core: health failure 1/", "the post-activation health fed the strike counter")
	matches, err := filepath.Glob(filepath.Join(f.p.backupDir, "config.json.bak-*"))
	require.NoError(t, err)
	assert.Len(t, matches, 1, "the full path backed up the pre-activation live config")

	st, err := hotapply.ReadState(f.p.dataDir)
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Equal(t, hotapply.ModeRestart, st.Mode, "the status state records the restart as the last activation")
	assert.False(t, st.PIDStable, "a restart is not pid-stable")
}

// TestWaveHotApplyFailureFallsBackLoudToFullActivation is the
// mutation-proven fallback pin: a hot-apply failure first heals the
// last-good routing (the plan's never-a-partial-state ladder — the heal
// payload IS the live routing), then falls back LOUD to the full activate
// path, whose mutations prove the fallback actually ran: backup, live.json
// replaced from the candidate, core restarted, health checked. The last
// activation recorded for status is the RESTART.
func TestWaveHotApplyFailureFallsBackLoudToFullActivation(t *testing.T) {
	t.Run("healing restores last-good before the fallback", func(t *testing.T) {
		f := newOwnFixture(t)
		f.cfg.Core.APIPort = f.cfg.Core.SocksPort + 4
		writeHotApplyPair(t, f, "direct")
		mgr := hotTestManager(t, f)

		client := &recordedHotClient{
			replaceErrs: []error{errors.New("adrules: rpc error: internal — the replace died mid-flight")},
			ruleQueue: [][]hotapply.RuleEntry{
				rulesForVerification(t, mustParseConfig(t, hotApplyConfigBytes(f.cfg.Core.SocksPort, "pool-route-1", "direct"))),
			},
		}
		hotPathOnly(t, client)

		require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr),
			"the fallback full activation converges the wave")

		verbs, payloads := client.snapshot()
		require.Equal(t, []string{"reachable", "adrules", "adrules", "lsrules"}, verbs,
			"probe, failed replace, healing reload, healing verification")
		require.Len(t, payloads, 2)
		assert.Contains(t, string(payloads[0]), "pool-route-2", "the first replace carried the candidate")
		assert.Contains(t, string(payloads[1]), "pool-route-1",
			"the healing reload re-applied the LAST-GOOD routing")

		out := f.out.String()
		assert.Contains(t, out, "hot-apply FAILED", "the failure is loud")
		assert.Contains(t, out, "previous routing restored", "the healing outcome is named")
		assert.Contains(t, out, "full activate path", "the fallback is loud")

		// Mutation proof: the full activate path really ran.
		live, err := os.ReadFile(ownLivePath(f.p))
		require.NoError(t, err)
		cand, err := os.ReadFile(ownCandidatePath(f.p))
		require.NoError(t, err)
		assert.Equal(t, string(cand), string(live), "the fallback replaced live.json from the candidate")
		logs := f.log.String()
		assert.Contains(t, logs, "core: spawned pid", "the fallback restarted the core")
		matches, err := filepath.Glob(filepath.Join(f.p.backupDir, "config.json.bak-*"))
		require.NoError(t, err)
		assert.Len(t, matches, 1, "the fallback backed up the pre-activation live config")

		st, err := hotapply.ReadState(f.p.dataDir)
		require.NoError(t, err)
		require.NotNil(t, st)
		assert.Equal(t, hotapply.ModeRestart, st.Mode, "status records the restart as the last activation")
	})

	t.Run("healing failure still falls back loud", func(t *testing.T) {
		f := newOwnFixture(t)
		f.cfg.Core.APIPort = f.cfg.Core.SocksPort + 4
		writeHotApplyPair(t, f, "direct")
		mgr := hotTestManager(t, f)

		client := &recordedHotClient{
			replaceErrs: []error{
				errors.New("adrules: rpc error: internal — the replace died"),
				errors.New("exec xray api adrules: failed to dial 127.0.0.1:1: the core went unreachable"),
			},
		}
		hotPathOnly(t, client)

		require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr))

		out := f.out.String()
		assert.Contains(t, out, "hot-apply FAILED", "the failure is loud")
		assert.Contains(t, out, "healing", "the healing failure is named")
		assert.Contains(t, out, "full activate path", "the fallback is loud")

		live, err := os.ReadFile(ownLivePath(f.p))
		require.NoError(t, err)
		assert.Contains(t, string(live), "pool-route-2", "the fallback still converged the core to the candidate")
		logs := f.log.String()
		assert.Contains(t, logs, "core: spawned pid", "the fallback restarted the core")
	})
}

// TestWaveHotSkipsLoudWhenCoreUnreachable pins the probe discipline in the
// wave: a probe failure is a first-class loud input, NOTHING is mutated
// through the API (the adrules verb never fires), and the classified
// reason (core down / RoutingService missing) names itself before the full
// activate path converges the core.
func TestWaveHotSkipsLoudWhenCoreUnreachable(t *testing.T) {
	for _, tt := range []struct {
		name    string
		kind    hotapply.FailureKind
		wantMsg string
	}{
		{name: "core down", kind: hotapply.CoreDown, wantMsg: "core is unreachable"},
		{name: "RoutingService missing", kind: hotapply.ServiceMissing, wantMsg: "RoutingService"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newOwnFixture(t)
			f.cfg.Core.APIPort = f.cfg.Core.SocksPort + 4
			writeHotApplyPair(t, f, "direct")
			mgr := hotTestManager(t, f)

			client := &recordedHotClient{reachableErr: hotDialError(tt.kind)}
			hotPathOnly(t, client)

			require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr),
				"the full activate path is the remedy for an unreachable hot target")

			verbs, payloads := client.snapshot()
			assert.Equal(t, []string{"reachable"}, verbs, "only the probe fired")
			assert.Empty(t, payloads, "nothing was mutated through the API")

			out := f.out.String()
			assert.Contains(t, out, "hot-apply skipped", "the skip is loud")
			assert.Contains(t, out, tt.wantMsg, "the classified reason names itself")
			assert.Contains(t, out, "nothing was mutated", "the no-mutation guarantee is stated")

			live, err := os.ReadFile(ownLivePath(f.p))
			require.NoError(t, err)
			assert.Contains(t, string(live), "pool-route-2", "the full path converged the core")
		})
	}
}

// TestWaveHotGateFailureAbortsLoudBeforeAnyAPITouch pins L10 on the new
// path: the hot path's -test gate runs BEFORE any API verb, and a
// routing-only candidate the gate refuses ends the stage loud with
// live.json untouched and the client never invoked (the full path would
// refuse the same file at the same gate — a fallback would only churn a
// backup). The gate-fail marker rides INSIDE the routing section, so the
// diff-classifier picks the hot path first and the pin proves the HOT
// gate ordering.
func TestWaveHotGateFailureAbortsLoudBeforeAnyAPITouch(t *testing.T) {
	f := newOwnFixture(t)
	f.cfg.Core.APIPort = f.cfg.Core.SocksPort + 4
	writeHotApplyPair(t, f, "direct")
	cand := mustParseConfig(t, hotApplyConfigBytes(f.cfg.Core.SocksPort, "pool-route-2", "direct"))
	routing := cand["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	rules[0].(map[string]any)["note"] = cliFakeGateFail
	raw, err := json.Marshal(cand)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(ownCandidatePath(f.p), raw, 0o600))
	mgr := hotTestManager(t, f)
	pidBefore := readCorePID(f.p.dataDir)

	client := &recordedHotClient{}
	hotPathOnly(t, client)

	err = runActivateStageWithManager(f.cmd, f.cfg, mgr)
	require.Error(t, err, "a gate-refused candidate fails the stage loud")
	assert.Contains(t, err.Error(), "-test gate failed", "the gate refusal is named")

	verbs, payloads := client.snapshot()
	assert.Empty(t, verbs, "the API is never touched on a gate failure")
	assert.Empty(t, payloads)

	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.NotContains(t, string(live), cliFakeGateFail, "live.json is untouched")
	pidAfter := readCorePID(f.p.dataDir)
	assert.Equal(t, pidBefore, pidAfter, "the core pid is unchanged")
	assert.True(t, mgr.Alive(), "the core keeps serving the last-good config")
}

// TestWaveHotYieldsToInFlightApply pins the apply-lock serialization: with
// a manual `assay apply` holding <data>/apply.lock, the wave hot path
// yields loud (the client is never invoked) and the full activate path
// converges — the pre-T5 behavior for the contention shape.
func TestWaveHotYieldsToInFlightApply(t *testing.T) {
	f := newOwnFixture(t)
	f.cfg.Core.APIPort = f.cfg.Core.SocksPort + 4
	writeHotApplyPair(t, f, "direct")
	mgr := hotTestManager(t, f)

	release, err := lockApplyFile(f.p.dataDir)
	require.NoError(t, err)
	t.Cleanup(release)

	client := &recordedHotClient{}
	hotPathOnly(t, client)

	require.NoError(t, runActivateStageWithManager(f.cmd, f.cfg, mgr))

	verbs, _ := client.snapshot()
	assert.Empty(t, verbs, "the hot path yields to the in-flight apply")

	out := f.out.String()
	assert.Contains(t, out, "hot-apply skipped", "the yield is loud")
	assert.Contains(t, out, "apply is already in flight", "the contention is named")

	live, err := os.ReadFile(ownLivePath(f.p))
	require.NoError(t, err)
	assert.Contains(t, string(live), "pool-route-2", "the full path converged the core")
}

// TestStatusCoreBlockShowsHotApplyState pins the status surface (the T5
// status item): the own-core block renders the hot-apply state honestly —
// the hot mode with the stable pid, the restart mode with the pid
// transition, a corrupt state file as a degraded line, and NO line when no
// activation was ever recorded.
func TestStatusCoreBlockShowsHotApplyState(t *testing.T) {
	// printCoreStatus drives a coreState built through the collector's
	// state-file read (the same hotapply.ReadState the collector calls);
	// the exact line texts are the pin.
	render := func(t *testing.T, dataDir string) string {
		t.Helper()
		cs := &coreState{}
		cs.hot, cs.hotErr = hotapply.ReadState(dataDir)
		var sb strings.Builder
		printCoreStatus(&sb, cs, false)
		return sb.String()
	}

	t.Run("hot mode with the stable pid", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, hotapply.WriteState(dir, &hotapply.State{
			Mode: hotapply.ModeHot, PIDBefore: 4242, PIDAfter: 4242,
		}))
		out := render(t, dir)
		assert.Contains(t, out, "hotapply:", "the core block carries the hot-apply line")
		assert.Contains(t, out, "HOT", "the mode is named")
		assert.Contains(t, out, "4242", "the pid is shown")
		assert.Contains(t, out, "no core restart", "pid stability is stated")
	})

	t.Run("restart mode with the pid transition", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, hotapply.WriteState(dir, &hotapply.State{
			Mode: hotapply.ModeRestart, PIDBefore: 4242, PIDAfter: 5252,
		}))
		out := render(t, dir)
		assert.Contains(t, out, "RESTART", "the mode is named")
		assert.Contains(t, out, "4242", "the before-pid is shown")
		assert.Contains(t, out, "5252", "the after-pid is shown")
	})

	t.Run("corrupt state degrades honest", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, hotapply.StateFileName),
			[]byte("{not json"), 0o600))
		out := render(t, dir)
		assert.Contains(t, out, "unreadable", "the corrupt state is a degraded line, never silence")
	})

	t.Run("no state file renders no line", func(t *testing.T) {
		out := render(t, t.TempDir())
		assert.NotContains(t, out, "hotapply:", "a fresh deployment has no hot-apply line")
	})
}
