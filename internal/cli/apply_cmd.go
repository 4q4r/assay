package cli

// `assay apply` — the hot-apply CLI verb (the 2026-11-13 plan §3, Order B):
// render → diff vs the running state → hot-apply the hot-applicable subset
// (the ENTIRE routing section through the running core's own API CLI) →
// verify → persist to disk. Any API failure heals with the last-good routing
// and, when healing is impossible, falls back LOUD to the full activate
// path — never a silent partial state (D7 spirit; the daemon owns the core,
// so this verb talks to the RUNNING core's API and spawns nothing except in
// the daemon-free restart fallback).
//
// Reconciliation axiom: <data>/rendered/live.json on disk stays the single
// source of truth. Hot-applied state is ephemeral (any core restart
// re-converges to disk); because a successful apply PERSISTS the applied
// render, disk and runtime agree — the wave pipeline IS the reconciler.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"assay/internal/activate"
	"assay/internal/config"
	"assay/internal/core"
	"assay/internal/hotapply"
	"assay/internal/platform"
	"assay/internal/ui"

	"github.com/spf13/cobra"
)

// The apply flow's seams (production wiring below; the unit battery injects
// recorded fakes — the argv contracts are identical in both modes).
var (
	// renderLeg produces <data>/rendered/candidate.json — the SAME artifact
	// the wave produces (plan §3.1: never a parallel render).
	renderLeg = runRender
	// newApplyClient builds the API client against the RESOLVED core binary
	// (S1) and the rendered api inbound's port — dialect-neutral by
	// construction (R3).
	newApplyClient = func(cfg *config.Config) *hotapply.Client {
		return hotapply.NewClient(coreXrayBin(cfg), cfg.Core.APIPort)
	}
	// acquireApplyLock serializes concurrent applies (plan §3.9): a
	// non-blocking flock on <data>/apply.lock.
	acquireApplyLock = lockApplyFile
	// restartFallback is the full activate path (plan §3.8b): the existing
	// runActivateStageWithManager semantics with a transient manager.
	restartFallback = runApplyRestartFallback
)

func newApplyCommand(cfgPath *string) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Hot-apply routing-only config changes to the RUNNING core (no restart)",
		Long: `Applies a routing-only config delta to the running core through its API
inbound — no daemon restart, no W17 stage-boundary wait, no balancer
warm-up outage. The flow: render the candidate (the wave's own
artifact), -test gate it, classify the diff against live.json, probe
the API (lsrules round trip — core down is a first-class loud input),
replace the ENTIRE routing section (adrules without -append — the
catch-all makes appended rules dead), verify the running rule tags,
and persist the applied render to live.json (disk truth converges —
the next wave re-render is a clean no-op).

Anything outside routing (outbound set, inbounds, log, observatory,
api services) is RESTART-ONLY: the verb refuses loud, names the
sections, and prints the exact restart commands — it never partially
applies. Any API failure heals with the previous (last-good) routing;
when even healing is impossible, the full activate path runs (or, under
the daemon, the convergence-guarantee message prints). The on-disk
live.json remains the single source of truth: hot state is ephemeral by
design and always converges to disk.

The FIRST apply after the hot-apply render lands fails at the probe —
the running core still runs the pre-enablement services list. One
normal activation (or wave) restarts the core with RoutingService
enabled; from then on applies are hot.

Flags:
  --dry-run     print the diff classification and exit; no API call`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			return runApply(cmd, res.Config, dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"print the diff classification (hot-capable or the blocking sections) and exit")
	attachColorFlags(cmd)
	return cmd
}

// applyPair is the diff source pair (plan §1.6: the on-disk artifacts —
// live.json vs candidate.json; there is no full-config dump RPC).
type applyPair struct {
	livePath  string
	live      map[string]any
	candPath  string
	cand      map[string]any
	noChanges bool // semantically identical pair — nothing to hot-apply
}

// readApplyPair loads and parses the on-disk pair after the render leg.
func readApplyPair(p paths) (*applyPair, error) {
	liveBytes, err := os.ReadFile(ownLivePath(p))
	if err != nil {
		return nil, fmt.Errorf("apply: read live config %s: %w "+
			"(the core has never been activated — run `assay activate` first)", ownLivePath(p), err)
	}
	candBytes, err := os.ReadFile(ownCandidatePath(p))
	if os.IsNotExist(err) {
		return nil, errors.New("apply: no rendered candidate (empty selection or render not run) — nothing to apply")
	}
	if err != nil {
		return nil, fmt.Errorf("apply: read candidate %s: %w", ownCandidatePath(p), err)
	}
	pair := &applyPair{livePath: ownLivePath(p), candPath: ownCandidatePath(p)}
	if err := json.Unmarshal(liveBytes, &pair.live); err != nil {
		return nil, fmt.Errorf("apply: parse live config: %w", err)
	}
	if err := json.Unmarshal(candBytes, &pair.cand); err != nil {
		return nil, fmt.Errorf("apply: parse candidate: %w", err)
	}
	diff := hotapply.Classify(pair.live, pair.cand)
	pair.noChanges = diff.HotCapable && !diff.RoutingChanged
	return pair, nil
}

// runApply is the Order B flow (plan §3 steps 1-9). Steps are sequenced so
// that EVERY failure before the ReplaceRouting call mutates nothing (steps:
// render → classify → gate → lock → probe are all read-only or live-config
// untouched), and every failure AFTER it goes through the healing ladder.
func runApply(cmd *cobra.Command, cfg *config.Config, dryRun bool) error {
	out := cmd.OutOrStdout()
	p := newPaths(cfg)
	// The core lifecycle belongs to a configured deployment (the W12
	// configless boundary — same grammar as render/activate).
	if cfg.Configless {
		return config.ConfiglessBoundaryError("apply")
	}

	// Step 1: the render leg — the wave's own artifact, never a parallel
	// render. An empty selection removes the candidate; the read below
	// refuses loud.
	if err := renderLeg(cmd, cfg); err != nil {
		return fmt.Errorf("apply: render leg: %w", err)
	}

	// Step 3 (before the gate — a restart-only delta must not spend a gate
	// exec): classify the on-disk pair.
	pair, err := readApplyPair(p)
	if err != nil {
		return err
	}
	if pair.noChanges {
		// A semantically identical pair: nothing to hot-apply (the byte-level
		// no-op the wave's activate would also skip).
		outln(out, "apply: no changes — the live config already matches the rendered routing; nothing to apply")
		return nil
	}
	diff := hotapply.Classify(pair.live, pair.cand)
	done, err := classifyStep(out, diff, pair.cand, dryRun)
	if done || err != nil {
		return err
	}

	// Step 2: the -test gate on the candidate through the SINGLE binary knob
	// (S1) — a bad config never reaches the API (L10).
	if err := activate.TestGate(activate.Input{
		RenderedPath: pair.candPath,
		XrayBin:      coreXrayBin(cfg),
		AssetDir:     coreAssetDir(cfg, p),
		TestTimeout:  activateTestTimeout(cfg),
	}); err != nil {
		return err
	}

	// Step 9: serialize concurrent applies (an in-flight wave is NOT blocked
	// — Order B means the wave's own re-render converges over the hot state
	// by construction; disk truth wins).
	release, err := acquireApplyLock(p.dataDir)
	if err != nil {
		return err
	}
	defer release()

	// Step 4: the reachability probe — NOTHING has been mutated yet, and a
	// probe failure is a first-class loud no-op (core down / RoutingService
	// not yet enabled).
	client := newApplyClient(cfg)
	ctx := context.Background()
	if err := client.Reachable(ctx); err != nil {
		return probeFailure(cfg, err)
	}

	// Steps 5+6: payload = the candidate's ENTIRE routing section verbatim
	// from the gated render; adrules WITHOUT -append; then verify.
	candRouting, ok := pair.cand["routing"].(map[string]any)
	if !ok {
		return errors.New("apply: candidate render has no routing section")
	}
	candTags, candCount, err := hotapply.ExpectedFromRouting(candRouting)
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	added, removed := ruleTagDelta(pair.live, pair.cand)
	applyErr := applyRouting(ctx, client, pair.cand, candTags, candCount)
	if applyErr == nil {
		persistAppliedRender(cmd, cfg, p, out, added, removed)
		return nil
	}

	// Step 8a: the healing reload — the PREVIOUS live routing (last-good).
	healed, healErr := healPreviousRouting(ctx, client, pair.live)
	if healed {
		return fmt.Errorf("apply: hot-apply FAILED, previous routing restored (no restart needed): %w", applyErr)
	}

	// Step 8b: healing failed or the core went unreachable — the full
	// activate path is the remedy (restart fallback, loud).
	outf(out, "apply: hot-apply failed AND healing failed (%s: %v) — falling back to the full activate path\n",
		healErrClass(healErr), healErr)
	return restartFallback(cmd, cfg)
}

// classifyStep renders the pre-mutation verdicts (plan §3.3): the dry-run
// classification, or the loud not-hot-capable refusal naming the changed
// restart-only sections and the exact restart commands — apply never
// partially applies. done=true means the flow stops here having mutated
// nothing.
func classifyStep(out io.Writer, diff hotapply.Diff, cand map[string]any, dryRun bool) (bool, error) {
	if dryRun {
		if diff.HotCapable {
			outf(out, "apply (dry-run): HOT-CAPABLE — routing-only delta (%d rule(s) now, no restart needed)\n",
				ruleCount(cand))
		} else {
			outf(out, "apply (dry-run): NOT hot-capable — changed sections outside routing: %s\n",
				strings.Join(diff.Reasons, ", "))
		}
		return true, nil
	}
	if !diff.HotCapable {
		return true, fmt.Errorf("apply: NOT hot-capable — changed sections outside routing: %s\n"+
			"  only routing changes hot-apply; for these run `assay activate` (no daemon) or wait for the next wave;\n"+
			"  under the daemon: `systemctl --user restart assay-watch.service` (waits for the stage boundary, W17)",
			strings.Join(diff.Reasons, ", "))
	}
	return false, nil
}

// persistAppliedRender is step 7 (Order B — hot first, disk second): the
// applied render is persisted through activate.Run (gate again, dated backup
// — the D8 rollback source — atomic replace). Disk and runtime now agree →
// the next wave re-render is a clean no-op. A persist failure is loud but
// NOT an apply failure: the hot state is live on the core and converges at
// the next wave's render by construction.
func persistAppliedRender(
	cmd *cobra.Command, cfg *config.Config, p paths, out io.Writer, added, removed []string,
) {
	if _, err := activate.Run(activate.Input{
		RenderedPath: ownCandidatePath(p),
		TargetPath:   ownLivePath(p),
		XrayBin:      coreXrayBin(cfg),
		AssetDir:     coreAssetDir(cfg, p),
		BackupDir:    p.backupDir,
		Backup:       true,
		BackupBase:   "config.json",
		TestTimeout:  activateTestTimeout(cfg),
		BackupKeep:   cfg.Activate.BackupKeep,
	}); err != nil {
		outf(out, "WARNING: hot-apply succeeded but persisting live.json failed: %v "+
			"(the next wave re-render converges the disk)\n", err)
	}
	outf(out, "%s\n", ui.Chip("apply:", fmt.Sprintf(
		"hot-applied routing: +%d/-%d ruleTag(s) (no core restart); live.json converged",
		len(added), len(removed)), stageColor(cmd)))
}

// applyRouting writes the payload file and executes the replace + verify
// (plan §3.5/3.6). A verification miss counts as an apply failure (the
// caller heals) — no verification, no success claim (R1).
func applyRouting(
	ctx context.Context, client *hotapply.Client, cand map[string]any, wantTags []string, wantCount int,
) error {
	payloadPath, cleanup, err := hotapply.WritePayloadFile(cand)
	defer cleanup()
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}
	if err := client.ReplaceRouting(ctx, payloadPath); err != nil {
		return err
	}
	entries, err := client.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("post-apply verification query: %w", err)
	}
	if err := hotapply.VerifyApplied(entries, wantTags, wantCount); err != nil {
		return fmt.Errorf("post-apply verification: %w", err)
	}
	return nil
}

// healPreviousRouting re-applies the PREVIOUS live routing (last-good) and
// verifies it (plan §3.8a). false + nil error = the live config has no
// routing section to heal with (bootstrap shape); false + err = the healing
// attempt failed — the restart fallback is the remedy.
func healPreviousRouting(ctx context.Context, client *hotapply.Client, live map[string]any) (bool, error) {
	routing, ok := live["routing"].(map[string]any)
	if !ok {
		return false, errors.New("live config has no routing section to heal with")
	}
	tags, count, err := hotapply.ExpectedFromRouting(routing)
	if err != nil {
		return false, err
	}
	payloadPath, cleanup, err := hotapply.WritePayloadFile(live)
	defer cleanup()
	if err != nil {
		return false, err
	}
	if err := client.ReplaceRouting(ctx, payloadPath); err != nil {
		return false, err
	}
	entries, err := client.ListRules(ctx)
	if err != nil {
		return false, err
	}
	if err := hotapply.VerifyApplied(entries, tags, count); err != nil {
		return false, err
	}
	return true, nil
}

// probeFailure renders the loud, classified probe-failure messages (plan
// §3.4/R2/R10): core down, service missing, other. NOTHING was mutated on
// any probe path.
func probeFailure(cfg *config.Config, err error) error {
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Core.APIPort)
	switch hotapply.ProbeFailureKind(err) {
	case hotapply.CoreDown:
		return fmt.Errorf("apply: the core API is unreachable on %s (the core is down or the api inbound is gone)\n"+
			"  start it first: `systemctl --user start assay-watch.service` (daemon) or `assay activate` (no daemon)\n"+
			"  nothing was mutated", addr)
	case hotapply.ServiceMissing:
		return errors.New("apply: the running core has no RoutingService — the hot-apply enablement restart " +
			"has not happened yet\n" +
			"  one restart enables it: `assay activate` (or the next wave); from then on applies are hot\n" +
			"  nothing was mutated")
	case hotapply.FailureOther:
		return fmt.Errorf("apply: the core API probe failed (nothing was mutated): %w", err)
	default:
		return fmt.Errorf("apply: the core API probe failed (nothing was mutated): %w", err)
	}
}

// runApplyRestartFallback is the production restart fallback (plan §3.8b):
// the existing full activate path with a transient manager. Under the
// daemon the flock refuses — the loud convergence-guarantee message states
// exactly what converges the running core and the exact commands; nothing
// spawns.
func runApplyRestartFallback(cmd *cobra.Command, cfg *config.Config) error {
	out := cmd.OutOrStdout()
	p := newPaths(cfg)
	mgr, err := core.NewTransientManager(cfg.Core, p.dataDir, out)
	if errors.Is(err, core.ErrDaemonHoldsCore) {
		return errors.New("apply: hot-apply failed and healing failed; the daemon owns the core — " +
			"the restart path is not reachable from here\n" +
			"  the running core may serve degraded routing until the next wave converges it (or restart the unit — " +
			"it waits for the stage boundary, W17):\n" +
			"  `systemctl --user restart assay-watch.service`")
	}
	if err != nil {
		return fmt.Errorf("apply: restart fallback (transient manager): %w", err)
	}
	// The one-shot lifecycle: the lock hold is this process (A2 — the stage
	// never stops a core it adopted; the daemon re-adopts it).
	defer mgr.Release()
	if err := runActivateStageWithManager(cmd, cfg, mgr); err != nil {
		return fmt.Errorf("apply: restart fallback: %w", err)
	}
	outln(out, "apply: the full activate path completed — the core restarted on the rendered config")
	return nil
}

// lockApplyFile takes the exclusive non-blocking hold on <data>/apply.lock
// (the flock singleton discipline of core.lock, applied to applies).
func lockApplyFile(dataDir string) (func(), error) {
	path := filepath.Join(dataDir, "apply.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("apply: open %s: %w", path, err)
	}
	if err := platform.LockFile(f); err != nil {
		_ = f.Close()
		if errors.Is(err, platform.ErrLockHeld) {
			return nil, fmt.Errorf("apply: another apply is already in flight (lock on %s)", path)
		}
		return nil, fmt.Errorf("apply: lock %s: %w", path, err)
	}
	return func() {
		_ = platform.UnlockFile(f)
		_ = f.Close()
	}, nil
}

// ruleTagDelta computes the added/removed ruleTag sets between live and
// candidate (the journal line's +N/-M).
func ruleTagDelta(live, cand map[string]any) ([]string, []string) {
	var liveTags, candTags []string
	if routing, ok := live["routing"].(map[string]any); ok {
		liveTags = ruleTagsOf(routing)
	}
	if routing, ok := cand["routing"].(map[string]any); ok {
		candTags = ruleTagsOf(routing)
	}
	candSet := map[string]bool{}
	for _, tag := range candTags {
		candSet[tag] = true
	}
	liveSet := map[string]bool{}
	for _, tag := range liveTags {
		liveSet[tag] = true
	}
	var added, removed []string
	for _, tag := range candTags {
		if !liveSet[tag] {
			added = append(added, tag)
		}
	}
	for _, tag := range liveTags {
		if !candSet[tag] {
			removed = append(removed, tag)
		}
	}
	return added, removed
}

func ruleTagsOf(routing map[string]any) []string {
	tags, _, err := hotapply.ExpectedFromRouting(routing)
	if err != nil {
		return nil
	}
	return tags
}

func ruleCount(m map[string]any) int {
	routing, ok := m["routing"].(map[string]any)
	if !ok {
		return 0
	}
	rules, ok := routing["rules"].([]any)
	if !ok {
		return 0
	}
	return len(rules)
}

// healErrClass names the healing failure class for the fallback banner.
func healErrClass(err error) string {
	if err == nil {
		return "unknown"
	}
	switch hotapply.ProbeFailureKind(err) {
	case hotapply.CoreDown:
		return "core unreachable"
	case hotapply.ServiceMissing:
		return "RoutingService missing"
	case hotapply.FailureOther:
		return "healing reload failed"
	default:
		return "healing reload failed"
	}
}
