package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"public_vpn/internal/activate"
	"public_vpn/internal/checker"
	"public_vpn/internal/config"
	"public_vpn/internal/fetch"
	"public_vpn/internal/filter"
	"public_vpn/internal/geo"
	"public_vpn/internal/model"
	"public_vpn/internal/parse"
	"public_vpn/internal/plugins"
	"public_vpn/internal/probe"
	"public_vpn/internal/prune"
	"public_vpn/internal/rank"
	"public_vpn/internal/render"
	"public_vpn/internal/restart"
	"public_vpn/internal/stats"
	"public_vpn/internal/store"
	"public_vpn/internal/timeoutcal"
	"public_vpn/internal/ui"

	"github.com/spf13/cobra"
)

// fetchManifest records what a fetch wave stored, so parse reads exactly what
// fetch downloaded (source → cached files). Cache file names come from
// fetch.SafePath — the single definition of the path→name mapping.
//
// Merge contract (fetch × enrichment layering): the fetch stage owns and
// refreshes the fetch-layer fields every wave (FetchedAt, Sources; on each
// PluginStats row TotalNodes and DuplicateCount). The enrichment tail
// (runPluginStatsEnrichment) owns the enrichment-layer fields (LiveNodes,
// HostingCount, ProxyCount, CleanCount, ClassifiedCount, UnlockCount,
// UniqueYield, TopOverlaps, PluginOverlap) and refreshes them once per full
// wave cycle. The fetch stage PRESERVES the enrichment layer via
// carryOverEnrichment (carry-over is at most one wave interval stale until
// the next enrichment tail refreshes it) — without it the next fetch would
// clobber the enriched manifest seconds after the tail wrote it.
type fetchManifest struct {
	FetchedAt   time.Time                      `json:"fetched_at"`
	Sources     map[string][]fetch.FetchedFile `json:"sources"`
	PluginStats []plugins.PluginStats          `json:"plugin_stats,omitempty"`
	// PluginOverlap carries the full pairwise identity-overlap matrix the
	// enrichment pass computes (Phase 4's --overlap view consumes it; the
	// per-plugin TopOverlaps/UniqueYield are its top-2 projection).
	PluginOverlap *plugins.OverlapMatrix `json:"plugin_overlap,omitempty"`
}

// providerHistoryFile is the provider time-series artifact under the data
// directory (internal/stats owns its schema and atomic persistence).
const providerHistoryFile = "provider-history.json"

// adaptConcurrencyFunc is the in-wave adaptation seam (tests may swap).
var adaptConcurrencyFunc = AdaptConcurrency

// recordStageStatFunc is the per-stage stat persistence seam (tests may swap).
var recordStageStatFunc = RecordStageStat

// adjustBaseConcurrencyFunc is the inter-wave EMA seam (tests may swap).
var adjustBaseConcurrencyFunc = AdjustBaseConcurrency

// adaptTickerInterval is the in-wave adaptation tick cadence.
var adaptTickerInterval = 5 * time.Second

// outf writes formatted output; terminal writes never fail in practice and a
// broken pipe must not mask the command result — the error is deliberately
// discarded (checked at gate).
func outf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func outln(w io.Writer, a ...any) {
	_, _ = fmt.Fprintln(w, a...)
}

func newFetchCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "fetch",
		Short: "Run the Lua source plugins and store their raw links (D9 via plugins, cached)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			return runFetch(cmd, res.Config)
		},
	}
}

// runFetch is the one-shot entry: fresh registry from disk (materialize
// defaults, compile everything) — one-shot is implicitly fresh.
func runFetch(cmd *cobra.Command, cfg *config.Config) error {
	_, err := runFetchWith(cmd, cfg, nil)
	return err
}

// runFetchWith executes every plugin in the (shared or fresh) registry and
// materializes the returned raw links as ONE synthetic cache file per source
// id (cacheDir/<source>/<plugin>.txt) recorded in the fetch manifest. The
// downstream parse/filter stages are unchanged: Go keeps owning URI
// normalization, parsing, rejection counters, and dedupe. reg == nil loads a
// fresh registry from disk; the watch daemon passes its shared, watchdog-
// maintained registry (the wave snapshots it once, at fetch start).
//
// The registry the wave used is RETURNED so later stages — the plugin-stats
// enrichment seam — enforce thresholds on THE SAME registry. The old
// enrichment path reloaded a throwaway copy and recorded its breaker
// failures into it: loud lines, zero enforcement (adversarial review F1).
func runFetchWith(cmd *cobra.Command, cfg *config.Config, reg *plugins.Registry) (*plugins.Registry, error) {
	p := newPaths(cfg)
	out := cmd.OutOrStdout()
	if err := os.MkdirAll(p.cacheDir, 0o750); err != nil {
		return reg, err
	}
	if reg == nil {
		if err := plugins.EnsureDefaults(config.ExpandHome(cfg.Plugins.Dir)); err != nil {
			return reg, err
		}
		fresh, err := plugins.LoadDir(config.ExpandHome(cfg.Plugins.Dir), out)
		if err != nil {
			return reg, err
		}
		reg = fresh
	}
	snapshot := reg.Snapshot()
	if len(snapshot) == 0 {
		return reg, fmt.Errorf("no plugins in %s — add .lua files or delete the dir to restore the defaults",
			config.ExpandHome(cfg.Plugins.Dir))
	}
	engine := plugins.NewEngine(fetch.ClientConfig{
		APIBase:     cfg.Fetch.APIBase,
		RawBase:     cfg.Fetch.RawBase,
		Token:       cfg.Fetch.GitHubToken,
		Timeout:     cfg.Fetch.Timeout.Duration,
		Retries:     cfg.Fetch.Retries,
		Concurrency: cfg.Fetch.Concurrency,
		UserAgent:   cfg.HTTP.UserAgent,
	}, out)

	// Create stats collector for plugin statistics (geo records added later for enrichment)
	statsCollector := plugins.NewPluginStatsCollector(nil)

	collected, failed, hinted, totalNodes := runAllPlugins(out, engine, snapshot, pluginRunTimeout(cfg),
		pluginMaxFailures(cfg), reg, statsCollector)
	if failed == len(snapshot) {
		return reg, fmt.Errorf("all %d attempted plugins failed; nothing fetched", failed)
	}

	// Compute basic stats (TotalNodes, DuplicateCount) after all plugins have run
	statsCollector.ComputeBasicStats()

	// Threshold enforcement: check MaxDuplicatePercent
	checkMaxDuplicatePercent(out, reg, cfg, statsCollector)

	manifest, files, err := writePluginArtifacts(p.cacheDir, collected)
	if err != nil {
		return reg, err
	}
	// Store plugin stats in manifest
	manifest.PluginStats = statsCollector.GetStats()

	// Merge contract (see fetchManifest): preserve the previous manifest's
	// enrichment-layer fields for plugins the new fetch still carries — the
	// enrichment tail rewrote them ~2h ago and the next tail is ~2h away.
	// Missing prior manifest = cold start (as before); corrupt prior
	// manifest = loud WARNING, then also as before (never fails the wave).
	if prior := loadPriorFetchManifest(p.manifest, out); prior != nil {
		carryOverEnrichment(&manifest, prior)
	}

	//nolint:musttag // fetchManifest has JSON tags; musttag false positive
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return reg, err
	}
	if err := store.WriteManifest(p.manifest, b); err != nil {
		return reg, err
	}
	outf(out, "fetch wave complete: %d nodes from %d plugins (%d source files, %d hinted) → %s\n",
		totalNodes, len(snapshot)-failed, files, hinted, p.manifest)
	return reg, nil
}

// loadPriorFetchManifest reads the fetch manifest the previous wave left at
// path. A missing file is a cold start (nil, silent — every deployment's
// first wave lands here). A corrupt or otherwise unreadable file is a loud
// WARNING and a cold start too: a broken stats overlay must never fail the
// fetch wave, it only degrades the manifest to fresh-basic-stats shape
// until the next enrichment tail refills it.
func loadPriorFetchManifest(path string, out io.Writer) *fetchManifest {
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			outf(out, "WARNING: read prior fetch manifest %s: %v — continuing without enrichment carry-over\n", path, err)
		}
		return nil
	}
	var m fetchManifest
	//nolint:musttag // fetchManifest has JSON tags; musttag false positive
	if err := json.Unmarshal(b, &m); err != nil {
		outf(out, "WARNING: prior fetch manifest %s is corrupt (%v) — continuing without enrichment carry-over\n", path, err)
		return nil
	}
	return &m
}

// carryOverEnrichment merges the prior manifest's enrichment-layer fields
// into the fresh fetch manifest, per plugin id, for plugins the new fetch
// still carries:
//
//   - fetch layer (refreshed every wave by THIS stage): TotalNodes,
//     DuplicateCount, fetched_at, sources;
//   - enrichment layer (refreshed by runPluginStatsEnrichment once per full
//     wave cycle): LiveNodes, HostingCount, ProxyCount, CleanCount,
//     ClassifiedCount, UnlockCount, UniqueYield, TopOverlaps, plugin_overlap.
//
// A plugin absent from the prior manifest starts unenriched (status renders
// it pending until the next enrichment tail observes it — honest, not
// fake); a plugin dropped from the new fetch takes its stale stats with it
// (only fresh-fetch plugins exist in the merged stats). Freshness bound:
// carried values are at most one wave interval stale.
func carryOverEnrichment(fresh *fetchManifest, prior *fetchManifest) {
	if fresh == nil || prior == nil {
		return
	}
	if fresh.PluginOverlap == nil {
		fresh.PluginOverlap = prior.PluginOverlap
	}
	priorByID := make(map[string]plugins.PluginStats, len(prior.PluginStats))
	for _, st := range prior.PluginStats {
		priorByID[st.PluginID] = st
	}
	for i := range fresh.PluginStats {
		p, ok := priorByID[fresh.PluginStats[i].PluginID]
		if !ok {
			continue
		}
		fresh.PluginStats[i].LiveNodes = p.LiveNodes
		fresh.PluginStats[i].HostingCount = p.HostingCount
		fresh.PluginStats[i].ProxyCount = p.ProxyCount
		fresh.PluginStats[i].CleanCount = p.CleanCount
		fresh.PluginStats[i].ClassifiedCount = p.ClassifiedCount
		fresh.PluginStats[i].UnlockCount = p.UnlockCount
		fresh.PluginStats[i].UniqueYield = p.UniqueYield
		if len(p.TopOverlaps) > 0 {
			fresh.PluginStats[i].TopOverlaps = append([]plugins.OverlapPair(nil), p.TopOverlaps...)
		}
	}
}

// checkMaxDuplicatePercent checks if any plugin's duplicate percentage exceeds
// the configured MaxDuplicatePercent threshold and disables them via the registry.
func checkMaxDuplicatePercent(
	out io.Writer,
	reg *plugins.Registry,
	cfg *config.Config,
	statsCollector *plugins.PluginStatsCollector,
) {
	if reg == nil || cfg == nil || cfg.Plugins.MaxDuplicatePercent == nil {
		return
	}
	maxDupPct := *cfg.Plugins.MaxDuplicatePercent
	for _, st := range statsCollector.GetStats() {
		if st.TotalNodes == 0 {
			continue
		}
		dupPct := float64(st.DuplicateCount) * 100.0 / float64(st.TotalNodes)
		if dupPct <= maxDupPct {
			continue
		}
		if reg.RecordFailure(st.PluginID, 1) {
			outf(out, "plugin %-10s DISABLED: duplicate%% %.1f > threshold %.1f (total=%d, duplicates=%d)\n",
				st.PluginID, dupPct, maxDupPct, st.TotalNodes, st.DuplicateCount)
		}
	}
}

// pluginLinks carries one plugin's raw-link output plus its per-source
// grouping (Node.Source override or the plugin id).
type pluginLinks struct {
	plugin string
	nodes  []plugins.Node
}

// pluginRunTimeout resolves [plugins].run_timeout: the knob's explicit "0s"
// means UNBOUNDED (owner ruling — no artificial floor); nil (unset, after
// config.Load defaults) means DefaultPluginRunTimeout. This helper only
// guards direct struct construction (tests): a nil pointer there reads as
// the default, mirroring activateTestTimeout.
func pluginRunTimeout(cfg *config.Config) time.Duration {
	if cfg.Plugins.RunTimeout == nil {
		return config.DefaultPluginRunTimeout
	}
	return cfg.Plugins.RunTimeout.Duration
}

// pluginMaxFailures resolves [plugins].max_consecutive_failures for the
// circuit breaker: the knob's explicit 0 means UNLIMITED (breaker off —
// owner ruling, same no-floor class as run_timeout "0s"); nil (unset,
// after config.Load defaults) means DefaultMaxConsecutiveFailures. This
// helper only guards direct struct construction (tests).
func pluginMaxFailures(cfg *config.Config) int {
	if cfg.Plugins.MaxConsecutiveFailures == nil {
		return config.DefaultMaxConsecutiveFailures
	}
	return *cfg.Plugins.MaxConsecutiveFailures
}

// runAllPlugins executes every snapshot plugin, grouping the returned nodes
// by their effective source id. Per-plugin failures are LOUD and non-fatal —
// one bad provider must not kill the wave.
//
// Each run is bounded by runTimeout (> 0): the fetch executes in a goroutine
// and the wave selects on the run's completion vs the timer. HONEST
// TRADE-OFF, by design: gopher-lua v1.1.2 has no hook/budget API, so a
// spinning plugin (`while true do end`) cannot be interrupted — on timeout
// the wave ABANDONS it: the goroutine keeps running (hot Lua loop) and its
// LState leaks, one per wave, for as long as the plugin keeps hanging. The
// wave itself ALWAYS proceeds — that is the contract this function pins.
// Plugins are pure fetch (no temp side effects), so abandonment loses
// nothing but the nodes. The leak is the detection-first mitigation; the
// honest backstop for the hang class itself is the daemon's systemd
// watchdog (public_vpn-watch.service: Type=notify + WatchdogSec) and the
// operator removing the offending .lua. runTimeout <= 0 = unbounded (owner
// ruling: an explicit "0s" is legitimate).
//
// Circuit breaker (round-7 item 6): every FAILURE event (a run-timeout
// abandonment or a loud run error) feeds the registry's consecutive-failure
// counter; a SUCCESS resets it. On hitting maxFailures (> 0) the plugin is
// AUTO-DISABLED — loud line here, excluded from subsequent wave snapshots,
// listed in the wave's breaker summary. maxFailures <= 0 = unlimited: the
// breaker never fires. The state lives in the registry (see Registry docs):
// per-wave in one-shot runs, persistent across waves in the watch daemon.
//
// Plugin stats collection: if statsCollector is non-nil, it accumulates
// per-plugin node counts and duplicate detection during the fetch wave.
func runAllPlugins(
	out io.Writer, engine *plugins.Engine, snapshot []*plugins.Plugin, runTimeout time.Duration,
	maxFailures int, reg *plugins.Registry, statsCollector *plugins.PluginStatsCollector,
) ([]pluginLinks, int, int, int) {
	collected := []pluginLinks{}
	failed, hinted, total := 0, 0, 0
	for _, pl := range snapshot {
		nodes, err := runOnePlugin(engine, pl, runTimeout)
		if err != nil {
			failed++
			if errors.Is(err, errPluginAbandoned) {
				// Loud, plugin-attributed, bound-naming abandonment — the
				// detection signal for the operator to fix or remove the
				// file.
				outf(out, "plugin %-10s exceeded %s — abandoned\n", pl.ID, runTimeout)
			} else {
				outf(out, "plugin %-10s FAILED: %v\n", pl.ID, err)
			}
			// Breaker bookkeeping: this failure is one MORE consecutive
			// event; tripping the limit disables the plugin loud.
			if reg != nil && reg.RecordFailure(pl.ID, maxFailures) {
				outf(out, "plugin %-10s DISABLED after %d consecutive failures "+
					"(breaker limit %d) — excluded from future waves; edit the file to re-enable\n",
					pl.ID, maxFailures, maxFailures)
			}
			continue
		}
		if reg != nil {
			reg.RecordSuccess(pl.ID) // a healthy run resets the counter
		}
		for _, n := range nodes {
			if n.Scheme != "" || n.Host != "" || n.Port != 0 {
				hinted++
			}
		}
		collected = append(collected, pluginLinks{plugin: pl.ID, nodes: nodes})
		total += len(nodes)
		outf(out, "plugin %-10s ok: %d nodes\n", pl.ID, len(nodes))

		// Collect plugin stats if collector provided
		if statsCollector != nil {
			statsCollector.AddPluginNodes(pl.ID, nodes)
		}
	}
	if reg != nil {
		if disabled := reg.DisabledPlugins(); len(disabled) > 0 {
			// The breaker status surface: every wave names the plugins the
			// breaker currently keeps offline (one-shot runs list them too —
			// they were disabled by earlier waves in the daemon, or by THIS
			// wave).
			outf(out, "breaker: %d plugin(s) disabled — %s (a file edit reloads and re-enables)\n",
				len(disabled), strings.Join(disabled, ", "))
		}
	}
	return collected, failed, hinted, total
}

// errPluginAbandoned marks a run that hit the [plugins].run_timeout bound
// (internal sentinel; the abandonment line is the user-facing surface).
var errPluginAbandoned = errors.New("plugin run exceeded the timeout and was abandoned")

// runOnePlugin bounds one plugin run. runTimeout <= 0 runs unbounded in the
// caller's goroutine (explicit "0s" — the honest no-deadline mode).
// When runTimeout > 0, execution is bound to a context with timeout and passed
// to engine.Run. If the run exceeds the timeout, ctx cancellation terminates
// the underlying Lua VM (via LState.SetContext) and unblocks engine.Run,
// preventing goroutine and memory leaks.
func runOnePlugin(engine *plugins.Engine, pl *plugins.Plugin, runTimeout time.Duration) ([]plugins.Node, error) {
	if runTimeout <= 0 {
		return engine.Run(context.Background(), pl)
	}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	type runResult struct {
		nodes []plugins.Node
		err   error
	}
	done := make(chan runResult, 1)
	go func() {
		nodes, err := engine.Run(ctx, pl)
		done <- runResult{nodes: nodes, err: err}
	}()
	select {
	case r := <-done:
		return r.nodes, r.err
	case <-ctx.Done():
		return nil, errPluginAbandoned
	}
}

// writePluginArtifacts materializes the collected raw links as one cache
// file per (source id, plugin) and records them in the fetch manifest — the
// unchanged contract the parse stage reads.
func writePluginArtifacts(cacheDir string, collected []pluginLinks) (fetchManifest, int, error) {
	manifest := fetchManifest{FetchedAt: time.Now().UTC(), Sources: map[string][]fetch.FetchedFile{}}
	files := 0
	for _, cl := range collected {
		groups := map[string]*strings.Builder{}
		for _, n := range cl.nodes {
			source := n.Source
			if source == "" {
				source = cl.plugin
			}
			if groups[source] == nil {
				groups[source] = &strings.Builder{}
			}
			_, _ = groups[source].WriteString(n.Raw)
			_, _ = groups[source].WriteString("\n")
		}
		sources := make([]string, 0, len(groups))
		for source := range groups {
			sources = append(sources, source)
		}
		sort.Strings(sources)
		for _, source := range sources {
			body := []byte(groups[source].String())
			sum := sha256.Sum256(body)
			dir := filepath.Join(cacheDir, source)
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return manifest, files, err
			}
			// 0600: the link lists carry node credentials, like every other
			// pipeline artifact on disk.
			if err := os.WriteFile(filepath.Join(dir, cl.plugin+".txt"), body, 0o600); err != nil {
				return manifest, files, err
			}
			manifest.Sources[source] = append(manifest.Sources[source], fetch.FetchedFile{
				Source: source, Path: cl.plugin + ".txt",
				URL: "plugin://" + cl.plugin, Body: body,
				Sha256:    hex.EncodeToString(sum[:]),
				FetchedAt: manifest.FetchedAt,
			})
			files++
		}
	}
	return manifest, files, nil
}

func newParseCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "parse",
		Short: "Parse cached source bodies into normalized node records",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			return runParse(cmd, res.Config)
		},
	}
}

func runParse(cmd *cobra.Command, cfg *config.Config) error {
	p := newPaths(cfg)
	b, err := os.ReadFile(p.manifest)
	if err != nil {
		return fmt.Errorf("no fetch manifest (%s) — run `publicvpn fetch` first", p.manifest)
	}
	var manifest fetchManifest
	//nolint:musttag // fetchManifest has JSON tags; musttag false positive
	if err := json.Unmarshal(b, &manifest); err != nil {
		return fmt.Errorf("decode fetch manifest: %w", err)
	}

	var all []*model.Node
	totalRejected, totalMalformed := 0, 0
	kindCounts := map[string]int{}
	// Stable source order: manifest.Sources is a Go map, and its iteration
	// order is randomized. The node file order feeds dedup/cap/tag decisions
	// downstream, so identical inputs must always parse identically (M-b).
	sourceIDs := make([]string, 0, len(manifest.Sources))
	for id := range manifest.Sources {
		sourceIDs = append(sourceIDs, id)
	}
	sort.Strings(sourceIDs)
	for _, id := range sourceIDs {
		files := manifest.Sources[id]
		res := &parse.Result{RejectedKinds: map[string]int{}}
		for _, f := range files {
			body, err := os.ReadFile(filepath.Join(p.cacheDir, id, fetch.SafePath(f.Path)))
			if err != nil {
				return fmt.Errorf("read cached file %s: %w", f.Path, err)
			}
			r := parse.Lines(id, string(body))
			res.Nodes = append(res.Nodes, r.Nodes...)
			res.Rejected += r.Rejected
			res.Malformed += r.Malformed
			for k, v := range r.RejectedKinds {
				res.RejectedKinds[k] += v
			}
		}
		totalRejected += res.Rejected
		totalMalformed += res.Malformed
		for k, v := range res.RejectedKinds {
			kindCounts[k] += v
		}
		outf(cmd.OutOrStdout(), "source %-10s parsed: %d nodes, %d rejected, %d malformed\n",
			id, len(res.Nodes), res.Rejected, res.Malformed)
		all = append(all, res.Nodes...)
	}
	if err := store.WriteNodes(p.nodes, all); err != nil {
		return err
	}
	outf(cmd.OutOrStdout(), "parse complete: %d nodes, %d rejected (%v), %d malformed → %s\n",
		len(all), totalRejected, kindCounts, totalMalformed, p.nodes)
	return nil
}

func newFilterCommand(cfgPath *string) *cobra.Command {
	var sourceCap int
	cmd := &cobra.Command{
		Use:   "filter",
		Short: "Apply the ingest security filter (reality|tls, no insecure, no private hosts, dedupe)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			return runFilter(cmd, res.Config, sourceCap)
		},
	}
	cmd.Flags().IntVar(&sourceCap, "source-cap", 0,
		"per-source cap override (0 = fall back to [filter].source_cap; both 0 = unlimited)")
	return cmd
}

func runFilter(cmd *cobra.Command, cfg *config.Config, sourceCapFlag int) error {
	p := newPaths(cfg)
	nodes, err := store.ReadNodes(p.nodes)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return fmt.Errorf("no parsed nodes (%s) — run `publicvpn parse` first", p.nodes)
	}
	// Precedence: an explicit --source-cap flag overrides [filter].source_cap;
	// 0 on both means unlimited.
	sourceCap := sourceCapFlag
	if sourceCap == 0 {
		sourceCap = cfg.Filter.SourceCap
	}
	opts := []filter.Option{
		filter.WithProtocols(cfg.Filter.Protocols),
		filter.WithAllowInsecure(cfg.Filter.AllowInsecure),
	}
	if sourceCap > 0 {
		opts = append(opts, filter.WithSourceCap(sourceCap))
	}
	kept, dropped := filter.Run(nodes, opts...)
	if err := store.WriteNodes(p.filtered, kept); err != nil {
		return err
	}
	reasons := map[string]int{}
	for _, d := range dropped {
		reasons[classifyDrop(d.Reason)]++
	}
	outf(cmd.OutOrStdout(), "filter complete: %d kept, %d dropped %v → %s\n", len(kept), len(dropped), reasons, p.filtered)
	return nil
}

func classifyDrop(reason string) string {
	switch {
	case strings.Contains(reason, "insecure"):
		return "insecure"
	case strings.Contains(reason, "allowlist"):
		return "scheme-not-allowed"
	case strings.Contains(reason, "private/loopback"):
		return "private"
	case strings.Contains(reason, "duplicate"):
		return "duplicate"
	case strings.Contains(reason, "cap"):
		return "source-cap"
	case strings.Contains(reason, "reality/tls"):
		return "no-tls-security"
	default:
		return "invalid"
	}
}

func newProbeCommand(cfgPath *string) *cobra.Command {
	var (
		limit     int
		speedtest bool
	)
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Out-of-band probe: a temp single-node xray per node — liveness, latency, exit IP (D8), optional speed",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			return runProbe(cmd, res.Config, limit, speedtest)
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "probe only the first N filtered nodes (0 = all)")
	cmd.Flags().BoolVar(&speedtest, "speedtest", false,
		"run the throughput measurement even when the config disables it (slow)")
	return cmd
}

// probeOptions translates config + CLI flags into one probe wave's options.
// The prober binary and its database are GONE (W14): every node gets a
// temporary single-node xray from the SAME factory the check/geo stages
// use, so there is no per-stage tooling left to configure. ExitProbe stays
// nil: the D8 exit-IP echo defaults ON in production (nil = on — every
// alive record carries its tunnel exit IP).
func probeOptions(cfg *config.Config, speedtestFlag bool) probe.Options {
	return probe.Options{
		Timeout:          cfg.Probe.Timeout.Duration,
		Threads:          cfg.Probe.Threads,
		BatchSize:        cfg.Probe.BatchSize,
		BatchConcurrency: cfg.Probe.BatchConcurrency,
		URL:              cfg.Probe.URL,
		Attempts:         cfg.Probe.Attempts,
		Speedtest:        speedtestFlag || cfg.Probe.IsSpeedtest(),
		SpeedtestURL:     cfg.Probe.SpeedtestURL,
		SpeedtestTimeout: cfg.Probe.SpeedtestTimeout.Duration,
		SkipFreshWithin:  cfg.Probe.SkipFreshWithin.Duration,
		// Wave-1 TCP pre-filter (owner-approved probe-optimization program):
		// the config knob carries the materialized tri-state (absent = ON).
		TCPPrefilter:        cfg.Probe.TCPPrefilter,
		TCPPrefilterWorkers: cfg.Probe.TCPPrefilterWorkers,
		TCPPrefilterTimeout: cfg.Probe.TCPPrefilterTimeout.Duration,
	}
}

func newProbeBatchFactory(cfg *config.Config, p paths) probe.BatchFactory {
	return probe.BatchFactory(func(ctx context.Context, nodes []*model.Node) (probe.BatchSocksInstance, error) {
		outbounds := make([]map[string]any, len(nodes))
		for i, n := range nodes {
			rcfg := render.Config{
				TCPMaxSeg:      cfg.Render.TCPMaxSeg,
				TLSFingerprint: cfg.Render.TLSFingerprint,
			}
			if rcfg.TCPMaxSeg == 0 {
				rcfg.TCPMaxSeg = config.DefaultTCPMaxSeg
			}
			if rcfg.TLSFingerprint == "" {
				rcfg.TLSFingerprint = config.DefaultTLSFingerprint
			}
			ob, _, err := render.BuildOutbound(n, fmt.Sprintf("probe-out-%d", i), rcfg)
			if err != nil {
				return nil, fmt.Errorf("render outbound for batch node %d: %w", i, err)
			}
			outbounds[i] = ob
		}
		return checker.StartTempXrayBatch(ctx, config.ExpandHome(cfg.Activate.XrayBin), p.workDir, outbounds)
	})
}

func loadKnownAliveForProbe(p paths, opts probe.Options) (map[string]store.KnownAliveRecord, probe.Options, error) {
	ka, err := store.ReadKnownAlive(p.knownAlive)
	if err != nil {
		return nil, opts, err
	}
	opts.KnownAlive = ka
	if opts.KnownAliveTTL <= 0 {
		opts.KnownAliveTTL = 2 * time.Hour
	}
	if opts.SkipFreshWithin > 0 {
		latest, err := store.LatestProbeByKey(p.probeResults)
		if err != nil {
			return nil, opts, err
		}
		opts.Latest = latest
	}
	return ka, opts, nil
}

// classifierFor wires the merged classification pass: nil when the
// [geo].unlock_probes escape hatch is explicitly false (a probe-only wave —
// zero classification requests), a fresh wave Classifier otherwise. The
// seam keeps the knob decision unit-testable without running a wave.
func classifierFor(cfg *config.Config, p paths, progress io.Writer) *geo.Classifier {
	if !cfg.Geo.UnlockProbesEnabled() {
		return nil
	}
	return geo.NewClassifier(geo.ClassifyInput{
		DataDir:   p.dataDir,
		Cfg:       cfg.Geo,
		UserAgent: cfg.HTTP.UserAgent,
		Progress:  progress,
	})
}

// flushClassifier merges the wave's classification outcomes into geo-base
// after probe.Run persisted the wave's outcomes: the same merge-and-upsert
// contract the old separate geo stage had (probe outcomes on every probed
// record, classification where it ran), minus the freshness gates. Failures
// are loud but never fail the wave (the probe outcomes stand).
func flushClassifier(clf *geo.Classifier, cmd *cobra.Command, p paths, nodes []*model.Node, started time.Time) {
	probeByKey, err := store.LatestProbeByKey(p.probeResults)
	if err != nil {
		outf(cmd.OutOrStdout(), "ERROR: classification flush skipped — probe store read failed: %v\n", err)
		return
	}
	wave := uint64(0)
	if ws, werr := store.ReadWaveState(p.waveState); werr == nil {
		wave = ws.CurrentWaveSeq
	}
	if _, _, ferr := clf.Flush(cmd.OutOrStdout(), nodes, probeByKey, wave, started); ferr != nil {
		outf(cmd.OutOrStdout(), "ERROR: classification flush failed: %v\n", ferr)
	}
}

//nolint:cyclop,gocognit // runProbe orchestrates the whole probe stage (probe + merged classification)
func runProbe(cmd *cobra.Command, cfg *config.Config, limit int, speedtest bool) error {
	classifyStart := time.Now()
	p := newPaths(cfg)
	// Probe work lives on tmpfs and is ephemeral: clean it up after the wave.
	defer func() { _ = os.RemoveAll(p.workDir) }()
	// Increment the global wave sequence (run-count liveness).
	_, _ = store.IncrementWaveState(p.waveState)
	// Apply calibrated timeout from previous wave, if enabled.
	if cfg.Probe.CalibrationEnabled {
		if st, err := timeoutcal.Load(p.dataDir); err == nil {
			if v := st.Probe.TimeoutFor("global"); v > 0 {
				cfg.Probe.Timeout.Duration = v
			}
		}
	}
	nodes, err := store.ReadNodes(p.filtered)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return fmt.Errorf("no filtered nodes (%s) — run `publicvpn filter` first", p.filtered)
	}
	if limit > 0 && limit < len(nodes) {
		nodes = nodes[:limit]
	}
	if err := os.MkdirAll(p.workDir, 0o750); err != nil {
		return err
	}
	// The SAME temp-instance infrastructure the check/geo stages use — one
	// factory, one render.BuildOutbound outbound builder, zero drift (W14).
	xrayFactory := checker.NewXrayFactory(config.ExpandHome(cfg.Activate.XrayBin), p.workDir, render.Config{
		TCPMaxSeg:      cfg.Render.TCPMaxSeg,
		TLSFingerprint: cfg.Render.TLSFingerprint,
	})
	factory := probe.Factory(func(ctx context.Context, n *model.Node) (probe.SocksInstance, error) {
		return xrayFactory(ctx, n)
	})
	batchFactory := newProbeBatchFactory(cfg, p)
	opts := probeOptions(cfg, speedtest)
	// Apply the wave-start resource budget (CPU/RAM/ports) to probe
	// concurrency (threads + batch concurrency) — the scarcest resource wins.
	portBudget := cfg.Probe.Threads
	if portBudget < 1 {
		portBudget = cfg.Resources.EffectiveCPUCores()
	}
	budget := ComputeConcurrencyBudget(cfg, portBudget)
	if budget > 0 {
		if opts.Threads <= 0 || budget < opts.Threads {
			opts.Threads = budget
		}
		if opts.BatchConcurrency <= 0 || budget < opts.BatchConcurrency {
			opts.BatchConcurrency = budget
		}
	}
	opts.Progress = cmd.OutOrStdout()
	// Wire AdaptConcurrency: in-wave adaptation goroutine ticks every 5s,
	// sampling memory/CPU/port pressure and adjusting the worker count.
	adaptCtx, cancelAdapt := context.WithCancel(context.Background())
	defer cancelAdapt()
	go func() {
		runAdapt := func(current int) int {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			maxRAM := uint64(512 * 1024 * 1024)
			memUsedPct := 0.0
			if maxRAM > 0 {
				memUsedPct = float64(ms.HeapAlloc) / float64(maxRAM) * 100.0
			}
			cpuIdle := runtime.NumGoroutine() < 1000
			portExhausted := false
			return adaptConcurrencyFunc(current, memUsedPct, cpuIdle, portExhausted)
		}
		current := max(opts.Threads, 1)
		// immediate tick
		if next := runAdapt(current); next != current {
			outf(cmd.OutOrStdout(), "probe concurrency adapted: %d -> %d\n", current, next)
			current = next
		}
		ticker := time.NewTicker(adaptTickerInterval)
		defer ticker.Stop()
		for {
			select {
			case <-adaptCtx.Done():
				return
			case <-ticker.C:
				if next := runAdapt(current); next != current {
					outf(cmd.OutOrStdout(), "probe concurrency adapted: %d -> %d\n", current, next)
					current = next
				}
			}
		}
	}()
	ka, opts, err := loadKnownAliveForProbe(p, opts)
	if err != nil {
		return err
	}
	// The merged classification pass (owner order 2026-11-07 «сразу на чеке»):
	// every alive node gets the FULL battery — ip-api self-report ladder +
	// unlock battery v2 — through the SAME hot xray instance the probe just
	// passed, before that instance is torn down. [geo].unlock_probes is the
	// explicit-off escape hatch: false = probe-only wave (no classification).
	if clf := classifierFor(cfg, p, cmd.OutOrStdout()); clf != nil {
		opts.Classifier = clf.ClassifyNode
		defer flushClassifier(clf, cmd, p, nodes, classifyStart)
	}
	results, err := probe.RunWithBatchFactory(context.Background(), nodes, factory, batchFactory, opts, p.probeResults)
	if err != nil {
		return err
	}
	alive := 0
	for _, r := range results {
		if r.Alive {
			alive++
		}
	}
	if cfg.Probe.CalibrationEnabled {
		agg := probe.Aggregate(results)
		tc := timeoutcal.Config{
			Margin:               cfg.Probe.CalibrationMargin,
			Alpha:                0.3,
			MinSamples:           50,
			HighTimeoutRate:      0.15,
			HistorySize:          20,
			MinHistory:           3,
			MaxHistory:           50,
			StabilityCVThreshold: 0.10,
			MinChange:            0.5,
		}
		_ = timeoutcal.UpdateWithConfig(p.dataDir, "probe", timeoutcal.Observation{
			Key:      "global",
			Stage:    "probe",
			Total:    len(results),
			TimedOut: agg.TimedOutCount,
			RTTsMs:   agg.ObservedRTTMs,
			At:       time.Now().UTC(),
		}, tc)
	}
	// (entries absent from the current source list) with TTL decay + log.
	now := time.Now().UTC()
	nodeKeys := map[string]bool{}
	for _, n := range nodes {
		nodeKeys[n.Key] = true
	}
	if err := updateKnownAliveSet(cmd, opts, ka, nodeKeys, results, now); err != nil {
		return err
	}
	if err := store.WriteKnownAlive(p.knownAlive, ka); err != nil {
		return err
	}
	outf(cmd.OutOrStdout(), "probe complete: %d/%d alive → %s\n", alive, len(results), p.probeResults)
	return nil
}

// updateKnownAliveSet merges probe results into the known-alive set, logs
// orphaned entries, prunes expired ones, and persists the set.
func updateKnownAliveSet(
	cmd *cobra.Command,
	opts probe.Options,
	ka map[string]store.KnownAliveRecord,
	nodeKeys map[string]bool,
	results []store.ProbeResult,
	now time.Time,
) error {
	for _, r := range results {
		if !r.Alive {
			continue
		}
		rec := ka[r.Key]
		if rec.Key == "" {
			rec.Key = r.Key
		}
		rec.Host = r.Host
		rec.LastSeen = r.CheckedAt
		if rec.LastSeen.IsZero() {
			rec.LastSeen = now
		}
		rec.LastStatus = r.Status
		if rec.LastStatus == "" {
			rec.LastStatus = "passed"
		}
		rec.AliveStreak++
		rec.AliveWaveSeq++
		ka[r.Key] = rec
	}
	for k, rec := range ka {
		if nodeKeys[k] {
			continue
		}
		remaining := opts.KnownAliveTTL - now.Sub(rec.LastSeen)
		remaining = max(remaining, 0)
		outf(cmd.OutOrStdout(), "known-alive but absent from sources — retained (TTL %s remaining): %s\n",
			remaining.Round(time.Second), k)
	}
	store.PruneKnownAlive(ka, now, opts.KnownAliveTTL)
	return nil
}

func newSelectCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "select",
		Short: "Rank alive nodes (alive → checks → speed), apply caps D7, assign pool tags",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			return runSelect(cmd, res.Config)
		},
	}
}

func runSelect(cmd *cobra.Command, cfg *config.Config) error {
	p := newPaths(cfg)
	nodes, err := store.ReadNodes(p.filtered)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return fmt.Errorf("no filtered nodes (%s) — run `publicvpn filter` first", p.filtered)
	}
	geoRecs, err := store.ReadGeo(p.geoBase)
	if err != nil {
		return err
	}
	if len(geoRecs) == 0 {
		return fmt.Errorf("geo base empty (%s) — run `publicvpn geo` first", p.geoBase)
	}
	probeByKey, err := store.LatestProbeByKey(p.probeResults)
	if err != nil {
		return err
	}
	ka, err := store.ReadKnownAlive(p.knownAlive)
	if err != nil {
		outf(cmd.OutOrStdout(), "WARNING: failed to read known-alive set (%s): %v\n", p.knownAlive, err)
		// If file exists and failed to decode, preserve a copy for diagnostics
		if !os.IsNotExist(err) {
			corruptPath := fmt.Sprintf("%s.corrupt.%d", p.knownAlive, time.Now().Unix())
			if cpErr := os.Rename(p.knownAlive, corruptPath); cpErr == nil {
				outf(cmd.OutOrStdout(), "backed up corrupt known-alive file to %s\n", corruptPath)
			}
		}
		ka = map[string]store.KnownAliveRecord{}
	}
	sel := rank.Select(nodes, geoRecs, probeByKey, cfg.Select, cfg.Geo.TTL.Duration, ka)
	if err := store.WriteSelection(p.selection, sel); err != nil {
		return err
	}
	// Display label: unknown-geo nodes carry a raw empty country — shown as
	// the pool_unknown pseudo-location they render under (W16).
	byCountry := map[string]int{}
	for _, n := range sel.Nodes {
		label := n.Country
		if label == "" {
			label = "unknown"
		}
		byCountry[label]++
	}
	outf(cmd.OutOrStdout(), "select complete: %d active nodes (cap %d, %d alive cities), countries: %v → %s\n",
		len(sel.Nodes), sel.CapApplied, sel.CitiesAlive, byCountry, p.selection)
	// TLS-intercept exclusions are loud (owner-ordered safety cut): the
	// counted drop is reported at the select stage every wave it fires.
	if sel.HijackExcluded > 0 {
		outf(cmd.OutOrStdout(),
			"select: %d candidate(s) excluded — TLS-intercepting exit "+
				"(hijack=true on own geo evidence): not rendered, not active\n",
			sel.HijackExcluded)
	}
	return nil
}

func newRenderCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "render",
		Short: "Render the full xray client config (template + pool + balancers + Plan A observatory)",
		Long: `Renders the full client config from the configured template (render.template)
plus the selected pool. The template is a REQUIRED configured value: a
configless run (no -c, no home/cwd config) fails loud at this boundary —
"configless mode cannot render — provide -c or a config at
~/.config/publicvpn/config.toml" — instead of silently defaulting the
template to the live client's config.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			return runRender(cmd, res.Config)
		},
	}
}

func runRender(cmd *cobra.Command, cfg *config.Config) error {
	// Loud stage boundary (W12): render needs a CONFIGURED template. A
	// configless run leaves render.template deliberately empty (the old
	// default pointed at the live client's config — silently rendering
	// against it from pure defaults is exactly the accident this refuses).
	if cfg.Render.Template == "" {
		return config.ConfiglessBoundaryError("render")
	}
	p := newPaths(cfg)
	sel, err := store.ReadSelection(p.selection)
	if err != nil {
		return err
	}
	if sel == nil {
		return fmt.Errorf("no selection (%s) — run `publicvpn select` first", p.selection)
	}
	filtered, err := store.ReadNodes(p.filtered)
	if err != nil {
		return err
	}
	byKey := map[string]*model.Node{}
	for _, n := range filtered {
		byKey[n.Key] = n
	}
	templatePath := config.ExpandHome(cfg.Render.Template)
	template, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("read template %s: %w", templatePath, err)
	}
	// Phase-3 service pools ride the Phase-1 unlock evidence: one geo read,
	// keyed by the shared identity — the same join the stats enrichment uses
	// (model.GeoIdentity). A missing geo base is the documented empty state
	// (unlock pools render absent, pool_clean falls back to flags-only); a
	// corrupt one fails the render loud.
	geoRecords, err := store.ReadGeo(p.geoBase)
	if err != nil {
		return fmt.Errorf("read geo records for render: %w", err)
	}
	geoByKey := make(map[string]*model.GeoRecord, len(geoRecords))
	for _, gr := range geoRecords {
		geoByKey[model.GeoIdentity(gr)] = gr
	}
	res, err := render.Render(render.Input{
		Template:   template,
		Selection:  sel,
		NodesByKey: byKey,
		GeoByKey:   geoByKey,
		Cfg: render.Config{
			StatsPort:           cfg.Render.StatsPort,
			PoolRoutes:          toRenderRoutes(cfg.Render.PoolRoutes),
			PoolInboundTags:     cfg.Render.PoolInboundTags,
			ObservatoryInterval: cfg.Render.ObservatoryInterval,
			TCPMaxSeg:           cfg.Render.TCPMaxSeg,
			TLSFingerprint:      cfg.Render.TLSFingerprint,
			BalancerTolerance:   cfg.Render.BalancerTolerance,
		},
	})
	if err != nil {
		return err
	}
	if len(sel.Nodes) == 0 {
		outf(cmd.OutOrStdout(), "WARNING: empty pool — no pool observatory/balancers rendered (L1 hard gate)\n")
	}
	for _, w := range res.DroppedParams {
		outf(cmd.OutOrStdout(), "WARNING: %s (%s): link params not renderable, left out of the outbound: %v\n",
			w.Tag, w.Host, w.Params)
	}
	for _, b := range res.BlockedRoutes {
		outf(cmd.OutOrStdout(), "WARNING: %s\n", b)
	}
	if err := os.MkdirAll(p.renderedDir, 0o750); err != nil {
		return err
	}
	// 0600 deliberate: the rendered config carries pool node credentials
	// (UUIDs/passwords). The live target keeps ITS OWN mode — atomicReplace
	// preserves it (review finding 11). Atomic+synced write: a crash during
	// write must never leave a truncated rendered config.
	if err := store.WriteFileAtomic(p.rendered, func(f *os.File) error {
		_, err := f.Write(res.Config)
		return err
	}); err != nil {
		return err
	}
	outf(cmd.OutOrStdout(), "render complete: %d pool outbounds → %s\n", len(sel.Nodes), p.rendered)
	return nil
}

func toRenderRoutes(rs []config.PoolRoute) []render.PoolRoute {
	out := make([]render.PoolRoute, len(rs))
	for i, r := range rs {
		out[i] = render.PoolRoute{Balancer: r.Balancer, Domains: r.Domains}
	}
	return out
}

func newActivateCommand(cfgPath *string) *cobra.Command {
	var (
		target string
		backup bool
	)
	cmd := &cobra.Command{
		Use:   "activate",
		Short: "-test gate, date-stamped backup, atomic replace, then the gated auto-restart",
		Long: `Runs the -test gate, takes a date-stamped backup, and atomically replaces
the configured live target (activate.target). The target is a REQUIRED
configured value: a configless run fails loud at this boundary —
"configless mode cannot activate — provide -c or a config at
~/.config/publicvpn/config.toml" — instead of silently defaulting the target
to the live client's config.

After a real replacement the live client is restarted through the
byte-pinned allowlist executor (internal/restart) when
[maintain].auto_restart is enabled (the default — hands-off, W13); with
auto_restart = false the manual restart command is printed instead. A
byte-identical render is a no-op: nothing is replaced, nothing restarts.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			color, err := commandColor(cmd, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			reportConfigSourceStyled(cmd.OutOrStdout(), res, color)
			return runActivate(cmd, res.Config, target, backup, productionRestartWiring())
		},
	}
	attachColorFlags(cmd)
	cmd.Flags().StringVar(&target, "target", "", "override the activation target path (default from config)")
	cmd.Flags().BoolVar(&backup, "backup", true, "date-stamped backup of the target before replace")
	return cmd
}

// restartWiring bundles the W13 auto-restart seam: the byte-pinned allowlist
// executor (package restart — the daemon's only systemd surface besides
// install) and the health check's port-probe dialer. Sleep carries the W17
// health ladder's clock (tests inject a no-op; production leaves nil for the
// real time.Sleep). The maintainStages seam injects fakes in tests;
// production is SystemctlExecutor + the real dialer.
type restartWiring struct {
	Executor restart.Executor
	Dialer   restart.Dialer
	Sleep    func(time.Duration)
}

// productionRestartWiring wires the real allowlist executor (the restart
// package's production type); the dialer is left nil (the restart package's
// default net dialer).
func productionRestartWiring() *restartWiring {
	return &restartWiring{Executor: restart.SystemctlExecutor{}}
}

func runActivate(cmd *cobra.Command, cfg *config.Config, target string, backup bool, wiring *restartWiring) error {
	p := newPaths(cfg)
	// Loud stage boundary (W12): activate needs a CONFIGURED target, and the
	// boundary fires AT STAGE ENTRY on the configured value alone — the
	// --target flag cannot bypass it (I-1). A configless run has no
	// configured template either, so there is nothing legitimate to activate
	// against; keying on the flag let a configless --target run fall into the
	// misleading "no rendered config — run render first" loop, while
	// configless render refuses with the same boundary.
	if cfg.Activate.Target == "" {
		return config.ConfiglessBoundaryError("activate")
	}
	if target == "" {
		target = config.ExpandHome(cfg.Activate.Target)
	}
	if _, err := os.Stat(p.rendered); err != nil {
		return fmt.Errorf("no rendered config (%s) — run `publicvpn render` first", p.rendered)
	}
	res, err := activate.Run(activate.Input{
		RenderedPath: p.rendered,
		TargetPath:   target,
		XrayBin:      cfg.Activate.XrayBin,
		AssetDir:     config.ExpandHome(cfg.Activate.AssetDir),
		BackupDir:    p.backupDir,
		Backup:       backup,
		NoRestart:    true,
		TestTimeout:  activateTestTimeout(cfg),
		ServiceName:  cfg.Activate.ServiceName,
		BackupKeep:   cfg.Activate.BackupKeep,
	})
	if err != nil {
		return err
	}

	// W13 auto-restart ruling: a REAL replacement restarts the live client
	// through the byte-pinned executor, then verifies health. A nil wiring
	// with auto_restart enabled is a programming error — never a silent
	// skip.
	//
	// W17 non-interruptibility: the replace→restart→health sequence below
	// is ONE non-interruptible step. The daemon's shutdown checkpoint is
	// consulted only BETWEEN wave stages (runMaintainGraceful), never here
	// — a SIGTERM landing between the atomic replace and the xray restart
	// must not pause the stage, or the live client would be orphaned (new
	// config on disk, old config running, no restart issued). The
	// guard pin is TestW17MidActivateShutdownCannotInterruptRestart; the
	// unit's TimeoutStopSec gives systemd the matching patience to wait for
	// the step (and the stage around it) instead of SIGKILLing mid-activate.
	auto := cfg.Maintain.AutoRestartEnabled()
	if auto && wiring == nil {
		return errors.New(
			"activation: [maintain].auto_restart is enabled but no restart executor is wired (programming error)")
	}
	if !auto {
		// Manual semantics (auto_restart = false): print the operator hint.
		outf(cmd.OutOrStdout(), "%s\nbackup: %s\ndiff summary: %d pool nodes in the active set\n",
			ui.Chip("activation hint:", res.RestartHint, stageColor(cmd)),
			orNone(res.BackupPath), selectionSize(p.selection))
		return nil
	}
	outf(cmd.OutOrStdout(),
		"%s\nbackup: %s\ndiff summary: %d pool nodes in the active set\n",
		ui.Chip("activation complete:", fmt.Sprintf("%s replaced from %s", target, p.rendered), stageColor(cmd)),
		orNone(res.BackupPath), selectionSize(p.selection))
	rres, rerr := restart.Run(restart.Input{
		Executor:   wiring.Executor,
		Dialer:     wiring.Dialer,
		Sleep:      wiring.Sleep,
		SocksPort:  extractSocksPort(p.rendered),
		BackupPath: res.BackupPath,
	})
	var restartFailed *restart.Error
	switch {
	case rerr == nil:
		outf(cmd.OutOrStdout(), "%s\n",
			ui.Chip("restart:", ui.Colorize(ui.Green, rres.Verdict, stageColor(cmd)), stageColor(cmd)))
	case errors.As(rerr, &restartFailed):
		outf(cmd.OutOrStdout(),
			"ERROR: restart FAILED: %v\n"+
				"  the config on disk IS the gated new one; the live client still runs the previous config\n"+
				"%s\n",
			rerr,
			ui.Chip("  wave verdict:", ui.Colorize(ui.Amber,
				"DONE_WITH restart-failure (backup: "+orNone(res.BackupPath)+"; no auto-restore in this generation)",
				stageColor(cmd)), stageColor(cmd)))
	default:
		outf(cmd.OutOrStdout(),
			"WARNING: the restart completed but the post-restart health check FAILED: %v\n"+
				"%s\n",
			rerr,
			ui.Chip("  wave verdict:", ui.Colorize(ui.Amber,
				"DONE_WITH health-failure (report-only; no auto-restore)", stageColor(cmd)), stageColor(cmd)))
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// activateTestTimeout resolves [activate].test_timeout: the knob's explicit
// 0s means NO deadline; nil (unset) means the DefaultTestTimeout.
func activateTestTimeout(cfg *config.Config) time.Duration {
	if cfg.Activate.TestTimeout == nil {
		return config.DefaultTestTimeout
	}
	return cfg.Activate.TestTimeout.Duration
}

func selectionSize(path string) int {
	sel, err := store.ReadSelection(path)
	if err != nil || sel == nil {
		return 0
	}
	return len(sel.Nodes)
}

func newMaintainCommand(cfgPath *string) *cobra.Command {
	var opts maintainOptions
	cmd := &cobra.Command{
		Use:   "maintain",
		Short: "One refresh wave: fetch → parse → filter → probe → geo → stats → prune → select → render → activate",
		Long: `Runs the full maintenance wave (DESIGN.md §4.9): the W1–W3 pipeline stages
in order, then the W4 stats poll (outbound traffic → geo-base) and dead-node
pruning, and finally activates ONLY when the rendered config differs from the
live one and passes the -test gate (L10). An unchanged render is a clear
"no changes" no-op — the live config is never rewritten without a diff.

Configless runs (no -c, no home/cwd config) work for the data stages; the
render/activate stages fail loud at their boundary and end the wave — the
daemon keeps the schedule (see ` + "`publicvpn watch`" + `).

Flags:
  --no-activate  render and diff only; never touch the live config
  --skip-probe   reselect from the cold base without probing (geo is skipped
                 too — it consumes fresh probe exit IPs; rank's geo.ttl
                 freshness gate drops stale-alive records on its own)
  --speedtest    run the probe wave with -S throughput measurement (weekly
                 speedtest timer)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			color, err := commandColor(cmd, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			opts.color = color
			reportConfigSourceStyled(cmd.OutOrStdout(), res, color)
			return runMaintain(cmd.OutOrStdout(), res.Config, opts, defaultMaintainStages(opts))
		},
	}
	cmd.Flags().BoolVar(&opts.noActivate, "no-activate", false,
		"render and diff only; never activate even when the render differs")
	cmd.Flags().BoolVar(&opts.skipProbe, "skip-probe", false,
		"reselect from the cold base without probing (skips probe and geo)")
	cmd.Flags().BoolVar(&opts.speedtest, "speedtest", false,
		"run the probe wave with throughput measurement (weekly speedtest wave)")
	attachColorFlags(cmd)
	return cmd
}

// maintainOptions carries the maintain command's flags into the wave.
type maintainOptions struct {
	noActivate bool
	skipProbe  bool
	speedtest  bool
	// color is the resolved color mode for the wave's verdict lines (the
	// stage progress lines stay plain — journald-friendly).
	color bool
}

// maintainStages is the wave's seam: each pipeline stage as a function, so
// orchestration is testable without network/tooling. Production stages are
// the W1–W3 runners — the wave reuses them 1:1, never duplicating logic.
type maintainStages struct {
	fetch             func(*cobra.Command, *config.Config) error
	parse             func(*cobra.Command, *config.Config) error
	filter            func(*cobra.Command, *config.Config) error
	probe             func(*cobra.Command, *config.Config) error
	pluginStatsEnrich func(*cobra.Command, *config.Config) error
	stats             func(*cobra.Command, *config.Config) error
	prune             func(*cobra.Command, *config.Config) error
	selectS           func(*cobra.Command, *config.Config) error
	render            func(*cobra.Command, *config.Config) error
	activate          func(*cobra.Command, *config.Config) error
}

// defaultMaintainStages wires the real runners. filter runs with the config
// cap (no CLI override inside the wave); probe runs full-set with speedtest
// only when the wave carries it. The activate stage carries the production
// restart wiring — the W13 byte-pinned allowlist executor (package restart):
// every gated activation restarts the live client unless
// [maintain].auto_restart is disabled. The one-shot wave threads the fetch
// stage's registry into the enrichment seam (F1): threshold enforcement
// never reloads a throwaway copy.
func defaultMaintainStages(opts maintainOptions) *maintainStages {
	var waveReg *plugins.Registry
	return &maintainStages{
		fetch: func(c *cobra.Command, cc *config.Config) error {
			reg, err := runFetchWith(c, cc, nil)
			waveReg = reg
			return err
		},
		parse:  runParse,
		filter: func(c *cobra.Command, cfg *config.Config) error { return runFilter(c, cfg, 0) },
		probe:  func(c *cobra.Command, cfg *config.Config) error { return runProbe(c, cfg, 0, opts.speedtest) },
		pluginStatsEnrich: func(c *cobra.Command, cc *config.Config) error {
			return runPluginStatsEnrichment(c, cc, waveReg)
		},
		stats:   runStatsStage,
		prune:   runPruneStage,
		selectS: runSelect,
		render:  runRender,
		activate: func(c *cobra.Command, cfg *config.Config) error {
			return runActivateStage(c, cfg, productionRestartWiring())
		},
	}
}

// runMaintain executes one maintenance wave (the one-shot entry — no
// shutdown checkpoints).
func runMaintain(w io.Writer, cfg *config.Config, opts maintainOptions, stages *maintainStages) error {
	return runMaintainGraceful(w, cfg, opts, stages, nil)
}

// errWavePaused is internal: between() fired — the wave stops after the
// last COMPLETED stage (graceful shutdown; nothing is torn down, stores are
// already flushed by the completed stages).
var errWavePaused = errors.New("shutdown requested between stages")

// runMaintainGraceful executes one maintenance wave with an optional
// between-stage shutdown checkpoint: between() is checked BEFORE each stage;
// when it fires, the wave returns nil (clean pause — the caller decides what
// graceful means) after finishing the current stage. A nil between never
// fires. Stage failures still fail the wave loud, except the stats poll,
// which is accounting, not correctness (classified by reportStatsFailure).
func runMaintainGraceful(
	w io.Writer, cfg *config.Config, opts maintainOptions, stages *maintainStages, between func() bool,
) error {
	// The wave's stages print through their own writer; give them a command
	// shim bound to w so the seam stays signature-compatible with the W1–W3
	// runners. The shim carries the wave's resolved color mode so stage
	// verdict lines (activation complete / restart / wave verdict) chip the
	// same way the interactive command would.
	cmd := &cobra.Command{}
	cmd.SetOut(w)
	attachColorFlags(cmd)
	if opts.color {
		_ = cmd.Flags().Set("color", "always")
	}

	outf(w, "maintain: refresh wave starting (probe=%t, speedtest=%t, activate=%t)\n",
		!opts.skipProbe, opts.speedtest, !opts.noActivate)

	wave := &waveRunState{
		w: w, cmd: cmd, cfg: cfg, stages: stages, between: between,
	}
	run := func(name string, stage func(*cobra.Command, *config.Config) error) bool {
		return wave.runStage(name, stage)
	}
	if !run("fetch", stages.fetch) {
		return wave.pauseOrErr()
	}
	if !run("parse", stages.parse) {
		return wave.pauseOrErr()
	}
	if !run("filter", stages.filter) {
		return wave.pauseOrErr()
	}
	if !opts.skipProbe {
		if !run("probe", stages.probe) {
			return wave.pauseOrErr()
		}
	}
	return wave.runTail(opts)
}

// waveRunState carries one wave's mutable run state through the stage
// closures (writers, the current stage error, and the shutdown checkpoint).
type waveRunState struct {
	w       io.Writer
	cmd     *cobra.Command
	cfg     *config.Config
	stages  *maintainStages
	between func() bool
	waveErr error
}

// runStage checks the shutdown checkpoint, then runs one stage; a false
// result means the wave stops (waveErr carries the pause sentinel or the
// loud stage failure).
func (s *waveRunState) runStage(name string, stage func(*cobra.Command, *config.Config) error) bool {
	if s.between != nil && s.between() {
		outf(s.w, "maintain: shutdown requested — wave paused before stage %s (completed stages are flushed)\n", name)
		s.waveErr = errWavePaused
		return false
	}
	start := time.Now()
	if err := stage(s.cmd, s.cfg); err != nil {
		s.waveErr = fmt.Errorf("maintain stage %s: %w", name, err)
		return false
	}
	// Wire RecordStageStat: persist per-stage cost for inter-wave EMA.
	costMs := time.Since(start).Milliseconds()
	p := newPaths(s.cfg)
	wave := 0
	if ws, err := store.ReadWaveState(p.waveState); err == nil {
		wave = int(ws.CurrentWaveSeq) //nolint:gosec
	}
	conc := ComputeConcurrencyBudget(s.cfg, 0)
	conc = max(conc, 1)
	if err := recordStageStatFunc(p.dataDir, StageStat{
		Stage: name, CostMs: costMs, Concurrency: conc,
		Wave: wave, At: time.Now().UTC(),
	}); err != nil {
		outf(s.w, "ERROR: stage-stats write failed: %v\n", err)
	}
	return true
}

func (s *waveRunState) pauseOrErr() error {
	if errors.Is(s.waveErr, errWavePaused) {
		return nil
	}
	return s.waveErr
}

// runTail executes the accounting + selection + activation half of the wave
// (plugin-stats-enrich → stats → prune → select → render → activate-if-changed).
//
//nolint:cyclop // runTail orchestrates the tail half of the wave
func (s *waveRunState) runTail(opts maintainOptions) error {
	if s.checkpoint("plugin-stats-enrich") {
		return nil
	}
	if s.stages.pluginStatsEnrich != nil {
		psStart := time.Now()
		if err := s.stages.pluginStatsEnrich(s.cmd, s.cfg); err != nil {
			// Plugin stats enrichment is accounting, not correctness — warn but continue
			outf(s.w, "WARNING: plugin stats enrichment failed: %v (continuing)\n", err)
		}
		psCost := time.Since(psStart).Milliseconds()
		psP := newPaths(s.cfg)
		psWave := 0
		if ws, e := store.ReadWaveState(psP.waveState); e == nil {
			psWave = int(ws.CurrentWaveSeq) //nolint:gosec
		}
		psConc := ComputeConcurrencyBudget(s.cfg, 0)
		psConc = max(psConc, 1)
		if err := recordStageStatFunc(psP.dataDir, StageStat{
			Stage: "plugin-stats-enrich", CostMs: psCost,
			Concurrency: psConc, Wave: psWave, At: time.Now().UTC(),
		}); err != nil {
			outf(s.w, "ERROR: stage-stats write failed: %v\n", err)
		}
	}
	if s.checkpoint("stats") {
		return nil
	}
	statsStart := time.Now()
	if err := s.stages.stats(s.cmd, s.cfg); err != nil {
		// W7 item 9: the stats stage classifies its own failures (see
		// reportStatsFailure). Injected stages returning plain errors keep
		// the WARNING behavior.
		if fatal := reportStatsFailure(s.w, err); fatal != nil {
			return fatal
		}
	}
	statsCost := time.Since(statsStart).Milliseconds()
	statsP := newPaths(s.cfg)
	statsWave := 0
	if ws, e := store.ReadWaveState(statsP.waveState); e == nil {
		statsWave = int(ws.CurrentWaveSeq) //nolint:gosec
	}
	statsConc := max(ComputeConcurrencyBudget(s.cfg, 0), 1)
	if err := recordStageStatFunc(statsP.dataDir, StageStat{
		Stage: "stats", CostMs: statsCost, Concurrency: statsConc,
		Wave: statsWave, At: time.Now().UTC(),
	}); err != nil {
		outf(s.w, "ERROR: stage-stats write failed: %v\n", err)
	}
	if !s.runStage("prune", s.stages.prune) {
		return s.pauseOrErr()
	}
	if !s.runStage("select", s.stages.selectS) {
		return s.pauseOrErr()
	}
	// Config reconciliation (wave 1): surface configured pool_routes whose
	// target country has no live node in the (just-selected) cold base, so the
	// owner can drop stale entries (pool_us, pool_fr, pool_sg_singapore) instead
	// of discovering them as blocked routes at render time. Non-fatal: a stale
	// entry is dropped to "block" at render and the wave keeps going.
	s.reconcilePoolRoutes()
	if !s.runStage("render", s.stages.render) {
		return s.pauseOrErr()
	}
	// Inter-wave EMA: adjust base concurrency from stage stats and persist,
	// even when activation is skipped (--no-activate).
	{
		emaP := newPaths(s.cfg)
		base := 0
		if b, err := os.ReadFile(filepath.Join(emaP.dataDir, "base-concurrency.txt")); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				base = n
			}
		}
		if base < 1 {
			base = ComputeConcurrencyBudget(s.cfg, 0)
		}
		base = max(base, 1)
		allStats, _ := ReadStageStats(emaP.dataDir)
		newBase := adjustBaseConcurrencyFunc(base, allStats)
		_ = os.WriteFile(filepath.Join(emaP.dataDir, "base-concurrency.txt"), []byte(strconv.Itoa(newBase)), 0o600)
	}
	if opts.noActivate {
		outln(s.w, "maintain: --no-activate — live config not touched")
		return nil
	}
	if s.checkpoint("activate") {
		return nil
	}
	actStart := time.Now()
	if err := s.stages.activate(s.cmd, s.cfg); err != nil {
		return fmt.Errorf("maintain stage activate: %w", err)
	}
	actCost := time.Since(actStart).Milliseconds()
	actP := newPaths(s.cfg)
	actWave := 0
	if ws, e := store.ReadWaveState(actP.waveState); e == nil {
		actWave = int(ws.CurrentWaveSeq) //nolint:gosec
	}
	actConc := max(ComputeConcurrencyBudget(s.cfg, 0), 1)
	if err := recordStageStatFunc(actP.dataDir, StageStat{
		Stage: "activate", CostMs: actCost, Concurrency: actConc,
		Wave: actWave, At: time.Now().UTC(),
	}); err != nil {
		outf(s.w, "ERROR: stage-stats write failed: %v\n", err)
	}
	return nil
}

// reconcilePoolRoutes logs configured pool_routes whose target country has no
// live node in the just-selected cold base. Non-fatal: render drops such routes
// to "block" and the wave keeps going. The reconciliation is keyed on the
// selection file the select stage just wrote.
func (s *waveRunState) reconcilePoolRoutes() {
	p := newPaths(s.cfg)
	sel, err := store.ReadSelection(p.selection)
	if err != nil || sel == nil {
		return
	}
	selected := map[string]bool{}
	for _, n := range sel.Nodes {
		selected[n.Country] = true
	}
	for _, route := range s.cfg.Render.PoolRoutes {
		bal := route.Balancer
		// Global balancers are rendered whenever any pool node exists; they are
		// not country-keyed, so country-level reconciliation does not apply.
		if bal == "pool_all" || bal == "pool_all_clean" {
			continue
		}
		country := balancerCountry(bal)
		if selected[country] {
			continue
		}
		const msg = "WARNING: config reconciliation: pool route %q references balancer %q " +
			"but country %q has no live nodes — consider removing or changing this route\n"
		outf(s.w, msg, bal, bal, country)
	}
}

// balancerCountry extracts the ISO-ish country code a pool balancer/outbound is
// keyed on. Unknown-geo balancers map to "" (the selection's unknown-country
// bucket); global balancers are handled by the caller.
func balancerCountry(balancer string) string {
	if rest, ok := strings.CutPrefix(balancer, "pool-"); ok {
		parts := strings.SplitN(rest, "-", 2)
		if len(parts) == 0 {
			return ""
		}
		cc := parts[0]
		if strings.EqualFold(cc, "xx") {
			return ""
		}
		return strings.ToLower(cc)
	}
	if rest, ok := strings.CutPrefix(balancer, "pool_"); ok {
		// Strip a trailing "_clean" suffix so clean balancers key on the same
		// country as their all-variant.
		rest = strings.TrimSuffix(rest, "_clean")
		if rest == "unknown" {
			return ""
		}
		if rest == "all" {
			return ""
		}
		parts := strings.SplitN(rest, "_", 2)
		if len(parts) == 0 {
			return ""
		}
		cc := parts[0]
		if strings.EqualFold(cc, "xx") {
			return ""
		}
		return strings.ToLower(cc)
	}
	return ""
}

// checkpoint checks the shutdown signal before a stage; returns true if the
// wave should pause (prints the pause message and returns true).
func (s *waveRunState) checkpoint(stage string) bool {
	if s.between == nil {
		return false
	}
	if s.between() {
		outf(s.w, "maintain: shutdown requested — wave paused before stage %s (completed stages are flushed)\n", stage)
		s.waveErr = errWavePaused
		return true
	}
	return false
}

// reportStatsFailure surfaces one stats-stage failure by its class
// (W7 item 9):
//   - LOUD — a fold/write error into the geo-base: returned as a real wave
//     failure, because traffic data loss is never silent;
//   - INFO — an expected first-run shape (the live config has never carried
//     the rendered api/stats block, or the endpoint refuses connections
//     because the service was not restarted after activation): printed as an
//     INFO line, never a warning;
//   - WARNING (also the fallback for plain errors from injected stages) —
//     today's accounting-only behavior: printed as the "stats poll
//     unavailable" line, and the wave continues.
func reportStatsFailure(w io.Writer, err error) error {
	var ce *stats.ClassifiedError
	switch {
	case errors.As(err, &ce) && ce.Class == stats.ClassLoud:
		return fmt.Errorf("maintain stage stats: %w", err)
	case errors.As(err, &ce) && ce.Class == stats.ClassInfo:
		outf(w, "INFO: %v\n", err)
	default:
		outf(w, "WARNING: stats poll unavailable: %v (continuing — traffic accounting is not correctness)\n", err)
	}
	return nil
}

// runStatsStage polls the live client's StatsService and folds the per-tag
// deltas into the geo-base (W4 accounting; package stats owns the contract).
// W7 item 9: every failure leaves this function CLASSIFIED —
//   - INFO: the activate target lacks the rendered api/stats shape (we render
//     it, so we read it back), or the loopback endpoint refuses connections
//     (the service was not restarted since activation). The poll is skipped
//     without exec'ing xray; the wave continues, exit status unaffected.
//   - WARNING: the endpoint is reachable but the poll fails at the protocol
//     level (or the store/target cannot be read) — today's accounting-only
//     behavior.
//   - LOUD: a fold/write failure into the geo-base. Returning it as a real
//     error (not a warning) retires the old behavior where the generic
//     "stats poll unavailable" line masked write failures — traffic data
//     loss never passes silently.
func runStatsStage(cmd *cobra.Command, cfg *config.Config) error {
	p := newPaths(cfg)
	// Deliberate asymmetry: a geo-base READ failure is a WARNING (accounting
	// skips this wave, destroys nothing), while the WRITE failure below is
	// LOUD because freshly polled deltas would be discarded — never flip
	// this read arm to LOUD and block node refresh on a transient store
	// hiccup.
	records, err := store.ReadGeo(p.geoBase)
	if err != nil {
		return stats.NewClassified(stats.ClassWarning,
			fmt.Errorf("read geo-base for stats folding: %w", err))
	}
	server := fmt.Sprintf("127.0.0.1:%d", cfg.Render.StatsPort)

	target := config.ExpandHome(cfg.Activate.Target)
	if target == "" {
		// Configless boundary (W12): without activate.target there is no
		// live config to inspect and nothing to poll against. Accounting
		// skips the wave — INFO (expected shape), never LOUD: no data is
		// lost, the working stages keep running.
		return stats.NewClassified(stats.ClassInfo, fmt.Errorf(
			"configless mode: no activate.target — stats accounting unavailable "+
				"(provide -c or a config at %s to enable the poll)", config.ShareConfigDisplay))
	}
	hasAPI, err := stats.TargetHasAPI(target, cfg.Render.StatsPort)
	if err != nil {
		return stats.NewClassified(stats.ClassWarning, err)
	}
	if !hasAPI {
		return stats.NewClassified(stats.ClassInfo, fmt.Errorf(
			"stats will be available after the first activation + service restart; "+
				"skipping accounting this wave (target %s lacks the rendered api/stats shape)", target))
	}
	if !stats.EndpointReachable(context.Background(), server) {
		return stats.NewClassified(stats.ClassInfo, fmt.Errorf(
			"stats will be available after the first activation + service restart; "+
				"skipping accounting this wave (%s connection refused — the service is not running the activated config)", server))
	}

	res, err := stats.Run(context.Background(), stats.Options{
		BinPath: config.ExpandHome(cfg.Activate.XrayBin),
		Server:  server,
		Pattern: "outbound>>>pool-",
		Timeout: cfg.Maintain.StatsTimeout.Duration,
	})
	if err != nil {
		return stats.NewClassified(stats.ClassWarning, err)
	}
	updated, totalUp, totalDown := stats.Fold(records, res.Deltas)
	if updated > 0 {
		if err := store.WriteGeo(p.geoBase, records); err != nil {
			return stats.NewClassified(stats.ClassLoud,
				fmt.Errorf("fold stats deltas into %s: %w — traffic accounting data would be lost", p.geoBase, err))
		}
	}
	outf(cmd.OutOrStdout(), "stats: polled at %s — %d pool counters, %d records updated (+%d up / +%d down bytes)\n",
		res.PolledAt, res.RawCounters, updated, totalUp, totalDown)
	return nil
}

// runPluginStatsEnrichment enriches the plugin stats in the fetch manifest
// with live nodes (from probe) and hosting/proxy/clean counts (from geo).
// Called after probe and geo stages have completed. reg is the WAVE's
// registry: the MinLivePercent enforcement lands its breaker failures there
// — in the daemon that is the long-lived watchdog registry, so a disabled
// plugin stays disabled across waves. The wave always has a registry (the
// fetch stage loads or receives one and fails loud on load errors — no
// silent reload-and-discard path here, adversarial review F1).
func runPluginStatsEnrichment(cmd *cobra.Command, cfg *config.Config, reg *plugins.Registry) error {
	p := newPaths(cfg)

	// Read the fetch manifest to get existing plugin stats
	b, err := os.ReadFile(p.manifest)
	if err != nil {
		// No manifest yet - nothing to enrich (not an error)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read fetch manifest for plugin stats enrichment: %w", err)
	}
	var manifest fetchManifest
	//nolint:musttag // fetchManifest has JSON tags; musttag false positive
	if err := json.Unmarshal(b, &manifest); err != nil {
		return fmt.Errorf("decode fetch manifest for plugin stats enrichment: %w", err)
	}
	if len(manifest.PluginStats) == 0 {
		// No plugin stats to enrich
		return nil
	}

	// Read probe results for liveness
	probeByKey, err := store.LatestProbeByKey(p.probeResults)
	if err != nil {
		return fmt.Errorf("read probe results for plugin stats: %w", err)
	}
	liveByKey := make(map[string]bool, len(probeByKey))
	for k, pr := range probeByKey {
		if pr.Alive {
			liveByKey[k] = true
		}
	}

	// Read geo records once: the plugins-package projection feeds the
	// collector; the model records carry the Phase-1 unlock evidence the
	// counts need.
	modelGeoRecords, pluginGeoRecords, err := readGeoRecords(p)
	if err != nil {
		return err
	}
	modelGeoByKey := make(map[string]*model.GeoRecord, len(modelGeoRecords))
	for _, gr := range modelGeoRecords {
		modelGeoByKey[model.GeoIdentity(gr)] = gr
	}

	// Recreate collector with existing stats and enrich
	statsCollector := plugins.NewPluginStatsCollector(pluginGeoRecords)
	// Pre-populate with existing stats from manifest
	for _, st := range manifest.PluginStats {
		statsCollector.Stats[st.PluginID] = &st
	}

	// Read filtered nodes to get keys for matching
	filtered, err := store.ReadNodes(p.filtered)
	if err != nil {
		return fmt.Errorf("read filtered nodes for plugin stats enrichment: %w", err)
	}

	// Compute LiveNodes for each plugin
	computePluginLiveNodes(statsCollector, manifest, filtered, liveByKey)

	// Compute hosting/proxy/clean from geo records
	computePluginGeoCounts(statsCollector, filtered)

	// Compute unlock counts from the Phase-1 media-unlock evidence
	computePluginUnlockCounts(statsCollector, modelGeoByKey, filtered)

	// Pairwise overlap matrix: per-plugin DISTINCT GeoIdentity sets (the W19
	// multi-parse-record landmine dedupes within a plugin first), then the
	// full matrix for the --overlap view and the top-2/unique-yield
	// projection onto each plugin's stats.
	identities := identitySetsFromNodes(filtered)
	overlapMatrix := plugins.ComputeOverlapMatrix(identities)
	statsCollector.ApplyOverlap(overlapMatrix, identities)
	manifest.PluginOverlap = &overlapMatrix

	// Update manifest with enriched stats
	manifest.PluginStats = statsCollector.GetStats()

	// Provider time-series: one snapshot per provider, recorded AFTER the
	// stats are fully enriched. Accounting, not correctness — a failure is a
	// loud WARNING and the wave continues (same class as the stats poll).
	if err := updateProviderTimeSeriesHistory(cmd, p.dataDir, statsCollector, filtered, probeByKey); err != nil {
		outf(cmd.OutOrStdout(), "WARNING: provider history update failed: %v (continuing)\n", err)
	}

	// Threshold enforcement: check MinLivePercent — on the WAVE's registry.
	checkMinLivePercent(cmd, cfg, statsCollector, reg)

	// Write back the manifest
	//nolint:musttag // fetchManifest has JSON tags; musttag false positive
	b, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal enriched manifest: %w", err)
	}
	if err := store.WriteManifest(p.manifest, b); err != nil {
		return fmt.Errorf("write enriched manifest: %w", err)
	}

	outf(cmd.OutOrStdout(), "plugin-stats: enriched %d plugins with live/geo data\n", len(manifest.PluginStats))
	return nil
}

// readGeoRecords reads the geo base once and returns both views: the model
// records (the Phase-1 unlock evidence source) and the plugins-package
// projection the stats collector consumes.
func readGeoRecords(p paths) ([]*model.GeoRecord, []*plugins.GeoRecord, error) {
	geoRecords, err := store.ReadGeo(p.geoBase)
	if err != nil {
		return nil, nil, fmt.Errorf("read geo records for plugin stats: %w", err)
	}

	pluginGeoRecords := make([]*plugins.GeoRecord, len(geoRecords))
	for i, gr := range geoRecords {
		pluginGeoRecords[i] = &plugins.GeoRecord{
			Scheme:      gr.Scheme,
			Host:        gr.Host,
			Port:        gr.Port,
			IP:          gr.IP,
			Country:     gr.Country,
			City:        gr.City,
			ASN:         gr.ASN,
			ASName:      gr.ASName,
			ISP:         gr.ISP,
			ProxyFlag:   gr.ProxyFlag,
			HostingFlag: gr.HostingFlag,
			GeoSource:   gr.GeoSource,
			FirstSeen:   gr.FirstSeen,
			LastSeen:    gr.LastSeen,
			LastProbe:   gr.LastProbe,
			RTTMs:       gr.RTTMs,
			SpeedBPS:    gr.SpeedBPS,
			Alive:       gr.Alive,
			BytesUp:     gr.BytesUp,
			BytesDown:   gr.BytesDown,
			Tag:         gr.Tag,
			Source:      gr.Source,
		}
	}
	return geoRecords, pluginGeoRecords, nil
}

// computePluginLiveNodes computes LiveNodes for each plugin by matching filtered nodes against probe results.
func computePluginLiveNodes(
	statsCollector *plugins.PluginStatsCollector,
	manifest fetchManifest,
	filtered []*model.Node,
	liveByKey map[string]bool,
) {
	for _, st := range manifest.PluginStats {
		liveCount := 0
		for _, n := range filtered {
			if n.Source == st.PluginID && liveByKey[n.Key] {
				liveCount++
			}
		}
		if statsCollector.Stats[st.PluginID] != nil {
			statsCollector.Stats[st.PluginID].LiveNodes = liveCount
		}
	}
}

// computePluginGeoCounts computes HostingCount, ProxyCount, CleanCount and
// ClassifiedCount for each plugin from geo records. Classified-only counting
// (owner ruling 2026-11-04): a node without a geo record is UNCLASSIFIED —
// never folded into clean (the old else-branch fabricated clean evidence,
// adversarial review F6). The honest clean share is CleanPercent =
// CleanCount/ClassifiedCount, derived at reporting points.
//
// Hosting/proxy evidence honesty: a zero HostingCount with a non-zero
// ClassifiedCount is a TRUE reading, not an attribution bug — the identity
// join below is the same one clean counts ride (verified against
// production: classified counts match exactly). Zeroes mean the cold base
// itself carries no flags: ip-api hosting/proxy evidence exists only on
// records that went through self-report (geo_source set), and the Phase-1
// is_hosting/is_proxy evidence only lands when [geo].unlock_probes is on.
// The status funnel's "hosting/proxy exits" transfer line is NOT a
// counter-source here: its magnitude is dominated by probe-store
// inversions (alive probe keys outnumber alive geo records), so never
// reconcile the two numbers against each other.
func computePluginGeoCounts(statsCollector *plugins.PluginStatsCollector, filtered []*model.Node) {
	for pluginID, st := range statsCollector.Stats {
		hosting, proxy, clean, classified := 0, 0, 0, 0
		for _, n := range filtered {
			if n.Source != pluginID {
				continue
			}
			geoKey := plugins.GeoIdentityKey(n.Scheme, n.Host, n.Port)
			if gr, ok := statsCollector.GeoByKey[geoKey]; ok {
				classified++
				if gr.HostingFlag {
					hosting++
				}
				if gr.ProxyFlag {
					proxy++
				}
				if !gr.HostingFlag && !gr.ProxyFlag {
					clean++
				}
			}
		}
		st.HostingCount = hosting
		st.ProxyCount = proxy
		st.CleanCount = clean
		st.ClassifiedCount = classified
	}
}

// computePluginUnlockCounts counts, per plugin, the parse records whose geo
// record carries a CHECKED Phase-1 media-unlock status with at least one
// positive unlock signal. Attribution is per parse record (the W19 landmine:
// one GeoIdentity may carry several records across plugins — each plugin's
// records count for that plugin via the record's own source).
func computePluginUnlockCounts(
	statsCollector *plugins.PluginStatsCollector,
	modelGeoByKey map[string]*model.GeoRecord,
	filtered []*model.Node,
) {
	for _, n := range filtered {
		st := statsCollector.Stats[n.Source]
		if st == nil {
			continue
		}
		geoKey := model.GeoIdentity(&model.GeoRecord{Scheme: n.Scheme, Host: n.Host, Port: n.Port})
		gr := modelGeoByKey[geoKey]
		if gr == nil {
			continue
		}
		if unlockPositive(gr.MediaUnlocks) {
			st.UnlockCount++
		}
	}
}

// unlockPositive reports whether a Phase-1 media-unlock status carries at
// least one positive unlock signal (model.Unlock* vocabulary). An unchecked
// status (empty CheckedAt) is never positive; blocked/unknown and a missing
// YouTube region are not unlocks.
func unlockPositive(ms model.MediaUnlockStatus) bool {
	if ms.CheckedAt == "" {
		return false
	}
	switch ms.ChatGPT {
	case model.UnlockYes, model.UnlockWebOnly, model.UnlockAppOnly:
		return true
	}
	switch ms.Netflix {
	case model.UnlockNetflixFull, model.UnlockNetflixOriginals:
		return true
	}
	if ms.Disney == model.UnlockYes || ms.TikTok == model.UnlockYes {
		return true
	}
	if ms.YouTubeRegion != "" &&
		ms.YouTubeRegion != model.UnlockBlocked && ms.YouTubeRegion != model.UnlockUnknown {
		return true
	}
	return false
}

// identitySetsFromNodes builds the per-plugin DISTINCT GeoIdentity sets the
// overlap matrix consumes: identity = scheme|lower(host)|port (the
// model.GeoIdentity format — plugins.GeoIdentityKey produces the same
// string), deduped within each plugin before any pairwise math.
func identitySetsFromNodes(filtered []*model.Node) map[string]map[string]bool {
	sets := make(map[string]map[string]bool)
	for _, n := range filtered {
		set := sets[n.Source]
		if set == nil {
			set = make(map[string]bool)
			sets[n.Source] = set
		}
		set[plugins.GeoIdentityKey(n.Scheme, n.Host, n.Port)] = true
	}
	return sets
}

// updateProviderTimeSeriesHistory records one WaveSnapshot per provider into
// <dataDir>/provider-history.json (ring ≤48, 48h prune, diurnal + momentum
// state inside internal/stats). Median RTT is taken over the plugin's ALIVE
// parse records' own probe results (even counts average the two middles); a
// provider with no RTT evidence records 0.
func updateProviderTimeSeriesHistory(
	cmd *cobra.Command,
	dataDir string,
	statsCollector *plugins.PluginStatsCollector,
	filtered []*model.Node,
	probeByKey map[string]store.ProbeResult,
) error {
	now := time.Now().UTC()
	rttsByPlugin := map[string][]float64{}
	for _, n := range filtered {
		pr, ok := probeByKey[n.Key]
		if !ok || !pr.Alive {
			continue
		}
		rttsByPlugin[n.Source] = append(rttsByPlugin[n.Source], pr.RTTMs)
	}
	historyPath := filepath.Join(dataDir, providerHistoryFile)
	for _, st := range statsCollector.GetStats() {
		snap := stats.WaveSnapshot{
			Timestamp: now.Unix(),
			Total:     st.TotalNodes,
			Live:      st.LiveNodes,
			Clean:     st.CleanCount,
			Hosting:   st.HostingCount,
			MedianRTT: medianRTT(rttsByPlugin[st.PluginID]),
		}
		if _, err := stats.RecordWaveSnapshot(historyPath, st.PluginID, snap, now); err != nil {
			return fmt.Errorf("record %s wave snapshot: %w", st.PluginID, err)
		}
	}
	outf(cmd.OutOrStdout(), "provider-history: recorded %d provider snapshots → %s\n",
		len(statsCollector.Stats), historyPath)
	return nil
}

// medianRTT is the standard median (even counts average the two middles);
// no evidence → 0.
func medianRTT(values []float64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	var median float64
	if len(sorted)%2 == 1 {
		median = sorted[mid]
	} else {
		median = (sorted[mid-1] + sorted[mid]) / 2
	}
	return int64(math.Round(median))
}

// checkMinLivePercent checks if any plugin's live percentage falls below
// the configured MinLivePercent threshold and disables them via the wave's
// registry (the same one the fetch stage and its duplicate-percent check
// use — never a throwaway reload, adversarial review F1). reg == nil skips
// the check (same contract as checkMaxDuplicatePercent): the wave's
// registry load already failed loud in the fetch stage.
func checkMinLivePercent(
	cmd *cobra.Command,
	cfg *config.Config,
	statsCollector *plugins.PluginStatsCollector,
	reg *plugins.Registry,
) {
	if reg == nil || cfg == nil || cfg.Plugins.MinLivePercent == nil {
		return
	}
	minLivePct := *cfg.Plugins.MinLivePercent
	for _, st := range statsCollector.GetStats() {
		if st.TotalNodes == 0 {
			continue
		}
		livePct := float64(st.LiveNodes) * 100.0 / float64(st.TotalNodes)
		if livePct >= minLivePct {
			continue
		}
		if reg.RecordFailure(st.PluginID, 1) {
			outf(cmd.OutOrStdout(), "plugin %-10s DISABLED: live%% %.1f < threshold %.1f (total=%d, live=%d)\n",
				st.PluginID, livePct, minLivePct, st.TotalNodes, st.LiveNodes)
		}
	}
}

// runPruneStage removes dead/ttl-stale-orphan records from the geo-base and
// reports the wave's filter set as "still referenced" (package prune owns the
// rules). A pruning pass that removes anything leaves a .bak-<ts> backup of
// the pre-prune store next to it.
func runPruneStage(cmd *cobra.Command, cfg *config.Config) error {
	p := newPaths(cfg)
	records, err := store.ReadGeo(p.geoBase)
	if err != nil {
		return err
	}
	filtered, err := store.ReadNodes(p.filtered)
	if err != nil {
		return err
	}
	referenced := make(map[string]bool, len(filtered))
	for _, n := range filtered {
		referenced[model.GeoIdentity(&model.GeoRecord{Scheme: n.Scheme, Host: n.Host, Port: n.Port})] = true
	}
	kept, removed, report := prune.Select(records, referenced, prune.Options{
		DeadAfter: cfg.Maintain.PruneDeadAfter.Duration,
		TTL:       cfg.Geo.TTL.Duration,
		Now:       time.Now().UTC(),
	})
	if len(removed) == 0 {
		outf(cmd.OutOrStdout(), "prune: nothing to remove (%d records checked, dead_after=%s ttl=%s)\n",
			len(records), cfg.Maintain.PruneDeadAfter.Duration, cfg.Geo.TTL.Duration)
		return nil
	}
	backupPath, err := store.RewriteGeoWithBackup(p.geoBase, kept, time.Now().UTC(), cfg.Maintain.PruneBackupKeep)
	if err != nil {
		return err
	}
	outf(cmd.OutOrStdout(), "prune: removed %d records (%d dead_after, %d ttl-stale orphans), %d kept → backup %s\n",
		len(removed), report.RemovedDead, report.RemovedStale, report.Kept, orNone(backupPath))
	return nil
}

// runActivateStage is the activate-if-changed gate: an unchanged render is a
// no-op with a clear line (the live config is never rewritten without a
// diff — and nothing restarts); a differing render goes through the W3
// activate path (-test gate → backup → atomic replace) and, since W13, the
// gated auto-restart + health check via the injected wiring.
func runActivateStage(cmd *cobra.Command, cfg *config.Config, wiring *restartWiring) error {
	p := newPaths(cfg)
	rendered, err := os.ReadFile(p.rendered)
	if err != nil {
		return fmt.Errorf("no rendered config (%s) — the render stage must run before activation", p.rendered)
	}
	// Configless boundary (W12): no configured target — refuse before any
	// diff/replace consideration (runActivate enforces the same contract).
	if cfg.Activate.Target == "" {
		return config.ConfiglessBoundaryError("activate")
	}
	live, err := os.ReadFile(config.ExpandHome(cfg.Activate.Target))
	if err == nil && bytes.Equal(rendered, live) {
		outln(cmd.OutOrStdout(), "no changes — the live config already matches the rendered pool; nothing activated")
		return nil
	}
	return runActivate(cmd, cfg, "", true, wiring)
}

func newStatusCommand(cfgPath *string) *cobra.Command {
	var (
		binDir  string
		unitDir string
		jsonOut bool
		overlap bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Pipeline state summary (read-only)",
		Long: `Read-only summary of the pipeline (fetch, parse, filter, probe, geo,
selection, render) plus the intelligence dashboard: the pipeline funnel,
global pool quality, the provider intelligence table, and the media/unlock
summary. The resolved config source is printed as the config line (explicit
-c, home default, cwd default, or configless built-in defaults).

--overlap (-v) appends the pairwise provider-overlap matrix view with
pruning recommendations. --json bypasses the dashboard entirely and emits
one machine-readable JSON document (schema_version 1.0); both flags
compose — the overlap matrix is always part of the JSON.

Install detection reads the directories given via --bin-dir / --unit-dir
(defaults identical to ` + "`install`" + `: ~/.local/bin and
~/.config/systemd/user). An install made with custom paths is tracked by
passing the same values here — publicvpn keeps no state file by design.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			return runStatus(cmd, res)
		},
	}
	cmd.Flags().StringVar(&binDir, "bin-dir", "~/.local/bin",
		"directory to inspect for the installed publicvpn binary (same default as install)")
	cmd.Flags().StringVar(&unitDir, "unit-dir", "~/.config/systemd/user",
		"systemd user unit directory to inspect (same default as install)")
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"emit one machine-readable JSON document instead of the dashboard (schema_version 1.1)")
	cmd.Flags().BoolVarP(&overlap, "overlap", "v", false,
		"append the pairwise provider-overlap matrix view with pruning recommendations")
	attachColorFlags(cmd)
	return cmd
}

// statusOutputFlags reads the Phase-4 dashboard flags off the command
// (round-7 pattern: direct runStatus callers with a bare cobra command get
// the zero-value dashboard behavior).
func statusOutputFlags(cmd *cobra.Command) (bool, bool) {
	var jsonOut, overlap bool
	if f := cmd.Flags().Lookup("json"); f != nil {
		jsonOut, _ = strconv.ParseBool(f.Value.String())
	}
	if f := cmd.Flags().Lookup("overlap"); f != nil {
		overlap, _ = strconv.ParseBool(f.Value.String())
	}
	return jsonOut, overlap
}

func runStatus(cmd *cobra.Command, res *config.Resolved) error {
	p := newPaths(res.Config)
	out := cmd.OutOrStdout()
	color, err := commandColor(cmd, out)
	if err != nil {
		return err
	}
	jsonOut, overlap := statusOutputFlags(cmd)

	configSource := res.Source.String()
	if res.Path != "" {
		configSource += " " + res.Path
	}
	si, err := collectStatusIntel(p, configSource)
	if err != nil {
		return err
	}
	if jsonOut {
		return emitStatusJSON(out, si)
	}

	outln(out, ui.Header("publicvpn pipeline status", color))
	reportConfigSourceStyled(out, res, color)
	outln(out, ui.Chip("data dir:", p.dataDir, color))
	printFetchStatus(out, p, color)
	printStageCounts(out, si.stages, color)
	printProbeStatus(out, p, color)
	printGeoStatus(out, p, color)
	printCalibrationStatus(out, p, res.Config, color)
	printPipelineFunnel(out, si, color)
	printGlobalQuality(out, &si.geo, color)
	printMediaSummary(out, &si.geo.Media, color)
	printPluginLivenessStatus(out, si, res.Config, color)
	if overlap {
		printOverlapMatrix(out, si, color)
	}
	printSelectionStatus(out, p, color)
	printRenderStatus(out, p, color)
	binDir, unitDir := statusInstallDirs(cmd)
	printInstallStatus(out, res.Config, res.Path, binDir, unitDir, color)
	return nil
}

// statusInstallDirs reads the status command's --bin-dir/--unit-dir values
// (round-7 item 11), falling back to the install defaults when the flags
// are absent — direct runStatus callers with a bare cobra command get the
// documented default behavior.
func statusInstallDirs(cmd *cobra.Command) (string, string) {
	binDir, unitDir := "~/.local/bin", "~/.config/systemd/user"
	if f := cmd.Flags().Lookup("bin-dir"); f != nil {
		binDir = f.Value.String()
	}
	if f := cmd.Flags().Lookup("unit-dir"); f != nil {
		unitDir = f.Value.String()
	}
	return config.ExpandHome(binDir), config.ExpandHome(unitDir)
}

// printFetchStatus, printSelectionStatus and printRenderStatus join
// printStageCounts and printPluginLivenessStatus in status_intel.go — the
// intelligence dashboard owns the whole status rendering chain alongside
// the funnel/quality/media sections (dashboard-honesty wave, 2026-11-05:
// local-time stamps, unbounded select label).

func printProbeStatus(out io.Writer, p paths, color bool) {
	results, err := store.ReadProbeResults(p.probeResults)
	if err != nil || len(results) == 0 {
		outln(out, ui.ChipKV("probe:    ", "empty", color))
		return
	}
	alive := 0
	for _, r := range results {
		if r.Alive {
			alive++
		}
	}
	outf(out, "%s\n", ui.ChipKV("probe:    ",
		fmt.Sprintf("%d results logged, %d alive (latest wave per node)", len(results), alive), color))
}

func printGeoStatus(out io.Writer, p paths, color bool) {
	recs, err := store.ReadGeo(p.geoBase)
	if err != nil || len(recs) == 0 {
		outln(out, ui.ChipKV("geo:      ", "empty", color))
		return
	}
	alive, countries := 0, map[string]bool{}
	var up, down int64
	for _, r := range recs {
		if r.Alive {
			alive++
		}
		if r.Country != "" {
			countries[r.Country] = true
		}
		up += r.BytesUp
		down += r.BytesDown
	}
	outf(out, "%s\n", ui.ChipKV("geo:      ",
		fmt.Sprintf("%d records, %d alive, %d countries, traffic folded: %d up / %d down bytes",
			len(recs), alive, len(countries), up, down), color))
}

func printCalibrationStatus(out io.Writer, p paths, cfg *config.Config, color bool) {
	if !cfg.Probe.CalibrationEnabled {
		outln(out, ui.ChipKV("calibration:", "disabled", color))
		return
	}
	st, err := timeoutcal.Load(p.dataDir)
	if err != nil {
		outln(out, ui.ChipKV("calibration:", "state unreadable", color))
		return
	}
	// probe
	probeCur := st.Probe.TimeoutFor("global")
	if probeCur == 0 {
		probeCur = time.Duration(cfg.Probe.CalibrationBase * float64(time.Second))
	}
	probeBase := time.Duration(cfg.Probe.CalibrationBase * float64(time.Second))
	probeCV := 0.0
	hist := make([]float64, 0, len(st.Probe.Global.History))
	for _, h := range st.Probe.Global.History {
		hist = append(hist, h.P95Ms)
	}
	if len(hist) > 0 {
		probeCV = timeoutcal.CV(hist)
	}
	outf(out, "%s\n", ui.ChipKV("calibration:",
		fmt.Sprintf("probe: %s (base %s, floor %s, ceiling %s, CV %.3f, wave %d)", probeCur, probeBase,
			time.Duration(timeoutcal.FloorMs)*time.Millisecond,
			time.Duration(timeoutcal.CeilingMs)*time.Millisecond,
			probeCV,
			st.Probe.Global.Waves), color))
	// The state file's geo slot is legacy compatibility only: since the
	// classification merge no stage calibrates or consumes geo timeouts
	// separately (the probe budget governs the whole classification pass),
	// so the slot stays in the state file but is intentionally not rendered.
	// regions slowest 3
	type regionKV struct {
		key string
		dur time.Duration
	}
	var regions []regionKV
	for k, v := range st.Probe.Regions {
		regions = append(regions, regionKV{k, v.Current})
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].dur > regions[j].dur })
	if len(regions) > 3 {
		regions = regions[:3]
	}
	if len(regions) > 0 {
		parts := make([]string, 0, len(regions))
		for _, r := range regions {
			parts = append(parts, fmt.Sprintf("%s %s", r.key, r.dur))
		}
		msg := fmt.Sprintf("%d calibrated; slowest: %s", len(st.Probe.Regions), strings.Join(parts, ", "))
		outf(out, "%s\n", ui.ChipKV("  regions:", msg, color))
	}
	// state file path
	outf(out, "%s\n", ui.ChipKV("  state:", filepath.Join(p.dataDir, "timeout-calibration.json"), color))
}

func countLines(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n := 0
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n, nil
}
