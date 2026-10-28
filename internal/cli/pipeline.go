package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"public_vpn/internal/activate"
	"public_vpn/internal/config"
	"public_vpn/internal/fetch"
	"public_vpn/internal/filter"
	"public_vpn/internal/geo"
	"public_vpn/internal/model"
	"public_vpn/internal/parse"
	"public_vpn/internal/probe"
	"public_vpn/internal/prune"
	"public_vpn/internal/rank"
	"public_vpn/internal/render"
	"public_vpn/internal/stats"
	"public_vpn/internal/store"

	"github.com/spf13/cobra"
)

// fetchManifest records what a fetch wave stored, so parse reads exactly what
// fetch downloaded (source → cached files). Cache file names come from
// fetch.SafePath — the single definition of the path→name mapping.
type fetchManifest struct {
	FetchedAt time.Time                      `json:"fetched_at"`
	Sources   map[string][]fetch.FetchedFile `json:"sources"`
}

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
		Short: "Discover and download source files (D9 dynamic discovery, cached)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runFetch(cmd, cfg)
		},
	}
}

func runFetch(cmd *cobra.Command, cfg *config.Config) error {
	p := newPaths(cfg)
	if err := os.MkdirAll(p.cacheDir, 0o750); err != nil {
		return err
	}
	cl := fetch.NewClient(fetch.ClientConfig{
		APIBase:     cfg.Fetch.APIBase,
		RawBase:     cfg.Fetch.RawBase,
		Token:       cfg.Fetch.GitHubToken,
		Timeout:     cfg.Fetch.Timeout.Duration,
		Retries:     cfg.Fetch.Retries,
		Concurrency: cfg.Fetch.Concurrency,
		UserAgent:   cfg.HTTP.UserAgent,
	})
	// Per-file freshness skips are stage progress: they flow through the same
	// writer as the per-source summary lines.
	cl.LogOut = cmd.OutOrStdout()
	manifest := fetchManifest{FetchedAt: time.Now().UTC(), Sources: map[string][]fetch.FetchedFile{}}
	totalFiles, failed := 0, 0
	for id, src := range cfg.Sources {
		if !src.IsEnabled() {
			outf(cmd.OutOrStdout(), "source %-10s disabled, skipped\n", id)
			continue
		}
		files, err := cl.SourceCached(context.Background(), id, src, p.cacheDir, cfg.Fetch.CacheMaxAge.Duration)
		if err != nil {
			failed++
			outf(cmd.OutOrStdout(), "source %-10s FAILED: %v\n", id, err)
			continue
		}
		manifest.Sources[id] = files
		totalFiles += len(files)
		cached := 0
		for _, f := range files {
			if f.Cached {
				cached++
			}
		}
		outf(cmd.OutOrStdout(), "source %-10s ok: %d files (%d from cache)\n", id, len(files), cached)
	}
	if totalFiles == 0 && failed > 0 {
		return fmt.Errorf("all %d attempted sources failed; nothing fetched", failed)
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := store.WriteManifest(p.manifest, b); err != nil {
		return err
	}
	outf(cmd.OutOrStdout(), "fetch wave complete: %d files from %d sources (manifest: %s)\n",
		totalFiles, len(manifest.Sources), p.manifest)
	return nil
}

func newParseCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "parse",
		Short: "Parse cached source bodies into normalized node records",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runParse(cmd, cfg)
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
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runFilter(cmd, cfg, sourceCap)
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
		preset    string
	)
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Out-of-band xray-knife probe: liveness, latency, exit IP (D8), optional speed/grading",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runProbe(cmd, cfg, limit, speedtest, preset)
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "probe only the first N filtered nodes (0 = all)")
	cmd.Flags().BoolVar(&speedtest, "speedtest", false, "run -S throughput measurement (slow)")
	cmd.Flags().StringVar(&preset, "check-preset", "", "panel grading preset (cloudflare|global|google|gstatic|streaming)")
	return cmd
}

// probeOptions translates config + CLI flags into one probe wave's options
// (paths are the caller's concern — they come from newPaths). Extracted so
// the config→Options wiring (max_passed, speedtest OR-flag, check-preset
// precedence) is unit-testable (review finding 7).
func probeOptions(cfg *config.Config, speedtestFlag bool, presetFlag string) probe.Options {
	return probe.Options{
		Timeout:             cfg.Probe.Timeout.Duration,
		Threads:             cfg.Probe.Threads,
		URL:                 cfg.Probe.URL,
		Speedtest:           speedtestFlag || cfg.Probe.Speedtest,
		SpeedtestTimeout:    cfg.Probe.SpeedtestTimeout.Duration,
		CheckPreset:         firstNonEmpty(presetFlag, cfg.Probe.CheckPreset),
		URLSuccessThreshold: cfg.Probe.URLSuccessThreshold,
		MaxPassed:           cfg.Probe.MaxPassed,
		SkipFreshWithin:     cfg.Probe.SkipFreshWithin.Duration,
	}
}

func runProbe(cmd *cobra.Command, cfg *config.Config, limit int, speedtest bool, preset string) error {
	p := newPaths(cfg)
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
	runner := &probe.KnifeRunner{BinPath: config.ExpandHome(cfg.Probe.Path)}
	opts := probeOptions(cfg, speedtest, preset)
	opts.DBPath = p.knifeDB
	opts.WorkDir = p.workDir
	opts.Progress = cmd.OutOrStdout()
	if opts.SkipFreshWithin > 0 {
		// The freshness skip reads the recorded history: skipped nodes keep
		// their last passed outcome for rank's geo.ttl gate.
		latest, err := store.LatestProbeByKey(p.probeResults)
		if err != nil {
			return err
		}
		opts.Latest = latest
	}
	results, err := probe.Run(context.Background(), nodes, runner, opts, p.probeResults)
	if err != nil {
		return err
	}
	alive := 0
	for _, r := range results {
		if r.Alive {
			alive++
		}
	}
	outf(cmd.OutOrStdout(), "probe complete: %d/%d alive → %s\n", alive, len(results), p.probeResults)
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func newGeoCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "geo",
		Short: "Geo-enrich alive nodes' tunnel exit IPs via ip-api batch (L6 rate-capped)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runGeo(cmd, cfg)
		},
	}
}

func runGeo(cmd *cobra.Command, cfg *config.Config) error {
	p := newPaths(cfg)
	nodes, err := store.ReadNodes(p.filtered)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return fmt.Errorf("no filtered nodes (%s) — run `publicvpn filter` first", p.filtered)
	}
	probeByKey, err := store.LatestProbeByKey(p.probeResults)
	if err != nil {
		return err
	}
	if len(probeByKey) == 0 {
		return fmt.Errorf("no probe results (%s) — run `publicvpn probe` first (geo keys on exit IPs, D8)",
			p.probeResults)
	}
	records, err := geo.Run(context.Background(), geo.Input{
		DataDir:    p.dataDir,
		Nodes:      nodes,
		ProbeByKey: probeByKey,
		Cfg:        cfg.Geo,
		UserAgent:  cfg.HTTP.UserAgent,
	})
	if err != nil {
		return err
	}
	withGeo := 0
	alive := 0
	for _, r := range records {
		if r.Country != "" {
			withGeo++
		}
		if r.Alive {
			alive++
		}
	}
	outf(cmd.OutOrStdout(), "geo complete: %d records (%d alive, %d geo-enriched) → %s\n",
		len(records), alive, withGeo, p.geoBase)
	return nil
}

func newSelectCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "select",
		Short: "Rank alive nodes (alive → checks → speed), apply caps D7, assign pool tags",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runSelect(cmd, cfg)
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
	sel := rank.Select(nodes, geoRecs, probeByKey, cfg.Select, cfg.Geo.TTL.Duration)
	if err := store.WriteSelection(p.selection, sel); err != nil {
		return err
	}
	byCountry := map[string]int{}
	for _, n := range sel.Nodes {
		byCountry[n.Country]++
	}
	outf(cmd.OutOrStdout(), "select complete: %d active nodes (cap %d, %d alive cities), countries: %v → %s\n",
		len(sel.Nodes), sel.CapApplied, sel.CitiesAlive, byCountry, p.selection)
	return nil
}

func newRenderCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "render",
		Short: "Render the full xray client config (template + pool + balancers + Plan A observatory)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runRender(cmd, cfg)
		},
	}
}

func runRender(cmd *cobra.Command, cfg *config.Config) error {
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
	res, err := render.Render(render.Input{
		Template:   template,
		Selection:  sel,
		NodesByKey: byKey,
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
	if err := os.MkdirAll(p.renderedDir, 0o750); err != nil {
		return err
	}
	// 0600 deliberate: the rendered config carries pool node credentials
	// (UUIDs/passwords). The live target keeps ITS OWN mode — atomicReplace
	// preserves it (review finding 11).
	if err := os.WriteFile(p.rendered, res.Config, 0o600); err != nil {
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
		Short: "-test gate, date-stamped backup, atomic replace of the live config (never restarts)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runActivate(cmd, cfg, target, backup)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "override the activation target path (default from config)")
	cmd.Flags().BoolVar(&backup, "backup", true, "date-stamped backup of the target before replace")
	return cmd
}

func runActivate(cmd *cobra.Command, cfg *config.Config, target string, backup bool) error {
	p := newPaths(cfg)
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
	outf(cmd.OutOrStdout(), "%s\nbackup: %s\ndiff summary: %d pool nodes in the active set\n",
		res.RestartHint, orNone(res.BackupPath), selectionSize(p.selection))
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

Flags:
  --no-activate  render and diff only; never touch the live config
  --skip-probe   reselect from the cold base without probing (geo is skipped
                 too — it consumes fresh probe exit IPs; rank's geo.ttl
                 freshness gate drops stale-alive records on its own)
  --speedtest    run the probe wave with -S throughput measurement (weekly
                 speedtest timer)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runMaintain(cmd.OutOrStdout(), cfg, opts, defaultMaintainStages(opts))
		},
	}
	cmd.Flags().BoolVar(&opts.noActivate, "no-activate", false,
		"render and diff only; never activate even when the render differs")
	cmd.Flags().BoolVar(&opts.skipProbe, "skip-probe", false,
		"reselect from the cold base without probing (skips probe and geo)")
	cmd.Flags().BoolVar(&opts.speedtest, "speedtest", false,
		"run the probe wave with throughput measurement (weekly speedtest wave)")
	return cmd
}

// maintainOptions carries the maintain command's flags into the wave.
type maintainOptions struct {
	noActivate bool
	skipProbe  bool
	speedtest  bool
}

// maintainStages is the wave's seam: each pipeline stage as a function, so
// orchestration is testable without network/tooling. Production stages are
// the W1–W3 runners — the wave reuses them 1:1, never duplicating logic.
type maintainStages struct {
	fetch    func(*cobra.Command, *config.Config) error
	parse    func(*cobra.Command, *config.Config) error
	filter   func(*cobra.Command, *config.Config) error
	probe    func(*cobra.Command, *config.Config) error
	geo      func(*cobra.Command, *config.Config) error
	stats    func(*cobra.Command, *config.Config) error
	prune    func(*cobra.Command, *config.Config) error
	selectS  func(*cobra.Command, *config.Config) error
	render   func(*cobra.Command, *config.Config) error
	activate func(*cobra.Command, *config.Config) error
}

// defaultMaintainStages wires the real runners. filter runs with the config
// cap (no CLI override inside the wave); probe runs full-set with speedtest
// only when the wave carries it.
func defaultMaintainStages(opts maintainOptions) *maintainStages {
	return &maintainStages{
		fetch:    runFetch,
		parse:    runParse,
		filter:   func(c *cobra.Command, cfg *config.Config) error { return runFilter(c, cfg, 0) },
		probe:    func(c *cobra.Command, cfg *config.Config) error { return runProbe(c, cfg, 0, opts.speedtest, "") },
		geo:      runGeo,
		stats:    runStatsStage,
		prune:    runPruneStage,
		selectS:  runSelect,
		render:   runRender,
		activate: runActivateStage,
	}
}

// runMaintain executes one maintenance wave. Stage failures fail the wave
// loud — except the stats poll, which is accounting, not correctness: an
// unreachable API inbound (first run before the owner ever activated) must
// not block the refresh, so it surfaces as a loud warning line instead.
func runMaintain(w io.Writer, cfg *config.Config, opts maintainOptions, stages *maintainStages) error {
	// The wave's stages print through their own writer; give them a command
	// shim bound to w so the seam stays signature-compatible with the W1–W3
	// runners.
	cmd := &cobra.Command{}
	cmd.SetOut(w)

	outf(w, "maintain: refresh wave starting (probe=%t, speedtest=%t, activate=%t)\n",
		!opts.skipProbe, opts.speedtest, !opts.noActivate)

	run := func(name string, stage func(*cobra.Command, *config.Config) error) error {
		if err := stage(cmd, cfg); err != nil {
			return fmt.Errorf("maintain stage %s: %w", name, err)
		}
		return nil
	}
	if err := run("fetch", stages.fetch); err != nil {
		return err
	}
	if err := run("parse", stages.parse); err != nil {
		return err
	}
	if err := run("filter", stages.filter); err != nil {
		return err
	}
	if !opts.skipProbe {
		if err := run("probe", stages.probe); err != nil {
			return err
		}
		if err := run("geo", stages.geo); err != nil {
			return err
		}
	}
	if err := stages.stats(cmd, cfg); err != nil {
		outf(w, "WARNING: stats poll unavailable: %v (continuing — traffic accounting is not correctness)\n", err)
	}
	if err := run("prune", stages.prune); err != nil {
		return err
	}
	if err := run("select", stages.selectS); err != nil {
		return err
	}
	if err := run("render", stages.render); err != nil {
		return err
	}
	if opts.noActivate {
		outln(w, "maintain: --no-activate — live config not touched")
		return nil
	}
	if err := stages.activate(cmd, cfg); err != nil {
		return fmt.Errorf("maintain stage activate: %w", err)
	}
	return nil
}

// runStatsStage polls the live client's StatsService and folds the per-tag
// deltas into the geo-base (W4 accounting; package stats owns the contract).
func runStatsStage(cmd *cobra.Command, cfg *config.Config) error {
	p := newPaths(cfg)
	records, err := store.ReadGeo(p.geoBase)
	if err != nil {
		return err
	}
	res, err := stats.Run(context.Background(), stats.Options{
		BinPath: config.ExpandHome(cfg.Activate.XrayBin),
		Server:  fmt.Sprintf("127.0.0.1:%d", cfg.Render.StatsPort),
		Pattern: "outbound>>>pool-",
		Timeout: cfg.Maintain.StatsTimeout.Duration,
	})
	if err != nil {
		return err
	}
	updated, totalUp, totalDown := stats.Fold(records, res.Deltas)
	if updated > 0 {
		if err := store.WriteGeo(p.geoBase, records); err != nil {
			return err
		}
	}
	outf(cmd.OutOrStdout(), "stats: polled at %s — %d pool counters, %d records updated (+%d up / +%d down bytes)\n",
		res.PolledAt, res.RawCounters, updated, totalUp, totalDown)
	return nil
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
		referenced[prune.Identity(&model.GeoRecord{Scheme: n.Scheme, Host: n.Host, Port: n.Port})] = true
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
// diff); a differing render goes through the W3 activate path (-test gate →
// backup → atomic replace).
func runActivateStage(cmd *cobra.Command, cfg *config.Config) error {
	p := newPaths(cfg)
	rendered, err := os.ReadFile(p.rendered)
	if err != nil {
		return fmt.Errorf("no rendered config (%s) — the render stage must run before activation", p.rendered)
	}
	live, err := os.ReadFile(config.ExpandHome(cfg.Activate.Target))
	if err == nil && bytes.Equal(rendered, live) {
		outln(cmd.OutOrStdout(), "no changes — the live config already matches the rendered pool; nothing activated")
		return nil
	}
	return runActivate(cmd, cfg, "", true)
}

func newStatusCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Pipeline state summary (read-only)",
		Long: `Read-only summary of the pipeline (fetch, parse, filter, probe, geo,
selection, render) plus the install state: installed binary, unit files,
timers, and configured-vs-installed timer periods.

Install detection reads the DEFAULT directories only — ~/.local/bin for the
binary and ~/.config/systemd/user for the units — because publicvpn keeps no
state file by design. An install made with custom --bin-dir/--unit-dir paths
is NOT tracked here; inspect those locations directly.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runStatus(cmd, cfg, *cfgPath)
		},
	}
}

func runStatus(cmd *cobra.Command, cfg *config.Config, cfgPath string) error {
	p := newPaths(cfg)
	out := cmd.OutOrStdout()

	outln(out, "publicvpn pipeline status")
	outln(out, "data dir:", p.dataDir)
	printFetchStatus(out, p)
	printStageCounts(out, p)
	printProbeStatus(out, p)
	printGeoStatus(out, p)
	printSelectionStatus(out, p)
	printRenderStatus(out, p)
	printInstallStatus(out, cfg, cfgPath)
	return nil
}

func printFetchStatus(out io.Writer, p paths) {
	b, err := os.ReadFile(p.manifest)
	if err != nil {
		outln(out, "fetch:    no manifest (never fetched)")
		return
	}
	var m fetchManifest
	if json.Unmarshal(b, &m) != nil {
		outln(out, "fetch:    manifest unreadable")
		return
	}
	files := 0
	for _, fs := range m.Sources {
		files += len(fs)
	}
	outf(out, "fetch:    %d files from %d sources at %s\n", files, len(m.Sources), m.FetchedAt.Format(time.RFC3339))
}

func printStageCounts(out io.Writer, p paths) {
	for label, path := range map[string]string{"nodes": p.nodes, "filtered": p.filtered} {
		n, err := countLines(path)
		if err != nil || n == 0 {
			outf(out, "%-9s empty\n", label+":")
			continue
		}
		outf(out, "%-9s %d\n", label+":", n)
	}
}

func printProbeStatus(out io.Writer, p paths) {
	results, err := store.ReadProbeResults(p.probeResults)
	if err != nil || len(results) == 0 {
		outln(out, "probe:    empty")
		return
	}
	alive := 0
	for _, r := range results {
		if r.Alive {
			alive++
		}
	}
	outf(out, "probe:    %d results logged, %d alive (latest wave per node)\n", len(results), alive)
}

func printGeoStatus(out io.Writer, p paths) {
	recs, err := store.ReadGeo(p.geoBase)
	if err != nil || len(recs) == 0 {
		outln(out, "geo:      empty")
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
	outf(out, "geo:      %d records, %d alive, %d countries, traffic folded: %d up / %d down bytes\n",
		len(recs), alive, len(countries), up, down)
}

func printSelectionStatus(out io.Writer, p paths) {
	sel, err := store.ReadSelection(p.selection)
	if err != nil || sel == nil {
		outln(out, "select:   empty")
		return
	}
	byCountry := map[string]int{}
	for _, n := range sel.Nodes {
		byCountry[n.Country]++
	}
	outf(out, "select:   %d active (cap %d) %v\n", len(sel.Nodes), sel.CapApplied, byCountry)
}

func printRenderStatus(out io.Writer, p paths) {
	st, err := os.Stat(p.rendered)
	if err != nil {
		outln(out, "render:   none")
		return
	}
	outf(out, "render:   %s (%d bytes, %s)\n", p.rendered, st.Size(), st.ModTime().Format(time.RFC3339))
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
