package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	"public_vpn/internal/rank"
	"public_vpn/internal/render"
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
		Token:       cfg.Fetch.GitHubToken,
		Timeout:     cfg.Fetch.Timeout.Duration,
		Retries:     cfg.Fetch.Retries,
		Concurrency: cfg.Fetch.Concurrency,
	})
	manifest := fetchManifest{FetchedAt: time.Now().UTC(), Sources: map[string][]fetch.FetchedFile{}}
	totalFiles, failed := 0, 0
	for id, src := range cfg.Sources {
		if !src.IsEnabled() {
			outf(cmd.OutOrStdout(), "source %-10s disabled, skipped\n", id)
			continue
		}
		files, err := cl.SourceCached(context.Background(), id, src, p.cacheDir)
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
	for id, files := range manifest.Sources {
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
	opts := []filter.Option{}
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
			StatsPort:  cfg.Render.StatsPort,
			PoolRoutes: toRenderRoutes(cfg.Render.PoolRoutes),
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

func selectionSize(path string) int {
	sel, err := store.ReadSelection(path)
	if err != nil || sel == nil {
		return 0
	}
	return len(sel.Nodes)
}

func newStatusCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Pipeline state summary (read-only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load(*cfgPath)
			if err != nil {
				return err
			}
			return runStatus(cmd, cfg)
		},
	}
}

func runStatus(cmd *cobra.Command, cfg *config.Config) error {
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
	for _, r := range recs {
		if r.Alive {
			alive++
		}
		if r.Country != "" {
			countries[r.Country] = true
		}
	}
	outf(out, "geo:      %d records, %d alive, %d countries\n", len(recs), alive, len(countries))
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

func newMaintainCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "maintain",
		Short: "Timed maintenance waves (refresh/speedtest/stats poll) — NOT IMPLEMENTED in W1–W3",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("%s: maintain (timers, stats pruning, README) is wave W4 per DESIGN.md §11 — nothing executed",
				notImplemented)
		},
	}
}
