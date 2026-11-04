package cli

// Phase 4 — the `publicvpn status` intelligence dashboard: pipeline funnel,
// global pool quality, provider intelligence table, pairwise overlap view,
// media/unlock summary, and the machine-readable --json payload.
//
// Data sources are FILES ONLY (no network, read-only): the fetch manifest
// (plugin stats + overlap matrix), the probe store, the geo cold base, the
// selection, and provider-history.json (internal/stats owns the model). The
// verdict thresholds follow the dashboard spec's traffic-light bands; the
// per-plugin chip lines below the table keep the pre-Phase-4 bytes (their
// OK/WARNING status stays config-threshold-driven — different semantics,
// deliberately untouched).
//
// Cold start: manifests written before the enrichment pass carry zero
// liveness/quality/overlap data, and provider-history.json may not exist
// yet. Every history/enrichment-derived element degrades to an explicit
// "pending / calibrating" rendering — never a crash, never a fabricated 0%
// presented as a measured fact.
//
// Color contract: internal/ui is the single styling owner. NO_COLOR /
// --color=never switch the ASCII fallbacks pinned in the tests (sparkline
// ladder " ..--==#", funnel bars "=-", verdicts [OK]/[!!]/[XX]); unicode
// table borders stay in both modes (the repo's plain-mode convention).

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/plugins"
	"public_vpn/internal/stats"
	"public_vpn/internal/store"
	"public_vpn/internal/ui"
)

// statusSchemaVersion is the --json document version (dashboard spec §4).
const statusSchemaVersion = "1.0"

// Verdict bands (dashboard spec §3.1 traffic-light hierarchy). Alive bands
// are spec-verbatim; the clean lower bands and the unique-yield bands are
// code-owned completions of the spec's "overlapping → amber, 100% redundant
// → red" semantics (reported as spec deltas, not hidden).
const (
	verdictAliveGreenPct  = 60.0
	verdictAliveAmberPct  = 30.0
	verdictCleanGreenPct  = 70.0
	verdictCleanAmberPct  = 40.0
	verdictUniqueGreenPct = 40.0
	verdictUniqueAmberPct = 15.0
	// verdictUniqueKeepPct opens the explicit KEEP band of the pruning
	// recommendations (high-yield providers).
	verdictUniqueKeepPct = 60.0
)

// Verdict vocabulary (the exact words the table, JSON, and recommendations
// render). NONE marks "no enrichment evidence yet" — a verdict that has not
// been earned, never rendered as a measured OK/WARN/DROP.
const (
	verdictOK   = "OK"
	verdictWarn = "WARN"
	verdictDrop = "DROP"
	verdictNone = "NONE"
)

// asciiVerdicts maps the colored verdict words onto the ASCII fallbacks
// pinned in the tests (dashboard spec §3.2).
var asciiVerdicts = map[string]string{
	verdictOK:   "[OK]",
	verdictWarn: "[!!]",
	verdictDrop: "[XX]",
	verdictNone: "n/a",
}

// asciiSparkline transliterates the stats.SparklineGlyphs ladder onto the
// pinned ASCII ladder " ..--==#" (one ASCII glyph per unicode level — the
// computation stays in internal/stats, only the rendering falls back).
var asciiSparkline = map[rune]string{
	' ': " ",
	'▂': ".",
	'▃': ".",
	'▄': "-",
	'▅': "-",
	'▆': "=",
	'▇': "=",
	'█': "#",
}

// sparklineTrendWaves is how many history waves the table renders.
const sparklineTrendWaves = 6

// providerNameCap is the width-guard from the spec (§3.2): longer provider
// ids truncate with an ellipsis.
const providerNameCap = 20

// overlapLabelCap caps each partner label inside the Primary Overlap cell.
const overlapLabelCap = 12

// regionTop shows at most this many named regions before folding the rest.
const regionTop = 8

// mediaRegionTop shows at most this many distinct YouTube regions.
const mediaRegionTop = 3

// regionUnknown is the bucket code for records without geo evidence (the
// pool_unknown pseudo-group's raw key, W16).
const regionUnknown = "unknown"

// ---------------------------------------------------------------------------
// Collection (one read-only pass over the data dir)
// ---------------------------------------------------------------------------

// stageCounts carries the line counts behind the stage chips and the funnel.
type stageCounts struct {
	Nodes    int
	Filtered int
}

// regionCount is one region bucket of the geo base.
type regionCount struct {
	Code  string
	Count int
}

// mediaIntel aggregates the Phase-1 unlock vocabulary over checked records.
// Counts are keyed by the model.Unlock* constants; only observed keys are
// present.
type mediaIntel struct {
	Probed         int
	ChatGPT        map[string]int
	Netflix        map[string]int
	YouTubeOK      int
	YouTubeBlocked int
	YouTubeRegions []string
	RiskSum        float64
	RiskN          int
}

// geoIntel aggregates the cold base for the quality/media sections and the
// funnel's geo-clean stage. Classified counts only records with Phase-1
// evidence: legacy records decode every flag false/0, and counting them as
// "clean" would fabricate a 100%-clean pool.
type geoIntel struct {
	Records        int
	Classified     int
	Clean          int
	Hosting        int
	Proxy          int
	Residential    int
	Tagged         int
	UnknownCountry int
	Regions        []regionCount
	Media          mediaIntel
	cleanAlive     int // alive ∧ ¬hosting ∧ ¬proxy — the funnel's Geo Clean stage
}

// GeoCleanAlive exposes the funnel's geo-clean count.
func (g *geoIntel) GeoCleanAlive() int { return g.cleanAlive }

// residentialPct is the clean-residential share of classified nodes.
func (g *geoIntel) residentialPct() float64 {
	return pctOf(g.Residential, g.Classified)
}

// funnelStage is one row of the pipeline funnel.
type funnelStage struct {
	Name  string
	Count int
	Note  string // the drop/transfer annotation entering this stage
}

// providerRow is one provider intelligence table row (manifest stats joined
// with provider history). enriched=false marks a pre-upgrade manifest: the
// liveness/quality columns have no evidence yet and render as pending.
type providerRow struct {
	stats      plugins.PluginStats
	history    *stats.ProviderSeries
	alivePct   float64
	alive24    float64
	cleanPct   float64
	uniquePct  float64
	enriched   bool
	verdict    string
	verdictCol string // ui palette name; "" = no color (NONE)
}

// statusIntel is everything one status run renders, collected once.
type statusIntel struct {
	stages       stageCounts
	funnel       []funnelStage
	geo          geoIntel
	manifest     *fetchManifest
	history      *stats.ProviderHistory
	providers    []providerRow
	configSource string
}

// collectStatusIntel performs the whole read-only collection pass. A missing
// artifact is the documented cold start (empty state); a corrupt one fails
// loud — silent zero rows would mask data damage.
func collectStatusIntel(p paths, configSource string) (*statusIntel, error) {
	si := &statusIntel{configSource: configSource}

	si.stages.Nodes, _ = countLines(p.nodes)
	si.stages.Filtered, _ = countLines(p.filtered)

	probes, err := store.ReadProbeResults(p.probeResults)
	if err != nil {
		return nil, fmt.Errorf("status: read probe results: %w", err)
	}
	alive := 0
	for _, r := range probes {
		if r.Alive {
			alive++
		}
	}

	geoRecs, err := store.ReadGeo(p.geoBase)
	if err != nil {
		return nil, fmt.Errorf("status: read geo base: %w", err)
	}
	si.geo = aggregateGeo(geoRecs)

	sel, err := store.ReadSelection(p.selection)
	if err != nil {
		return nil, fmt.Errorf("status: read selection: %w", err)
	}
	selected := 0
	if sel != nil {
		selected = len(sel.Nodes)
	}

	si.funnel = buildFunnel(si.stages, len(probes), alive, si.geo.GeoCleanAlive(), selected)

	if b, err := os.ReadFile(p.manifest); err == nil {
		var m fetchManifest
		//nolint:musttag // fetchManifest has JSON tags; musttag false positive
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("status: decode manifest: %w", err)
		}
		si.manifest = &m
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("status: read manifest: %w", err)
	}

	history, err := stats.ReadProviderHistory(filepath.Join(p.dataDir, providerHistoryFile))
	if err != nil {
		return nil, fmt.Errorf("status: read provider history: %w", err)
	}
	si.history = history

	si.providers = buildProviderRows(si.manifest, history, time.Now())
	return si, nil
}

// aggregateGeo folds the cold base into quality, region, and media views.
func aggregateGeo(recs []*model.GeoRecord) geoIntel {
	g := geoIntel{
		Records: len(recs),
		Media: mediaIntel{
			ChatGPT: map[string]int{},
			Netflix: map[string]int{},
		},
	}
	countries := map[string]int{}
	for _, r := range recs {
		if r.Country != "" {
			countries[r.Country]++
			g.Tagged++
		} else {
			g.UnknownCountry++
		}
		if r.Alive && !r.HostingFlag && !r.ProxyFlag {
			g.cleanAlive++
		}
		if phase1Evidence(r) {
			g.Classified++
			switch {
			case r.IsProxy:
				g.Proxy++
			case r.IsHosting:
				g.Hosting++
			default:
				g.Clean++
			}
			if r.IsResidential {
				g.Residential++
			}
		}
		collectMedia(&g.Media, r)
	}
	g.Regions = topRegions(countries, g.UnknownCountry)
	return g
}

// phase1Evidence reports whether a cold-base record carries ANY Phase-1
// quality evidence. Legacy records decode every flag as false/0, so an
// all-zero record is treated as unclassified — never counted as "clean"
// evidence it does not have.
func phase1Evidence(r *model.GeoRecord) bool {
	return r.IsHosting || r.IsProxy || r.IsResidential || r.IsMobile ||
		r.IPType != "" || r.RiskScore > 0
}

// collectMedia folds one record's unlock vocabulary into the aggregates.
// Only records with a CheckedAt stamp count as probed; RiskScore folds
// whenever the record carries a score (≥ 0 — the -1 unchecked sentinel is
// excluded by the contract).
func collectMedia(m *mediaIntel, r *model.GeoRecord) {
	mu := r.MediaUnlocks
	if mu.CheckedAt == "" {
		return
	}
	m.Probed++
	if mu.ChatGPT != "" {
		m.ChatGPT[mu.ChatGPT]++
	}
	if mu.Netflix != "" {
		m.Netflix[mu.Netflix]++
	}
	switch mu.YouTubeRegion {
	case "":
		// never probed for this service
	case model.UnlockBlocked:
		m.YouTubeBlocked++
	case model.UnlockUnknown:
		// probed, no definite answer — neither unlock nor block
	default:
		m.YouTubeOK++
		if !containsString(m.YouTubeRegions, mu.YouTubeRegion) {
			m.YouTubeRegions = append(m.YouTubeRegions, mu.YouTubeRegion)
		}
	}
	if r.RiskScore >= 0 {
		m.RiskSum += float64(r.RiskScore)
		m.RiskN++
	}
}

// topRegions sorts named countries descending (code ascending on ties) and
// appends the unknown bucket last when present.
func topRegions(countries map[string]int, unknown int) []regionCount {
	out := make([]regionCount, 0, len(countries)+1)
	for code, n := range countries {
		out = append(out, regionCount{Code: code, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Code < out[j].Code
	})
	if unknown > 0 {
		out = append(out, regionCount{Code: regionUnknown, Count: unknown})
	}
	return out
}

// buildFunnel assembles the six funnel stages with short drop annotations.
// Store inversions (a later stage holding more than the previous one —
// probe results accumulate latest-per-key across waves while filtered is
// one wave's output) render honestly as "+" transfers, never as negative
// drops.
func buildFunnel(stages stageCounts, probed, alive, geoClean, selected int) []funnelStage {
	transfer := func(delta int, drop, gain string) string {
		switch {
		case delta < 0:
			return fmt.Sprintf("-%s %s", formatCount(-delta), drop)
		case delta > 0:
			return fmt.Sprintf("+%s %s", formatCount(delta), gain)
		default:
			return "no change"
		}
	}
	return []funnelStage{
		{Name: "Fetched", Count: stages.Nodes},
		{Name: "Filtered", Count: stages.Filtered,
			Note: transfer(stages.Filtered-stages.Nodes, "filter policy", "filter gain")},
		{Name: "Probed", Count: probed,
			Note: transfer(probed-stages.Filtered, "probe coverage", "accumulated store (latest-per-key)")},
		{Name: "Alive", Count: alive,
			Note: transfer(alive-probed, "dead / unreachable", "store carries more alive keys")},
		{Name: "Geo Clean", Count: geoClean,
			Note: transfer(geoClean-alive, "hosting/proxy exits + geo fold", "geo fold ahead of probe store")},
		{Name: "Selected", Count: selected,
			Note: transfer(selected-geoClean, "rank cut", "rank admits beyond geo fold")},
	}
}

// buildProviderRows joins manifest stats with provider history and computes
// the verdict per the spec bands. Enrichment detection: a manifest from the
// pre-upgrade binary carries zero LiveNodes/CleanCount in EVERY row — such
// a manifest has no liveness evidence at all, so no row may present a
// measured verdict. (The enrichment pass rewrites these fields after every
// full wave; a genuine all-dead pool is a pathological corner that renders
// as pending — documented, honest.)
func buildProviderRows(m *fetchManifest, history *stats.ProviderHistory, now time.Time) []providerRow {
	if m == nil || len(m.PluginStats) == 0 {
		return nil
	}
	enriched := false
	for _, st := range m.PluginStats {
		if st.LiveNodes > 0 || st.CleanCount > 0 || st.HostingCount > 0 || st.ProxyCount > 0 {
			enriched = true
			break
		}
	}
	rows := make([]providerRow, 0, len(m.PluginStats))
	for _, st := range m.PluginStats {
		row := providerRow{stats: st, enriched: enriched, verdict: verdictNone}
		if st.TotalNodes > 0 {
			row.alivePct = float64(st.LiveNodes) * 100 / float64(st.TotalNodes)
		}
		// Honest clean share (owner ruling 2026-11-04, adversarial review
		// F6): classified-only numerator AND denominator —
		// CleanCount/ClassifiedCount; 0 when nothing is geo-classified.
		// The old Clean/TotalNodes mixed a classified numerator into a
		// pre-filter denominator and folded never-geo'd nodes into clean.
		row.cleanPct = st.CleanPercent()
		row.uniquePct = st.UniqueYield
		if series := history.Providers[st.PluginID]; series != nil {
			row.history = series
			row.alive24 = stats.WeightedLiveness(series.Waves, now) * 100
		}
		if enriched {
			row.verdict, row.verdictCol = providerVerdict(row.alivePct, row.cleanPct, row.uniquePct)
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].stats.PluginID < rows[j].stats.PluginID })
	return rows
}

// providerVerdict applies the spec traffic-light bands: worst class wins.
func providerVerdict(alivePct, cleanPct, uniquePct float64) (string, string) {
	class := ui.Green
	worst := func(pct, green, amber float64) {
		switch {
		case pct < amber:
			class = ui.Red
		case pct < green && class != ui.Red:
			class = ui.Amber
		}
	}
	worst(alivePct, verdictAliveGreenPct, verdictAliveAmberPct)
	worst(cleanPct, verdictCleanGreenPct, verdictCleanAmberPct)
	worst(uniquePct, verdictUniqueGreenPct, verdictUniqueAmberPct)
	switch class {
	case ui.Red:
		return verdictDrop, ui.Red
	case ui.Amber:
		return verdictWarn, ui.Amber
	default:
		return verdictOK, ui.Green
	}
}

// ---------------------------------------------------------------------------
// Dashboard rendering (standard view)
// ---------------------------------------------------------------------------

// funnelBarWidth is the proportional bar's fixed cell width.
const funnelBarWidth = 20

// printPipelineFunnel renders the six-stage funnel as the shared bordered
// table: stage, count, proportional bar with the survival share, and the
// drop annotation. Bars stay uncolored on purpose — the numbers speak, and
// every stage below the top would otherwise scream red.
func printPipelineFunnel(out io.Writer, si *statusIntel, color bool) {
	outln(out, ui.Header("pipeline funnel", color))
	base := si.funnel[0].Count
	rows := make([][]ui.Cell, 0, len(si.funnel))
	cols := []ui.Column{
		{Header: "stage", Width: 10},
		{Header: "nodes", Width: 9, Right: true},
		{Header: "survival", Width: 28},
		{Header: "drop note", Width: 40},
	}
	for i, st := range si.funnel {
		share := 0.0
		switch {
		case base > 0:
			share = float64(st.Count) * 100 / float64(base)
		case i == 0:
			// An all-zero funnel renders the fetched base as full and every
			// later stage as empty — never a fabricated full funnel.
			share = 100.0
		}
		note := st.Note
		if note == "" {
			note = "base"
		}
		rows = append(rows, []ui.Cell{
			{S: st.Name},
			{S: formatCount(st.Count)},
			{S: funnelBar(share, color)},
			{S: note, Color: ui.ColorPlainName},
		})
	}
	outf(out, "%s", ui.Table(cols, rows, color))
}

// funnelBar renders the proportional bar: █/░ under color, =/- in the
// pinned ASCII fallback (spec §3.2; the mockup's ">" arrowhead is dropped —
// one ladder, pinned in tests).
func funnelBar(pct float64, color bool) string {
	filled := int(pct / 100 * float64(funnelBarWidth))
	filled = min(max(filled, 0), funnelBarWidth)
	full, empty := "█", "░"
	if !color {
		full, empty = "=", "-"
	}
	return strings.Repeat(full, filled) + strings.Repeat(empty, funnelBarWidth-filled) +
		fmt.Sprintf(" %.1f%%", pct)
}

// printGlobalQuality renders the classified-pool quality and the regional
// spread. Zero classified records is the explicit cold start — the geo
// unlock stage has never classified anything, and claiming a 100% clean
// pool from flag-less legacy records would be fabrication.
func printGlobalQuality(out io.Writer, g *geoIntel, color bool) {
	outln(out, ui.Header("global quality & pool distribution", color))
	if g.Classified == 0 {
		outf(out, "%s\n", ui.ChipKV("quality:   ",
			"no ip-quality evidence yet — the geo unlock stage has not classified any node", color))
	} else {
		outf(out, "%s\n", ui.ChipKV("quality:   ", fmt.Sprintf(
			"%s classified — clean %s (%.1f%%), hosting %s (%.1f%%), proxy %s (%.1f%%)",
			formatCount(g.Classified),
			formatCount(g.Clean), pctOf(g.Clean, g.Classified),
			formatCount(g.Hosting), pctOf(g.Hosting, g.Classified),
			formatCount(g.Proxy), pctOf(g.Proxy, g.Classified)), color))
		outf(out, "%s\n", ui.ChipKV("residential: ",
			fmt.Sprintf("%.1f%% clean-residential (%s of %s classified)",
				g.residentialPct(), formatCount(g.Residential), formatCount(g.Classified)), color))
	}
	outf(out, "%s\n", ui.ChipKV("regions:   ", formatRegions(g), color))
}

// formatRegions renders the top region buckets with the unknown tail.
func formatRegions(g *geoIntel) string {
	if len(g.Regions) == 0 {
		return "no geo records"
	}
	parts := make([]string, 0, regionTop)
	named := 0
	for _, r := range g.Regions {
		if r.Code == regionUnknown {
			continue
		}
		if named < regionTop {
			parts = append(parts, fmt.Sprintf("%s %s", r.Code, formatCount(r.Count)))
		}
		named++
	}
	var b strings.Builder
	b.WriteString(formatCount(g.Tagged) + " tagged")
	if g.UnknownCountry > 0 {
		b.WriteString(", " + formatCount(g.UnknownCountry) + " " + regionUnknown)
	}
	if len(parts) > 0 {
		b.WriteString(" — top: ")
		b.WriteString(strings.Join(parts, ", "))
		if named > regionTop {
			b.WriteString(" (+")
			b.WriteString(strconv.Itoa(named - regionTop))
			b.WriteString(" more)")
		}
	}
	return b.String()
}

// printMediaSummary renders the global Phase-1 unlock aggregates. Everything
// derives from records with a CheckedAt stamp — unchecked vocabulary never
// leaks into counts.
func printMediaSummary(out io.Writer, m *mediaIntel, color bool) {
	outln(out, ui.Header("media & unlock summary", color))
	if m.Probed == 0 {
		outf(out, "%s\n", ui.ChipKV("media:     ",
			"no unlock evidence yet — the [geo].unlock_probes stage has not run", color))
		return
	}
	outf(out, "%s\n", ui.ChipKV("media:     ", fmt.Sprintf("%s exits probed — chatgpt %s, netflix %s",
		formatCount(m.Probed), formatVocab(m.ChatGPT), formatVocab(m.Netflix)), color))
	yt := fmt.Sprintf("%d unlocked", m.YouTubeOK)
	if len(m.YouTubeRegions) > 0 {
		shown := m.YouTubeRegions
		if len(shown) > mediaRegionTop {
			yt += fmt.Sprintf(" across %s (+%d more)",
				strings.Join(shown[:mediaRegionTop], "/"), len(m.YouTubeRegions)-mediaRegionTop)
		} else {
			yt += " across " + strings.Join(shown, "/")
		}
	}
	yt += fmt.Sprintf(", %d blocked", m.YouTubeBlocked)
	outf(out, "%s\n", ui.ChipKV("  youtube: ", yt, color))
	risk := "no risk scores yet"
	if m.RiskN > 0 {
		risk = fmt.Sprintf("mean risk %.1f (0–100) over %s scored exits",
			m.RiskSum/float64(m.RiskN), formatCount(m.RiskN))
	}
	outf(out, "%s\n", ui.ChipKV("  risk:    ", risk, color))
}

// formatVocab renders one unlock-status counter map as "yes 40 / blocked 12"
// (keys sorted; empty map → "no data").
func formatVocab(counts map[string]int) string {
	if len(counts) == 0 {
		return "no data"
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, counts[k]))
	}
	return strings.Join(parts, " / ")
}

// ---------------------------------------------------------------------------
// Provider intelligence table
// ---------------------------------------------------------------------------

// printStageCounts renders the pre-Phase-4 stage chips byte-stably (moved
// from pipeline.go; empty and unreadable both print "empty" as before). The
// fixed iteration order replaces the old map iteration's random chip order —
// status output must be deterministic.
func printStageCounts(out io.Writer, sc stageCounts, color bool) {
	chips := []struct {
		label string
		count int
	}{
		{"nodes", sc.Nodes},
		{"filtered", sc.Filtered},
	}
	for _, chip := range chips {
		value := strconv.Itoa(chip.count)
		if chip.count == 0 {
			value = "empty"
		}
		outf(out, "%s\n", ui.ChipKV(fmt.Sprintf("%-9s ", chip.label+":"), value, color))
	}
}

// printPluginLivenessStatus renders the plugins section: the intelligence
// table (Phase 4) followed by the pre-Phase-4 per-plugin chip lines, which
// keep their exact legacy bytes (the status golden surface; their
// OK/WARNING stays config-threshold-driven).
func printPluginLivenessStatus(out io.Writer, si *statusIntel, cfg *config.Config, color bool) {
	if si.manifest == nil {
		outln(out, ui.ChipKV("plugins:  ", "no manifest", color))
		return
	}
	if len(si.manifest.PluginStats) == 0 {
		outln(out, ui.ChipKV("plugins:  ", "no plugin stats", color))
		return
	}

	outln(out, ui.Header("provider intelligence", color))
	printProviderIntelTable(out, si, color)
	if len(si.providers) > 0 && !si.providers[0].enriched {
		outf(out, "%s\n", ui.ChipKV("  pending: ",
			"liveness/quality columns fill after the plugin-stats enrichment pass (next full wave)", color))
	}

	// --- legacy chip lines (byte-stable) ---
	outln(out, ui.ChipKV("plugins:  ", "", color))
	printPluginChipsLegacy(out, si.manifest.PluginStats, cfg, color)
}

// printPluginChipsLegacy renders the pre-Phase-4 per-plugin chip lines
// byte-stably (moved from pipeline.go; the OK/WARNING status stays driven by
// the config's plugin thresholds — different semantics from the dashboard
// verdict above, deliberately untouched).
func printPluginChipsLegacy(out io.Writer, rows []plugins.PluginStats, cfg *config.Config, color bool) {
	var maxDupPct, minLivePct *float64
	if cfg != nil && cfg.Plugins.MaxDuplicatePercent != nil {
		maxDupPct = cfg.Plugins.MaxDuplicatePercent
	}
	if cfg != nil && cfg.Plugins.MinLivePercent != nil {
		minLivePct = cfg.Plugins.MinLivePercent
	}

	for _, st := range rows {
		livePct, dupPct, hostingPct, proxyPct, cleanPct := 0.0, 0.0, 0.0, 0.0, 0.0
		if st.TotalNodes > 0 {
			livePct = float64(st.LiveNodes) * 100.0 / float64(st.TotalNodes)
			dupPct = float64(st.DuplicateCount) * 100.0 / float64(st.TotalNodes)
			hostingPct = float64(st.HostingCount) * 100.0 / float64(st.TotalNodes)
			proxyPct = float64(st.ProxyCount) * 100.0 / float64(st.TotalNodes)
			cleanPct = float64(st.CleanCount) * 100.0 / float64(st.TotalNodes)
		}

		status := "OK"
		statusColor := ui.Green
		if maxDupPct != nil && dupPct > *maxDupPct {
			status = "WARNING"
			statusColor = ui.Amber
		}
		if minLivePct != nil && livePct < *minLivePct {
			status = "WARNING"
			statusColor = ui.Amber
		}

		statsLine := fmt.Sprintf(
			"total=%d live=%d (%.1f%%) dup=%d (%.1f%%) hosting=%d (%.1f%%) proxy=%d (%.1f%%) clean=%d (%.1f%%) status=%s",
			st.TotalNodes, st.LiveNodes, livePct,
			st.DuplicateCount, dupPct,
			st.HostingCount, hostingPct,
			st.ProxyCount, proxyPct,
			st.CleanCount, cleanPct,
			status,
		)

		pluginLabel := fmt.Sprintf("plugin %-8s ", st.PluginID+":")
		pluginLine := ui.ChipKV(pluginLabel, statsLine, color)

		if color {
			coloredStatus := ui.Colorize(statusColor, status, true)
			pluginLine = strings.Replace(pluginLine, "status="+status, "status="+coloredStatus, 1)
		}

		outf(out, "%s\n", pluginLine)
	}
}

// printProviderIntelTable renders the spec §2.3 table: provider, total,
// current alive with share, 24h volume-weighted average, the history
// sparkline + trend (all history math lives in internal/stats), clean %,
// unique %, top-2 overlap, and the verdict chip.
func printProviderIntelTable(out io.Writer, si *statusIntel, color bool) {
	cols := []ui.Column{
		{Header: "provider", Width: providerNameCap},
		{Header: "total", Width: 8, Right: true},
		{Header: "alive", Width: 13, Right: true},
		{Header: "24h avg", Width: 8, Right: true},
		{Header: "trend", Width: 10},
		{Header: "clean %", Width: 8, Right: true},
		{Header: "unique %", Width: 8, Right: true},
		{Header: "primary overlap", Width: 18},
		{Header: "verdict", Width: 8},
	}
	rows := make([][]ui.Cell, 0, len(si.providers))
	for _, row := range si.providers {
		aliveCell, avgCell, cleanCell, uniqueCell := "n/a", "n/a", "n/a", "n/a"
		trendCell := "calibrating"
		if row.enriched {
			aliveCell = fmt.Sprintf("%d (%.1f%%)", row.stats.LiveNodes, row.alivePct)
			avgCell = fmt.Sprintf("%.1f%%", row.alive24)
			cleanCell = fmt.Sprintf("%.1f%%", row.cleanPct)
			uniqueCell = fmt.Sprintf("%.1f%%", row.uniquePct)
		}
		if row.history != nil {
			spark := row.history.Sparkline(sparklineTrendWaves)
			if !color {
				spark = asciiSparklineString(spark)
			}
			trendCell = strings.TrimRight(spark+" "+row.history.Trend(), " ")
		}
		verdictCell := asciiVerdicts[row.verdict]
		verdictColor := ""
		if color {
			verdictCell = row.verdict
			verdictColor = row.verdictCol
		}
		rows = append(rows, []ui.Cell{
			{S: truncateName(row.stats.PluginID, providerNameCap)},
			{S: formatCount(row.stats.TotalNodes)},
			{S: aliveCell},
			{S: avgCell},
			{S: trendCell},
			{S: cleanCell},
			{S: uniqueCell},
			{S: overlapCell(row.stats.TopOverlaps)},
			{S: verdictCell, Color: verdictColor},
		})
	}
	outf(out, "%s", ui.Table(cols, rows, color))
}

// overlapCell renders the top-2 overlap partners "matin 61%, mhd 18%".
func overlapCell(pairs []plugins.OverlapPair) string {
	if len(pairs) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%s %.0f%%", truncateName(p.PluginID, overlapLabelCap), p.Percent))
	}
	return strings.Join(parts, ", ")
}

// truncateName applies the spec width guard: longer names cut at the cap
// with an ellipsis.
func truncateName(name string, limit int) string {
	r := []rune(name)
	if len(r) <= limit {
		return name
	}
	return string(r[:limit-1]) + "…"
}

// asciiSparklineString transliterates a stats sparkline onto the pinned
// ASCII ladder; unknown runes pass through (the ladder itself is pinned by
// stats' own tests).
func asciiSparklineString(spark string) string {
	var b strings.Builder
	for _, r := range spark {
		if a, ok := asciiSparkline[r]; ok {
			b.WriteString(a)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Overlap view (--overlap / -v)
// ---------------------------------------------------------------------------

// printOverlapMatrix renders the pairwise identity-overlap matrix plus the
// pruning recommendations (spec §1.2). A manifest without the matrix is the
// documented cold start: the enrichment pass computes it after geo.
func printOverlapMatrix(out io.Writer, si *statusIntel, color bool) {
	outln(out, ui.Header("provider overlap inspection", color))
	m := si.manifestOverlap()
	if m == nil {
		outf(out, "%s\n", ui.ChipKV("overlap:   ",
			"matrix not computed yet — the plugin-stats enrichment pass builds it after the geo stage", color))
		printRecommendations(out, si, color)
		return
	}
	ids := overlapIDs(m)
	header := make([]ui.Column, 0, len(ids)+1)
	header = append(header, ui.Column{Header: "provider", Width: 10})
	for _, id := range ids {
		header = append(header, ui.Column{Header: truncateName(id, 8), Width: 7, Right: true})
	}
	rows := make([][]ui.Cell, 0, len(ids))
	for _, a := range ids {
		row := make([]ui.Cell, 0, len(ids)+1)
		row = append(row, ui.Cell{S: truncateName(a, 10)})
		for _, b := range ids {
			row = append(row, ui.Cell{S: fmt.Sprintf("%.0f%%", m.Cells[a][b])})
		}
		rows = append(rows, row)
	}
	outf(out, "%s", ui.Table(header, rows, color))
	printRecommendations(out, si, color)
}

// manifestOverlap resolves the overlap matrix (nil-safe on cold manifests).
func (si *statusIntel) manifestOverlap() *plugins.OverlapMatrix {
	if si.manifest == nil {
		return nil
	}
	return si.manifest.PluginOverlap
}

// overlapIDs returns the matrix row/column order: sorted plugin ids.
func overlapIDs(m *plugins.OverlapMatrix) []string {
	ids := make([]string, 0, len(m.Sets))
	for id := range m.Sets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// recommendations derives the pruning/keep advice from the provider rows
// (deterministic: top-overlap percentage descending, id ascending on ties).
// Bands: <15% unique = prune candidate, ≥60% unique = explicit keep. The
// middle band stays silent — advice only where the signal is strong.
func recommendations(rows []providerRow) []string {
	type cand struct {
		id      string
		unique  float64
		topWith string
		topPct  float64
	}
	var cands []cand
	for _, r := range rows {
		if !r.enriched || len(r.stats.TopOverlaps) == 0 {
			continue
		}
		if r.uniquePct < verdictUniqueAmberPct || r.uniquePct >= verdictUniqueKeepPct {
			top := r.stats.TopOverlaps[0]
			cands = append(cands, cand{
				id:      r.stats.PluginID,
				unique:  r.uniquePct,
				topWith: top.PluginID,
				topPct:  top.Percent,
			})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].topPct != cands[j].topPct {
			return cands[i].topPct > cands[j].topPct
		}
		return cands[i].id < cands[j].id
	})
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		if c.unique < verdictUniqueAmberPct {
			out = append(out, fmt.Sprintf(
				"prune candidate '%s': only %.1f%% unique — %.0f%% shared with %s",
				c.id, c.unique, c.topPct, c.topWith))
			continue
		}
		out = append(out, fmt.Sprintf("keep '%s': %.1f%% unique nodes (low overlap, high yield)",
			c.id, c.unique))
	}
	return out
}

// printRecommendations renders the numbered pruning block.
func printRecommendations(out io.Writer, si *statusIntel, color bool) {
	recs := recommendations(si.providers)
	if len(recs) == 0 {
		outf(out, "%s\n", ui.ChipKV("advice:    ",
			"no strong pruning signal — pending enrichment data", color))
		return
	}
	for i, r := range recs {
		outf(out, "%s\n", ui.ChipKV(fmt.Sprintf("  %d. ", i+1), r, color))
	}
}

// ---------------------------------------------------------------------------
// Machine-readable payload (--json)
// ---------------------------------------------------------------------------

// The wire structs pin the documented schema (dashboard spec §4). Field
// names are a contract — the JSON tests pin them byte-exactly.
type statusJSONDoc struct {
	SchemaVersion   string               `json:"schema_version"`
	GeneratedAt     string               `json:"generated_at"`
	ConfigSource    string               `json:"config_source"`
	Pipeline        statusJSONPipeline   `json:"pipeline"`
	GlobalQuality   statusJSONQuality    `json:"global_quality"`
	Providers       []statusJSONProvider `json:"providers"`
	OverlapMatrix   []statusJSONOverlap  `json:"overlap_matrix"`
	Recommendations []string             `json:"recommendations"`
}

type statusJSONPipeline struct {
	Fetched  int `json:"fetched"`
	Filtered int `json:"filtered"`
	Probed   int `json:"probed"`
	Alive    int `json:"alive"`
	GeoClean int `json:"geo_clean"`
	Selected int `json:"selected"`
}

type statusJSONQuality struct {
	ResidentialPct float64            `json:"residential_pct"`
	HostingPct     float64            `json:"hosting_pct"`
	Regional       []statusJSONRegion `json:"regional"`
}

type statusJSONRegion struct {
	Code string  `json:"code"`
	Pct  float64 `json:"pct"`
}

type statusJSONProvider struct {
	ID           string           `json:"id"`
	TotalParsed  int              `json:"total_parsed"`
	AliveCurrent int              `json:"alive_current"`
	Alive24hAvg  float64          `json:"alive_24h_avg"`
	AlivePct     float64          `json:"alive_pct"`
	CleanPct     float64          `json:"clean_pct"`
	UniquePct    float64          `json:"unique_pct"`
	Sparkline    []float64        `json:"sparkline"`
	Overlaps     []statusJSONPair `json:"overlaps"`
	Verdict      string           `json:"verdict"`
}

type statusJSONPair struct {
	With string  `json:"with"`
	Pct  float64 `json:"pct"`
}

type statusJSONOverlap struct {
	A         string  `json:"a"`
	B         string  `json:"b"`
	SharedPct float64 `json:"shared_pct"`
}

// emitStatusJSON writes the machine-readable payload. The dashboard is
// bypassed entirely; the JSON is color-independent by construction.
func emitStatusJSON(out io.Writer, si *statusIntel) error {
	doc := statusJSONDoc{
		SchemaVersion: statusSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		ConfigSource:  si.configSource,
		Pipeline: statusJSONPipeline{
			Fetched:  si.funnel[0].Count,
			Filtered: si.funnel[1].Count,
			Probed:   si.funnel[2].Count,
			Alive:    si.funnel[3].Count,
			GeoClean: si.funnel[4].Count,
			Selected: si.funnel[5].Count,
		},
		GlobalQuality: statusJSONQuality{
			ResidentialPct: round6(si.geo.residentialPct()),
			HostingPct:     round6(pctOf(si.geo.Hosting, si.geo.Classified)),
			Regional:       jsonRegions(si.geo),
		},
		Providers:       jsonProviders(si.providers),
		OverlapMatrix:   jsonOverlap(si.manifestOverlap()),
		Recommendations: recommendations(si.providers),
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("status: marshal json: %w", err)
	}
	outf(out, "%s\n", string(b))
	return nil
}

// jsonRegions maps the region buckets onto the wire shape (percent of all
// records; empty base → empty list).
func jsonRegions(g geoIntel) []statusJSONRegion {
	if g.Records == 0 {
		return []statusJSONRegion{}
	}
	out := make([]statusJSONRegion, 0, len(g.Regions))
	for _, r := range g.Regions {
		out = append(out, statusJSONRegion{
			Code: r.Code,
			Pct:  round6(float64(r.Count) * 100 / float64(g.Records)),
		})
	}
	return out
}

// jsonProviders maps the rows onto the wire shape; the sparkline carries the
// last ≤6 waves' liveness rates in percent (empty history → []).
func jsonProviders(rows []providerRow) []statusJSONProvider {
	out := make([]statusJSONProvider, 0, len(rows))
	for _, r := range rows {
		spark := []float64{}
		if r.history != nil {
			n := min(len(r.history.Waves), sparklineTrendWaves)
			for _, w := range r.history.Waves[len(r.history.Waves)-n:] {
				spark = append(spark, round6(stats.LivenessRate(w)*100))
			}
		}
		overlaps := make([]statusJSONPair, 0, len(r.stats.TopOverlaps))
		for _, p := range r.stats.TopOverlaps {
			overlaps = append(overlaps, statusJSONPair{With: p.PluginID, Pct: round6(p.Percent)})
		}
		out = append(out, statusJSONProvider{
			ID:           r.stats.PluginID,
			TotalParsed:  r.stats.TotalNodes,
			AliveCurrent: r.stats.LiveNodes,
			Alive24hAvg:  round6(r.alive24),
			AlivePct:     round6(r.alivePct),
			CleanPct:     round6(r.cleanPct),
			UniquePct:    round6(r.uniquePct),
			Sparkline:    spark,
			Overlaps:     overlaps,
			Verdict:      r.verdict,
		})
	}
	return out
}

// jsonOverlap flattens the upper triangle (a < b, both ascending) of the
// pairwise matrix; a cold manifest yields an empty list.
func jsonOverlap(m *plugins.OverlapMatrix) []statusJSONOverlap {
	out := []statusJSONOverlap{}
	if m == nil {
		return out
	}
	ids := overlapIDs(m)
	for i, a := range ids {
		for _, b := range ids[i+1:] {
			out = append(out, statusJSONOverlap{A: a, B: b, SharedPct: round6(m.Cells[a][b])})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Small shared formatters
// ---------------------------------------------------------------------------

// formatCount renders counts with comma-grouped thousands (the spec
// mockup's "14,208" formatting).
func formatCount(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	head := len(s) % 3
	if head > 0 {
		b.WriteString(s[:head])
	}
	for i := head; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// pctOf is a division guard shared by the quality chips.
func pctOf(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

// round6 clamps wire floats to 1e-6 (the store's determinism convention).
func round6(f float64) float64 {
	return math.Round(f*1e6) / 1e6
}

// containsString is a membership helper over the distinct YouTube regions.
func containsString(list []string, s string) bool {
	return slices.Contains(list, s)
}
