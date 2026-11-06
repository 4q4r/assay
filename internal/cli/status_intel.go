package cli

// Phase 4 — the `publicvpn status` intelligence dashboard: pipeline funnel,
// global pool quality, provider intelligence table, pairwise overlap view,
// media/unlock summary, and the machine-readable --json payload.
//
// Data sources are FILES ONLY (no network, read-only): the fetch manifest
// (plugin stats + overlap matrix), the probe store, the geo cold base, the
// selection, and provider-history.json (internal/stats owns the model).
//
// Verdict engine (owner ruling 2026-11-05, "pool-relative verdicts"): the
// old absolute alive-bands are replaced by a composite score per provider,
// score(P) = Σ w_f × percentile_rank(P.factor_f) over the provider's
// AVAILABLE factors with weights renormalized to 1.0 when a factor drops
// out. Normalization-before-aggregation with per-factor robustness follows
// the OECD/JRC Handbook on Constructing Composite Indicators; absolute
// anchors (metacubexd-style node scoring) are dead in this regime — the
// pool's alive share (~1.5%) would pin every absolute band to its floor.
// The verdict is POINT-IN-TIME: it is derived at render from the current
// pool and never persisted into provider history.
//
// Clean% honesty (owner ruling 2026-11-05): the global quality section, the
// provider table's clean% cell, and the JSON payload all gate on the SAME
// phase1Evidence predicate over the cold geo base — one evidence definition
// everywhere; a provider without Phase-1 evidence renders clean% n/a and
// drops the cleanliness factor from its composite.
//
// Cold start: manifests written before the enrichment pass carry zero
// liveness/quality/overlap data, and provider-history.json may not exist
// yet. Every history/enrichment-derived element degrades to an explicit
// "pending / calibrating" rendering — never a crash, never a fabricated 0%
// presented as a measured fact.
//
// Color contract: internal/ui is the single styling owner. NO_COLOR /
// --color=never switch the ASCII fallbacks pinned in the tests (sparkline
// ladder " ..--==#", funnel bars "=-"); unicode table borders stay in both
// modes (the repo's plain-mode convention). Verdict words are
// self-describing (GOOD/FAIR/WEAK/POOR/DEAD) and render verbatim in plain
// mode; NONE renders n/a.

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

// statusSchemaVersion is the --json document version. 1.1 (owner ruling
// 2026-11-05): clean_pct and classified_coverage_pct are nullable floats —
// null means "no Phase-1 evidence", never a fabricated 0.
const statusSchemaVersion = "1.1"

// Verdict bands for the pool-relative composite score (0..100 after the
// trend modifier, clamped): ≥75 GOOD, 50–75 FAIR, 25–50 WEAK, <25 POOR.
const (
	verdictGoodFloorPct = 75.0
	verdictFairFloorPct = 50.0
	verdictWeakFloorPct = 25.0
)

// Composite factor weights (owner-specified, Σ=1.0). The cleanliness weight
// participates ONLY when Phase-1 evidence exists for the provider; the
// remaining available weights renormalize to 1.0 (OECD/JRC: aggregate only
// normalized, available dimensions).
const (
	verdictWeightLiveCount   = 0.30 // absolute live nodes
	verdictWeightAliveShare  = 0.15 // alive %
	verdictWeightGeoBreadth  = 0.20 // distinct countries+cities among live nodes
	verdictWeightCleanliness = 0.20 // Phase-1 clean% — dropped without evidence
	verdictWeightUniqueness  = 0.15 // unique %
)

// Trend modifier deltas (from stats.ClassifyTrend), applied to the composite
// before banding and clamped to [0,100].
const (
	verdictTrendUpStrongDelta   = 5.0
	verdictTrendUpDelta         = 2.5
	verdictTrendDownDelta       = -2.5
	verdictTrendDownStrongDelta = -5.0
)

// Override thresholds. A provider is DEAD when zero live nodes AND the 24h
// volume-weighted average is under 1% (a long-dead source, not a diurnal
// dip) — and ONLY once it has enough recorded history to prove death: the
// 3-wave floor is stats.ColdStartMin, the same floor the Z-score cold start
// applies (fix round 1, 2026-11-06: freshly-ingested sources carry
// fetch-stage live=0 with ZERO history waves — scoring them DEAD on zero
// evidence fabricated a verdict the pool had never earned). Pools with
// fewer than verdictMinPoolSize scored providers cannot rank meaningfully —
// the absolute fallback applies instead.
const (
	verdictDeadAlive24Pct = 1.0
	verdictMinPoolSize    = 3
)

// verdictMinHistoryWaves is the recorded-wave floor under which an
// enriched row is NEW (not DEAD, not composite-scored): one constant with
// the Z-score cold start so "enough waves to conclude anything" has a
// single definition.
const verdictMinHistoryWaves = stats.ColdStartMin

// recUniqueDeadFloorPct gates the "unique but dead" recommendation class:
// a dead provider still contributing ≥25% unique identities is worth a
// source-health check, not a prune.
const recUniqueDeadFloorPct = 25.0

// The dashboard's unique-yield bands (recommendations): <15% unique is a
// prune candidate, ≥60% unique is the explicit keep band (keep additionally
// requires liveness — see recommendations).
const (
	verdictUniqueAmberPct = 15.0
	verdictUniqueKeepPct  = 60.0
)

// Verdict vocabulary (the exact words the table, JSON, and recommendations
// render). NONE marks "no enrichment evidence yet" — a verdict that has not
// been earned, never rendered as a measured class. TRIP is RESERVED for
// breaker persistence (a future wave persists consecutive breaker trips and
// renders TRIP); the engine never returns it today (pinned by test).
const (
	verdictGood = "GOOD"
	verdictFair = "FAIR"
	verdictWeak = "WEAK"
	verdictPoor = "POOR"
	verdictDead = "DEAD"
	verdictNew  = "NEW"
	verdictTrip = "TRIP"
	verdictNone = "NONE"
)

// asciiVerdicts maps the colored verdict words onto the plain-mode fallbacks
// pinned in the tests. The pool-relative vocabulary is self-describing, so
// plain mode renders the word itself; NONE keeps its n/a cold-start bytes
// and NEW keeps its bracketed [NEW] badge (controller fix-round-1 spec).
var asciiVerdicts = map[string]string{
	verdictGood: "GOOD",
	verdictFair: "FAIR",
	verdictWeak: "WEAK",
	verdictPoor: "POOR",
	verdictDead: "DEAD",
	verdictNew:  "[NEW]",
	verdictTrip: "TRIP",
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
	HijackCount    int // exits whose v2 battery verdict carries hijack=true
	RotatingCount  int // exits whose echo IPs spanned >1 /24 (rotating=true)
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

// providerGeoIntel is one provider's Phase-1 evidence fold over the cold
// geo base (the unified evidence definition — see phase1Evidence). Breadth
// counts distinct country+city pairs among the provider's LIVE probe-store
// nodes; records without country evidence carry no location and never
// fabricate breadth.
type providerGeoIntel struct {
	Classified int // phase1Evidence-gated record count
	Clean      int // classified ∧ ¬proxy ∧ ¬hosting (same switch as aggregateGeo)
	Breadth    int // distinct (country, city) pairs among live nodes
}

// providerRow is one provider intelligence table row (manifest stats joined
// with provider history and the provider's geo evidence). enriched=false
// marks a pre-upgrade manifest: the liveness/quality columns have no
// evidence yet and render as pending.
type providerRow struct {
	stats         plugins.PluginStats
	history       *stats.ProviderSeries
	trend         string // stats.ClassifyTrend glyph; "" without history
	alivePct      float64
	alive24       float64
	cleanPct      float64 // classified-only clean share
	uniquePct     float64
	classified    int // Phase-1 classified count (providerGeoIntel)
	geoBreadth    int
	cleanEvidence bool // classified > 0 — the cleanliness factor's availability
	enriched      bool
	verdict       string
	verdictCol    string // ui palette name; "" = no color (NONE)
}

// statusIntel is everything one status run renders, collected once.
type statusIntel struct {
	stages             stageCounts
	funnel             []funnelStage
	geo                geoIntel
	manifest           *fetchManifest
	history            *stats.ProviderHistory
	providers          []providerRow
	selectedCount      int
	selectedUnknownGeo int // selected nodes without geo country evidence
	configSource       string
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
		si.selectedCount = selected
		for _, n := range sel.Nodes {
			if n.Country == "" {
				si.selectedUnknownGeo++
			}
		}
	}

	// Per-provider Phase-1 evidence: the SAME join the enrichment pass uses
	// (filtered parse records → probe keys → geo identities), folded under
	// the unified phase1Evidence predicate. The manifest's classified
	// counters are NOT the dashboard's evidence source — one definition
	// everywhere (owner ruling 2026-11-05).
	pgeo, err := collectProviderGeo(p, geoRecs)
	if err != nil {
		return nil, err
	}

	si.funnel = buildFunnel(si.stages, len(probes), alive, si.geo.GeoCleanAlive(), selected,
		si.geo.Hosting+si.geo.Proxy > 0)

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

	si.providers = buildProviderRows(si.manifest, history, pgeo, time.Now())
	return si, nil
}

// collectProviderGeo reads the wave artifacts the per-provider join needs
// (filtered parse records + the latest-per-key probe view) and folds the
// cold base into per-provider Phase-1 evidence.
func collectProviderGeo(p paths, geoRecs []*model.GeoRecord) (map[string]providerGeoIntel, error) {
	filteredNodes, err := store.ReadNodes(p.filtered) // missing file = cold start
	if err != nil {
		return nil, fmt.Errorf("status: read filtered nodes: %w", err)
	}
	probeByKey, err := store.LatestProbeByKey(p.probeResults)
	if err != nil {
		return nil, fmt.Errorf("status: reduce probe results: %w", err)
	}
	geoByID := make(map[string]*model.GeoRecord, len(geoRecs))
	for _, gr := range geoRecs {
		geoByID[model.GeoIdentity(gr)] = gr
	}
	return aggregateProviderGeo(filteredNodes, geoByID, probeByKey), nil
}

// aggregateProviderGeo folds the cold base into per-provider Phase-1
// evidence: classified/clean counts under the SAME phase1Evidence predicate
// the global quality section uses, plus the geo-breadth factor (distinct
// country+city pairs among the provider's LIVE nodes — probe-store truth,
// the same liveness that feeds LiveNodes). The join mirrors the enrichment
// pass exactly: per PARSE RECORD source (one geo identity may carry several
// parse records across plugins — W19 landmine), keyed through GeoIdentity.
func aggregateProviderGeo(
	nodes []*model.Node,
	geoByID map[string]*model.GeoRecord,
	probeByKey map[string]store.ProbeResult,
) map[string]providerGeoIntel {
	out := make(map[string]providerGeoIntel)
	breadth := make(map[string]map[string]bool)
	for _, n := range nodes {
		gr, ok := geoByID[model.GeoIdentity(&model.GeoRecord{Scheme: n.Scheme, Host: n.Host, Port: n.Port})]
		if !ok {
			continue
		}
		pg := out[n.Source]
		if phase1Evidence(gr) {
			pg.Classified++
			switch {
			case gr.IsProxy:
			case gr.IsHosting:
			default:
				pg.Clean++
			}
		}
		if pr, seen := probeByKey[n.Key]; seen && pr.Alive && gr.Country != "" {
			b := breadth[n.Source]
			if b == nil {
				b = map[string]bool{}
				breadth[n.Source] = b
			}
			b[gr.Country+"\x00"+model.CityKey(gr.City)] = true
		}
		out[n.Source] = pg
	}
	for id, b := range breadth {
		pg := out[id]
		pg.Breadth = len(b)
		out[id] = pg
	}
	return out
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
	if mu.Hijack {
		m.HijackCount++
	}
	if mu.Rotating {
		m.RotatingCount++
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
// drops. The geo-clean drop note is DYNAMIC (owner ruling 2026-11-05): with
// zero hosting/proxy evidence in the classified pool the drop is a
// probe-store inversion plus the geo fold — naming dirty-IP exits would
// fabricate evidence that does not exist; with evidence present the note
// keeps the hosting/proxy wording (the transfer() prefix carries the count).
func buildFunnel(stages stageCounts, probed, alive, geoClean, selected int, dirtyEvidence bool) []funnelStage {
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
	geoDrop := "hosting/proxy exits + geo fold"
	if !dirtyEvidence {
		geoDrop = "probe-store inversion + geo fold (no dirty-IP evidence)"
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
			Note: transfer(geoClean-alive, geoDrop, "geo fold ahead of probe store")},
		{Name: "Selected", Count: selected,
			Note: transfer(selected-geoClean, "rank cut", "rank admits beyond geo fold")},
	}
}

// buildProviderRows joins manifest stats with provider history and the
// provider's geo evidence, then derives the pool-relative verdicts.
// Enrichment detection: a manifest from the pre-upgrade binary carries zero
// LiveNodes/CleanCount in EVERY row — such a manifest has no liveness
// evidence at all, so no row may present a measured verdict. (The
// enrichment pass rewrites these fields after every full wave; a genuine
// all-dead pool is a pathological corner that renders as pending —
// documented, honest.)
func buildProviderRows(
	m *fetchManifest,
	history *stats.ProviderHistory,
	pgeo map[string]providerGeoIntel,
	now time.Time,
) []providerRow {
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
		geo := pgeo[st.PluginID]
		row := providerRow{
			stats:      st,
			enriched:   enriched,
			verdict:    verdictNone,
			trend:      "",
			classified: geo.Classified,
			geoBreadth: geo.Breadth,
		}
		if st.TotalNodes > 0 {
			row.alivePct = float64(st.LiveNodes) * 100 / float64(st.TotalNodes)
		}
		// Honest clean share, unified evidence definition: classified-only
		// numerator AND denominator, Phase-1-gated (the old Clean/TotalNodes
		// mixed a classified numerator into a pre-filter denominator and
		// folded never-geo'd nodes into clean; the manifest ClassifiedCount
		// counts geo-record presence, not Phase-1 evidence).
		row.cleanEvidence = geo.Classified > 0
		row.cleanPct = pctOf(geo.Clean, geo.Classified)
		row.uniquePct = st.UniqueYield
		if series := history.Providers[st.PluginID]; series != nil {
			row.history = series
			row.trend = series.Trend()
			row.alive24 = stats.WeightedLiveness(series.Waves, now) * 100
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].stats.PluginID < rows[j].stats.PluginID })
	computeVerdicts(rows)
	return rows
}

// verdictFactor is one composite input: its weight, the provider's
// pool-relative percentile (0..1), and whether the factor is AVAILABLE
// (dropped factors neither contribute weight nor value).
type verdictFactor struct {
	weight    float64
	value     float64
	available bool
}

// poolRelativeScore folds the available factors into the composite:
// Σ(w_f × p_f) / Σ(w_f available). With all factors available the weights
// sum to 1.0; a dropped factor renormalizes the rest (owner ruling:
// "weights renormalized to 1.0 when a factor is dropped"). OECD/JRC
// composite-indicator practice: never aggregate a missing dimension as a
// zero — renormalize over what exists.
func poolRelativeScore(factors []verdictFactor) float64 {
	var acc, wsum float64
	for _, f := range factors {
		if !f.available {
			continue
		}
		acc += f.weight * f.value
		wsum += f.weight
	}
	if wsum == 0 {
		return 0
	}
	return acc / wsum
}

// percentileRanks maps raw factor values onto pool-relative percentile
// ranks in [0,1] using competition MIDRANKS for ties: each tied group gets
// (rank_first + rank_last)/2 with 1-based ascending ranks, normalized by
// (midrank−1)/(N−1). N=1 → 0.5 (defensive; the N<3 fallback handles solo
// pools before percentiles ever run).
func percentileRanks(values []float64) []float64 {
	n := len(values)
	out := make([]float64, n)
	if n == 0 {
		return out
	}
	if n == 1 {
		out[0] = 0.5
		return out
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return values[order[a]] < values[order[b]] })
	for i := 0; i < n; {
		j := i
		for j+1 < n && values[order[j+1]] == values[order[i]] {
			j++
		}
		midrank := float64(i+1+j+1) / 2 // 1-based (rank_first + rank_last)/2
		rank := (midrank - 1) / float64(n-1)
		for k := i; k <= j; k++ {
			out[order[k]] = rank
		}
		i = j + 1
	}
	return out
}

// trendModifier maps the provider's ClassifyTrend glyph onto the composite
// delta; no history (or a flat trend) contributes nothing.
func trendModifier(row *providerRow) float64 {
	if row.history == nil {
		return 0
	}
	switch row.trend {
	case stats.TrendUpStrong:
		return verdictTrendUpStrongDelta
	case stats.TrendUp:
		return verdictTrendUpDelta
	case stats.TrendDown:
		return verdictTrendDownDelta
	case stats.TrendDownStrong:
		return verdictTrendDownStrongDelta
	default:
		return 0
	}
}

// applyTrendModifier adds the trend delta to the composite and clamps to
// [0,100] — the modifier fine-tunes within the scale, never beyond it.
func applyTrendModifier(score, delta float64) float64 {
	return min(max(score+delta, 0), 100)
}

// bandVerdict maps the composite onto the owner-specified bands:
// ≥75 GOOD, 50–75 FAIR, 25–50 WEAK, <25 POOR. Colors stay on the
// internal/ui traffic-light palette (GOOD green; FAIR and WEAK amber; POOR
// red).
func bandVerdict(score float64) (string, string) {
	switch {
	case score >= verdictGoodFloorPct:
		return verdictGood, ui.Green
	case score >= verdictFairFloorPct:
		return verdictFair, ui.Amber
	case score >= verdictWeakFloorPct:
		return verdictWeak, ui.Amber
	default:
		return verdictPoor, ui.Red
	}
}

// isDead renders the DEAD override: ENOUGH recorded history to prove death
// (≥ verdictMinHistoryWaves — a brand-new source's fetch-stage live=0 is
// not evidence), zero live nodes, and a 24h volume-weighted average under
// 1% — long-dead, not a diurnal dip. Shared by the verdict engine and the
// recommendation classes so "dead" has one definition.
func isDead(row *providerRow) bool {
	return verdictWaves(row) >= verdictMinHistoryWaves &&
		row.stats.LiveNodes == 0 && row.alive24 < verdictDeadAlive24Pct
}

// verdictWaves is the provider's recorded provider-history wave count (a
// missing series = zero waves — the brand-new source shape).
func verdictWaves(row *providerRow) int {
	if row.history == nil {
		return 0
	}
	return len(row.history.Waves)
}

// computeVerdicts derives the pool-relative verdicts in place. Priority:
// unenriched rows keep NONE (no evidence — nothing to score, nothing to
// override); enriched rows with fewer than verdictMinHistoryWaves recorded
// waves are NEW (a brand-new source — death cannot be concluded from the
// fetch-stage zeros, fix round 1 2026-11-06); the remainder first faces the
// DEAD override (which itself requires the same wave floor); the survivors
// either fall back absolutely (fewer than 3 scored providers — percentiles
// are meaningless in a tiny pool: live=0 → DEAD, alive>0 → FAIR) or land on
// the composite: score = Σ(w_f × percentile) over available factors,
// renormalized, + trend modifier, clamped [0,100], banded. TRIP stays
// reserved (breaker persistence is a future wave). Verdicts are
// POINT-IN-TIME — derived here, never persisted to provider history.
func computeVerdicts(rows []providerRow) {
	pool := make([]int, 0, len(rows))
	for i := range rows {
		if !rows[i].enriched {
			continue // NONE stays
		}
		if verdictWaves(&rows[i]) < verdictMinHistoryWaves {
			// NEW: a neutral badge in the ui dim palette — the source has
			// not been through enough scoring waves to earn ANY measured
			// verdict.
			rows[i].verdict, rows[i].verdictCol = verdictNew, ui.ColorPlainName
			continue
		}
		if isDead(&rows[i]) {
			rows[i].verdict, rows[i].verdictCol = verdictDead, ui.Red
			continue
		}
		pool = append(pool, i)
	}
	if len(pool) < verdictMinPoolSize {
		for _, i := range pool {
			if rows[i].stats.LiveNodes == 0 {
				rows[i].verdict, rows[i].verdictCol = verdictDead, ui.Red
			} else {
				rows[i].verdict, rows[i].verdictCol = verdictFair, ui.Amber
			}
		}
		return
	}
	liveRank := percentileRanks(factorValues(rows, pool, func(r providerRow) float64 {
		return float64(r.stats.LiveNodes)
	}))
	aliveRank := percentileRanks(factorValues(rows, pool, func(r providerRow) float64 { return r.alivePct }))
	breadthRank := percentileRanks(factorValues(rows, pool, func(r providerRow) float64 {
		return float64(r.geoBreadth)
	}))
	cleanRank := percentileRanks(factorValues(rows, pool, func(r providerRow) float64 { return r.cleanPct }))
	uniqueRank := percentileRanks(factorValues(rows, pool, func(r providerRow) float64 { return r.uniquePct }))
	for k, i := range pool {
		row := &rows[i]
		score := poolRelativeScore([]verdictFactor{
			{weight: verdictWeightLiveCount, value: liveRank[k], available: true},
			{weight: verdictWeightAliveShare, value: aliveRank[k], available: true},
			{weight: verdictWeightGeoBreadth, value: breadthRank[k], available: true},
			{weight: verdictWeightCleanliness, value: cleanRank[k], available: row.cleanEvidence},
			{weight: verdictWeightUniqueness, value: uniqueRank[k], available: true},
		}) * 100
		row.verdict, row.verdictCol = bandVerdict(applyTrendModifier(score, trendModifier(row)))
	}
}

// factorValues projects the pool rows through one factor extractor.
func factorValues(rows []providerRow, pool []int, f func(providerRow) float64) []float64 {
	out := make([]float64, 0, len(pool))
	for _, i := range pool {
		out = append(out, f(rows[i]))
	}
	return out
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
	// Funnel honesty annotation (owner ruling 2026-11-05): how much of the
	// active selection carries no geo country evidence at all. Skipped on
	// the cold start (nothing selected — nothing to annotate).
	if si.selectedCount > 0 {
		pct := float64(si.selectedUnknownGeo) * 100 / float64(si.selectedCount)
		outf(out, "%s\n", ui.ChipKV("geo unknown: ",
			fmt.Sprintf("%d (%.1f%% of selected)", si.selectedUnknownGeo, pct), color))
	}
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
	outf(out, "%s\n", ui.ChipKV("  exit:    ", fmt.Sprintf(
		"%d hijack-flagged, %d rotating (echo IPs span multiple /24 — no single exit identity)",
		m.HijackCount, m.RotatingCount), color))
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

	// --- legacy chip lines (byte-stable except the owner-ordered
	// dup-links rename, 2026-11-05) ---
	printPluginChipsLegacy(out, si.manifest.PluginStats, cfg, color)
}

// printPluginChipsLegacy renders the pre-Phase-4 per-plugin chip lines
// byte-stably EXCEPT the owner-ordered `dup=` → `dup-links=` rename
// (2026-11-05, deliberate byte-pin break). The OK/WARNING status stays
// driven by the config's plugin thresholds — different semantics from the
// dashboard verdict above (the breaker status), deliberately untouched.
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
			"total=%d live=%d (%.1f%%) dup-links=%d (%.1f%%) hosting=%d (%.1f%%) proxy=%d (%.1f%%) clean=%d (%.1f%%) status=%s",
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

// printFetchStatus renders the fetch chip: file/source counts and the fetch
// timestamp in the VIEWER'S LOCAL time (owner cosmetic ruling 2026-11-05;
// RFC3339 carries the numeric offset so the stamp stays unambiguous).
// Moved from pipeline.go — the intelligence dashboard owns the whole status
// rendering chain.
func printFetchStatus(out io.Writer, p paths, color bool) {
	b, err := os.ReadFile(p.manifest)
	if err != nil {
		outln(out, ui.ChipKV("fetch:    ", "no manifest (never fetched)", color))
		return
	}
	var m fetchManifest
	//nolint:musttag // fetchManifest has JSON tags; musttag false positive
	if json.Unmarshal(b, &m) != nil {
		outln(out, ui.ChipKV("fetch:    ", "manifest unreadable", color))
		return
	}
	files := 0
	for _, fs := range m.Sources {
		files += len(fs)
	}
	// Local-time display is the owner-mandated cosmetic (2026-11-05): the
	// machine TZ is the point, and the tests pin a fixed zone.
	stamp := m.FetchedAt.Local().Format(time.RFC3339) //nolint:gosmopolitan // owner ruling 2026-11-05
	outf(out, "%s\n", ui.ChipKV("fetch:    ",
		fmt.Sprintf("%d files from %d sources at %s", files, len(m.Sources), stamp), color))
}

// printSelectionStatus renders the select chip. The bound label follows the
// W19 unbounded semantics (owner cosmetic ruling 2026-11-05): CapApplied
// equals the selection size when no cap bound the wave, and that state
// renders "unbounded · N active" instead of the old tautological
// "N active (cap N)". An explicit cap that binds EXACTLY is indistinguishable
// on the persisted Selection (it carries only the applied bound) and renders
// unbounded too — documented corner. Moved from pipeline.go.
func printSelectionStatus(out io.Writer, p paths, color bool) {
	sel, err := store.ReadSelection(p.selection)
	if err != nil || sel == nil {
		outln(out, ui.ChipKV("select:   ", "empty", color))
		return
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
	bound := fmt.Sprintf("cap %d", sel.CapApplied)
	if sel.CapApplied == len(sel.Nodes) {
		bound = "unbounded"
	}
	outf(out, "%s\n", ui.ChipKV("select:   ",
		fmt.Sprintf("%s · %d active %v", bound, len(sel.Nodes), byCountry), color))
}

// printRenderStatus renders the render chip with the config mtime in the
// viewer's local time (same cosmetic ruling as the fetch stamp).
// Moved from pipeline.go.
func printRenderStatus(out io.Writer, p paths, color bool) {
	st, err := os.Stat(p.rendered)
	if err != nil {
		outln(out, ui.ChipKV("render:   ", "none", color))
		return
	}
	// Same local-time cosmetic as the fetch stamp (owner ruling 2026-11-05).
	stamp := st.ModTime().Local().Format(time.RFC3339) //nolint:gosmopolitan // owner ruling 2026-11-05
	outf(out, "%s\n", ui.ChipKV("render:   ",
		fmt.Sprintf("%s (%d bytes, %s)", p.rendered, st.Size(), stamp), color))
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
		aliveCell, avgCell, uniqueCell := "n/a", "n/a", "n/a"
		cleanCell := "n/a"
		trendCell := "calibrating"
		if row.enriched {
			aliveCell = fmt.Sprintf("%d (%.1f%%)", row.stats.LiveNodes, row.alivePct)
			avgCell = fmt.Sprintf("%.1f%%", row.alive24)
			uniqueCell = fmt.Sprintf("%.1f%%", row.uniquePct)
		}
		// Clean% honesty (owner ruling 2026-11-05): classified>0 renders the
		// clean share with its CLASSIFIED COVERAGE (classified/total) — the
		// reader sees how much of the pool the share describes; classified=0
		// renders n/a (no evidence, never a fabricated 0%).
		if row.cleanEvidence {
			cleanCell = fmt.Sprintf("%.1f%% ·%.1f%%·", row.cleanPct,
				pctOf(row.classified, row.stats.TotalNodes))
		}
		if row.history != nil {
			// Max-relative scale (owner ruling 2026-11-05, Stephen Few): the
			// sparkline shows the window's SHAPE; the alive% column carries
			// the magnitude.
			spark := row.history.SparklineScaled(sparklineTrendWaves, stats.SparklineMaxRelative)
			if !color {
				spark = asciiSparklineString(spark)
			}
			trendCell = strings.TrimRight(spark+" "+row.trend, " ")
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
// (deterministic: top-overlap percentage descending, LIVE ascending —
// owner ruling 2026-11-05 — plugin-id ascending on full ties). Bands:
// <15% unique = prune candidate, ≥60% unique = explicit keep — but a plain
// keep REQUIRES liveness (dead ⇒ live==0 ∧ 24h-avg<1%): a dead high-yield
// source becomes the "unique but dead" class (≥25% unique) instead — verify
// the upstream source before trusting its exclusive nodes. The alive middle
// band stays silent — advice only where the signal is strong.
func recommendations(rows []providerRow) []string {
	type cand struct {
		id      string
		unique  float64
		live    int
		topWith string
		topPct  float64
		dead    bool
	}
	var cands []cand
	for _, r := range rows {
		if !r.enriched || len(r.stats.TopOverlaps) == 0 {
			continue
		}
		dead := isDead(&r)
		if r.uniquePct < verdictUniqueAmberPct || r.uniquePct >= verdictUniqueKeepPct ||
			(dead && r.uniquePct >= recUniqueDeadFloorPct) {
			top := r.stats.TopOverlaps[0]
			cands = append(cands, cand{
				id:      r.stats.PluginID,
				unique:  r.uniquePct,
				live:    r.stats.LiveNodes,
				topWith: top.PluginID,
				topPct:  top.Percent,
				dead:    dead,
			})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].topPct != cands[j].topPct {
			return cands[i].topPct > cands[j].topPct
		}
		if cands[i].live != cands[j].live {
			return cands[i].live < cands[j].live
		}
		return cands[i].id < cands[j].id
	})
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		switch {
		case c.dead && c.unique >= recUniqueDeadFloorPct:
			out = append(out, fmt.Sprintf(
				"'%s' is unique but dead — verify upstream source (%.1f%% unique, 0 live nodes)",
				c.id, c.unique))
		case c.unique >= verdictUniqueKeepPct:
			out = append(out, fmt.Sprintf("keep '%s': %.1f%% unique nodes (low overlap, high yield)",
				c.id, c.unique))
		default:
			out = append(out, fmt.Sprintf(
				"prune candidate '%s': only %.1f%% unique — %.0f%% shared with %s",
				c.id, c.unique, c.topPct, c.topWith))
		}
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
	ID                    string           `json:"id"`
	TotalParsed           int              `json:"total_parsed"`
	AliveCurrent          int              `json:"alive_current"`
	Alive24hAvg           float64          `json:"alive_24h_avg"`
	AlivePct              float64          `json:"alive_pct"`
	CleanPct              *float64         `json:"clean_pct"`               // null = no Phase-1 evidence
	ClassifiedCoveragePct *float64         `json:"classified_coverage_pct"` // null = no Phase-1 evidence
	UniquePct             float64          `json:"unique_pct"`
	Sparkline             []float64        `json:"sparkline"`
	Overlaps              []statusJSONPair `json:"overlaps"`
	Verdict               string           `json:"verdict"`
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
// last ≤6 waves' liveness rates in percent (empty history → []). clean_pct
// and classified_coverage_pct are nil (→ JSON null, no omitempty) whenever
// the provider carries no Phase-1 evidence — the wire never fabricates a 0.
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
			ID:                    r.stats.PluginID,
			TotalParsed:           r.stats.TotalNodes,
			AliveCurrent:          r.stats.LiveNodes,
			Alive24hAvg:           round6(r.alive24),
			AlivePct:              round6(r.alivePct),
			CleanPct:              nullablePct(r.cleanPct, r.cleanEvidence),
			ClassifiedCoveragePct: nullablePct(pctOf(r.classified, r.stats.TotalNodes), r.cleanEvidence),
			UniquePct:             round6(r.uniquePct),
			Sparkline:             spark,
			Overlaps:              overlaps,
			Verdict:               r.verdict,
		})
	}
	return out
}

// nullablePct lifts a percentage into the nullable wire pointer: !ok → nil
// (encodes as JSON null — the explicit "no evidence" value).
func nullablePct(v float64, ok bool) *float64 {
	if !ok {
		return nil
	}
	f := round6(v)
	return &f
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
