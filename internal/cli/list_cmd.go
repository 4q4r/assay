package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"assay/internal/checker"
	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/store"
	"assay/internal/ui"

	"github.com/spf13/cobra"
)

// newListCommand is the W10 pool-inventory display command: the ACTIVE core
// grouped by location (the D5 two-layer view), optionally expanded to city
// sub-rows and extended with the cold base. Display only — it reads
// selection.json + probe results + the geo-base and writes nothing.
// --json emits the machine-readable twin (round-7 item 12a): one JSON
// document on stdout — countries → cities hierarchy, counts, alive, median
// RTT, and the W12 provenance as the config object — with the human
// config-source line and table banners suppressed (schema: README).
func newListCommand(cfgPath *string) *cobra.Command {
	var (
		cities  bool
		all     bool
		verbose bool
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Pool inventory by location: countries (with --cities: cities), counts, alive, median RTT",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			color := false
			if !jsonOut {
				mode, noColor := commandColorFlags(cmd)
				color, err = resolveColor(mode, noColor, cmd.OutOrStdout())
				if err != nil {
					return err
				}
				reportConfigSourceStyled(cmd.OutOrStdout(), res, color)
			}
			return runList(cmd.OutOrStdout(), res, listOptions{
				cities: cities, all: all, verbose: verbose, color: color, json: jsonOut,
			})
		},
	}
	cmd.Flags().BoolVar(&cities, "cities", false,
		"show indented city sub-rows under multi-city countries (the D5 two-layer view)")
	cmd.Flags().BoolVar(&all, "all", false,
		"append the cold base (geo-base) as a separate section, grouped the same way")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"show the pool balancer summary line (routing targets)")
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"emit one machine-readable JSON document instead of the table (schema in the README)")
	attachColorFlags(cmd)
	return cmd
}

// listOptions carries the list flags (seam for tests).
type listOptions struct {
	cities  bool
	all     bool
	verbose bool
	color   bool
	json    bool
}

// selectedStat is one country row of the active core plus its nodes (the
// --cities expansion re-groups them by city). code is the RAW country key
// the row was grouped by ("DE"; "" = the unknown-geo pseudo-group) — the
// wire structs consume it directly instead of re-parsing display labels.
type selectedStat struct {
	code        string
	flag        string
	nodes       []model.SelectedNode
	alive       int
	min         float64
	TopSpeedBPS float64
}

// coldStat is one cold-base country row (code: see selectedStat).
type coldStat struct {
	code        string
	flag        string
	count       int
	alive       int
	min         float64
	TopSpeedBPS float64
}

func runList(w io.Writer, res *config.Resolved, opts listOptions) error {
	cfg := res.Config
	speedtest := cfg.Probe.IsSpeedtest()
	p := newPaths(cfg)
	sel, err := store.ReadSelection(p.selection)
	if err != nil {
		return err
	}
	if sel == nil || len(sel.Nodes) == 0 {
		return fmt.Errorf("no active selection (%s) — run the maintain wave first", p.selection)
	}
	probeByKey, err := store.LatestProbeByKey(p.probeResults)
	if err != nil {
		return err
	}

	countries := groupSelected(sel.Nodes, probeByKey)

	if opts.json {
		return writeListJSON(w, res, p, sel, countries, probeByKey, opts)
	}

	// W18 screen: header accent + selection provenance chip, then the ONE
	// bordered table (countries; --cities adds tree-glyph city sub-rows
	// under their country), then the pools chip footer.
	outln(w, ui.Header("📦 pool inventory — active core: "+strconv.Itoa(len(sel.Nodes))+" nodes", opts.color))
	_, _ = fmt.Fprintln(w, ui.Chip("selection:", sel.GeneratedAt.Format(time.RFC3339), opts.color))

	_, _ = io.WriteString(w, ui.Table(
		listColumns(speedtest),
		listRows(countries, opts.cities, probeByKey, speedtest),
		opts.color,
	))

	if opts.all {
		records, err := store.ReadGeo(p.geoBase)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(w, "\ncold base: %d records (%s)\n", len(records), p.geoBase)
		_, _ = io.WriteString(w, ui.Table(listColumns(speedtest), coldRows(groupCold(records), speedtest), opts.color))
	}

	// W16 balancer awareness: the routing targets the current selection will
	// produce at render time — the pool-wide balancer (always), the country
	// balancers, and the unknown-geo pseudo-location when selected. City
	// balancers are render-time decisions (>= 2 live nodes per city) and are
	// not listed here.
	if opts.verbose {
		_, _ = fmt.Fprintln(w, "\n"+ui.Chip("⚖️ pools:", balancerSummary(sel.Nodes), opts.color))
	}
	return nil
}

// listColumns is the shape every list section renders (countries, expanded
// cities, cold base): one column set for the whole screen.
func listColumns(speedtest ...bool) []ui.Column {
	st := false
	if len(speedtest) > 0 {
		st = speedtest[0]
	}
	cols := []ui.Column{
		{Header: "loc", Width: 6},
		{Header: "nodes", Width: 5, Right: true},
		{Header: "alive", Width: 5, Right: true},
		{Header: "min", Width: 7, Right: true},
	}
	if st {
		cols = append(cols, ui.Column{Header: "topspd", Width: 8, Right: true})
	}
	return cols
}

// listRows builds the active-core table rows: one row per country and —
// under --cities — tree-glyph city sub-rows directly beneath their country
// (the D5 two-layer view in ONE table; no duplicate header blocks).
func listRows(
	countries []selectedStat, cities bool, probeByKey map[string]store.ProbeResult,
	speedtest ...bool,
) [][]ui.Cell {
	st := false
	if len(speedtest) > 0 {
		st = speedtest[0]
	}
	rows := make([][]ui.Cell, 0, len(countries))
	for _, s := range countries {
		cells := []ui.Cell{
			{S: s.flag},
			{S: strconv.Itoa(len(s.nodes))},
			{S: strconv.Itoa(s.alive), Color: aliveColor(s.alive, len(s.nodes))},
			{S: checker.FormatMS(s.min), Color: ui.TrafficName(s.min)},
		}
		if st {
			cells = append(cells, ui.Cell{S: checker.FormatBPS(s.TopSpeedBPS)})
		}
		rows = append(rows, cells)
		if !cities {
			continue
		}
		cityStats := cityView(s, probeByKey)
		for i, city := range cityStats {
			cityCells := []ui.Cell{
				// RAW glyph (the dim styling applies through the cell color —
				// glyph and city name are dim 240 together, owner spec).
				{S: ui.TreeGlyph(i, len(cityStats), false) + city.flag, Color: ui.ColorPlainName},
				{S: strconv.Itoa(len(city.nodes))},
				{S: strconv.Itoa(city.alive), Color: aliveColor(city.alive, len(city.nodes))},
				{S: checker.FormatMS(city.min), Color: ui.TrafficName(city.min)},
			}
			if st {
				cityCells = append(cityCells, ui.Cell{S: checker.FormatBPS(city.TopSpeedBPS)})
			}
			rows = append(rows, cityCells)
		}
	}
	return rows
}

// locationLabel renders one location row's display label: flag + code +
// country name, or the unknown pseudo-location for nodes with no geo
// evidence (the white flag — checker.FlagEmoji already maps empty codes to
// 🏳, the ONE emoji mapping in the repo).
func locationLabel(cc string) string {
	up := strings.ToUpper(strings.TrimSpace(cc))
	if up == "" {
		return checker.FlagEmoji(up) + " unknown"
	}
	return checker.FlagEmoji(up) + " " + strings.ToLower(up) + " " + countryName(up)
}

// listJSON* are the wire structs of `list --json` (round-7 item 12a): the
// machine-readable twin of the table — same aggregation, same ordering,
// color-independent by construction. The schema is pinned by
// TestListJSONGolden and documented in the README.
type listJSONDoc struct {
	GeneratedAt string            `json:"generated_at"`
	Config      listJSONConfig    `json:"config"`
	Selection   listJSONMetadata  `json:"selection"`
	Countries   []listJSONCountry `json:"countries"`
	ColdBase    *listJSONColdBase `json:"cold_base,omitempty"` // present only under --all
	// Balancers is the structured W16 routing-target view of the selection
	// (pool_all / pool_<cc> / pool_unknown with node counts) — the data
	// behind the table's `balancers:` display line, always present.
	Balancers []balancerTarget `json:"balancers"`
}

type listJSONConfig struct {
	Source string `json:"source"`
	Path   string `json:"path,omitempty"` // empty when configless
}

type listJSONMetadata struct {
	Path  string `json:"path"`
	Nodes int    `json:"nodes"`
}

type listJSONCountry struct {
	Code        string         `json:"code"` // ISO 3166-1 alpha-2, upper case
	Name        string         `json:"name"`
	Flag        string         `json:"flag"` // the country's flag emoji
	Nodes       int            `json:"nodes"`
	Alive       int            `json:"alive"`
	MinRTTms    float64        `json:"min_rtt_ms"`
	TopSpeedBPS float64        `json:"top_speed_bps,omitempty"` // present only when speedtest enabled
	Cities      []listJSONCity `json:"cities,omitempty"`        // present only under --cities
}

type listJSONCity struct {
	City        string  `json:"city"`
	Nodes       int     `json:"nodes"`
	Alive       int     `json:"alive"`
	MinRTTms    float64 `json:"min_rtt_ms"`
	TopSpeedBPS float64 `json:"top_speed_bps,omitempty"` // present only when speedtest enabled
}

type listJSONColdBase struct {
	Path      string            `json:"path"`
	Records   int               `json:"records"`
	Countries []listJSONCountry `json:"countries"`
}

// balancerTarget is one structured routing target of the current selection
// (W16): `pool_all` spans the whole pool, `pool_<cc>` is a country
// balancer, `pool_unknown` the unknown-geo pseudo-location. This is wire
// data — the table's `balancers:` display line renders from the SAME
// aggregation (balancerSummary), never a fork and never a parsed string.
type balancerTarget struct {
	Name  string `json:"name"`
	Nodes int    `json:"nodes"`
}

// jsonCountryName names a grouped row: the English short name for a real
// code, "unknown" for the unknown-geo pseudo-group (the raw empty country
// — the table renders the same row as `🏳 unknown`).
func jsonCountryName(cc string) string {
	if cc == "" {
		return "unknown"
	}
	return countryName(cc)
}

// writeListJSON renders the JSON twin. Deterministic: the country/city
// order is the table's sort order, cold-base rows the table's sort order,
// and the balancer targets are the table line's own aggregation.
func writeListJSON(
	w io.Writer, res *config.Resolved, p paths, sel *model.Selection,
	countries []selectedStat, probeByKey map[string]store.ProbeResult, opts listOptions,
) error {
	doc := listJSONDoc{
		GeneratedAt: sel.GeneratedAt.Format(time.RFC3339),
		Config:      listJSONConfig{Source: res.Source.String(), Path: res.Path},
		Selection:   listJSONMetadata{Path: p.selection, Nodes: len(sel.Nodes)},
		Countries:   make([]listJSONCountry, 0, len(countries)),
		Balancers:   balancerTargets(sel.Nodes),
	}
	speedtest := res.Config.Probe.IsSpeedtest()
	for _, cs := range countries {
		jc := listJSONCountry{
			Code:     cs.code,
			Name:     jsonCountryName(cs.code),
			Flag:     checker.FlagEmoji(cs.code),
			Nodes:    len(cs.nodes),
			Alive:    cs.alive,
			MinRTTms: cs.min,
		}
		if speedtest {
			jc.TopSpeedBPS = cs.TopSpeedBPS
		}
		if opts.cities {
			for _, city := range cityView(cs, probeByKey) {
				jcity := listJSONCity{
					City:     city.flag,
					Nodes:    len(city.nodes),
					Alive:    city.alive,
					MinRTTms: city.min,
				}
				if speedtest {
					jcity.TopSpeedBPS = city.TopSpeedBPS
				}
				jc.Cities = append(jc.Cities, jcity)
			}
		}
		doc.Countries = append(doc.Countries, jc)
	}
	if opts.all {
		records, err := store.ReadGeo(p.geoBase)
		if err != nil {
			return err
		}
		cold := &listJSONColdBase{Path: p.geoBase, Records: len(records)}
		for _, st := range groupCold(records) {
			jc := listJSONCountry{
				Code:     st.code,
				Name:     jsonCountryName(st.code),
				Flag:     checker.FlagEmoji(st.code),
				Nodes:    st.count,
				Alive:    st.alive,
				MinRTTms: st.min,
			}
			if speedtest {
				jc.TopSpeedBPS = st.TopSpeedBPS
			}
			cold.Countries = append(cold.Countries, jc)
		}
		doc.ColdBase = cold
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// groupSelected aggregates the active core by country, resolving liveness
// and RTT from the latest probe wave (selection fields are the fallback for
// nodes without a probe row). Unknown-geo nodes (raw empty country) form
// their own 🏳 unknown row (W16).
func groupSelected(sel []model.SelectedNode, probeByKey map[string]store.ProbeResult) []selectedStat {
	byCountry := map[string][]model.SelectedNode{}
	for _, n := range sel {
		cc := strings.ToUpper(strings.TrimSpace(n.Country))
		byCountry[cc] = append(byCountry[cc], n)
	}
	out := make([]selectedStat, 0, len(byCountry))
	for cc, nodes := range byCountry {
		st := selectedStat{code: cc, flag: locationLabel(cc), nodes: nodes}
		st.alive, st.min, st.TopSpeedBPS = aggregate(nodes, func(n model.SelectedNode) (bool, float64, float64) {
			if pr, ok := probeByKey[n.Key]; ok {
				return pr.Alive, pr.RTTMs, float64(pr.SpeedBPS)
			}
			return false, n.RTTMs, float64(n.Speed)
		})
		out = append(out, st)
	}
	sortSelected(out)
	return out
}

// groupCities aggregates one country's nodes by city.
// cityView is the --cities expansion of one country under the table's
// suppression rule — the ONE rule both outputs share (the JSON is the
// table's twin, never a fork): a single-node country needs no sub-rows, and
// a single-city country IS its own sub-row (two nodes in the same city are
// not two cities). Nil when the table would render nothing.
func cityView(cs selectedStat, probeByKey map[string]store.ProbeResult) []selectedStat {
	if len(cs.nodes) < 2 {
		return nil
	}
	cityStats := groupCities(cs.nodes, probeByKey)
	if len(cityStats) <= 1 {
		return nil
	}
	return cityStats
}

func groupCities(nodes []model.SelectedNode, probeByKey map[string]store.ProbeResult) []selectedStat {
	byCity := map[string][]model.SelectedNode{}
	// display: folded key → deterministic display spelling. The key folds
	// case (model.CityKey — geo case variants of one city are ONE city);
	// the shown name is the group's lowest-string variant (model.CityDisplay),
	// stable across runs regardless of node order.
	display := map[string]string{}
	for _, n := range nodes {
		city := strings.TrimSpace(n.City)
		if city == "" {
			city = "(unknown)"
		}
		k := model.CityKey(city)
		if _, seen := byCity[k]; !seen {
			byCity[k] = nil
			display[k] = city
		} else {
			display[k] = model.CityDisplay(display[k], city)
		}
		byCity[k] = append(byCity[k], n)
	}
	out := make([]selectedStat, 0, len(byCity))
	for k, group := range byCity {
		// flag = the deterministic display name (no prefix — the table adds
		// the tree glyph at render time, the JSON twin uses the name as-is).
		st := selectedStat{flag: display[k], nodes: group}
		st.alive, st.min, st.TopSpeedBPS = aggregate(group, func(n model.SelectedNode) (bool, float64, float64) {
			if pr, ok := probeByKey[n.Key]; ok {
				return pr.Alive, pr.RTTMs, float64(pr.SpeedBPS)
			}
			return false, n.RTTMs, float64(n.Speed)
		})
		out = append(out, st)
	}
	sortSelected(out)
	return out
}

// groupCold aggregates the geo-base by country (alive from each record's
// latest probe state). Unknown-geo records form their own 🏳 unknown row.
func groupCold(records []*model.GeoRecord) []coldStat {
	byCountry := map[string][]*model.GeoRecord{}
	for _, r := range records {
		cc := strings.ToUpper(strings.TrimSpace(r.Country))
		byCountry[cc] = append(byCountry[cc], r)
	}
	out := make([]coldStat, 0, len(byCountry))
	for cc, group := range byCountry {
		st := coldStat{
			code:  cc,
			flag:  locationLabel(cc),
			count: len(group),
		}
		st.alive, st.min, st.TopSpeedBPS = aggregate(group, func(r *model.GeoRecord) (bool, float64, float64) {
			return r.Alive, r.RTTMs, float64(r.SpeedBPS)
		})
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].flag < out[j].flag
	})
	return out
}

// balancerTargets aggregates the routing targets the current selection
// produces at render time (W16): the pool-wide balancer first (it spans the
// whole pool), then country balancers by code, then the unknown-geo
// pseudo-location when unknown nodes are selected. THE one aggregation both
// outputs share: the table's `balancers:` line renders from it
// (balancerSummary) and `list --json` serializes it directly. City
// balancers are render-time decisions (>= 2 live nodes per city) and are
// not listed.
func balancerTargets(sel []model.SelectedNode) []balancerTarget {
	counts := map[string]int{}
	var countries []string
	unknown := 0
	for _, n := range sel {
		cc := strings.ToUpper(strings.TrimSpace(n.Country))
		if cc == "" {
			unknown++
			continue
		}
		if counts[cc] == 0 {
			countries = append(countries, cc)
		}
		counts[cc]++
	}
	sort.Strings(countries)
	targets := make([]balancerTarget, 0, len(countries)+2)
	targets = append(targets, balancerTarget{Name: "pool_all", Nodes: len(sel)})
	for _, cc := range countries {
		targets = append(targets, balancerTarget{Name: "pool_" + strings.ToLower(cc), Nodes: counts[cc]})
	}
	if unknown > 0 {
		targets = append(targets, balancerTarget{Name: "pool_unknown", Nodes: unknown})
	}
	return targets
}

// balancerSummary renders balancerTargets as the table's display line
// (pool_all carries the spelled-out "nodes" — it spans the whole pool).
func balancerSummary(sel []model.SelectedNode) string {
	parts := make([]string, 0, len(sel))
	for _, t := range balancerTargets(sel) {
		if t.Name == "pool_all" {
			parts = append(parts, fmt.Sprintf("pool_all (%d nodes)", t.Nodes))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", t.Name, t.Nodes))
	}
	return strings.Join(parts, ", ")
}

// aggregate folds one group into (alive count, min RTT, top speed).
func aggregate[T any](group []T, liveness func(T) (bool, float64, float64)) (int, float64, float64) {
	alive := 0
	var rtts []float64
	var aliveTop, anyTop float64
	for _, n := range group {
		ok, rtt, speed := liveness(n)
		if ok {
			alive++
		}
		if rtt > 0 {
			rtts = append(rtts, rtt)
		}
		if speed > 0 {
			if speed > anyTop {
				anyTop = speed
			}
			if ok && speed > aliveTop {
				aliveTop = speed
			}
		}
	}
	top := aliveTop
	if top == 0 {
		top = anyTop
	}
	return alive, minVal(rtts), top
}

// sortSelected orders by node count descending, then display flag (stable,
// deterministic output for identical data).
func sortSelected(stats []selectedStat) {
	sort.Slice(stats, func(i, j int) bool {
		if len(stats[i].nodes) != len(stats[j].nodes) {
			return len(stats[i].nodes) > len(stats[j].nodes)
		}
		return stats[i].flag < stats[j].flag
	})
}

func minVal(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	m := values[0]
	for _, v := range values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

// coldRows builds the cold-base section rows (same columns as the active
// core table).
func coldRows(stats []coldStat, speedtest ...bool) [][]ui.Cell {
	st := false
	if len(speedtest) > 0 {
		st = speedtest[0]
	}
	rows := make([][]ui.Cell, 0, len(stats))
	for _, s := range stats {
		cells := []ui.Cell{
			{S: s.flag},
			{S: strconv.Itoa(s.count)},
			{S: strconv.Itoa(s.alive), Color: aliveColor(s.alive, s.count)},
			{S: checker.FormatMS(s.min), Color: ui.TrafficName(s.min)},
		}
		if st {
			cells = append(cells, ui.Cell{S: checker.FormatBPS(s.TopSpeedBPS)})
		}
		rows = append(rows, cells)
	}
	return rows
}

// aliveColor: green when every node is alive, amber for a mixed group,
// red for none — the ui palette classes the whole CLI shares (W18).
func aliveColor(alive, total int) string {
	switch {
	case alive == total && total > 0:
		return ui.Green
	case alive > 0:
		return ui.Amber
	default:
		return ui.Red
	}
}
