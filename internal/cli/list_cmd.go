package cli

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"public_vpn/internal/checker"
	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/spf13/cobra"
)

// newListCommand is the W10 pool-inventory display command: the ACTIVE core
// grouped by location (the D5 two-layer view), optionally expanded to city
// sub-rows and extended with the cold base. Display only — it reads
// selection.json + probe results + the geo-base and writes nothing.
func newListCommand(cfgPath *string) *cobra.Command {
	var (
		cities  bool
		all     bool
		noColor bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Pool inventory by location: countries (with --cities: cities), counts, alive, median RTT",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			color, err := resolveColor("auto", noColor, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			return runList(cmd.OutOrStdout(), res.Config, listOptions{cities: cities, all: all, color: color})
		},
	}
	cmd.Flags().BoolVar(&cities, "cities", false,
		"show indented city sub-rows under multi-city countries (the D5 two-layer view)")
	cmd.Flags().BoolVar(&all, "all", false,
		"append the cold base (geo-base) as a separate section, grouped the same way")
	cmd.Flags().BoolVar(&noColor, "no-color", false,
		"disable colors (NO_COLOR is honored too; default is terminal-detected)")
	return cmd
}

// listOptions carries the list flags (seam for tests).
type listOptions struct {
	cities bool
	all    bool
	color  bool
}

// selectedStat is one country row of the active core plus its nodes (the
// --cities expansion re-groups them by city).
type selectedStat struct {
	flag   string
	nodes  []model.SelectedNode
	alive  int
	median float64
}

// coldStat is one cold-base country row.
type coldStat struct {
	flag   string
	count  int
	alive  int
	median float64
}

func runList(w io.Writer, cfg *config.Config, opts listOptions) error {
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

	outf(w, "publicvpn pool inventory — active core: %d nodes (selection: %s)\n",
		len(sel.Nodes), sel.GeneratedAt.Format(time.RFC3339))

	countries := groupSelected(sel.Nodes, probeByKey)
	renderSection(w, "LOCATION", []string{"loc", "nodes", "alive", "median"},
		[]int{6, 5, 5, 7}, countryRows(countries, 0), opts.color)

	if opts.cities {
		for _, cs := range countries {
			if len(cs.nodes) < 2 {
				continue // a single-node country needs no sub-rows
			}
			cityStats := groupCities(cs.nodes, probeByKey)
			if len(cityStats) <= 1 {
				continue // a single-city country IS its own sub-row
			}
			renderSection(w, "", []string{"", "city", "nodes", "alive", "median"},
				[]int{2, 24, 5, 5, 7}, cityRows(cityStats), opts.color)
		}
	}

	if opts.all {
		records, err := store.ReadGeo(p.geoBase)
		if err != nil {
			return err
		}
		outf(w, "\ncold base: %d records (%s)\n", len(records), p.geoBase)
		renderSection(w, "LOCATION", []string{"loc", "nodes", "alive", "median"},
			[]int{6, 5, 5, 7}, coldRows(groupCold(records)), opts.color)
	}

	// W16 balancer awareness: the routing targets the current selection will
	// produce at render time — the pool-wide balancer (always), the country
	// balancers, and the unknown-geo pseudo-location when selected. City
	// balancers are render-time decisions (>= 2 live nodes per city) and are
	// not listed here.
	outf(w, "\nbalancers: %s\n", balancerSummary(sel.Nodes))
	return nil
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
		st := selectedStat{flag: locationLabel(cc), nodes: nodes}
		st.alive, st.median = aggregate(nodes, func(n model.SelectedNode) (bool, float64) {
			if pr, ok := probeByKey[n.Key]; ok {
				return pr.Alive, pr.RTTMs
			}
			return false, n.RTTMs
		})
		out = append(out, st)
	}
	sortSelected(out)
	return out
}

// groupCities aggregates one country's nodes by city.
func groupCities(nodes []model.SelectedNode, probeByKey map[string]store.ProbeResult) []selectedStat {
	byCity := map[string][]model.SelectedNode{}
	for _, n := range nodes {
		city := strings.TrimSpace(n.City)
		if city == "" {
			city = "(unknown)"
		}
		byCity[city] = append(byCity[city], n)
	}
	out := make([]selectedStat, 0, len(byCity))
	for city, group := range byCity {
		st := selectedStat{flag: "· " + city, nodes: group}
		st.alive, st.median = aggregate(group, func(n model.SelectedNode) (bool, float64) {
			if pr, ok := probeByKey[n.Key]; ok {
				return pr.Alive, pr.RTTMs
			}
			return false, n.RTTMs
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
			flag:  locationLabel(cc),
			count: len(group),
		}
		st.alive, st.median = aggregate(group, func(r *model.GeoRecord) (bool, float64) {
			return r.Alive, r.RTTMs
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

// balancerSummary lists the routing targets the current selection produces
// at render time (W16): the pool-wide balancer first (annotated "nodes" —
// it spans the whole pool), then country balancers by code, then the
// unknown-geo pseudo-location when unknown nodes are selected.
func balancerSummary(sel []model.SelectedNode) string {
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
	parts := []string{fmt.Sprintf("pool_all (%d nodes)", len(sel))}
	for _, cc := range countries {
		parts = append(parts, fmt.Sprintf("pool_%s (%d)", strings.ToLower(cc), counts[cc]))
	}
	if unknown > 0 {
		parts = append(parts, fmt.Sprintf("pool_unknown (%d)", unknown))
	}
	return strings.Join(parts, ", ")
}

// aggregate folds one group into (alive count, median RTT).
func aggregate[T any](group []T, liveness func(T) (bool, float64)) (int, float64) {
	alive := 0
	var rtts []float64
	for _, n := range group {
		ok, rtt := liveness(n)
		if ok {
			alive++
		}
		if rtt > 0 {
			rtts = append(rtts, rtt)
		}
	}
	return alive, median(rtts)
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

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// renderSection renders one table through the shared checker renderer (the
// ONE table implementation in the repo, shared with `check`). Rows arrive
// pre-built; callers own their column shapes.
func renderSection(w io.Writer, title string, headers []string, widths []int, rows [][]checker.TableCell, color bool) {
	if title != "" {
		outln(w, title)
	}
	_, _ = io.WriteString(w, checker.RenderTable(headers, widths, rows, color))
}

func countryRows(stats []selectedStat, indent int) [][]checker.TableCell {
	rows := make([][]checker.TableCell, 0, len(stats))
	for _, st := range stats {
		rows = append(rows, []checker.TableCell{
			{S: strings.Repeat(" ", indent) + st.flag},
			{S: strconv.Itoa(len(st.nodes))},
			{S: strconv.Itoa(st.alive), Color: aliveColor(st.alive, len(st.nodes))},
			{S: checker.FormatMS(st.median)},
		})
	}
	return rows
}

func cityRows(stats []selectedStat) [][]checker.TableCell {
	rows := make([][]checker.TableCell, 0, len(stats))
	for _, st := range stats {
		rows = append(rows, []checker.TableCell{
			{S: "  "},
			{S: st.flag},
			{S: strconv.Itoa(len(st.nodes))},
			{S: strconv.Itoa(st.alive), Color: aliveColor(st.alive, len(st.nodes))},
			{S: checker.FormatMS(st.median)},
		})
	}
	return rows
}

func coldRows(stats []coldStat) [][]checker.TableCell {
	rows := make([][]checker.TableCell, 0, len(stats))
	for _, st := range stats {
		rows = append(rows, []checker.TableCell{
			{S: st.flag},
			{S: strconv.Itoa(st.count)},
			{S: strconv.Itoa(st.alive), Color: aliveColor(st.alive, st.count)},
			{S: checker.FormatMS(st.median)},
		})
	}
	return rows
}

// aliveColor: green when every node is alive, yellow for a mixed group,
// red for none — the same rate classes the check report uses.
func aliveColor(alive, total int) string {
	switch {
	case alive == total && total > 0:
		return "green"
	case alive > 0:
		return "yellow"
	default:
		return "red"
	}
}
