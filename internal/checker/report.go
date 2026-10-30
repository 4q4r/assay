package checker

import (
	"fmt"
	"strconv"
	"strings"

	"public_vpn/internal/ui"

	"github.com/charmbracelet/x/ansi"
)

// RenderOptions controls one textual report.
type RenderOptions struct {
	Color bool // traffic-light + verdict palette; --no-color strips all ANSI
	Top   int  // geo-summary and recommendation rows per block (0 = all)
}

// RenderReport renders the full check report: one block per target (table +
// geo summaries + recommendation), then the staleness hint. Rows never wrap —
// long values are truncated to their column, every line is a single line.
// W18: tables render through the ui bordered builder; the owner traffic
// light (46/214/196 by latency band) colors the rtt/ttfb/avg columns and
// the geo medians/avgs; section titles carry the header accent.
func RenderReport(rep *Report, opts RenderOptions) string {
	b := &strings.Builder{}
	for _, tr := range rep.Targets {
		renderTarget(b, rep, tr, opts.Color, opts.Top)
	}
	if rep.Stale {
		fmt.Fprintf(b, "\nhint: probe data is %s old (geo.ttl %s) — run `publicvpn maintain` (probe + geo) for freshness\n",
			rep.StaleAge, rep.GeoTTL)
	}
	return b.String()
}

func renderTarget(b *strings.Builder, rep *Report, tr *TargetResult, color bool, top int) {
	fmt.Fprintf(b, "%s\n", ui.Header("site check — "+tr.URL, color))
	fmt.Fprintf(b, "nodes tested: %d · attempts: %d/node · timeout: %s\n",
		len(tr.Rows), rep.Attempts, rep.Timeout)
	fmt.Fprintf(b, "dns view: %s — dns.google/resolve queried through each node\n", dnsMethodLabel(tr))
	b.WriteString(ui.Table(reportColumns, nodeRows(tr.Rows), color))
	fmt.Fprintf(b, "\n%s\n", ui.Header("geo summary — countries", color))
	renderGroups(b, tr.Countries, false, color, top)
	fmt.Fprintf(b, "\n%s\n", ui.Header("geo summary — cities", color))
	renderGroups(b, tr.Cities, true, color, top)
	fmt.Fprintf(b, "\n%s\n", ui.Header("recommendation — best locations for matching rules ("+tr.URL+")", color))
	renderRecommendation(b, tr, color, top)
	b.WriteString("\n")
}

func dnsMethodLabel(tr *TargetResult) string {
	for _, r := range tr.Rows {
		if r.DNSMethod != "" {
			return r.DNSMethod
		}
	}
	return "doh-via-exit"
}

// table columns (static minimum widths; the ui builder grows columns to
// fit their widest cell instead of colliding).
var (
	reportColumns = []ui.Column{
		{Header: "node", Width: 13},
		{Header: "loc", Width: 6},
		{Header: "city", Width: 12},
		{Header: "asn/isp", Width: 24},
		{Header: "ok", Width: 5, Right: true},
		{Header: "statuses", Width: 13},
		{Header: "tls", Width: 4},
		{Header: "rtt", Width: 7, Right: true},
		{Header: "ttfb", Width: 8, Right: true},
		{Header: "avg", Width: 7, Right: true},
		{Header: "speed", Width: 9, Right: true},
		{Header: "resolved", Width: 15},
		{Header: "note", Width: 24},
	}
	groupColumns = []ui.Column{
		{Header: "loc", Width: 6},
		{Header: "nodes", Width: 5, Right: true},
		{Header: "ok", Width: 7, Right: true},
		{Header: "success", Width: 7, Right: true},
		{Header: "median", Width: 7, Right: true},
		{Header: "avg", Width: 7, Right: true},
		{Header: "speed", Width: 9, Right: true},
	}
	cityColumns = []ui.Column{
		{Header: "city", Width: 26},
		{Header: "nodes", Width: 5, Right: true},
		{Header: "ok", Width: 7, Right: true},
		{Header: "success", Width: 7, Right: true},
		{Header: "median", Width: 7, Right: true},
		{Header: "avg", Width: 7, Right: true},
		{Header: "speed", Width: 9, Right: true},
	}
)

// nodeRows builds the per-node table rows. Every cell carries the row's
// verdict color; the rtt/ttfb/avg cells carry the owner traffic light
// instead when they hold real latency data (a dash is not a latency).
func nodeRows(rows []*NodeResult) [][]ui.Cell {
	out := make([][]ui.Cell, 0, len(rows))
	for _, r := range rows {
		verdict := verdictColor(r.Verdict)
		node := r.Tag
		if strings.TrimSpace(node) == "" {
			node = r.Host // pre-select cold-base records carry no tags — the host identifies the row
		}
		out = append(out, []ui.Cell{
			{S: trunc(node, 13), Color: verdict},
			{S: flagEmoji(r.Country) + " " + strings.ToUpper(r.Country), Color: verdict},
			{S: trunc(orDash(r.City), 12), Color: verdict},
			{S: trunc(orDash(strings.TrimSpace(r.ASN+" "+r.ISP)), 24), Color: verdict},
			{S: fmt.Sprintf("%d/%d", r.OK, r.Total), Color: verdict},
			{S: trunc(orDash(joinInts(r.Statuses)), 13), Color: verdict},
			{S: orDash(r.TLSVersion), Color: verdict},
			latencyCell(fmtMS(r.ConnectMS), r.ConnectMS, verdict),
			latencyCell(fmtMS(r.AvgTTFBMS), r.AvgTTFBMS, verdict),
			latencyCell(fmtMS(r.AvgMS), r.AvgMS, verdict),
			{S: fmtBPS(r.AvgSpeedBPS), Color: verdict},
			{S: trunc(orDash(firstIP(r.ResolvedIPs)), 15), Color: verdict},
			{S: trunc(noteFor(r), 24), Color: verdict},
		})
	}
	return out
}

// latencyCell colors a millisecond cell by the traffic light when the value
// is real (> 0 — the em dash keeps the verdict color).
func latencyCell(shown string, ms float64, verdict string) ui.Cell {
	if name := ui.TrafficName(ms); name != "" {
		return ui.Cell{S: shown, Color: name}
	}
	return ui.Cell{S: shown, Color: verdict}
}

func renderGroups(b *strings.Builder, groups []GroupStat, city bool, color bool, top int) {
	cols := groupColumns
	if city {
		cols = cityColumns
	}
	if len(groups) == 0 {
		b.WriteString("(no data)\n")
		return
	}
	shown := groups
	if top > 0 && len(shown) > top {
		shown = shown[:top]
	}
	rows := make([][]ui.Cell, 0, len(shown))
	for i, g := range shown {
		rows = append(rows, groupCells(g, city, len(shown), i))
	}
	b.WriteString(ui.Table(cols, rows, color))
}

// groupCells builds one geo-summary row. The median/avg cells carry the
// traffic light; the success cell keeps the rate classes; city rows render
// the tree glyph + dim name after the flag+code (the same tree hierarchy
// the list screen uses for the expanded view).
func groupCells(g GroupStat, city bool, n, i int) []ui.Cell {
	rateStr := fmt.Sprintf("%.0f%%", g.SuccessRate*100)
	loc := flagEmoji(g.Country) + " " + g.Country
	first := ui.Cell{S: loc}
	if city {
		first = ui.Cell{
			S:     loc + " " + ui.TreeGlyph(i, n, false) + g.City,
			Color: ui.ColorPlainName,
		}
	}
	return []ui.Cell{
		first,
		{S: strconv.Itoa(g.Nodes)},
		{S: fmt.Sprintf("%d/%d", g.OK, g.Total)},
		{S: rateStr, Color: rateColor(g.SuccessRate)},
		{S: fmtMS(g.MedianMS), Color: ui.TrafficName(g.MedianMS)},
		{S: fmtMS(g.AvgMS), Color: ui.TrafficName(g.AvgMS)},
		{S: fmtBPS(g.AvgSpeedBPS)},
	}
}

func renderRecommendation(b *strings.Builder, tr *TargetResult, color bool, top int) {
	countries := filterServed(tr.Recommendation)
	if len(countries) == 0 {
		b.WriteString("no location served this URL — every tested node failed or was blocked\n")
		return
	}
	for i, g := range countries {
		if top > 0 && i >= top {
			break
		}
		fmt.Fprintf(b, "%d. %s — %s ok (%d/%d attempts) — median %s — %s\n",
			i+1, ui.Info(flagEmoji(g.Country)+" "+g.Country, color),
			rateColorized(g.SuccessRate, color),
			g.OK, g.Total,
			trafficColorized(fmtMS(g.MedianMS), g.MedianMS, color),
			ui.Info(fmtBPS(g.AvgSpeedBPS), color))
	}
	cities := filterServed(tr.Cities)
	if len(cities) > 0 {
		b.WriteString("cities:\n")
		for i, g := range cities {
			if top > 0 && i >= top {
				break
			}
			fmt.Fprintf(b, "  %s %s — %s ok (%d/%d) — median %s\n",
				ui.Info(flagEmoji(g.Country), color),
				ui.Info(trunc(g.City, 26), color),
				rateColorized(g.SuccessRate, color), g.OK, g.Total,
				trafficColorized(fmtMS(g.MedianMS), g.MedianMS, color))
		}
	}
}

// rateColorized renders a success-rate string in its rate class.
func rateColorized(rate float64, color bool) string {
	return ui.Colorize(rateColor(rate), fmt.Sprintf("%.0f%%", rate*100), color)
}

// trafficColorized renders a millisecond string in its traffic-light class.
func trafficColorized(shown string, ms float64, color bool) string {
	if name := ui.TrafficName(ms); name != "" {
		return ui.Colorize(name, shown, color)
	}
	return shown
}

// filterServed keeps only buckets that actually served the URL at least once.
func filterServed(groups []GroupStat) []GroupStat {
	out := make([]GroupStat, 0, len(groups))
	for _, g := range groups {
		if g.OK > 0 {
			out = append(out, g)
		}
	}
	return out
}

func verdictColor(v Verdict) string {
	switch v {
	case VerdictSuccess:
		return ui.Green
	case VerdictPartial:
		return ui.Amber
	case VerdictBlockedHTTP, VerdictBlockedPage, VerdictDNSFail, VerdictTLSFail,
		VerdictDialFail, VerdictReadTimeout, VerdictCanceled, VerdictTimeout,
		VerdictBlocked, VerdictFail, VerdictError:
		return ui.Red
	default:
		return ui.Red
	}
}

func rateColor(rate float64) string {
	switch {
	case rate >= 0.99:
		return ui.Green
	case rate >= 0.5:
		return ui.Amber
	default:
		return ui.Red
	}
}

// noteFor renders the compact diagnostic note for one node row.
func noteFor(r *NodeResult) string {
	switch r.Verdict {
	case VerdictError:
		if r.InstanceFailed {
			return "instance-failed: " + firstLine(r.InstanceErr)
		}
		return "error"
	case VerdictTLSFail:
		return "tls-fail: " + firstLine(r.TLSErr)
	case VerdictBlocked:
		if r.Signature != "" {
			return "blocked: " + r.Signature
		}
		return "blocked"
	case VerdictFail:
		return "no http answer (" + dominantAttemptClass(r) + ")"
	case VerdictPartial:
		return "partial"
	case VerdictSuccess, VerdictBlockedHTTP, VerdictBlockedPage, VerdictDNSFail,
		VerdictDialFail, VerdictReadTimeout, VerdictCanceled, VerdictTimeout:
		return ""
	default:
		return ""
	}
}

func dominantAttemptClass(r *NodeResult) string {
	counts := map[Verdict]int{}
	for _, a := range r.Attempts {
		counts[a.Verdict]++
	}
	best, n := VerdictError, 0
	for v, c := range counts {
		if c > n || (c == n && v < best) {
			best, n = v, c
		}
	}
	return string(best)
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func firstIP(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	return ips[0]
}

func joinInts(v []int) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		parts = append(parts, strconv.Itoa(x))
	}
	return strings.Join(parts, ",")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// trunc cuts a string to w display cells, appending an ellipsis when cut.
// Widths are display-cell aware (a flag emoji is two cells); the loop
// guarantees the RESULT (ellipsis included) never exceeds the width.
func trunc(s string, w int) string {
	if ansi.StringWidth(s) <= w {
		return s
	}
	r := []rune(s)
	cut := w - 1
	for cut > 0 && ansi.StringWidth(string(r[:cut])+"…") > w {
		cut--
	}
	return string(r[:cut]) + "…"
}

func fmtMS(ms float64) string {
	switch {
	case ms <= 0:
		return "—"
	case ms < 1:
		return "<1ms"
	default:
		return fmt.Sprintf("%.0fms", ms)
	}
}

func fmtBPS(bps float64) string {
	switch {
	case bps <= 0:
		return "—"
	case bps >= 1024*1024:
		return fmt.Sprintf("%.1fMB/s", bps/(1024*1024))
	case bps >= 1024:
		return fmt.Sprintf("%.0fKB/s", bps/1024)
	default:
		return fmt.Sprintf("%.0fB/s", bps)
	}
}

// flagEmoji maps an ISO-3166 alpha-2 code onto its regional-indicator pair
// (project aesthetics contract: flags must render). Unknown/empty → white flag.
func flagEmoji(cc string) string {
	up := strings.ToUpper(strings.TrimSpace(cc))
	if len(up) != 2 || up[0] < 'A' || up[0] > 'Z' || up[1] < 'A' || up[1] > 'Z' {
		return "🏳"
	}
	first := 0x1F1E6 + rune(up[0]-'A')
	second := 0x1F1E6 + rune(up[1]-'A')
	return string(first) + string(second)
}

// FlagEmoji is the exported flag renderer for the sibling display command
// (`publicvpn list`); there is ONE emoji mapping in the repo.
func FlagEmoji(cc string) string { return flagEmoji(cc) }

// FormatMS is the exported millisecond cell formatter for `publicvpn list`
// (same compact spellings as the check report: —, <1ms, 45ms).
func FormatMS(ms float64) string { return fmtMS(ms) }
