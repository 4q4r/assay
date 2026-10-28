package checker

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// RenderOptions controls one textual report.
type RenderOptions struct {
	Color bool // green success / yellow partial / red fail; --no-color strips all ANSI
	Top   int  // geo-summary and recommendation rows per block (0 = all)
}

// ANSI palette (zeroed in --no-color mode so every cell is plain text).
type palette struct{ green, yellow, red, reset string }

func newPalette(color bool) palette {
	if !color {
		return palette{}
	}
	return palette{green: "\x1b[32m", yellow: "\x1b[33m", red: "\x1b[31m", reset: "\x1b[0m"}
}

// RenderReport renders the full check report: one block per target (table +
// geo summaries + recommendation), then the staleness hint. Rows never wrap —
// long values are truncated to their column, every line is a single line.
func RenderReport(rep *Report, opts RenderOptions) string {
	p := newPalette(opts.Color)
	b := &strings.Builder{}
	for _, tr := range rep.Targets {
		renderTarget(b, rep, tr, p, opts.Top)
	}
	if rep.Stale {
		fmt.Fprintf(b, "\nhint: probe data is %s old (geo.ttl %s) — run `publicvpn maintain` (probe + geo) for freshness\n",
			rep.StaleAge, rep.GeoTTL)
	}
	return b.String()
}

func renderTarget(b *strings.Builder, rep *Report, tr *TargetResult, p palette, top int) {
	fmt.Fprintf(b, "site check — %s\n", tr.URL)
	fmt.Fprintf(b, "nodes tested: %d · attempts: %d/node · timeout: %s\n",
		len(tr.Rows), rep.Attempts, rep.Timeout)
	fmt.Fprintf(b, "dns view: %s — dns.google/resolve queried through each node\n", dnsMethodLabel(tr))
	renderRows(b, tr.Rows, p)
	fmt.Fprintf(b, "\ngeo summary — countries\n")
	renderGroups(b, tr.Countries, false, p, top)
	fmt.Fprintf(b, "\ngeo summary — cities\n")
	renderGroups(b, tr.Cities, true, p, top)
	fmt.Fprintf(b, "\nrecommendation — best locations for matching rules (%s)\n", tr.URL)
	renderRecommendation(b, tr, p, top)
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

// table headers and widths (visible cells; compact, no wrap).
var (
	reportHeaders = []string{
		"node", "loc", "city", "asn/isp", "ok", "statuses", "tls", "rtt", "ttfb", "avg", "speed", "resolved", "note",
	}
	reportWidths = []int{13, 6, 12, 24, 5, 13, 4, 7, 8, 7, 9, 15, 24}
	groupHeaders = []string{"loc", "nodes", "ok", "success", "median", "avg", "speed"}
	groupWidths  = []int{6, 5, 7, 7, 7, 7, 9}
	cityHeaders  = []string{"city", "nodes", "ok", "success", "median", "avg", "speed"}
	cityWidths   = []int{26, 5, 7, 7, 7, 7, 9}
)

func renderRows(b *strings.Builder, rows []*NodeResult, p palette) {
	header := make([]cell, len(reportHeaders))
	for i, h := range reportHeaders {
		header[i] = c(h)
	}
	lines := make([][]cell, 0, len(rows)+1)
	lines = append(lines, header)
	for _, r := range rows {
		lines = append(lines, rowCells(r))
	}
	widths := effectiveWidths(reportWidths, lines)
	for i, line := range lines {
		text := renderLine(line, widths)
		if i > 0 {
			text = p.apply(verdictColor(rows[i-1].Verdict), text)
		}
		b.WriteString(text)
	}
}

// rowCells builds one node row (cells and their visible widths).
func rowCells(r *NodeResult) []cell {
	node := r.Tag
	if strings.TrimSpace(node) == "" {
		node = r.Host // pre-select cold-base records carry no tags — the host identifies the row
	}
	return []cell{
		c(trunc(node, 13)),
		c(flagEmoji(r.Country) + " " + strings.ToUpper(r.Country)),
		c(trunc(orDash(r.City), 12)),
		c(trunc(orDash(strings.TrimSpace(r.ASN+" "+r.ISP)), 24)),
		c(fmt.Sprintf("%d/%d", r.OK, r.Total)),
		c(trunc(orDash(joinInts(r.Statuses)), 13)),
		c(orDash(r.TLSVersion)),
		c(fmtMS(r.ConnectMS)),
		c(fmtMS(r.AvgTTFBMS)),
		c(fmtMS(r.AvgMS)),
		c(fmtBPS(r.AvgSpeedBPS)),
		c(trunc(orDash(firstIP(r.ResolvedIPs)), 15)),
		c(trunc(noteFor(r), 24)),
	}
}

func renderGroups(b *strings.Builder, groups []GroupStat, city bool, p palette, top int) {
	headers, static := groupHeaders, groupWidths
	if city {
		headers, static = cityHeaders, cityWidths
	}
	if len(groups) == 0 {
		b.WriteString("(no data)\n")
		return
	}
	shown := groups
	if top > 0 && len(shown) > top {
		shown = shown[:top]
	}
	header := make([]cell, len(headers))
	for i, h := range headers {
		header[i] = c(h)
	}
	lines := make([][]cell, 0, len(shown)+1)
	lines = append(lines, header)
	for _, g := range shown {
		lines = append(lines, groupCells(g, city, p))
	}
	widths := effectiveWidths(static, lines)
	for _, line := range lines {
		b.WriteString(renderLine(line, widths))
	}
}

// groupCells builds one geo-summary row (cells and their visible widths).
func groupCells(g GroupStat, city bool, p palette) []cell {
	rateStr := fmt.Sprintf("%.0f%%", g.SuccessRate*100)
	loc := flagEmoji(g.Country) + " " + g.Country
	cells := []cell{
		c(loc),
		c(strconv.Itoa(g.Nodes)),
		c(fmt.Sprintf("%d/%d", g.OK, g.Total)),
		cw(p.apply(rateColor(g.SuccessRate), rateStr), len([]rune(rateStr))),
		c(fmtMS(g.MedianMS)),
		c(fmtMS(g.AvgMS)),
		c(fmtBPS(g.AvgSpeedBPS)),
	}
	if city {
		cells[0] = c(trunc(loc+" "+g.City, 26))
	}
	return cells
}

// effectiveWidths raises each static column width to the widest cell that
// column must carry (header included): extreme values — huge --attempts in
// the ok cell, ≥1GB/s speeds — widen their column instead of colliding into
// the next one. Columns whose content fits keep the static width byte-for-byte.
func effectiveWidths(static []int, lines [][]cell) []int {
	widths := append([]int(nil), static...)
	for _, line := range lines {
		for i, cl := range line {
			if i < len(widths) && cl.width > widths[i] {
				widths[i] = cl.width
			}
		}
	}
	return widths
}

func renderRecommendation(b *strings.Builder, tr *TargetResult, p palette, top int) {
	countries := filterServed(tr.Recommendation)
	if len(countries) == 0 {
		b.WriteString("no location served this URL — every tested node failed or was blocked\n")
		return
	}
	for i, g := range countries {
		if top > 0 && i >= top {
			break
		}
		fmt.Fprintf(b, "%d. %s %s %s— %.0f%% ok (%d/%d attempts) — median %s — %s\n",
			i+1, p.apply(rateColor(g.SuccessRate), flagEmoji(g.Country)), g.Country,
			p.reset, g.SuccessRate*100, g.OK, g.Total, fmtMS(g.MedianMS), fmtBPS(g.AvgSpeedBPS))
	}
	cities := filterServed(tr.Cities)
	if len(cities) > 0 {
		b.WriteString("cities:\n")
		for i, g := range cities {
			if top > 0 && i >= top {
				break
			}
			fmt.Fprintf(b, "  %s %s — %.0f%% ok (%d/%d) — median %s\n",
				flagEmoji(g.Country), trunc(g.City, 26), g.SuccessRate*100, g.OK, g.Total, fmtMS(g.MedianMS))
		}
	}
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

// cell is one table cell: the display string (possibly ANSI-colored) plus its
// VISIBLE width — padding must never count escape bytes.
type cell struct {
	s     string
	width int
}

func c(s string) cell { return cell{s: s, width: visibleWidth(s)} }

func cw(s string, width int) cell { return cell{s: s, width: width} }

func renderLine(cells []cell, widths []int) string {
	var line strings.Builder
	for i, w := range widths {
		cl := cell{}
		if i < len(cells) {
			cl = cells[i]
		}
		line.WriteString(cl.s)
		line.WriteString(strings.Repeat(" ", maxInt(w+2-cl.width, 2)))
	}
	return strings.TrimRight(line.String(), " ") + "\n"
}

// visibleWidth counts display cells: ASCII by rune; flag emoji pairs were
// built by flagEmoji and contribute exactly 2 cells each (handled upstream).
func visibleWidth(s string) int { return utf8.RuneCountInString(s) }

func (p palette) color(code, s string) string {
	if code == "" || s == "" {
		return s
	}
	return code + s + p.reset
}

func verdictColor(v Verdict) string {
	switch v {
	case VerdictSuccess:
		return "green"
	case VerdictPartial:
		return "yellow"
	case VerdictBlockedHTTP, VerdictBlockedPage, VerdictDNSFail, VerdictTLSFail,
		VerdictDialFail, VerdictReadTimeout, VerdictCanceled, VerdictTimeout,
		VerdictBlocked, VerdictFail, VerdictError:
		return "red"
	default:
		return "red"
	}
}

func rateColor(rate float64) string {
	switch {
	case rate >= 0.99:
		return "green"
	case rate >= 0.5:
		return "yellow"
	default:
		return "red"
	}
}

// colorize by name — verdictColor/rateColor return names, resolved here so
// the palette stays a render concern.
func (p palette) apply(name, s string) string {
	switch name {
	case "green":
		return p.color(p.green, s)
	case "yellow":
		return p.color(p.yellow, s)
	case "red":
		return p.color(p.red, s)
	}
	return s
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

// trunc cuts a string to w visible cells, appending an ellipsis when cut.
func trunc(s string, w int) string {
	if utf8.RuneCountInString(s) <= w {
		return s
	}
	r := []rune(s)
	return string(r[:w-1]) + "…"
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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
