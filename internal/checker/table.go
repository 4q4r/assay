package checker

import "strings"

// TableCell is one table cell for the exported table renderer: the display
// string (possibly colored), its VISIBLE width (0 = derive from S by rune
// count), and an optional palette color name ("green"/"yellow"/"red").
type TableCell struct {
	S     string
	Width int
	Color string
}

// RenderTable renders a compact, ANSI-safe table — headers plus row cells —
// with the exact cell/padding machinery the check report uses (visible
// width never counts escape bytes, columns widen instead of colliding).
// Exported for the sibling display command `publicvpn list`; there is ONE
// table implementation in this repo.
func RenderTable(headers []string, static []int, rows [][]TableCell, color bool) string {
	p := newPalette(color)
	header := make([]cell, len(headers))
	for i, h := range headers {
		header[i] = c(h)
	}
	lines := make([][]cell, 0, len(rows)+1)
	lines = append(lines, header)
	for _, row := range rows {
		cells := make([]cell, len(row))
		for i, tc := range row {
			s := tc.S
			if tc.Color != "" {
				s = p.apply(tc.Color, tc.S)
			}
			w := tc.Width
			if w == 0 {
				w = visibleWidth(s)
			}
			cells[i] = cw(s, w)
		}
		lines = append(lines, cells)
	}
	widths := effectiveWidths(static, lines)
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(renderLine(line, widths))
	}
	return b.String()
}
