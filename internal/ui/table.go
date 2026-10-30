package ui

import (
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/ansi"
)

// Column describes one table column: its header, the static MINIMUM width
// (columns grow to their widest cell instead of colliding — the M3
// contract), and whether the column is right-aligned (numeric data).
type Column struct {
	Header string
	Width  int
	Right  bool
}

// Cell is one table cell: the RAW display string (never pre-styled — colors
// apply through the table's StyleFunc so widths are computed from visible
// content only) and its optional palette color name (green/amber/red/dim;
// "" = inherit the row's plain look).
type Cell struct {
	S     string
	Color string
}

// Table renders the ONE bordered table every screen uses (owner spec W18):
// lipgloss NormalBorder box in dim 238, a bold 99 padded header row, and
// cells that keep a one-space padding on each side. Numeric columns
// right-align; every column is at least its static width and grows to fit
// its widest cell — rows never wrap, never collide. With color off, no
// style carries a color attribute and the bytes are the plain golden.
//
// Rows must carry exactly len(cols) cells — a short row panics inside
// lipgloss's StyleFunc. That is the fail-loud contract, deliberately
// unguarded: a malformed row is a programming error at the call site, not
// input to survive.
func Table(cols []Column, rows [][]Cell, color bool) string {
	widths := effectiveWidths(cols, rows)
	cellWidth := func(col int) int { return widths[col] + 2 } // + horizontal padding
	t := table.New().
		Border(lipgloss.NormalBorder()).
		StyleFunc(func(row, col int) lipgloss.Style {
			s := lipgloss.NewStyle().
				Padding(0, 1).
				Width(cellWidth(col))
			if cols[col].Right {
				s = s.Align(lipgloss.Right)
			}
			if row == table.HeaderRow {
				if !color {
					return s
				}
				return s.Bold(true).Foreground(lipgloss.Color(ColorHeader))
			}
			if !color {
				return s
			}
			if name := rows[row][col].Color; name != "" {
				s = s.Foreground(lipgloss.Color(paletteColor(name)))
			}
			return s
		})
	if color {
		// Owner spec: borders are dim 238.
		t = t.BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color(ColorBorder)))
	}
	headers := make([]string, len(cols))
	for i, c := range cols {
		headers[i] = c.Header
	}
	t = t.Headers(headers...)
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, cl := range r {
			cells[i] = cl.S
		}
		t = t.Row(cells...)
	}
	return t.String() + "\n"
}

// effectiveWidths raises each static column width to the widest visible
// cell that column must carry: extreme values — huge --attempts in the ok
// cell, ≥1GB/s speeds — widen their column instead of colliding into the
// next one. Widths are ANSI-aware (grapheme display width: a flag emoji is
// two cells), so styled content never skews the math.
func effectiveWidths(cols []Column, rows [][]Cell) []int {
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = max(ansi.StringWidth(c.Header), c.Width)
	}
	for _, row := range rows {
		for i := range cols {
			if i >= len(row) {
				continue
			}
			widths[i] = max(widths[i], ansi.StringWidth(row[i].S))
		}
	}
	return widths
}
