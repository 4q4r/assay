package ui

import (
	"fmt"

	"charm.land/lipgloss/v2"
)

// TreeGlyph renders the tree connector for one city sub-row inside its
// country's group (owner spec): ├── except the last row of the group, which
// closes with └──. The trailing space is part of the glyph so the city name
// follows with exactly one gap. pos must be inside [0,n) — a violation is a
// programming error in the caller.
func TreeGlyph(pos, n int, color bool) string {
	if n <= 0 || pos < 0 || pos >= n {
		panic(fmt.Sprintf("ui: tree glyph position %d out of range [0,%d)", pos, n))
	}
	glyph := "├── "
	if pos == n-1 {
		glyph = "└── "
	}
	if !color {
		return glyph
	}
	return style().Foreground(lipgloss.Color(ColorDimTree)).Render(glyph)
}
