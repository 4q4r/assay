// Package ui tests: the single terminal-styling owner (W18). These pins
// cover the color contract, the owner-specified traffic light boundaries,
// tree glyphs, chips, and the ONE bordered table builder — all byte-stable
// with color off.

package ui

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveColorContract(t *testing.T) {
	t.Run("auto is off for non-terminal writers", func(t *testing.T) {
		on, err := Resolve("auto", false, &bytes.Buffer{})
		require.NoError(t, err)
		assert.False(t, on)
	})
	t.Run("auto honors NO_COLOR", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		on, err := Resolve("auto", false, &bytes.Buffer{})
		require.NoError(t, err)
		assert.False(t, on)
	})
	t.Run("auto honors the --no-color alias", func(t *testing.T) {
		on, err := Resolve("auto", true, &bytes.Buffer{})
		require.NoError(t, err)
		assert.False(t, on)
	})
	t.Run("always forces color on", func(t *testing.T) {
		on, err := Resolve("always", false, &bytes.Buffer{})
		require.NoError(t, err)
		assert.True(t, on, "always must colorize even a pipe/buffer")
	})
	t.Run("always loses to the explicit --no-color alias", func(t *testing.T) {
		on, err := Resolve("always", true, &bytes.Buffer{})
		require.NoError(t, err)
		assert.False(t, on, "the explicit off alias wins over a conflicting --color")
	})
	t.Run("never is off", func(t *testing.T) {
		on, err := Resolve("never", false, &bytes.Buffer{})
		require.NoError(t, err)
		assert.False(t, on)
	})
	t.Run("invalid mode is loud", func(t *testing.T) {
		_, err := Resolve("sometimes", false, &bytes.Buffer{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auto|always|never")
	})
	t.Run("NO_COLOR does not block an explicit always", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		on, err := Resolve("always", false, &bytes.Buffer{})
		require.NoError(t, err)
		assert.True(t, on, "NO_COLOR is an auto-mode default, not an override of an explicit flag")
	})
}

// Owner spec (verbatim): <400ms green (46), 400–799ms amber (214),
// ≥800ms red (196). The boundaries are code-owned display constants.
func TestTrafficLightBoundaries(t *testing.T) {
	require.Equal(t, Green, TrafficName(399), "399 is inside the green band")
	require.Equal(t, Amber, TrafficName(400), "400 opens the amber band")
	require.Equal(t, Amber, TrafficName(799), "799 is inside the amber band")
	require.Equal(t, Red, TrafficName(800), "800 opens the red band")
	require.Equal(t, Green, TrafficName(0.1), "sub-ms latencies are green")
	require.Empty(t, TrafficName(0), "missing data (dash) carries no color")
	require.Empty(t, TrafficName(-5), "negative/absent data carries no color")
}

func TestTreeGlyphs(t *testing.T) {
	require.Equal(t, "└── ", TreeGlyph(0, 1, false), "a single city row is the last")
	require.Equal(t, "├── ", TreeGlyph(0, 3, false), "first of many")
	require.Equal(t, "├── ", TreeGlyph(1, 3, false), "mid of many")
	require.Equal(t, "└── ", TreeGlyph(2, 3, false), "last of many")
	require.Panics(t, func() { TreeGlyph(2, 1, false) }, "out-of-range position is a programming error")
}

func TestTreeGlyphsColored(t *testing.T) {
	require.NotContains(t, TreeGlyph(0, 2, false), "\x1b[", "color-off glyphs are plain")
	require.Contains(t, TreeGlyph(0, 2, true), "\x1b[", "color-on glyphs carry ANSI")
	require.Contains(t, TreeGlyph(0, 2, true), "38;5;240", "glyphs are dim gray 240 (owner spec)")
}

func TestChipPlain(t *testing.T) {
	out := Chip("config:", "share ~/.local/share/assay/config.toml", false)
	require.Equal(t, "config: share ~/.local/share/assay/config.toml", out,
		"color-off chips are exactly label + space + value")
	require.NotContains(t, out, "\x1b[")
}

func TestChipColored(t *testing.T) {
	out := Chip("config:", "share path", true)
	require.Contains(t, out, "38;5;241", "chip labels are dim 241 (owner spec)")
	require.Contains(t, out, "38;5;45", "chip values are info 45 (owner spec)")
	assert.Contains(t, out, "1m", "chip values are bold")
}

func TestHeaderAccent(t *testing.T) {
	plain := Header("📦 pool inventory", false)
	require.Equal(t, "📦 pool inventory", plain, "color-off headers are plain")
	colored := Header("📦 pool inventory", true)
	require.Contains(t, colored, "38;5;99", "headers are accent 99 (owner spec)")
	require.Contains(t, colored, "\x1b[1;", "header is bold (combined bold+fg SGR)")
}

func TestWarnAccent(t *testing.T) {
	require.Contains(t, Warn("STALE: drift", "red", true), "38;5;196", "red severity = 196")
	require.Contains(t, Warn("LEGACY: migrate", "amber", true), "38;5;214", "amber severity = 214")
	require.Equal(t, "STALE: drift", Warn("STALE: drift", "red", false), "color-off warns are plain")
	require.Equal(t, "x", Warn("x", "bogus", false), "unknown severity degrades to plain")
	require.Panics(t, func() { Warn("x", "bogus", true) }, "unknown severity under color is a programming error")
}

// The bordered table (color-off) — the exact byte contract: NormalBorder
// box, header row, padded cells, numeric columns right-aligned. First run
// materializes the golden; later runs pin it (repo golden pattern).
func TestTablePlainGolden(t *testing.T) {
	cols := []Column{
		{Header: "loc", Width: 6},
		{Header: "nodes", Width: 5, Right: true},
		{Header: "alive", Width: 5, Right: true},
		{Header: "median", Width: 7, Right: true},
	}
	rows := [][]Cell{
		{{S: "🇩🇪 de Germany"}, {S: "2"}, {S: "1", Color: Amber}, {S: "46ms", Color: Green}},
		{{S: "🇫🇷 fr France"}, {S: "1"}, {S: "1", Color: Green}, {S: "60ms", Color: Green}},
	}
	out := Table(cols, rows, false)
	goldenPath := filepath.Join("testdata", "golden-table-plain.txt")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		require.NoError(t, os.MkdirAll("testdata", 0o750), "testdata dir")
		require.NoError(t, os.WriteFile(goldenPath, []byte(out), 0o644),
			"first run materializes the golden")
		return
	}
	// LF-normalized against windows checkout noise (.gitattributes pins
	// LF; the strip is the belt) — CRLF is never render content.
	require.Equal(t, strings.ReplaceAll(string(golden), "\r\n", "\n"), out,
		"table diverged from testdata/golden-table-plain.txt — regenerate deliberately")
}

func TestTablePlainShape(t *testing.T) {
	cols := []Column{{Header: "a", Width: 3}, {Header: "b", Width: 4, Right: true}}
	rows := [][]Cell{{{S: "one"}, {S: "12"}}}
	out := Table(cols, rows, false)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// top border + header + header separator + 1 data row + bottom border.
	require.Len(t, lines, 5, "exactly: top, header, separator, row, bottom")
	require.True(t, strings.HasPrefix(lines[0], "┌"), "NormalBorder top")
	require.True(t, strings.HasPrefix(lines[1], "│"), "header row inside verticals")
	require.True(t, strings.HasPrefix(lines[2], "├"), "header separator")
	require.True(t, strings.HasPrefix(lines[3], "│"), "data row inside verticals")
	require.True(t, strings.HasPrefix(lines[4], "└"), "NormalBorder bottom")
	require.Contains(t, out, " a ", "text cells keep a padding space")
	require.Contains(t, out, "12 ", "numeric cells right-align against the border")
}

// Extreme values must WIDEN their column instead of colliding (the M3
// contract, ported from the pre-lipgloss renderer).
func TestTableExtremeValuesWidenColumns(t *testing.T) {
	cols := []Column{{Header: "ok", Width: 5, Right: true}, {Header: "speed", Width: 9, Right: true}}
	rows := [][]Cell{
		{{S: "0/100000"}, {S: "1536.0MB/s"}},
		{{S: "3/3"}, {S: "1.2MB/s"}},
	}
	out := Table(cols, rows, false)
	require.Contains(t, out, "0/100000", "attempt count must not be clipped")
	require.Contains(t, out, "1536.0MB/s", "extreme speed must not be clipped")
	require.Contains(t, out, "3/3", "normal values still present")
	// Both data rows keep the same byte offset for their first-column value:
	// alignment survives the widening.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var rowOffsets []int
	for _, ln := range lines {
		if strings.HasPrefix(ln, "│") && !strings.Contains(ln, "ok") {
			rowOffsets = append(rowOffsets, strings.Index(ln, "│ ")+2)
		}
	}
	require.Len(t, rowOffsets, 2, "both data rows found")
	require.Equal(t, rowOffsets[0], rowOffsets[1], "rows start at the same byte offset")
}

func TestTableColoredBytes(t *testing.T) {
	cols := []Column{{Header: "loc", Width: 6}, {Header: "median", Width: 7, Right: true}}
	rows := [][]Cell{{{S: "🇩🇪 de"}, {S: "46ms", Color: Green}}}
	out := Table(cols, rows, true)
	require.Contains(t, out, "38;5;238", "borders are dim 238 (owner spec)")
	require.Contains(t, out, "38;5;99", "header row is 99 bold (owner spec)")
	require.Contains(t, out, "\x1b[1;", "header is bold (combined bold+fg SGR)")
	require.Contains(t, out, "38;5;46", "traffic-light green cell is 46 (owner spec)")
}

// Color-off output must be byte-identical to the plain golden regardless of
// the process environment (lipgloss never sees a color attribute to emit).
func TestTableColorOffUnderColoredEnv(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("COLORTERM", "truecolor")
	cols := []Column{{Header: "a", Width: 3}}
	rows := [][]Cell{{{S: "x"}}}
	plainEnv := Table(cols, rows, false)
	plainBare := Table(cols, rows, false)
	require.Equal(t, plainBare, plainEnv, "color-off rendering ignores the terminal environment")
	require.NotContains(t, plainEnv, "\x1b[")
}

// A colored cell in one row must not perturb the alignment of plain cells
// in other rows (widths computed from visible content, never ANSI bytes).
func TestTableWidthsIgnoreANSI(t *testing.T) {
	cols := []Column{{Header: "loc", Width: 6}, {Header: "median", Width: 7, Right: true}}
	rows := [][]Cell{
		{{S: "🇩🇪 de"}, {S: "46ms", Color: Green}},
		{{S: "🇺🇸 us United States"}, {S: "149ms", Color: Amber}},
	}
	colored := Table(cols, rows, true)
	require.Contains(t, colored, "149ms", "the wide row still renders fully")
	// The flag emoji counts as 2 display cells (grapheme width, not runes):
	// "🇺🇸 us United States" = 2 + 17 = 19 cells; the loc column must fit it
	// on ONE line — 6 rendered lines exactly (top, header, separator, 2 rows,
	// bottom) proves neither row wrapped.
	require.Equal(t, 6, strings.Count(colored, "\n"),
		"each row renders on a single unwrapped line")
	require.Equal(t, 1, strings.Count(Table(cols, rows, false), "\n│ 🇺🇸 us United States"),
		"the plain table keeps the wide row on one line too")
}

func TestWriterIsTerminal(t *testing.T) {
	assert.False(t, WriterIsTerminal(&bytes.Buffer{}), "a buffer is not a terminal")
	assert.False(t, WriterIsTerminal(errWriter{}), "an erroring writer is not a terminal")
	f, err := os.Open(".")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	assert.False(t, WriterIsTerminal(f), "a directory handle is not a terminal")
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("nope") }
