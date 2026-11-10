// Package ui is the single owner of terminal styling for every assay
// CLI screen (W18): the lipgloss palette, the traffic-light helper, tree
// glyphs, chips, and the ONE bordered table builder shared by all screens.
//
// Color contract (W12 semantics preserved): --color=auto|always|never
// (auto = terminal-detected), NO_COLOR, and the --no-color alias force the
// resolved mode off. The package gates style application on the resolved
// mode — with color off, NO lipgloss style carries a color attribute, so
// rendering emits zero ANSI bytes (lipgloss v2 Render always emits
// full-fidelity ANSI for attributes that are set; the gate keeps every
// attribute unset). Goldens stay byte-stable color-off by construction.
//
// The owner's visual spec (verbatim, code-owned): traffic light <400ms
// green 46 / 400–799ms amber 214 / ≥800ms red 196; tree glyphs dim 240;
// chip labels dim 241 with bold info-45 values; table borders dim 238;
// header rows bold 99.
package ui

import (
	"fmt"
	"io"
	"os"
)

// The single palette: every color the CLI renders resolves through these
// ANSI-256 codes. Verdict/rate classes share the traffic-light trio so the
// screens stay visually coherent under one owner.
const (
	ColorGreen     = "46"  // traffic-light green / success
	ColorAmber     = "214" // traffic-light amber / partial / warnings
	ColorRed       = "196" // traffic-light red / failures / stale
	ColorDimTree   = "240" // tree glyphs
	ColorDimLabel  = "241" // chip labels
	ColorBorder    = "238" // table borders
	ColorHeader    = "99"  // table headers / section accents
	ColorInfo      = "45"  // chip values / recommendations
	ColorPlainName = "dim" // reserved name for dim data cells (tree rows)
)

// Palette color names used by Cell.Color and the verdict/rate mappers.
const (
	Green = "green"
	Amber = "amber"
	Red   = "red"
)

// paletteColor maps a palette name onto its ANSI-256 code; an unknown name
// is a programming error in the caller (panic — fail loud, never render a
// silent wrong color).
func paletteColor(name string) string {
	switch name {
	case Green:
		return ColorGreen
	case Amber:
		return ColorAmber
	case Red:
		return ColorRed
	case ColorPlainName:
		return ColorDimTree
	default:
		panic(fmt.Sprintf("ui: unknown palette color %q", name))
	}
}

// Resolve applies the --color mode contract: auto = a terminal decides
// (NO_COLOR and the --no-color alias force off); always/never force it.
// The --no-color alias wins over a conflicting --color — the explicit "off"
// is the safer reading of contradictory input. Invalid modes are loud.
func Resolve(mode string, noColor bool, out io.Writer) (bool, error) {
	switch mode {
	case "always":
		return !noColor, nil
	case "never":
		return false, nil
	case "auto":
	default:
		return false, fmt.Errorf("invalid --color %q (want auto|always|never)", mode)
	}
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false, nil
	}
	return WriterIsTerminal(out), nil
}

// WriterIsTerminal reports whether w is a character device (a TTY). A
// non-file writer (pipes, buffers, tests) is never a terminal.
func WriterIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
