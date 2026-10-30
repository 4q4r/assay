package ui

import (
	"fmt"

	"charm.land/lipgloss/v2"
)

// style is the base every accent builds on (empty — attributes are added
// only when color is on, so color-off rendering emits zero ANSI).
func style() lipgloss.Style { return lipgloss.NewStyle() }

// fg renders s in the given palette color name when color is on; plain
// otherwise.
func fg(name, s string, color bool) string {
	if !color {
		return s
	}
	return style().Foreground(lipgloss.Color(paletteColor(name))).Render(s)
}

// Chip renders one compact label:value chip (owner spec): the label dim
// 241, the value bold info 45. With color off it is exactly
// "label value" — the plain provenance line the logs already pin.
func Chip(label, value string, color bool) string {
	if !color {
		return label + " " + value
	}
	return style().Foreground(lipgloss.Color(ColorDimLabel)).Render(label) + " " +
		style().Bold(true).Foreground(lipgloss.Color(ColorInfo)).Render(value)
}

// Colorize renders s in the given palette color NAME (green/amber/red/dim)
// when color is on; plain otherwise. The helper for inline (non-table)
// colored spans — verdict lines, recommendation values.
func Colorize(name, s string, color bool) string { return fg(name, s, color) }

// ChipKV renders one label/value chip where the caller owns the exact
// spacing (the status screen's aligned "binary:    <path>" blocks). With
// color off it is label+value VERBATIM — byte-identical to the legacy
// plain lines; with color on, dim-241 label + bold info-45 value, same
// literals inside the styled spans.
func ChipKV(label, value string, color bool) string {
	if !color {
		return label + value
	}
	return style().Foreground(lipgloss.Color(ColorDimLabel)).Render(label) +
		style().Bold(true).Foreground(lipgloss.Color(ColorInfo)).Render(value)
}

// Header renders a section header accent (owner spec): bold 99.
func Header(s string, color bool) string {
	if !color {
		return s
	}
	return style().Bold(true).Foreground(lipgloss.Color(ColorHeader)).Render(s)
}

// Info renders a bold info-45 accent (recommendations, pool values).
func Info(s string, color bool) string {
	if !color {
		return s
	}
	return style().Bold(true).Foreground(lipgloss.Color(ColorInfo)).Render(s)
}

// Warn renders a warning-severity accent: "red" (196) for the urgent STALE
// class, "amber" (214) for migratable LEGACY / resolution warnings. An
// unknown severity under color is a programming error (fail loud — a
// silently unstyled warning would read as calm).
func Warn(s, severity string, color bool) string {
	switch severity {
	case Red:
	case Amber:
	case "plain":
		return s
	default:
		if color {
			panic(fmt.Sprintf("ui: unknown warning severity %q", severity))
		}
	}
	if !color {
		return s
	}
	return style().Bold(true).Foreground(lipgloss.Color(paletteColor(severity))).Render(s)
}
