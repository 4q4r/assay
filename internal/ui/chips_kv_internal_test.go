// Package ui W18 additions: ChipKV (verbatim-spacing chips for the status
// screen's aligned label blocks).

package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ChipKV renders one label/value chip where the caller owns the exact
// spacing (the status screen's aligned "binary:    <path>" blocks). Color
// off: label+value verbatim — byte-identical to the legacy plain lines.
// Color on: dim-241 label + bold info-45 value, same literals.
func TestChipKV(t *testing.T) {
	plain := ChipKV("binary:    /home/u/.local/bin/publicvpn (mode -rwxr-xr-x)\n", "", false)
	require.Equal(t, "binary:    /home/u/.local/bin/publicvpn (mode -rwxr-xr-x)\n", plain,
		"color-off ChipKV is exactly the legacy line (label carries the spacing)")

	colored := ChipKV("install:", " 3 files present", true)
	require.Contains(t, colored, "38;5;241", "labels are dim 241")
	require.Contains(t, colored, "38;5;45", "values are info 45")
	assert.Contains(t, colored, "install:", "the label text survives")
	assert.Contains(t, colored, "3 files present", "the value text survives")
}

// Status screen blocks: section titles carry the header accent.
func TestHeaderAccentStatus(t *testing.T) {
	require.Equal(t, "install:", Header("install:", false))
	require.Contains(t, Header("install:", true), "38;5;99")
}
