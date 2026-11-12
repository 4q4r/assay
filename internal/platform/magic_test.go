package platform

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecMagicTable pins the per-OS executable magic the self-update
// verifier accepts (plan Consequence C / §5.7): ELF \x7fELF on linux, the
// Mach-O 64-bit magic as the darwin primary, PE "MZ" on windows.
func TestExecMagicTable(t *testing.T) {
	tests := []struct {
		goos  string
		want  []byte
		names string
	}{
		{"linux", []byte{0x7f, 'E', 'L', 'F'}, "ELF"},
		{"darwin", []byte{0xcf, 0xfa, 0xed, 0xfe}, "Mach-O"}, // 0xFEEDFACF LE
		{"windows", []byte{'M', 'Z'}, "PE"},
		{"freebsd", []byte{0x7f, 'E', 'L', 'F'}, "ELF"}, // off-matrix unix → ELF
	}
	for _, tt := range tests {
		magic := ExecMagic(tt.goos)
		assert.Equal(t, tt.want, magic, "ExecMagic(%q) magic bytes", tt.goos)
		assert.Equal(t, tt.names, ExecFormatName(tt.goos),
			"ExecFormatName(%q) must name the format for verifier messages", tt.goos)
	}
}

// TestExecMagicsDarwinAccepts32And64 pins §5.7 "Mach-O 32/64 magic": the
// darwin verifier accepts BOTH Mach-O magics (0xfeedface 32-bit,
// 0xfeedfacf 64-bit), with the 64-bit one canonical (every §4.4 darwin
// release target is 64-bit).
func TestExecMagicsDarwinAccepts32And64(t *testing.T) {
	magics := ExecMagics("darwin")
	require.Len(t, magics, 2, "darwin must accept exactly the 32/64 Mach-O magics")
	assert.Equal(t, []byte{0xcf, 0xfa, 0xed, 0xfe}, magics[0], "primary = 64-bit Mach-O")
	assert.Equal(t, []byte{0xce, 0xfa, 0xed, 0xfe}, magics[1], "32-bit Mach-O accepted")
	// ExecMagic stays the pinned single-magic accessor = the primary.
	assert.True(t, slices.Equal(ExecMagic("darwin"), magics[0]),
		"ExecMagic(darwin) must be ExecMagics(darwin)[0]")

	linux := ExecMagics("linux")
	require.Len(t, linux, 1)
	assert.Equal(t, []byte{0x7f, 'E', 'L', 'F'}, linux[0])

	win := ExecMagics("windows")
	require.Len(t, win, 1)
	assert.Equal(t, []byte{'M', 'Z'}, win[0], "PE magic is the two-byte MZ DOS header")
}
