package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCoreBinaryNameTable pins the §4.2 path-table row "Managed core" and
// Review Focus 5: the binname table is the ONLY source of the managed Xray
// core's file name — xray.exe everywhere on windows, xray elsewhere. No
// resolution/update path may join a bare "xray" literal.
func TestCoreBinaryNameTable(t *testing.T) {
	tests := []struct {
		goos string
		want string
	}{
		{"linux", "xray"},
		{"darwin", "xray"},
		{"windows", "xray.exe"},
		// Off-matrix GOOS values keep the unsuffixed name (the unix
		// convention) rather than failing: the release matrix (§4.4) never
		// ships them, but the table must stay total.
		{"freebsd", "xray"},
		{"", "xray"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, CoreBinaryName(tt.goos),
			"CoreBinaryName(%q) must follow the §4.2 managed-core row", tt.goos)
	}
}

// TestAssayBinaryName pins the installed-binary name table (§4.2 "Installed
// binary"): assay.exe on windows (the SCM registration and CreateProcess
// need the PE extension), assay elsewhere — the S0 Review-Focus-5 discipline
// applied to assay's own name.
func TestAssayBinaryName(t *testing.T) {
	assert.Equal(t, "assay.exe", AssayBinaryName("windows"))
	assert.Equal(t, "assay", AssayBinaryName("linux"))
	assert.Equal(t, "assay", AssayBinaryName("darwin"))
}
