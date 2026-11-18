//go:build darwin

package platform

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseVMStat pins the vm_stat report grammar (fixture shape copied
// from a real macOS vm_stat report, page size 16384 for the Apple Silicon
// form): available = (Pages free + Pages speculative) × page size.
func TestParseVMStat(t *testing.T) {
	const fixture = `Mach VM Stats: (page size of 16384 bytes)
Pages free: 24566.
Pages active: 340381.
Pages inactive: 169906.
Pages speculative: 12345.
Pages throttled: 0.
Pages wired down: 148244.
Pages purgeable: 54703.
Pages translated: 798173.
Pages reserved but unused: 2534.
`
	got, err := parseVMStat(fixture)
	require.NoError(t, err)
	require.Equal(t, (uint64(24566)+12345)*16384, got)
}

// TestParseVMStatIntel pins the 4096-byte Intel page-size form.
func TestParseVMStatIntel(t *testing.T) {
	const fixture = "Mach VM Stats: (page size of 4096 bytes)\nPages free: 1000.\nPages speculative: 250.\n"
	got, err := parseVMStat(fixture)
	require.NoError(t, err)
	require.Equal(t, uint64(1250)*4096, got)
}

func TestParseVMStatErrors(t *testing.T) {
	t.Run("missing page size header", func(t *testing.T) {
		_, err := parseVMStat("Pages free: 1.\nPages speculative: 2.\n")
		require.Error(t, err)
	})
	t.Run("missing free line", func(t *testing.T) {
		_, err := parseVMStat("(page size of 4096 bytes)\nPages speculative: 2.\n")
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "Pages free"), "error must name the field: %v", err)
	})
	t.Run("garbage count", func(t *testing.T) {
		_, err := parseVMStat("(page size of 4096 bytes)\nPages free: banana.\nPages speculative: 2.\n")
		require.Error(t, err)
	})
}

// TestMemAvailableLiveSmoke runs the real vm_stat read once on darwin: a
// healthy macOS host always reports a non-zero immediately-reclaimable pool.
func TestMemAvailableLiveSmoke(t *testing.T) {
	v, err := MemAvailable()
	require.NoError(t, err)
	require.Positive(t, v)
}
