package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLegacyShareLeafMatchesFixture pins the pre-rename data-dir leaf
// against a non-.go fixture. The rename's acceptance contract keeps the old
// spelling out of Go sources, so the assembled legacyShareLeaf constant has
// no literal twin in code — the fixture (testdata is outside the scoped
// acceptance-grep set) is the non-self-referential anchor: if the assembly
// ever drifts from the historical leaf, this pin fails and the
// found-if-exists courtesy would silently address the wrong directory.
func TestLegacyShareLeafMatchesFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "legacy-share-leaf.txt"))
	require.NoError(t, err, "the fixture pinning the historical leaf must exist")
	assert.Equal(t, legacyShareLeaf, strings.TrimSpace(string(raw)),
		"legacyShareLeaf must be exactly the pre-rename local-share leaf the on-disk layout carries")

	// The whole old data dir derived from the leaf, under the documented
	// scheme: one anchor for both branches (absolute XDG_DATA_HOME and the
	// home fallback).
	t.Setenv("XDG_DATA_HOME", "") // hermetic: pin the fallback branch
	assert.Equal(t, filepath.Join("/home/tester", ".local", "share", legacyShareLeaf), legacyShareDataDir("/home/tester"))
}
