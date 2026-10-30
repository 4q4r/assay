// W18 xray-update verdict chips: the final outcome lines render as chips
// when Options.Color is set; stage progress lines stay plain.

package xrayupdate

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerdictLinesColored pins the chip treatment on the outcome lines and
// the plain contract on the progress lines.
func TestVerdictLinesColored(t *testing.T) {
	t.Run("installed verdict is green chip", func(t *testing.T) {
		asset := fakeXrayZip(t, "26.10.21")
		srv := releaseServer(t, "v26.10.21", asset, "")
		target := filepath.Join(t.TempDir(), "bin", "xray")
		installFakeXray(t, target, "Xray 26.3.27")

		opts := baseOpts(t, srv.URL)
		opts.TargetPath = target
		opts.AssumeYes = true
		opts.Color = true
		stdout := opts.Stdout.(*bytes.Buffer)
		_, err := Run(opts)
		require.NoError(t, err)

		s := stdout.String()
		require.Contains(t, s, "38;5;241", "the xray-update: label is dim 241")
		require.Contains(t, s, "38;5;46", "the installed verdict is green")
		require.Contains(t, s, "installed at", "the verdict text survives")
		require.Contains(t, s, "downloading", "progress lines survive")
		// Progress lines stay plain (journald-friendly).
		for line := range strings.SplitSeq(s, "\n") {
			if strings.Contains(line, "downloading") ||
				strings.Contains(line, "sha256 verified") ||
				strings.Contains(line, "staged binary") {
				require.NotContains(t, line, "\x1b[", "progress line stays plain: "+line)
			}
		}
	})

	t.Run("declined verdict stays dim", func(t *testing.T) {
		asset := fakeXrayZip(t, "26.10.21")
		srv := releaseServer(t, "v26.10.21", asset, "")
		target := filepath.Join(t.TempDir(), "bin", "xray")
		installFakeXray(t, target, "Xray 26.3.27")

		opts := baseOpts(t, srv.URL)
		opts.TargetPath = target
		opts.Stdin = strings.NewReader("n\n")
		opts.Color = true
		stdout := opts.Stdout.(*bytes.Buffer)
		_, err := Run(opts)
		require.NoError(t, err)

		assert.Contains(t, stdout.String(), "declined", "the declined line renders")
	})

	t.Run("color-off is byte-plain", func(t *testing.T) {
		asset := fakeXrayZip(t, "26.10.21")
		srv := releaseServer(t, "v26.10.21", asset, "")
		target := filepath.Join(t.TempDir(), "bin", "xray")
		installFakeXray(t, target, "Xray 26.3.27")

		opts := baseOpts(t, srv.URL)
		opts.TargetPath = target
		opts.AssumeYes = true
		stdout := opts.Stdout.(*bytes.Buffer)
		_, err := Run(opts)
		require.NoError(t, err)

		assert.NotContains(t, stdout.String(), "\x1b[", "no color option = plain bytes")
		assert.Contains(t, stdout.String(), "installed at", "the legacy plain verdict line")
	})
}
