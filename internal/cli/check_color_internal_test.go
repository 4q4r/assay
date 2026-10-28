package cli

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveColor(t *testing.T) {
	t.Run("auto is off for non-terminal writers (golden contract: color-off)", func(t *testing.T) {
		on, err := resolveColor("auto", false, &bytes.Buffer{})
		require.NoError(t, err)
		assert.False(t, on)
	})
	t.Run("auto honors NO_COLOR", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		on, err := resolveColor("auto", false, &bytes.Buffer{})
		require.NoError(t, err)
		assert.False(t, on)
	})
	t.Run("auto honors the --no-color alias", func(t *testing.T) {
		on, err := resolveColor("auto", true, &bytes.Buffer{})
		require.NoError(t, err)
		assert.False(t, on)
	})
	t.Run("always forces color on", func(t *testing.T) {
		on, err := resolveColor("always", false, &bytes.Buffer{})
		require.NoError(t, err)
		assert.True(t, on, "always must colorize even a pipe/buffer")
	})
	t.Run("always loses to the explicit --no-color alias", func(t *testing.T) {
		on, err := resolveColor("always", true, &bytes.Buffer{})
		require.NoError(t, err)
		assert.False(t, on, "the explicit off alias wins over a conflicting --color")
	})
	t.Run("never is off", func(t *testing.T) {
		on, err := resolveColor("never", false, &bytes.Buffer{})
		require.NoError(t, err)
		assert.False(t, on)
	})
	t.Run("invalid mode is loud", func(t *testing.T) {
		_, err := resolveColor("sometimes", false, &bytes.Buffer{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auto|always|never")
	})
	t.Run("NO_COLOR does not block an explicit always", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		on, err := resolveColor("always", false, &bytes.Buffer{})
		require.NoError(t, err)
		assert.True(t, on, "NO_COLOR is an auto-mode default, not an override of an explicit flag")
	})
}

func TestWriterIsTerminal(t *testing.T) {
	assert.False(t, writerIsTerminal(&bytes.Buffer{}), "a buffer is not a terminal")
	assert.False(t, writerIsTerminal(errWriter{}), "an erroring writer is not a terminal")
	// A real *os.File that is not a char device: the test's own source file.
	f, err := os.Open(".")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	assert.False(t, writerIsTerminal(f), "a directory handle is not a terminal")
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("nope") }
