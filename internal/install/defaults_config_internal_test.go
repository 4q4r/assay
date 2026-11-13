package install

import (
	"os"
	"path/filepath"
	"testing"

	"assay/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The materialized default config must PARSE on every OS. The data_dir value
// is a windows path on windows, and a TOML BASIC string reads \U as the start
// of a unicode escape — the windows SCM E2E leg died exactly there ("invalid
// hexadecimal digit in unicode escape sequence" while the daemon parsed
// %LOCALAPPDATA%\assay\config.toml at service start, so the SCM never saw
// Running within the install verify window). The template must therefore
// emit a TOML LITERAL string for data_dir (backslashes verbatim on every
// OS), and a path containing a single quote — unrepresentable in a literal
// string — must be refused loudly before anything is written.
func TestMaterializeDefaultConfigDataDirRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		dataDir string
		wantErr bool
	}{
		{"windows path with backslashes", `C:\Users\runneradmin\AppData\Local\assay\data`, false},
		{"unix path", "/home/user/.local/share/assay/data", false},
		{"single-quote path is refused", `C:\Users\O'Brien\assay\data`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "assay", "config.toml")
			created, err := MaterializeDefaultConfig(cfgPath, tc.dataDir)
			if tc.wantErr {
				require.Error(t, err, "a quote-hostile data_dir must be refused before write")
				assert.False(t, created)
				_, statErr := os.Stat(cfgPath)
				assert.True(t, os.IsNotExist(statErr), "a refused render must leave no file behind")
				return
			}
			require.NoError(t, err)
			assert.True(t, created)
			// THE CONTRACT: the daemon's own config loader — the exact
			// reader that died on windows — must load the file and see the
			// path VERBATIM.
			cfg, lerr := config.Load(cfgPath)
			require.NoError(t, lerr, "the materialized default config must parse with the daemon's own loader")
			assert.Equal(t, tc.dataDir, cfg.DataDir, "data_dir must round-trip verbatim")
		})
	}
}
