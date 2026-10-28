package cli_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"public_vpn/internal/cli"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckCommandExistsInTree(t *testing.T) {
	root := cli.New()
	var cmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "check" {
			cmd = c
			break
		}
	}
	require.NotNil(t, cmd, "check command must exist in the tree")
	assert.NotEmpty(t, cmd.Use)
	assert.True(t, cmd.HasAvailableFlags())
}

func TestCheckLoudOnEmptyColdBase(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf(`
data_dir = %q
[sources.dummy]
repo = "owner/repo"
discovery = "github-contents"
include = ["vless.txt"]
`, dir)), 0o600))

	root := cli.New()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"-c", cfgPath, "check", "https://example.com"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no checkable nodes")
	assert.Contains(t, err.Error(), "publicvpn probe")
}

func TestCheckLoudOnBadTarget(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf(`
data_dir = %q
[sources.dummy]
repo = "owner/repo"
discovery = "github-contents"
include = ["vless.txt"]
`, dir)), 0o600))

	root := cli.New()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"-c", cfgPath, "check", "ftp://nope"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not http/https")
}

func TestCheckColorFlagSurface(t *testing.T) {
	root := cli.New()
	var check *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "check" {
			check = c
			break
		}
	}
	require.NotNil(t, check)
	color := check.Flags().Lookup("color")
	require.NotNil(t, color, "--color must exist")
	assert.Equal(t, "auto", color.DefValue, "--color defaults to auto (tty-detected)")

	noColor := check.Flags().Lookup("no-color")
	require.NotNil(t, noColor, "--no-color stays as the deprecated-friendly alias")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf(`
data_dir = %q
[sources.dummy]
repo = "owner/repo"
discovery = "github-contents"
include = ["vless.txt"]
`, dir)), 0o600))

	root = cli.New()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"-c", cfgPath, "check", "--color", "bogus", "https://example.com"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auto|always|never", "an invalid --color value fails loud")
}
