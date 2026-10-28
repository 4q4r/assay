package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// findCmd resolves a subcommand by name from the command tree.
func findCmd(t *testing.T, root *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, c := range root.Commands() {
		if c.Name() == name {
			return c
		}
	}
	require.FailNow(t, "command not found", "%q must exist in the command tree", name)
	return nil
}
