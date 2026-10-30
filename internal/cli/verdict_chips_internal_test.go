// W18 verdict chips: the activate stage's final verdict lines
// ("activation complete:", "restart: …", "wave verdict: …") render as
// chips when color is on; stage progress lines stay plain (journald-safe).

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// coloredStageCmd is a stage command with the color mode forced on (the
// same resolution path the CLI commands use through their flags).
func coloredStageCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	attachColorFlags(cmd)
	require.NoError(t, cmd.Flags().Set("color", "always"))
	return cmd
}

// stageOutput returns the buffer a stage command writes into.
func stageOutput(cmd *cobra.Command) *bytes.Buffer {
	return cmd.OutOrStdout().(*bytes.Buffer)
}

// TestW18VerdictChipsColored pins the colored verdict block: restart ok is
// green (the traffic-light green), DONE_WITH wave verdicts are amber, and
// the diagnostic lines around them carry NO styling bytes.
func TestW18VerdictChipsColored(t *testing.T) {
	t.Run("restart ok → green chip", func(t *testing.T) {
		cfg, rec := restartFixture(t, "ok")
		writeMaintainFiles(t, cfg, `{"v":2}`, `{"old":true}`)
		wiring := &restartWiring{Executor: rec, Dialer: rec.dial, Sleep: noSleep}

		cmd := coloredStageCmd(t)
		require.NoError(t, runActivateStage(cmd, cfg, wiring))
		s := stageOutput(cmd).String()
		require.Contains(t, s, "38;5;241", "verdict labels are dim 241")
		require.Contains(t, s, "38;5;46", "restart ok is green")
		require.Contains(t, s, "activation complete:", "the verdict text survives")
		require.Equal(t, 1, strings.Count(s, "\x1b[38;5;241mactivation complete:"),
			"the activation-complete label is chip-styled exactly once")
	})

	t.Run("restart failure → amber wave verdict, plain diagnostics", func(t *testing.T) {
		cfg, rec := restartFixture(t, "ok")
		rec.restartErr = errors.New("exit status 1: bus")
		writeMaintainFiles(t, cfg, `{"v":2}`, `{"old":true}`)
		wiring := &restartWiring{Executor: rec, Dialer: rec.dial}

		cmd := coloredStageCmd(t)
		require.NoError(t, runActivateStage(cmd, cfg, wiring))
		s := stageOutput(cmd).String()
		require.Contains(t, s, "38;5;214m", "the DONE_WITH wave verdict is amber")
		require.Contains(t, s, "wave verdict:", "the verdict label survives")
		require.Contains(t, s, "DONE_WITH restart-failure", "the verdict class survives")
		require.Contains(t, s, "ERROR: restart FAILED",
			"diagnostic lines stay PLAIN (journald-friendly — no ANSI on them)")
	})

	t.Run("color-off stays byte-plain", func(t *testing.T) {
		cfg, rec := restartFixture(t, "ok")
		writeMaintainFiles(t, cfg, `{"v":2}`, `{"old":true}`)
		wiring := &restartWiring{Executor: rec, Dialer: rec.dial, Sleep: noSleep}

		out := runStageCapturing(t, cfg, wiring)
		require.NotContains(t, out, "\x1b[", "no color mode resolved = plain")
		require.Contains(t, out, "restart: restart ok", "the legacy plain verdict line")
	})
}
