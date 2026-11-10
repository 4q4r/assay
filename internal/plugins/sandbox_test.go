package plugins_test

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"assay/internal/fetch"
	"assay/internal/plugins"

	"github.com/stretchr/testify/require"
)

// TestSandboxInfiniteLoopTerminatesPromptly verifies that a rogue Lua plugin
// executing an infinite loop terminates immediately upon context timeout
// and does not hang or leak its runner goroutine.
func TestSandboxInfiniteLoopTerminatesPromptly(t *testing.T) {
	eng := plugins.NewEngine(fetch.ClientConfig{}, nil)
	//nolint:dupword // Lua infinite loop pattern
	pl, err := plugins.Compile("infinite_loop", "infinite_loop.lua", []byte(`
		return function()
			while true do end
		end
	`), nil)
	require.NoError(t, err)

	initialGoroutines := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, runErr := eng.Run(ctx, pl)
	elapsed := time.Since(start)

	require.Error(t, runErr, "expected error on context timeout")
	require.True(t, strings.Contains(runErr.Error(), "context deadline exceeded") ||
		strings.Contains(runErr.Error(), "canceled"), "error must reflect timeout: %v", runErr)
	require.Less(t, elapsed, 1*time.Second, "infinite loop must abort within reasonable time, elapsed: %v", elapsed)

	// Verify goroutines settle and no runaway goroutine is left spinning
	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= initialGoroutines+1
	}, 1*time.Second, 50*time.Millisecond, "goroutines must be cleaned up and not leak")
}
