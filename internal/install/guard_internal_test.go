package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W10 hard-scope guard, migrated through W13: the install package's ENTIRE
// systemctl surface stays the four-command allowlist — --user only, only
// assay-* units, daemon-reload / enable --now (watch) / disable --now
// (watch) / disable --now (the legacy W5 timers, solely for the one-time
// migration). UNCHANGED by W13: install still never restarts anything —
// the owner-ruled xray restart lives in internal/restart's own byte-pinned
// executor (the only other sanctioned exec-of-systemctl file in the tree).
// The maintain/pipeline surface keeps its separate spelling ban (cli units
// guard); the two executor files are the complete daemon surface.

func TestSystemctlAllowlistIsExactlyThePinnedSet(t *testing.T) {
	require.Len(t, allowedCommands, 4, "the allowlist is exactly four commands")
	assert.Equal(t, []string{"--user", "daemon-reload"}, allowedCommands[0])
	assert.Equal(t, []string{"--user", "enable", "--now", WatchService}, allowedCommands[1])
	assert.Equal(t, []string{"--user", "disable", "--now", WatchService}, allowedCommands[2])
	assert.Equal(t, []string{"--user", "disable", "--now", RefreshTimer, SpeedtestTimer}, allowedCommands[3])
	for _, cmd := range allowedCommands {
		assert.Equal(t, "--user", cmd[0], "every invocation MUST be --user")
		for _, arg := range cmd {
			assert.NotContains(t, arg, "xray", "no xray-raw or other foreign unit may ever appear")
		}
	}
}

func TestCommandConstructorsMatchAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  []string
		want []string
	}{
		{"daemon-reload", cmdDaemonReload(), allowedCommands[0]},
		{"enable-watch", cmdEnableWatch(), allowedCommands[1]},
		{"disable-watch", cmdDisableWatch(), allowedCommands[2]},
		{"disable-legacy", cmdDisableLegacyTimers(), allowedCommands[3]},
	} {
		assert.Equal(t, tc.want, tc.got, "constructor %s drifted from the allowlist", tc.name)
		assert.NoError(t, validateArgs(tc.got), "constructor %s must validate", tc.name)
	}
}

// TestUnitNameLiteralsArePinned closes the M-2 rider gap: the unit-name
// constants are otherwise compared only against themselves (the allowlist
// rows reference the same constants), so a constant revert would be
// invisible to the suite. The NEW names are spelled here as literals; the
// PRE-RENAME spellings are assembled from parts (same grep reason as the
// config package's fixture pin) and must be REFUSED — the allowlist carries
// assay-* names only, and a constant revert to the old names would re-add
// them and fail the refusal matrix below.
func TestUnitNameLiteralsArePinned(t *testing.T) {
	assert.Equal(t, "assay-watch.service", WatchService)
	assert.Equal(t, "assay-refresh.service", RefreshService)
	assert.Equal(t, "assay-refresh.timer", RefreshTimer)
	assert.Equal(t, "assay-speedtest.service", SpeedtestService)
	assert.Equal(t, "assay-speedtest.timer", SpeedtestTimer)

	old := "public" + "vpn"
	for _, bad := range [][]string{
		{"--user", "disable", "--now", old + "-refresh.timer", old + "-speedtest.timer"},
		{"--user", "disable", "--now", old + "-watch.service"},
		{"--user", "enable", "--now", old + "-watch.service"},
		{"--user", "restart", old + "-watch.service"},
	} {
		err := validateArgs(bad)
		require.Error(t, err, "invocation %v must be refused — the allowlist carries assay-* names only", bad)
		assert.Contains(t, err.Error(), "allowlist")
	}
}

func TestExecutorRejectsEverythingOutsideAllowlist(t *testing.T) {
	for _, bad := range [][]string{
		{"--user", "restart", "assay-watch.service"},                // never restart anything
		{"--user", "restart", "xray-raw.service"},                   // never touch the live client
		{"--user", "start", WatchService},                           // start is not in the set
		{"--user", "stop", WatchService},                            // stop is not in the set
		{"--user", "enable", "xray-raw.service"},                    // foreign unit
		{"--user", "daemon-reload", "extra"},                        // trailing args
		{"--system", "daemon-reload"},                               // system bus forbidden
		{"daemon-reload"},                                           // missing --user
		{"--user", "disable", "--now", RefreshTimer},                // partial legacy set
		{"--user", "enable", "--now", WatchService, "extra"},        // extra unit
		{"--user", "enable", "--now", RefreshTimer, SpeedtestTimer}, // timers are never ENABLED again
		{}, // empty
	} {
		err := validateArgs(bad)
		require.Error(t, err, "invocation %v must be refused", bad)
		assert.Contains(t, err.Error(), "allowlist")
	}
}

// TestInstallSourceUsesOnlyTheSanctionedConstructors pins the source-level
// shape: exactly one exec site (the SystemctlExecutor), and every Systemctl
// call goes through the command constructors — no literal args at call
// sites, no second exec path.
func TestInstallSourceUsesOnlyTheSanctionedConstructors(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	execSites, callSites := 0, 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", e.Name()))
		require.NoError(t, err)
		s := string(src)
		execSites += strings.Count(s, "exec.Command")
		callSites += strings.Count(s, ".Systemctl(cmd")
		assert.NotContains(t, s, `"restart"`,
			"%s: the string literal \"restart\" must never appear — no restart verb anywhere in the install surface", e.Name())
	}
	assert.Equal(t, 1, execSites, "exactly one exec site: the allowlist-checked systemctl executor")
	// Install: legacy disable (conditional) + reload + enable = up to 3;
	// cleanupLegacyUnits: legacy disable = 1; Uninstall: disable + post-removal
	// reload = 2. All flow through the constructors; no new command shape.
	assert.Equal(t, 6, callSites, "Install(3) + cleanupLegacyUnits(1) + Uninstall(2) call Systemctl only via the constructors")
}

// TestUnitTemplatesAreTheSingleSource pins that the embedded unit comes from
// the repo systemd/ directory — no duplicated template strings in Go code.
func TestUnitTemplatesAreTheSingleSource(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", e.Name()))
		require.NoError(t, err)
		assert.NotContains(t, string(src), "WantedBy=default.target",
			"%s must render the embedded repo template, not carry its own unit text", e.Name())
	}
}

// TestDaemonNeverTouchesSystemd is the W10 guard, kept through the W13
// migration with the same assertions and an updated meaning: the watch
// DAEMON entry (internal/cli watch path) must carry no exec-of-systemctl
// surface of its own — the restart capability lives in the byte-pinned
// allowlist executor (internal/restart) behind the stages seam, so this
// file stays process-spawn-free. (W4–W12 wording: "only install talks to
// systemd"; W13 adds the restart executor as the second — and last —
// sanctioned file.)
func TestDaemonNeverTouchesSystemd(t *testing.T) {
	cliDir := filepath.Join("..", "cli")
	entries, err := os.ReadDir(cliDir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		if e.Name() != "watch_cmd.go" {
			continue
		}
		src, err := os.ReadFile(filepath.Join(cliDir, e.Name()))
		require.NoError(t, err)
		s := string(src)
		// Prose may mention the ban; the CODE must not: no systemctl exec
		// surface, no process spawning, no systemd import.
		assert.NotContains(t, s, "exec.Command", "the daemon must not spawn processes")
		assert.NotContains(t, s, "Systemctl(", "the daemon must never invoke systemctl")
		assert.NotContains(t, s, "systemd/", "the daemon must not import the unit package")
	}
}
