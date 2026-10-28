package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W5 hard-scope guard: the install package's ENTIRE systemctl surface is the
// three-command allowlist — --user only, only the two public_vpn-* timers,
// daemon-reload / enable --now / disable --now. No restart, no other unit, no
// --system. The maintain/pipeline surface keeps its separate strict ban
// (cli units_internal_test.go, 8-file list untouched); THIS package is the
// only place allowed to talk to systemd at all.

func TestSystemctlAllowlistIsExactlyThePinnedSet(t *testing.T) {
	require.Len(t, allowedCommands, 3, "the allowlist is exactly three commands")
	assert.Equal(t, []string{"--user", "daemon-reload"}, allowedCommands[0])
	assert.Equal(t, []string{"--user", "enable", "--now", "public_vpn-refresh.timer", "public_vpn-speedtest.timer"}, allowedCommands[1])
	assert.Equal(t, []string{"--user", "disable", "--now", "public_vpn-refresh.timer", "public_vpn-speedtest.timer"}, allowedCommands[2])
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
		{"enable", cmdEnableTimers(), allowedCommands[1]},
		{"disable", cmdDisableTimers(), allowedCommands[2]},
	} {
		assert.Equal(t, tc.want, tc.got, "constructor %s drifted from the allowlist", tc.name)
		assert.NoError(t, validateArgs(tc.got), "constructor %s must validate", tc.name)
	}
}

func TestExecutorRejectsEverythingOutsideAllowlist(t *testing.T) {
	for _, bad := range [][]string{
		{"--user", "restart", "public_vpn-refresh.service"},                                              // never restart anything
		{"--user", "restart", "xray-raw.service"},                                                        // never touch the live client
		{"--user", "start", "public_vpn-refresh.timer"},                                                  // start is not in the set
		{"--user", "stop", "public_vpn-speedtest.timer"},                                                 // stop is not in the set
		{"--user", "enable", "xray-raw.service"},                                                         // foreign unit
		{"--user", "daemon-reload", "extra"},                                                             // trailing args
		{"--system", "daemon-reload"},                                                                    // system bus forbidden
		{"daemon-reload"},                                                                                // missing --user
		{"--user", "disable", "--now", "public_vpn-refresh.timer"},                                       // partial unit set
		{"--user", "enable", "--now", "public_vpn-refresh.timer", "public_vpn-speedtest.timer", "extra"}, // extra unit
		{}, // empty
	} {
		err := validateArgs(bad)
		require.Error(t, err, "invocation %v must be refused", bad)
		assert.Contains(t, err.Error(), "allowlist")
	}
}

// TestInstallSourceUsesOnlyTheSanctionedConstructors pins the source-level
// shape: exactly one exec site (the SystemctlExecutor), and every Systemctl
// call goes through one of the three command constructors — no literal args
// at call sites, no second exec path.
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
	// 4 = Install(2: reload+enable) + Uninstall(2: disable + post-removal
	// reload). The second Uninstall call site is DELIBERATE (I-2, W5 fix
	// round): without a daemon-reload after the unit files are gone the user
	// manager keeps ghost "not-found" entries. No new command shape — the
	// constructor set and allowlist stay exactly three commands.
	assert.Equal(t, 4, callSites, "Install(2) + Uninstall(2) call Systemctl only via the constructors")
}

// TestUnitTemplatesAreTheSingleSource pins that the embedded units come from
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
		assert.NotContains(t, string(src), "WantedBy=timers.target",
			"%s must render the embedded repo templates, not carry its own unit text", e.Name())
	}
}
