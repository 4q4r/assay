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
// migration). STILL TRUE after the self-held-core pivot (D3): install never
// restarts anything — the pre-pivot foreign-restart executor that used to
// live in internal/restart was REMOVED with the external mode, and install
// is once again the ONLY sanctioned exec-of-systemctl file in the tree.
// The maintain/pipeline surface keeps its separate spelling ban (cli units
// guard); install is the complete daemon systemd surface.

func TestSystemctlAllowlistIsExactlyThePinnedSet(t *testing.T) {
	require.Len(t, allowedCommands, 4, "the allowlist is exactly four commands")
	assert.Equal(t, []string{"--user", "daemon-reload"}, allowedCommands[0])
	assert.Equal(t, []string{"--user", "enable", "--now", WatchService}, allowedCommands[1])
	assert.Equal(t, []string{"--user", "disable", "--now", WatchService}, allowedCommands[2])
	assert.Equal(t, []string{"--user", "disable", "--now", RefreshTimer, SpeedtestTimer}, allowedCommands[3])
	for _, cmd := range allowedCommands {
		assert.Equal(t, "--user", cmd[0], "every invocation MUST be --user")
		for _, arg := range cmd {
			assert.NotContains(t, arg, "xray", "no foreign proxy-client unit may ever appear")
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
		{"--user", "restart", "foreign-client.service"},             // never touch the live client
		{"--user", "start", WatchService},                           // start is not in the set
		{"--user", "stop", WatchService},                            // stop is not in the set
		{"--user", "enable", "foreign-client.service"},              // foreign unit
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
// shape: exactly SEVEN exec sites — every one inside an allowlist-checked
// executor (systemctl + launchctl from W10/S1; sv, rc-update/rc-service,
// rc-status probe, s6-svc/s6-svscanctl/s6-svstat, crontab from S3 — the plan
// §3.2 surfaces, each pinned by its own allowlist guard) — and the systemd /
// launchd flows call only via their command constructors. The literal
// "restart" is banned EXCEPT inside runit.go, where the plan §3.2 allowlist
// explicitly pins `sv {status,stop,restart,up,down}` (an ops-surface verb no
// install flow ever invokes); the systemd/launchd surface stays restart-free
// (the W13 ruling: install never restarts anything).
func TestInstallSourceUsesOnlyTheSanctionedConstructors(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	execSites, callSites, launchctlCallSites := 0, 0, 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", e.Name()))
		require.NoError(t, err)
		s := string(src)
		execSites += strings.Count(s, "exec.Command")
		callSites += strings.Count(s, ".Systemctl(cmd")
		launchctlCallSites += strings.Count(s, ".Launchctl(cmd")
		if e.Name() == "runit.go" {
			// The plan §3.2 verb table — pinned here and by the allowlist
			// guard; no install flow ever sends `restart`.
			assert.Contains(t, s, `"restart"`, "runit.go must carry the §3.2 pinned verb table")
			continue
		}
		assert.NotContains(t, s, `"restart"`,
			"%s: the string literal \"restart\" must never appear — no restart verb in the systemd/launchd/s6/openrc/cron surface", e.Name())
	}
	assert.Equal(t, 7, execSites, "exactly seven exec sites, each inside an allowlist-checked executor "+
		"(systemctl, launchctl, sv, rc-update/rc-service, rc-status probe, s6, crontab)")
	// Install: legacy disable (conditional) + reload + enable = up to 3;
	// cleanupLegacyUnits: legacy disable = 1; Uninstall: disable + post-removal
	// reload = 2. All flow through the constructors; no new command shape.
	assert.Equal(t, 6, callSites, "Install(3) + cleanupLegacyUnits(1) + Uninstall(2) call Systemctl only via the constructors")
	// launchd flow: Install probe(1) + bootout(1) + bootstrap(1) +
	// waitBootout(1) + waitRunning(1); Uninstall print(1) + bootout(1);
	// Status print(1); HeldRegistration print(1). All flow through the four
	// pinned constructors; no new launchctl shape.
	assert.Equal(t, 9, launchctlCallSites, "the launchd flow calls Launchctl only via the pinned constructors")
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

// TestDaemonNeverTouchesSystemd is the W10 guard, kept with the same
// assertions and the meaning the self-held-core pivot (D3) restored: the
// watch DAEMON entry (internal/cli watch path) must carry no
// exec-of-systemctl surface of its own. (W4–W12 wording: "only install
// talks to systemd"; W13 added the then-new restart executor as the second
// sanctioned file; D3 removed it again — install is once again the only
// one.)
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
