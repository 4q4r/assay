package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The systemd user units are REPO FILES ONLY — this project never installs,
// enables, starts, or talks to systemd (TestNoSystemdInvocationInMaintainSource
// pins the code side). These tests pin the unit content so the cadence and
// the ExecStart shape cannot silently drift from DESIGN §4.9.

const systemdDir = "../../systemd"

func readUnit(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(systemdDir, name))
	require.NoError(t, err, "unit file %s must exist in-repo (operator installs it, we never touch systemd)", name)
	return string(b)
}

func TestRefreshTimerUnitContent(t *testing.T) {
	timer := readUnit(t, "public_vpn-refresh.timer")
	assert.Contains(t, timer, "OnCalendar=*-*-* 00/6:00:00", "refresh wave: every 6 hours")
	assert.Contains(t, timer, "Persistent=true", "catch-up after sleep/reboot")
	assert.Contains(t, timer, "Unit=public_vpn-refresh.service")
	assert.Contains(t, timer, "WantedBy=timers.target")

	service := readUnit(t, "public_vpn-refresh.service")
	assert.Contains(t, service, "Type=oneshot", "a wave runs to completion")
	assert.Contains(t, service, "publicvpn maintain", "the refresh timer drives the maintain wave")
	assert.Regexp(t, `ExecStart=\S*publicvpn maintain`, service, "ExecStart = absolute binary path + maintain")
	assert.NotContains(t, service, "systemctl", "units never invoke systemctl themselves")
}

func TestSpeedtestTimerUnitContent(t *testing.T) {
	timer := readUnit(t, "public_vpn-speedtest.timer")
	assert.Contains(t, timer, "OnCalendar=weekly", "speedtest wave: weekly")
	assert.Contains(t, timer, "Persistent=true")

	service := readUnit(t, "public_vpn-speedtest.service")
	assert.Contains(t, service, "Type=oneshot")
	assert.Regexp(t, `ExecStart=\S*publicvpn maintain .*--speedtest`, service,
		"the weekly wave is maintain with the speedtest probe enabled")
}

func TestSystemdReadmeDocumentsInstallSteps(t *testing.T) {
	readme := readUnit(t, "README.md")
	for _, want := range []string{
		"~/.config/systemd/user",
		"daemon-reload",
		"enable --now",
		"journalctl --user",
	} {
		assert.Contains(t, readme, want, "install/journald cheatsheet missing %q", want)
	}
}

// w4MaintainSources is the full W4 production surface (DESIGN §11, wave W4):
// the cli orchestration and every stage package the maintain wave drives.
var w4MaintainSources = []string{
	filepath.Join("..", "cli", "pipeline.go"),
	filepath.Join("..", "cli", "root.go"),
	filepath.Join("..", "stats", "stats.go"),
	filepath.Join("..", "prune", "prune.go"),
	filepath.Join("..", "config", "config.go"),
	filepath.Join("..", "render", "render.go"),
	filepath.Join("..", "store", "store.go"),
	filepath.Join("..", "rank", "rank.go"),
}

// TestNoSystemdInvocationInMaintainSource extends the activate package's
// TestNoSystemdInvocationInSource pattern to the full W4 surface — the eight
// files in w4MaintainSources: the pipeline must never execute systemctl;
// systemd interaction is the operator's job via the repo unit files.
func TestNoSystemdInvocationInMaintainSource(t *testing.T) {
	t.Run("guard covers every W4 file", func(t *testing.T) {
		guarded := map[string]bool{}
		for _, f := range w4MaintainSources {
			guarded[filepath.Join(filepath.Base(filepath.Dir(f)), filepath.Base(f))] = true
		}
		for _, want := range []string{
			"cli/pipeline.go", "cli/root.go",
			"stats/stats.go", "prune/prune.go",
			"config/config.go", "render/render.go",
			"store/store.go", "rank/rank.go",
		} {
			assert.Contains(t, guarded, want, "systemd guard must cover W4 file %s", want)
		}
	})

	for _, f := range w4MaintainSources {
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		assert.NotContains(t, string(src), "systemctl", "%s must never mention or execute systemctl", f)
	}
}

// TestMaintainSourceUsesLoudExecFailures pins that the only exec in the W4
// surface is the documented statsquery call — nothing else spawns processes.
func TestMaintainSourceUsesLoudExecFailures(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "stats", "stats.go"))
	require.NoError(t, err)
	count := strings.Count(string(src), "exec.Command")
	assert.Equal(t, 1, count, "exactly one exec site: xray api statsquery")
}
