package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The systemd user unit is a REPO TEMPLATE (single source of truth,
// embedded by internal/install via go:embed): `publicvpn install` renders it
// into the user unit dir and enables the daemon via the allowlisted executor
// seam. These tests pin the template content so the Restart=always daemon
// contract, the watch verb, and the placeholder set cannot silently drift.
// The W5 timer units are gone — their legacy names survive ONLY as the
// uninstall/migration cleanup set.

const systemdDir = "../../systemd"

func readUnit(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(systemdDir, name))
	require.NoError(t, err, "unit template %s must exist in-repo (install renders it)", name)
	return string(b)
}

func TestWatchUnitTemplate(t *testing.T) {
	service := readUnit(t, "public_vpn-watch.service")
	assert.Contains(t, service, "Type=notify", "sd_notify(3): READY=1 + WATCHDOG=1 pings")
	assert.Contains(t, service, "WatchdogSec=300",
		"a wedged daemon stops pinging — systemd kills and restarts it")
	assert.Contains(t, service, "TimeoutStopSec=1800",
		"a mid-wave stop waits for the current stage (a full probe stage runs ~28 min) "+
			"instead of SIGKILLing at the 90s default — the W17 mid-wave kill fix")
	assert.Regexp(t, `(?m)^ExecStart=\{\{ \.BinaryPath \}\} watch -c \{\{ \.ConfigPath \}\}$`,
		service, "ExecStart = installed binary + watch + the config the user passed")
	assert.Regexp(t, `(?m)^Restart=always$`, service, "a daemon crash restarts automatically")
	assert.NotContains(t, service, "{{ .RefreshInterval", "no timer-era placeholders survive")
	assert.NotContains(t, service, "{{ .SpeedtestInterval", "no timer-era placeholders survive")
	assert.NotContains(t, service, "systemctl", "units never invoke systemctl themselves")
	assert.NotContains(t, service, "OnBootSec", "the timer era is over — scheduling lives in the daemon")
}

// TestSystemdReadmeDocumentsInstallSteps pins that the repo README carries
// the install/journald cheatsheet (kept adjacent to the template pins).
func TestSystemdReadmeDocumentsInstallSteps(t *testing.T) {
	readme := readUnit(t, "README.md")
	for _, want := range []string{
		"publicvpn install",
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
var w4MaintainSources = [8]string{
	filepath.Join("..", "cli", "pipeline.go"),
	filepath.Join("..", "cli", "root.go"),
	filepath.Join("..", "stats", "stats.go"),
	filepath.Join("..", "prune", "prune.go"),
	filepath.Join("..", "config", "config.go"),
	filepath.Join("..", "render", "render.go"),
	filepath.Join("..", "store", "store.go"),
	filepath.Join("..", "rank", "rank.go"),
}

// compile-time: the surface is an immutable 8-element array (not a slice) —
// an append-capable slice would let the guard list drift silently.
var _ [8]string = w4MaintainSources

// TestNoSystemdInvocationInMaintainSource pins the orchestration surface's
// side of the W13 security rail. MIGRATION (W4 → W13): through W12 this was
// the total no-systemctl ban — "the pipeline must never execute systemctl;
// systemd interaction is the operator's job". The owner's round-6 ruling
// (hands-off, zero manual restarts) moved the restart capability into
// internal/restart's byte-pinned allowlist executor, wired through the
// restartWiring seam in pipeline.go. The ban's LETTER is unchanged — these
// eight files still never spell the word (all systemd verbs are spelled
// only inside the two allowlist executor packages, install + restart, both
// guard-pinned) — but its MEANING is now "the orchestration surface never
// touches systemd directly": the only sanctioned execution paths are the
// two executors, enforced by restart's TestDaemonSystemdSurfaceIsExactlyTwoExecutorFiles.
// The list is pinned EXACTLY (the EXACTLY-8 subtest): both directions of set
// equality, not merely "contains" — a silently added ninth file would escape
// the guard, a silently removed one would fake coverage.
func TestNoSystemdInvocationInMaintainSource(t *testing.T) {
	t.Run("guard covers EXACTLY the eight W4 files", func(t *testing.T) {
		guarded := map[string]bool{}
		for _, f := range w4MaintainSources {
			guarded[filepath.Join(filepath.Base(filepath.Dir(f)), filepath.Base(f))] = true
		}
		want := map[string]bool{
			"cli/pipeline.go": true, "cli/root.go": true,
			"stats/stats.go": true, "prune/prune.go": true,
			"config/config.go": true, "render/render.go": true,
			"store/store.go": true, "rank/rank.go": true,
		}
		assert.Len(t, guarded, 8, "the W4 surface is exactly eight files — widen this pin deliberately, never silently")
		for f := range guarded {
			assert.Contains(t, want, f, "guarded file %s is outside the pinned W4 surface", f)
		}
		for f := range want {
			assert.Contains(t, guarded, f, "pinned W4 file %s escaped the systemd guard", f)
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
