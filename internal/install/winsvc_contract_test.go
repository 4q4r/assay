package install

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The windows service contract pins (plan §2.2.4/§2.2.5/§2.2.7/§2.2.8).
// These are the GOOS-neutral halves of the windows installer: pure tables
// and message builders the //go:build windows implementation consumes, so
// the shapes stay pinned by the locally-runnable suite while the mgr
// call-wiring itself is pinned by the windows-tagged suite (CI leg).

// TestWinSvcIdentity pins the service identity constants (§2.2.4): the SCM
// database name is exactly "assay", with a human display name and a
// one-line description. The name is the handler's args[0] contract too —
// one definition everywhere.
func TestWinSvcIdentity(t *testing.T) {
	assert.Equal(t, "assay", WinSvcName)
	assert.Equal(t, "assay watch daemon", WinSvcDisplayName)
	assert.NotEmpty(t, WinSvcDescription)
	assert.False(t, strings.ContainsAny(WinSvcDescription, "\n\r"), "description must stay one line")
}

// TestWinSvcArgsAlwaysEmbedsConfig pins the §2.2.5 always-explicit--c rule:
// the CreateService argument vector is `watch -c <abs config>` — a -c-less
// service would run under LocalSystem, whose default resolution lands in
// the SYSTEM profile, and refuses to start (the fail-closed refusal).
// Installing one is refused loudly, never silently.
func TestWinSvcArgsAlwaysEmbedsConfig(t *testing.T) {
	args, err := WinSvcArgs(`C:\Users\u\AppData\Local\assay\config.toml`)
	require.NoError(t, err)
	assert.Equal(t, []string{"watch", "-c", `C:\Users\u\AppData\Local\assay\config.toml`}, args)

	_, err = WinSvcArgs("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "-c", "the refusal names the missing explicit config")
	assert.Contains(t, err.Error(), "LocalSystem")
}

// TestWinSvcRecoveryPins pins the recovery-action parity with systemd's
// Restart=always/RestartSec=5 (§2.2.4): exactly one ServiceRestart action
// after 5s, with the failure-count reset period at 86400 seconds (24h).
func TestWinSvcRecoveryPins(t *testing.T) {
	actions := WinSvcRecoveryActions()
	require.Len(t, actions, 1)
	assert.Equal(t, WinSvcRecoveryRestart, actions[0].Type)
	assert.Equal(t, 5*time.Second, actions[0].Delay)
	assert.Equal(t, uint32(86400), WinSvcRecoveryResetPeriod)
	// The windows value this maps to is SC_ACTION_RESTART (1) — pinned so an
	// accidental renumber cannot silently change the SCM recovery semantic.
	assert.Equal(t, WinSvcRecoveryRestart, WinSvcRecoveryType(1))
}

// TestWinSvcStartPendingWaitHintPinned pins the §2.2.2 start window (the run
// 43358084471 fix): the ONE contract constant the handler declares to the
// SCM and the installer's running-verify waits. The scheduler-side parity
// pin (budget == hint) lives in the windows-tagged suite beside the
// constructor it pins.
func TestWinSvcStartPendingWaitHintPinned(t *testing.T) {
	assert.Equal(t, 30*time.Second, WinSvcStartPendingWaitHint)
}

// TestWinSvcStateStrings pins the Query-state rendering (§2.2.8): the
// stable Win32 SERVICE_* numbers map to honest human names; unknown values
// render with their number (never a fake "Running").
func TestWinSvcStateStrings(t *testing.T) {
	assert.Equal(t, "Stopped", WinSvcStateString(WinSvcStateStopped))
	assert.Equal(t, "Start Pending", WinSvcStateString(WinSvcStateStartPending))
	assert.Equal(t, "Stop Pending", WinSvcStateString(WinSvcStateStopPending))
	assert.Equal(t, "Running", WinSvcStateString(WinSvcStateRunning))
	assert.Equal(t, "Paused", WinSvcStateString(WinSvcStatePaused))
	assert.Equal(t, "State(99)", WinSvcStateString(99))
	// The Win32 numbers the mapping encodes (stable SERVICE_* values).
	assert.Equal(t, uint32(1), WinSvcStateStopped)
	assert.Equal(t, uint32(4), WinSvcStateRunning)
}

// TestWinSvcStopTimeoutMessage pins the §2.2.7/§2.2.9 stop-timeout loudness:
// a bounded-wait expiry carries the verb of the flow that hit it (install
// and uninstall both poll through awaitStopped) and the EXACT commands to
// run by hand — sc.exe query assay plus taskkill /PID <pid> /F when a pid
// is known.
func TestWinSvcStopTimeoutMessage(t *testing.T) {
	msg := WinSvcStopTimeoutMessage(4242, 30*time.Minute, "install")
	assert.Contains(t, msg, "install: the assay service did not reach Stopped within 30m")
	assert.Contains(t, msg, "re-run `assay install`")
	assert.Contains(t, msg, "sc.exe query assay")
	assert.Contains(t, msg, "taskkill /PID 4242 /F")

	msg = WinSvcStopTimeoutMessage(4242, 30*time.Minute, "uninstall")
	assert.Contains(t, msg, "uninstall: the assay service did not reach Stopped within 30m")
	assert.Contains(t, msg, "re-run `assay uninstall`")
	assert.Contains(t, msg, "taskkill /PID 4242 /F")

	msg = WinSvcStopTimeoutMessage(0, 30*time.Minute, "uninstall")
	assert.Contains(t, msg, "sc.exe query assay")
	assert.NotContains(t, msg, "taskkill", "no pid → no taskkill line (never a fabricated pid)")
}

// TestServiceDefaultDataDirRefusal pins the §2.2.5 fail-closed refusal
// message: it names the resolved dir, the SYSTEM profile it landed under,
// and BOTH fixes verbatim (re-run `assay install`, or pass `-c`). An empty
// profile means the check cannot apply — no refusal.
func TestServiceDefaultDataDirRefusal(t *testing.T) {
	msg := ServiceDefaultDataDirRefusal(
		`C:\Windows\System32\config\systemprofile\AppData\Local\assay`,
		`C:\Windows\System32\config\systemprofile`,
	)
	require.NotEmpty(t, msg)
	assert.Contains(t, msg, `C:\Windows\System32\config\systemprofile\AppData\Local\assay`)
	assert.Contains(t, msg, "assay install")
	assert.Contains(t, msg, "-c")
	assert.Contains(t, msg, "LocalSystem")

	assert.Empty(t, ServiceDefaultDataDirRefusal(`C:\Users\u\AppData\Local\assay`, `C:\Windows\System32\config\systemprofile`))
	assert.Empty(t, ServiceDefaultDataDirRefusal(`C:\Windows\system32\config\systemprofile\AppData\Local\assay`, ""))
}
