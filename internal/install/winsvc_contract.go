// The GOOS-neutral windows service contract (plan §2.2.4-§2.2.8): the
// identity constants, the CreateService argument vector, the recovery
// table, the Query-state names, and the loud-message builders. The
// //go:build windows implementation (winsvc.go) consumes these tables, so
// the shapes stay pinned by the locally-runnable suite while the mgr
// call-wiring is pinned by the windows-tagged suite (CI leg).

package install

import (
	"errors"
	"fmt"
	"time"

	"assay/internal/platform"
)

// WinSvcName is the SCM database name of the service (§2.2.4) — also the
// handler's args[0] contract (x/sys windows/svc delivers the service name
// first) and the svc.Run name. One definition everywhere.
const WinSvcName = "assay"

// WinSvcDisplayName and WinSvcDescription are the SCM-visible identity
// (§2.2.4 Config{DisplayName, Description}). The description stays one
// line — it renders in the services snap-in.
const (
	WinSvcDisplayName = "assay watch daemon"
	WinSvcDescription = "assay: fetches public proxy pools, runs maintain waves on schedule, and supervises the xray core"
)

// WinSvcArgs renders the CreateService argument vector (§2.2.4): ALWAYS
// `watch -c <abs config>` — the service runs under LocalSystem (§2.2.5),
// whose default resolution lands in the SYSTEM profile and refuses to
// start (the fail-closed refusal). A -c-less registration is refused
// loudly here, never silently created.
func WinSvcArgs(configPath string) ([]string, error) {
	if configPath == "" {
		return nil, errors.New("install: the windows service runs as LocalSystem and MUST carry an explicit " +
			"-c <abs config> — a -c-less service would resolve the SYSTEM profile and refuses to start; " +
			"re-run `assay install` (it embeds your absolute config path)")
	}
	return []string{"watch", "-c", configPath}, nil
}

// WinSvcRecoveryType mirrors the mgr recovery-action kinds with our own
// neutral type (the windows file maps it onto mgr.RecoveryAction; the
// number is the stable Win32 SC_ACTION_* value).
type WinSvcRecoveryType int

// WinSvcRecoveryRestart is SC_ACTION_RESTART — the Restart=always parity.
const WinSvcRecoveryRestart WinSvcRecoveryType = 1

// Recovery-action geometry (§2.2.4): ServiceRestart after 5s — the exact
// Restart=always/RestartSec=5 parity — with the failure count resetting
// after 86400 seconds (24h) without failures. Code-owned, not knobs.
const (
	WinSvcRecoveryDelay       = 5 * time.Second
	WinSvcRecoveryResetPeriod = uint32(86400) // seconds — mgr.SetRecoveryActions(resetPeriod)
)

// WinSvcRecoveryAction is the neutral recovery action (the windows file
// maps it onto mgr.RecoveryAction).
type WinSvcRecoveryAction struct {
	Type  WinSvcRecoveryType
	Delay time.Duration
}

// WinSvcRecoveryActions returns the recovery ladder (§2.2.4): exactly one
// ServiceRestart after 5s.
func WinSvcRecoveryActions() []WinSvcRecoveryAction {
	return []WinSvcRecoveryAction{{Type: WinSvcRecoveryRestart, Delay: WinSvcRecoveryDelay}}
}

// WinSvc states — the stable Win32 SERVICE_* numbers our own neutral
// constants mirror (the windows file converts svc.State through these).
const (
	WinSvcStateStopped      uint32 = 1
	WinSvcStateStartPending uint32 = 2
	WinSvcStateStopPending  uint32 = 3
	WinSvcStateRunning      uint32 = 4
	WinSvcStatePaused       uint32 = 7
)

// WinSvcStateString renders a Query state (§2.2.8): honest human names for
// the known SERVICE_* values, the raw number otherwise (never a fake
// "Running").
func WinSvcStateString(state uint32) string {
	switch state {
	case WinSvcStateStopped:
		return "Stopped"
	case WinSvcStateStartPending:
		return "Start Pending"
	case WinSvcStateStopPending:
		return "Stop Pending"
	case WinSvcStateRunning:
		return "Running"
	case WinSvcStatePaused:
		return "Paused"
	default:
		return fmt.Sprintf("State(%d)", state)
	}
}

// winSvcStopBound is the §2.2.7 uninstall stop-poll bound: 30 minutes —
// the exact TimeoutStopSec=1800 parity.
const winSvcStopBound = 30 * time.Minute

// WinSvcStartPendingWaitHint is ONE definition for the start window: the
// service handler declares it to the SCM as its StartPending WaitHint
// (cmd/assay svc handler — "we may take this long to reach Running"), and
// the installer's running-verify (awaitRunning) waits exactly this long —
// the installer may never give up BEFORE the window it itself declared.
// Wiring on the daemon side is sub-second (§5.10), but the daemon's first
// bootstrap is best-effort-retried inside the wired path, and a cold runner
// (SCM process creation, Defender first-run scan of a fresh image) adds
// seconds — the live first-ever SCM E2E run hit the old arbitrary 10×500ms
// bound before Running (run 43358084471).
const WinSvcStartPendingWaitHint = 30 * time.Second

// WinSvcStopBound exposes the uninstall stop-poll bound for the installer
// (§2.2.7: bounded 30 min, TimeoutStopSec=1800 parity).
func WinSvcStopBound() time.Duration { return winSvcStopBound }

// WinSvcStopTimeoutMessage is the loud §2.2.7 expiry: the bounded wait ran
// out, so the message carries the EXACT commands to run by hand — the
// status probe and, when the Query reported a pid, the forceful kill. The
// verb names the flow that hit the bound ("install" §2.2.9 or "uninstall"
// §2.2.7 — both poll through awaitStopped), so the prefix and the re-run
// advice always name the same command.
func WinSvcStopTimeoutMessage(pid uint32, bound time.Duration, verb string) string {
	msg := fmt.Sprintf("%s: the assay service did not reach Stopped within %s — "+
		"stop it by hand, then re-run `assay %s`:\n"+
		"  sc.exe query assay", verb, bound, verb)
	if pid > 0 {
		msg += fmt.Sprintf("\n  taskkill /PID %d /F", pid)
	}
	return msg
}

// ServiceDefaultDataDirRefusal is the §2.2.5 fail-closed refusal: the
// service runs as LocalSystem; a default-location resolution that landed
// under the SYSTEM profile would silently create and use the SYSTEM's data
// dir — refused before anything is created, naming BOTH fixes. An empty
// profile means the check cannot apply: no refusal.
func ServiceDefaultDataDirRefusal(dataDir, profile string) string {
	if profile == "" {
		return ""
	}
	if !platform.UnderSystemProfile(dataDir, profile) {
		return ""
	}
	return "windows service refuses to start: no -c was given and the resolved default data dir " +
		dataDir + " is under the SYSTEM profile (" + profile + ") — the service runs as " +
		"LocalSystem, so a default-location resolution would silently create and use the " +
		"SYSTEM's data dir, not yours. Fix it one of two ways: " +
		"(1) re-run `assay install` from your account — it embeds your absolute config path as -c; " +
		"(2) register the service with an explicit config: `assay install -c <path>`."
}
