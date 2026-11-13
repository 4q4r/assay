//go:build windows

package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// The windows installer pins (plan §2.2.4/§2.2.7/§2.2.8/§2.2.9 + ADDENDUM
// §1): the typed allowlist discipline — a recorded svcActions double pins
// the EXACT mgr call shapes and their ORDER:
//   - fresh install: CreateService{StartAutomatic, DisplayName,
//     Description, args `watch -c <abs>`} → SetRecoveryActions
//     [{ServiceRestart, 5s}, reset 86400] → Start;
//   - upgrade (§2.2.9, the running-image lock): Control(Stop) + wait →
//     copyBinary → UpdateConfig → recovery → Start;
//   - uninstall (§2.2.7): Control(Stop) → poll Stopped (bounded 30m) →
//     Delete → Close;
//   - status (§2.2.8): Query → state + pid; a Connect failure carries the
//     exact elevated command line.
// The real SCM lifecycle is the windows-scm CI leg.

// fakeWinSvcActions is the recorded svcActions double: every method stores
// its payload; the STEP RECORDING lives on the scheduler (one unified verb
// list across SCM calls and copyBinary — the ordering pins need both).
type fakeWinSvcActions struct {
	createName, createBinPath string
	createCfg                 mgrServiceConfig
	createArgs                []string

	updateName  string
	updateCfg   mgrServiceConfig
	updateArgs  []string
	updateCalls int

	recoveryName    string
	recoveryActions []WinSvcRecoveryAction
	recoveryReset   uint32

	startName    string
	startErr     error
	controlCalls int
	deleted      bool
	closed       bool

	// queryScript replays (state, pid) answers in order; the last one
	// repeats forever. openErr scripts the OpenService failure.
	queryScript [][2]uint32
	queryIdx    int
	openErr     error
	connectErr  error
}

func (f *fakeWinSvcActions) connect() error {
	if f.connectErr != nil {
		return f.connectErr
	}
	return nil
}

func (f *fakeWinSvcActions) disconnect() error { return nil }

func (f *fakeWinSvcActions) openService(string) error { return f.openErr }

func (f *fakeWinSvcActions) closeService() { f.closed = true }

func (f *fakeWinSvcActions) createService(name, binPath string, cfg mgrServiceConfig, args []string) error {
	f.createName, f.createBinPath, f.createCfg, f.createArgs = name, binPath, cfg, args
	return nil
}

func (f *fakeWinSvcActions) updateServiceConfig(name, binPath string, cfg mgrServiceConfig, args []string) error {
	f.updateName, f.updateCfg, f.updateArgs = name, cfg, args
	_ = binPath
	f.updateCalls++
	return nil
}

func (f *fakeWinSvcActions) setRecovery(name string, actions []WinSvcRecoveryAction, resetPeriod uint32) error {
	f.recoveryName, f.recoveryActions, f.recoveryReset = name, actions, resetPeriod
	return nil
}

func (f *fakeWinSvcActions) start(string) error {
	f.startName = "assay"
	return f.startErr
}

func (f *fakeWinSvcActions) controlStop(string) (bool, error) {
	f.controlCalls++
	return true, nil
}

func (f *fakeWinSvcActions) query(string) (uint32, uint32, error) {
	if len(f.queryScript) == 0 {
		return WinSvcStateStopped, 0, nil
	}
	if f.queryIdx >= len(f.queryScript) {
		f.queryIdx = len(f.queryScript) - 1
	}
	ans := f.queryScript[f.queryIdx]
	f.queryIdx++
	return ans[0], ans[1], nil
}

func (f *fakeWinSvcActions) deleteService(string) error {
	f.deleted = true
	return nil
}

// winSvcTestScheduler builds the scheduler over the double with test-scale
// pacing (the 30-minute production bounds must not stretch unit tests) and
// the unified step recorder.
func winSvcTestScheduler(f *fakeWinSvcActions) *WinSvcScheduler {
	return NewWinSvcScheduler(f).
		withStopPolling(time.Millisecond, 8).
		withVerifyPolling(time.Millisecond, 8)
}

// runningBinary stages the fake running image (copyBinary's source).
func runningBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "running-assay.exe")
	require.NoError(t, os.WriteFile(p, []byte("#!running\n"), 0o755))
	return p
}

// winSvcSpec builds a hermetic install spec under a temp home (the §4.2
// windows layout: <local>\assay holds config+data, <local>\assay\bin the
// binary).
func winSvcSpec(t *testing.T) (SchedulerInstallSpec, string) {
	t.Helper()
	home := t.TempDir()
	local := filepath.Join(home, "AppData", "Local")
	dataDir := filepath.Join(local, "assay")
	spec := SchedulerInstallSpec{
		RunningBinary:     runningBinary(t),
		BinDir:            filepath.Join(dataDir, "bin"),
		ConfigPath:        "",
		DefaultConfigPath: filepath.Join(dataDir, "config.toml"),
		DataDir:           dataDir,
	}
	return spec, dataDir
}

// TestWinSvcInstallFreshPins pins the fresh-install call shapes (§2.2.4):
// CreateService with StartType=StartAutomatic (2), the DisplayName and the
// one-line Description, NO account fields (LocalSystem by omission, §2.2.5),
// args exactly `watch -c <abs config>`; recovery = [{ServiceRestart, 5s}]
// with reset 86400; Start after recovery. The copy lands at
// <bin>\assay.exe (the §4.2 table name) BEFORE the service exists.
func TestWinSvcInstallFreshPins(t *testing.T) {
	f := &fakeWinSvcActions{openErr: errors.New("does not exist")}
	// Fresh install: the service starts Stopped and the verify loop must see
	// it RUNNING after Start — the fake holds its last scripted answer, so
	// the post-start Running entry is load-bearing (its absence exhausted
	// awaitRunning on the first real windows run, 43330792666).
	f.queryScript = append(f.queryScript,
		[2]uint32{WinSvcStateStopped, 0},
		[2]uint32{WinSvcStateRunning, 4242})
	s := winSvcTestScheduler(f)
	spec, _ := winSvcSpec(t)

	res, err := s.Install(spec)
	require.NoError(t, err)
	assert.True(t, res.ServiceActive)
	assert.Equal(t, filepath.Join(spec.BinDir, "assay.exe"), res.BinaryPath)
	assert.True(t, f.closed, "the openService handle is released on every Install path (P3-1)")

	// The call-shape pins:
	require.Equal(t, "assay", f.createName)
	require.Equal(t, res.BinaryPath, f.createBinPath)
	assert.Equal(t, uint32(mgr.StartAutomatic), f.createCfg.StartType)
	assert.Equal(t, WinSvcDisplayName, f.createCfg.DisplayName)
	assert.Equal(t, WinSvcDescription, f.createCfg.Description)
	assert.Empty(t, f.createCfg.ServiceStartName, "no account fields — LocalSystem by omission (§2.2.5)")
	assert.Empty(t, f.createCfg.Password, "no password — no secrets on disk (§2.2.5)")
	assert.Equal(t, []string{"watch", "-c", spec.DefaultConfigPath}, f.createArgs)

	require.NotNil(t, f.recoveryActions)
	assert.Equal(t, WinSvcName, f.recoveryName)
	require.Len(t, f.recoveryActions, 1)
	assert.Equal(t, WinSvcRecoveryRestart, f.recoveryActions[0].Type)
	assert.Equal(t, 5*time.Second, f.recoveryActions[0].Delay)
	assert.Equal(t, uint32(86400), f.recoveryReset)

	// Ordering: the copy precedes CreateService; recovery precedes Start.
	verbs := s.Verbs()
	copyIdx := indexOf(verbs, "copyBinary")
	createIdx := indexOf(verbs, "createService")
	recoveryIdx := indexOf(verbs, "setRecovery")
	startIdx := indexOf(verbs, "start")
	require.NotEqual(t, -1, copyIdx)
	require.NotEqual(t, -1, createIdx)
	require.NotEqual(t, -1, recoveryIdx)
	require.NotEqual(t, -1, startIdx)
	assert.Less(t, copyIdx, createIdx, "copyBinary before CreateService")
	assert.Less(t, createIdx, recoveryIdx, "CreateService before recovery actions")
	assert.Less(t, recoveryIdx, startIdx, "recovery actions before Start")
}

// TestWinSvcInstallUpgradeOrderingPins pins §2.2.9 — the running-image lock
// discipline: the service is STOPPED and polled to Stopped BEFORE
// copyBinary replaces the image; Start comes last. Review Focus 4: an
// upgrade never surfaces a locked-file error.
func TestWinSvcInstallUpgradeOrderingPins(t *testing.T) {
	f := &fakeWinSvcActions{}
	// Running (pid 4242) → Stopped → Running again after start.
	f.queryScript = append(f.queryScript,
		[2]uint32{WinSvcStateRunning, 4242},
		[2]uint32{WinSvcStateStopped, 0},
		[2]uint32{WinSvcStateRunning, 9999},
	)
	s := winSvcTestScheduler(f)
	spec, _ := winSvcSpec(t)
	spec.ConfigPath = `C:\Users\u\AppData\Local\assay\config.toml`
	spec.DefaultConfigPath = ""

	res, err := s.Install(spec)
	require.NoError(t, err)
	assert.True(t, res.ServiceActive)
	assert.Equal(t, 1, f.controlCalls, "the running service was stopped exactly once")
	assert.Equal(t, 1, f.updateCalls, "an existing service is updated, never double-created")
	assert.Equal(t, "assay", f.updateName)
	assert.Equal(t, []string{"watch", "-c", spec.ConfigPath}, f.updateArgs)

	verbs := s.Verbs()
	stopIdx := indexOf(verbs, "controlStop")
	pollIdx := indexOf(verbs, "pollStopped")
	copyIdx := indexOf(verbs, "copyBinary")
	updateIdx := indexOf(verbs, "updateServiceConfig")
	startIdx := indexOf(verbs, "start")
	require.NotEqual(t, -1, stopIdx)
	require.NotEqual(t, -1, pollIdx)
	require.NotEqual(t, -1, copyIdx)
	require.NotEqual(t, -1, updateIdx)
	require.NotEqual(t, -1, startIdx)
	assert.Less(t, stopIdx, pollIdx, "§2.2.9: poll Stopped right after the stop")
	assert.Less(t, pollIdx, copyIdx, "§2.2.9: copyBinary only after Stopped (running-image lock)")
	assert.Less(t, copyIdx, updateIdx)
	assert.Less(t, updateIdx, startIdx)
}

// TestWinSvcInstallAlwaysEmbedsConfig pins the §2.2.5 install-side rule: a
// spec with neither ConfigPath nor DefaultConfigPath refuses loudly — the
// service must never be registered without an explicit -c.
func TestWinSvcInstallAlwaysEmbedsConfig(t *testing.T) {
	f := &fakeWinSvcActions{openErr: errors.New("does not exist")}
	s := winSvcTestScheduler(f)
	spec, _ := winSvcSpec(t)
	spec.ConfigPath = ""
	spec.DefaultConfigPath = ""

	_, err := s.Install(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "-c")
	assert.Empty(t, s.Verbs(), "nothing happens — no copy, no SCM call")
}

// TestWinSvcStartAlreadyRunningNote pins the §2.2.4 success-with-note:
// Start failing with ERROR_SERVICE_ALREADY_RUNNING is success, and the
// result carries the note.
func TestWinSvcStartAlreadyRunningNote(t *testing.T) {
	f := &fakeWinSvcActions{}
	f.startErr = windows.ERROR_SERVICE_ALREADY_RUNNING
	// Script: Running (the install's exists-probe sees the live service and
	// Control-Stops it per §2.2.9) → Stopped (awaitStopped) → Running again
	// (start returns ERROR_SERVICE_ALREADY_RUNNING — someone started it in
	// between — and awaitRunning must see Running for the note path). The
	// fake holds its LAST answer forever, so every leg needs its own entry.
	f.queryScript = append(f.queryScript,
		[2]uint32{WinSvcStateRunning, 4242},
		[2]uint32{WinSvcStateStopped, 0},
		[2]uint32{WinSvcStateRunning, 4242})
	s := winSvcTestScheduler(f)
	spec, _ := winSvcSpec(t)
	spec.ConfigPath = `C:\x\config.toml`
	spec.DefaultConfigPath = ""

	res, err := s.Install(spec)
	require.NoError(t, err, "ERROR_SERVICE_ALREADY_RUNNING is success-with-note (§2.2.4)")
	assert.True(t, res.ServiceActive)
	assert.Contains(t, res.ServiceNote, "already running")
}

// TestWinSvcUninstallOrderingPins pins §2.2.7: Control(Stop) (only when not
// stopped) → poll Stopped → Delete → Close, then the managed-core teardown.
func TestWinSvcUninstallOrderingPins(t *testing.T) {
	f := &fakeWinSvcActions{}
	f.queryScript = append(f.queryScript,
		[2]uint32{WinSvcStateRunning, 4242},
		[2]uint32{WinSvcStateStopPending, 4242},
		[2]uint32{WinSvcStateStopped, 0},
	)
	s := winSvcTestScheduler(f)
	home := t.TempDir()
	res, err := s.Uninstall(SchedulerUninstallSpec{DataDir: filepath.Join(home, "assay")})
	require.NoError(t, err)
	assert.Equal(t, 1, f.controlCalls)
	require.True(t, f.deleted, "the service is deleted")
	require.True(t, f.closed, "the service handle is closed (Delete marks; Close releases — §2.2.7)")
	assert.Contains(t, res.RemovedUnits, WinSvcName)
	assert.Contains(t, res.DisabledUnits, WinSvcName)

	verbs := s.Verbs()
	stopIdx := indexOf(verbs, "controlStop")
	deleteIdx := indexOf(verbs, "deleteService")
	closeIdx := indexOf(verbs, "closeService")
	require.NotEqual(t, -1, stopIdx)
	require.NotEqual(t, -1, deleteIdx)
	require.NotEqual(t, -1, closeIdx)
	assert.Less(t, stopIdx, deleteIdx, "stop before delete")
	assert.Less(t, deleteIdx, closeIdx, "Delete before Close")
}

// TestWinSvcUninstallAbsentReports pins the absent-registration case: no
// service → reported honestly (nothing disabled/removed), teardown still
// runs, no error.
func TestWinSvcUninstallAbsentReports(t *testing.T) {
	f := &fakeWinSvcActions{openErr: errors.New("does not exist")}
	s := winSvcTestScheduler(f)
	res, err := s.Uninstall(SchedulerUninstallSpec{DataDir: filepath.Join(t.TempDir(), "assay")})
	require.NoError(t, err)
	assert.Empty(t, res.DisabledUnits)
	assert.Empty(t, res.RemovedUnits)
	assert.False(t, f.deleted)
}

// TestWinSvcUninstallStopTimeoutMessage pins the §2.2.7 loud timeout: a
// service stuck in StopPending past the bounded wait fails with the EXACT
// sc.exe/taskkill lines.
func TestWinSvcUninstallStopTimeoutMessage(t *testing.T) {
	f := &fakeWinSvcActions{}
	f.queryScript = append(f.queryScript, [2]uint32{WinSvcStateStopPending, 4242})
	s := winSvcTestScheduler(f).withStopPolling(time.Millisecond, 3)
	_, err := s.Uninstall(SchedulerUninstallSpec{DataDir: filepath.Join(t.TempDir(), "assay")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uninstall: the assay service did not reach Stopped",
		"the uninstall flow names its own verb (P3-3)")
	assert.Contains(t, err.Error(), "re-run `assay uninstall`")
	assert.Contains(t, err.Error(), "sc.exe query assay")
	assert.Contains(t, err.Error(), "taskkill /PID 4242 /F")
}

// TestWinSvcInstallStopTimeoutMessage pins the §2.2.9 install-side stop
// expiry: the message carries the INSTALL verb — the prefix and the re-run
// advice name the same command (P3-3).
func TestWinSvcInstallStopTimeoutMessage(t *testing.T) {
	f := &fakeWinSvcActions{}
	// The service exists (openService succeeds) and never leaves
	// StopPending within the bounded wait.
	f.queryScript = append(f.queryScript, [2]uint32{WinSvcStateStopPending, 4242})
	s := winSvcTestScheduler(f).withStopPolling(time.Millisecond, 3)
	spec, _ := winSvcSpec(t)
	_, err := s.Install(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "install: the assay service did not reach Stopped",
		"the install flow names its own verb (P3-3)")
	assert.Contains(t, err.Error(), "re-run `assay install`")
	assert.Contains(t, err.Error(), "taskkill /PID 4242 /F")
}

// TestWinSvcStatusPins pins §2.2.8: Query → honest state + pid + the
// ADDENDUM §1 supervision note.
func TestWinSvcStatusPins(t *testing.T) {
	f := &fakeWinSvcActions{}
	f.queryScript = append(f.queryScript, [2]uint32{WinSvcStateRunning, 4242})
	s := winSvcTestScheduler(f)

	st, err := s.Status()
	require.NoError(t, err)
	assert.True(t, st.Active)
	assert.Equal(t, 4242, st.PID)
	assert.Contains(t, st.Note, "recovery: ServiceRestart after 5s")
	assert.Contains(t, st.Note, "self-watchdog")
	assert.Contains(t, st.Note, "SCM recovery-actions restart")

	// Not installed → an honest inactive status, never an error.
	f2 := &fakeWinSvcActions{openErr: errors.New("does not exist")}
	st2, err := winSvcTestScheduler(f2).Status()
	require.NoError(t, err)
	assert.False(t, st2.Active)
	assert.Contains(t, st2.Note, "assay install")
}

// TestWinSvcStatusConnectDeniedNamesElevatedCommand pins §2.2.8: a
// Connect failure (non-admin shell) carries the exact elevated command
// line, never a bare error.
func TestWinSvcStatusConnectDeniedNamesElevatedCommand(t *testing.T) {
	f := &fakeWinSvcActions{connectErr: errors.New("access is denied")}
	_, err := winSvcTestScheduler(f).Status()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assay status")
	assert.Contains(t, err.Error(), "Administrator")
}

// TestWinSvcHeldRegistrationPins the double-install refusal seam: the SCM
// entry existing = this scheduler holds the registration.
func TestWinSvcHeldRegistrationPins(t *testing.T) {
	f := &fakeWinSvcActions{}
	held, where := winSvcTestScheduler(f).HeldRegistration()
	assert.True(t, held)
	assert.Equal(t, WinSvcName, where)

	f2 := &fakeWinSvcActions{openErr: errors.New("does not exist")}
	held2, where2 := winSvcTestScheduler(f2).HeldRegistration()
	assert.False(t, held2)
	assert.Empty(t, where2)
}

// TestWinSvcCommandLineEscapingPins pins the UpdateConfig command-line
// rendering: CreateService escapes internally (mgr.go), UpdateConfig does
// NOT — the updater must render the escaped string itself, with args
// appended exactly like mgr.CreateService does.
func TestWinSvcCommandLineEscapingPins(t *testing.T) {
	got := winSvcCommandLine(`C:\Users\u\AppData\Local\assay\bin\assay.exe`,
		[]string{"watch", "-c", `C:\Users\u\AppData\Local\assay\config.toml`})
	assert.Equal(t,
		`C:\Users\u\AppData\Local\assay\bin\assay.exe watch -c C:\Users\u\AppData\Local\assay\config.toml`,
		got)

	// A path with a space must be quoted (EscapeArg's contract).
	spaced := winSvcCommandLine(`C:\Program Files\assay\assay.exe`, nil)
	assert.True(t, strings.HasPrefix(spaced, `"C:\Program Files\assay\assay.exe"`),
		"spaces force quoting, got %q", spaced)
}

// TestWinSvcMaterializesDefaultConfig pins the configless install flow: the
// default config is materialized (never overwritten) at DefaultConfigPath
// and embedded as -c; an existing file is kept and still embedded.
func TestWinSvcMaterializesDefaultConfig(t *testing.T) {
	f := &fakeWinSvcActions{openErr: errors.New("does not exist")}
	f.queryScript = append(f.queryScript,
		[2]uint32{WinSvcStateStopped, 0},
		[2]uint32{WinSvcStateRunning, 4242}) // the post-start verify leg
	s := winSvcTestScheduler(f)
	spec, dataDir := winSvcSpec(t)

	res, err := s.Install(spec)
	require.NoError(t, err)
	assert.Equal(t, spec.DefaultConfigPath, res.ConfigWritten, "configless → materialized")
	_, err = os.Stat(spec.DefaultConfigPath)
	require.NoError(t, err)

	// Kept: re-install over the existing file.
	f2 := &fakeWinSvcActions{openErr: errors.New("does not exist")}
	f2.queryScript = append(f2.queryScript,
		[2]uint32{WinSvcStateStopped, 0},
		[2]uint32{WinSvcStateRunning, 4242}) // the post-start verify leg
	res2, err := winSvcTestScheduler(f2).Install(spec)
	require.NoError(t, err)
	assert.Empty(t, res2.ConfigWritten)
	assert.Equal(t, spec.DefaultConfigPath, res2.ConfigKept)
	assert.Equal(t, []string{"watch", "-c", spec.DefaultConfigPath}, f2.createArgs,
		"the embedded -c still points at the data-dir config")
	_ = dataDir
}

// TestWinSvcAvailablePins the scheduler seam: windows = available, other
// GOOS = unavailable with a reason (production never routes there).
func TestWinSvcAvailablePins(t *testing.T) {
	f := &fakeWinSvcActions{}
	s := winSvcTestScheduler(f)
	avail, reason := s.Available()
	assert.True(t, avail)
	assert.Empty(t, reason)
	assert.Equal(t, "windows-service", s.Name())
}

func indexOf(vs []string, v string) int {
	for i, x := range vs {
		if x == v {
			return i
		}
	}
	return -1
}
