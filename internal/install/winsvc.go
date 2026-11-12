//go:build windows

// The windows service installer (plan §2.2.4/§2.2.5/§2.2.7/§2.2.8/§2.2.9 +
// ADDENDUM §1): an svc/mgr-based installer — CreateService("assay", …,
// StartAutomatic, DisplayName, Description, args `watch -c <abs config>`),
// SetRecoveryActions([{ServiceRestart, 5s}], 86400) for the
// Restart=always/RestartSec=5 parity, in-process Start / Control(Stop) /
// Query / Delete — no sc.exe, no NSSM, no elevation beyond the SCM's own
// UAC surface.
//
// The allowlist discipline adapts to typed calls (§2.2.4): the
// winSvcActions seam is the installer's ENTIRE SCM surface — the recorded
// double pins the exact call shapes and their order (winsvc_test.go);
// production wires the mgr implementation. The §2.2.9 running-image lock
// discipline lives in Install: stop + wait BEFORE copyBinary, Start last.
package install

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// mgrServiceConfig is the neutral service-registration payload the seam
// carries (the windows file maps it onto mgr.Config). ServiceStartName and
// Password stay EMPTY by contract (§2.2.5): omitted account = LocalSystem —
// the sc.exe documented default; a user account would demand storing the
// user's Windows password (rejected: no secrets on disk).
type mgrServiceConfig struct {
	StartType        uint32
	DisplayName      string
	Description      string
	ServiceStartName string
	Password         string
}

// winSvcActions is the installer's SCM seam (the typed allowlist, §2.2.4):
// every method the installer may call, nothing else. The production impl
// wraps svc/mgr; the recorded double (winsvc_test.go) pins shapes + order.
// Handles are held by the impl (one service, one handle at a time).
type winSvcActions interface {
	connect() error
	disconnect() error
	openService(name string) error
	closeService()
	createService(name, binPath string, cfg mgrServiceConfig, args []string) error
	updateServiceConfig(name, binPath string, cfg mgrServiceConfig, args []string) error
	setRecovery(name string, actions []WinSvcRecoveryAction, resetPeriod uint32) error
	start(name string) error
	// controlStop sends SERVICE_CONTROL_STOP; accepted=false means the
	// service was not active (nothing to stop — never an error).
	controlStop(name string) (accepted bool, err error)
	query(name string) (state uint32, pid uint32, err error)
	deleteService(name string) error
}

// WinSvcScheduler is the windows-service Scheduler implementation (§4.1).
// pacing fields are test-shrunk (the production bounds mirror the systemd
// contracts: the stop poll 30 min = TimeoutStopSec=1800 parity, the running
// verify bounded like the launchd activation loop).
type WinSvcScheduler struct {
	actions winSvcActions

	stopPollInterval time.Duration
	stopPollAttempts int
	verifyInterval   time.Duration
	verifyAttempts   int

	// verbs records the flow steps (SCM calls + copyBinary alike) — the
	// unified ordering-pin channel the guard tests read. Production never
	// reads it.
	verbs []string
}

// NewWinSvcScheduler wires the scheduler over the given SCM seam with the
// production pacing.
func NewWinSvcScheduler(actions winSvcActions) *WinSvcScheduler {
	return &WinSvcScheduler{
		actions:          actions,
		stopPollInterval: 500 * time.Millisecond,
		// 30 minutes — the §2.2.7 bound (TimeoutStopSec=1800 parity).
		stopPollAttempts: 30 * 60 * 2,
		verifyInterval:   500 * time.Millisecond,
		verifyAttempts:   10,
	}
}

// withStopPolling shrinks the uninstall/install stop-poll bound (tests).
func (s *WinSvcScheduler) withStopPolling(interval time.Duration, attempts int) *WinSvcScheduler {
	s.stopPollInterval, s.stopPollAttempts = interval, attempts
	return s
}

// withVerifyPolling shrinks the running-verify loop (tests).
func (s *WinSvcScheduler) withVerifyPolling(interval time.Duration, attempts int) *WinSvcScheduler {
	s.verifyInterval, s.verifyAttempts = interval, attempts
	return s
}

// Verbs returns the recorded flow steps (ordering pins; tests only).
func (s *WinSvcScheduler) Verbs() []string { return s.verbs }

// step records one flow step.
func (s *WinSvcScheduler) step(verb string) { s.verbs = append(s.verbs, verb) }

// Name implements the Scheduler seam (§4.1).
func (s *WinSvcScheduler) Name() string { return "windows-service" }

// Available implements the Scheduler seam: windows-only (other GOOSes
// route to their own schedulers; production never asks elsewhere).
func (s *WinSvcScheduler) Available() (bool, string) {
	if runtime.GOOS != "windows" {
		return false, "the windows service scheduler is windows-only; this host is " + runtime.GOOS
	}
	return true, ""
}

// connectError wraps an SCM connect failure with the §2.2.8 elevated
// command line — never a bare error (owner UX rule).
func connectError(verb string, err error) error {
	return fmt.Errorf("install: connecting to the service control manager failed: %v — "+
		"service %s needs an elevated shell. Open Terminal (Administrator) and run:\n"+
		"  assay %s\n"+
		"(`assay status` still reports its own data dir from a normal shell; only the service query needs elevation)",
		err, verb, verb)
}

// Install runs the §2.2.4 flow with the §2.2.9 ordering:
// stop-if-running → poll Stopped → copyBinary → materialize →
// create-or-update → recovery actions → Start (ERROR_SERVICE_ALREADY_
// RUNNING = success-with-note) → bounded running verify.
func (s *WinSvcScheduler) Install(spec SchedulerInstallSpec) (Result, error) {
	res := Result{}
	if spec.RunningBinary == "" || spec.BinDir == "" {
		return res, errors.New("install: RunningBinary and BinDir are required")
	}
	// §2.2.5: the service ALWAYS carries an explicit -c — the embedded path
	// is the explicit config when given, else the materialization target.
	embedded := spec.ConfigPath
	if embedded == "" {
		embedded = spec.DefaultConfigPath
	}
	if embedded == "" {
		return res, errors.New("install: the windows service runs as LocalSystem and MUST carry an explicit " +
			"-c <abs config> — a -c-less service would resolve the SYSTEM profile and refuses to start; " +
			"resolve a config (-c) or let install materialize the default one")
	}
	args, err := WinSvcArgs(embedded)
	if err != nil {
		return res, err
	}
	if err := s.actions.connect(); err != nil {
		return res, connectError("install", err)
	}
	defer func() { _ = s.actions.disconnect() }()
	// The openService exists-probe below opens the service handle; release
	// it on EVERY exit path, exactly like Uninstall's teardown does (the
	// seam already owns the idempotent closeService).
	defer s.actions.closeService()

	// §2.2.9 (load-bearing): the running image is locked by Windows —
	// Control(Stop) + wait BEFORE copyBinary. A fresh host skips this.
	exists := s.actions.openService(WinSvcName) == nil
	if exists {
		s.step("openService")
		if state, pid, qerr := s.actions.query(WinSvcName); qerr == nil && state != WinSvcStateStopped {
			accepted, serr := s.actions.controlStop(WinSvcName)
			if serr != nil {
				return res, fmt.Errorf("install: stopping the running assay service: %w\n"+
					"(run by hand: sc.exe stop assay, then re-run `assay install`)", serr)
			}
			_ = accepted
			s.step("controlStop")
			if werr := s.awaitStopped(&pid, "install"); werr != nil {
				return res, werr
			}
		}
	}
	// The copy lands at <bin>\assay.exe (the §4.2 table name) — AFTER the
	// stop, BEFORE the registration/start.
	s.step("copyBinary")
	binPath, err := copyBinary(spec.RunningBinary, spec.BinDir)
	if err != nil {
		return res, err
	}
	res.BinaryPath = binPath
	// Configless install: materialize the default config at the embedded
	// path (never overwrite; kept = reported) — the launchd contract.
	if spec.ConfigPath == "" && spec.DefaultConfigPath != "" {
		created, merr := MaterializeDefaultConfig(spec.DefaultConfigPath, spec.DataDir)
		if merr != nil {
			return res, merr
		}
		if created {
			res.ConfigWritten = spec.DefaultConfigPath
		} else {
			res.ConfigKept = spec.DefaultConfigPath
		}
	}
	cfg := mgrServiceConfig{
		StartType:   mgr.StartAutomatic,
		DisplayName: WinSvcDisplayName,
		Description: WinSvcDescription,
	}
	if exists {
		s.step("updateServiceConfig")
		if uerr := s.actions.updateServiceConfig(WinSvcName, binPath, cfg, args); uerr != nil {
			return res, fmt.Errorf("install: update the assay service config: %w", uerr)
		}
	} else {
		s.step("createService")
		if cerr := s.actions.createService(WinSvcName, binPath, cfg, args); cerr != nil {
			return res, fmt.Errorf("install: CreateService(\"%s\"): %w\n"+
				"(is the shell elevated? run `assay install` from an Administrator terminal)", WinSvcName, cerr)
		}
	}
	// §2.2.4: Restart=always/RestartSec=5 parity — ServiceRestart after 5s,
	// the failure count resetting after 86400s without failures.
	s.step("setRecovery")
	if rerr := s.actions.setRecovery(WinSvcName, WinSvcRecoveryActions(), WinSvcRecoveryResetPeriod); rerr != nil {
		return res, fmt.Errorf("install: SetRecoveryActions: %w", rerr)
	}
	s.step("start")
	if serr := s.actions.start(WinSvcName); serr != nil {
		if errors.Is(serr, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			// §2.2.4: success-with-note — the service runs the PREVIOUS
			// image; the next SCM restart (or reboot) loads the new one.
			res.ServiceNote = "the service was already running (ERROR_SERVICE_ALREADY_RUNNING — " +
				"success-with-note; the new image loads on the next restart)"
		} else {
			return res, fmt.Errorf("install: start the assay service: %w\n"+
				"(inspect by hand: sc.exe query assay; event log: Windows Logs → Application)", serr)
		}
	}
	if verr := s.awaitRunning(); verr != nil {
		return res, verr
	}
	res.UnitPaths = []string{WinSvcName + " (SCM database entry)"}
	res.ServiceActive = true
	return res, nil
}

// awaitStopped polls Query until Stopped (§2.2.7/§2.2.9), bounded. The
// timeout error carries the flow's verb (install/uninstall) plus the EXACT
// sc.exe/taskkill lines (owner UX rule).
func (s *WinSvcScheduler) awaitStopped(lastPID *uint32, verb string) error {
	s.step("pollStopped")
	for range s.stopPollAttempts {
		state, pid, err := s.actions.query(WinSvcName)
		if err != nil {
			return fmt.Errorf("install: query the assay service: %w", err)
		}
		*lastPID = pid
		if state == WinSvcStateStopped {
			return nil
		}
		time.Sleep(s.stopPollInterval)
	}
	return errors.New(WinSvcStopTimeoutMessage(*lastPID, WinSvcStopBound(), verb))
}

// awaitRunning polls Query until Running with a real pid (bounded) —
// install never claims ServiceActive without a confirmed running service
// (the launchd verify-loop precedent).
func (s *WinSvcScheduler) awaitRunning() error {
	for range s.verifyAttempts {
		state, pid, err := s.actions.query(WinSvcName)
		if err == nil && state == WinSvcStateRunning && pid > 0 {
			return nil
		}
		time.Sleep(s.verifyInterval)
	}
	return errors.New("install: the assay service did not report Running within " +
		fmt.Sprintf("%d×%s — inspect by hand: sc.exe query assay", s.verifyAttempts, s.verifyInterval))
}

// winSvcCommandLine renders the service command line for UpdateConfig
// (mgr escapes INSIDE CreateService; UpdateConfig takes BinaryPathName
// verbatim — the updater escapes itself, args appended exactly like
// mgr.CreateService does).
func winSvcCommandLine(binPath string, args []string) string {
	s := syscall.EscapeArg(binPath)
	for _, a := range args {
		s += " " + syscall.EscapeArg(a)
	}
	return s
}

// Uninstall runs the §2.2.7 teardown: Control(Stop) (only when not
// stopped) → poll Stopped (bounded 30 min; the timeout carries the exact
// sc.exe/taskkill lines) → Delete → Close, then the managed-core teardown
// and the purge passthrough (unchanged semantics). An absent registration
// is reported honestly, never faked.
func (s *WinSvcScheduler) Uninstall(spec SchedulerUninstallSpec) (UninstallResult, error) {
	res := UninstallResult{}
	if err := s.actions.connect(); err != nil {
		return res, connectError("uninstall", err)
	}
	defer func() { _ = s.actions.disconnect() }()
	if s.actions.openService(WinSvcName) != nil {
		// Absent — nothing to stop or delete; the teardown below still runs.
		coreRemoved, err := removeManagedCore(spec.DataDir)
		if err != nil {
			return res, err
		}
		res.CoreRemoved = coreRemoved
		return res, purgePassthrough(spec.PurgeConfigPath, spec.PurgeDataDir, &res)
	}
	if state, pid, qerr := s.actions.query(WinSvcName); qerr == nil && state != WinSvcStateStopped {
		if _, serr := s.actions.controlStop(WinSvcName); serr != nil {
			return res, fmt.Errorf("uninstall: stopping the assay service: %w\n"+
				"(run by hand: sc.exe stop assay, then re-run `assay uninstall`)", serr)
		}
		s.step("controlStop")
		if werr := s.awaitStopped(&pid, "uninstall"); werr != nil {
			return res, werr
		}
	}
	s.step("deleteService")
	if derr := s.actions.deleteService(WinSvcName); derr != nil {
		return res, fmt.Errorf("uninstall: Delete: %w\n"+
			"(run by hand: sc.exe delete assay)", derr)
	}
	s.step("closeService")
	s.actions.closeService()
	res.DisabledUnits = []string{WinSvcName}
	res.RemovedUnits = []string{WinSvcName}
	coreRemoved, err := removeManagedCore(spec.DataDir)
	if err != nil {
		return res, err
	}
	res.CoreRemoved = coreRemoved
	if err := purgePassthrough(spec.PurgeConfigPath, spec.PurgeDataDir, &res); err != nil {
		return res, err
	}
	return res, nil
}

// purgePassthrough applies the destructive --purge semantics (unchanged
// from the systemd/launchd schedulers): remove the config file and the
// data dir, report every purged path.
func purgePassthrough(purgeConfigPath, purgeDataDir string, res *UninstallResult) error {
	for _, purge := range []string{purgeConfigPath, purgeDataDir} {
		if purge == "" {
			continue
		}
		if err := os.RemoveAll(purge); err != nil {
			return fmt.Errorf("uninstall: purge %s: %w", purge, err)
		}
		res.Purged = append(res.Purged, purge)
	}
	return nil
}

// Status implements the Scheduler seam (§2.2.8): Query → state + pid plus
// the honest supervision note (ADDENDUM §1: recovery actions for crashes,
// the self-watchdog transport for hangs). A Connect failure carries the
// exact elevated command (owner UX rule); a missing registration is an
// honest inactive status, not an error.
func (s *WinSvcScheduler) Status() (SchedulerStatus, error) {
	if err := s.actions.connect(); err != nil {
		return SchedulerStatus{}, connectError("status", err)
	}
	defer func() { _ = s.actions.disconnect() }()
	if s.actions.openService(WinSvcName) != nil {
		return SchedulerStatus{
			Active: false,
			Note:   "service not installed (" + WinSvcName + " — run `assay install`)",
		}, nil
	}
	state, pid, err := s.actions.query(WinSvcName)
	if err != nil {
		return SchedulerStatus{}, fmt.Errorf("install: query the assay service: %w", err)
	}
	return SchedulerStatus{
		Active: state != WinSvcStateStopped,
		PID:    int(pid),
		Note: "recovery: ServiceRestart after 5s; child stop: CTRL_BREAK (process group) → " +
			"bounded wait → TerminateProcess last resort; containment: Job Object (KILL_ON_JOB_CLOSE); " +
			"hang detection: self-watchdog → clean self-exit → SCM recovery-actions restart",
	}, nil
}

// HeldRegistration implements the Scheduler seam (§4.1): the SCM entry
// existing = this scheduler holds the registration. A connect failure
// reports not-held (the install itself fails loud at the SCM moments
// later — the refusal seam stays best-effort like the launchd print probe).
func (s *WinSvcScheduler) HeldRegistration() (bool, string) {
	if s.actions.connect() != nil {
		return false, ""
	}
	defer func() { _ = s.actions.disconnect() }()
	if s.actions.openService(WinSvcName) != nil {
		return false, ""
	}
	return true, WinSvcName
}

// NewProductionWinSvcScheduler wires the scheduler over the real svc/mgr.
func NewProductionWinSvcScheduler() *WinSvcScheduler {
	return NewWinSvcScheduler(&mgrSvcActions{})
}

// mgrSvcActions is the production winSvcActions: svc/mgr, one service
// handle at a time.
type mgrSvcActions struct {
	mgr *mgr.Mgr
	svc *mgr.Service
}

func (m *mgrSvcActions) connect() error {
	m2, err := mgr.Connect()
	if err != nil {
		return err
	}
	m.mgr = m2
	return nil
}

func (m *mgrSvcActions) disconnect() error {
	if m.mgr == nil {
		return nil
	}
	err := m.mgr.Disconnect()
	m.mgr = nil
	return err
}

func (m *mgrSvcActions) openService(name string) error {
	if m.mgr == nil {
		return errors.New("install: SCM not connected")
	}
	svcHandle, err := m.mgr.OpenService(name)
	if err != nil {
		return err
	}
	m.svc = svcHandle
	return nil
}

func (m *mgrSvcActions) closeService() {
	if m.svc == nil {
		return
	}
	_ = m.svc.Close()
	m.svc = nil
}

func toMgrConfig(cfg mgrServiceConfig) mgr.Config {
	return mgr.Config{
		StartType:        cfg.StartType,
		DisplayName:      cfg.DisplayName,
		Description:      cfg.Description,
		ServiceStartName: cfg.ServiceStartName,
		Password:         cfg.Password,
	}
}

func (m *mgrSvcActions) createService(name, binPath string, cfg mgrServiceConfig, args []string) error {
	if m.mgr == nil {
		return errors.New("install: SCM not connected")
	}
	// mgr.CreateService escapes BinaryPathName and the args itself
	// (mgr.go: syscall.EscapeArg per token) — pass the RAW pieces.
	svcHandle, err := m.mgr.CreateService(name, binPath, toMgrConfig(cfg), args...)
	if err != nil {
		return err
	}
	m.svc = svcHandle
	return nil
}

func (m *mgrSvcActions) updateServiceConfig(name, binPath string, cfg mgrServiceConfig, args []string) error {
	if m.svc == nil {
		return errors.New("install: service not open")
	}
	updated := toMgrConfig(cfg)
	// UpdateConfig takes the command line verbatim — escape here (see
	// winSvcCommandLine).
	updated.BinaryPathName = winSvcCommandLine(binPath, args)
	return m.svc.UpdateConfig(updated)
}

func (m *mgrSvcActions) setRecovery(name string, actions []WinSvcRecoveryAction, resetPeriod uint32) error {
	if m.svc == nil {
		return errors.New("install: service not open")
	}
	mapped := make([]mgr.RecoveryAction, len(actions))
	for i, a := range actions {
		mapped[i] = mgr.RecoveryAction{Type: int(a.Type), Delay: a.Delay}
	}
	return m.svc.SetRecoveryActions(mapped, resetPeriod)
}

func (m *mgrSvcActions) start(name string) error {
	if m.svc == nil {
		return errors.New("install: service not open")
	}
	return m.svc.Start()
}

func (m *mgrSvcActions) controlStop(name string) (bool, error) {
	if m.svc == nil {
		return false, errors.New("install: service not open")
	}
	_, err := m.svc.Control(svc.Stop)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return false, nil // nothing running — nothing to stop
		}
		return false, err
	}
	return true, nil
}

func (m *mgrSvcActions) query(name string) (uint32, uint32, error) {
	if m.svc == nil {
		return 0, 0, errors.New("install: service not open")
	}
	st, err := m.svc.Query()
	if err != nil {
		return 0, 0, err
	}
	return uint32(st.State), st.ProcessId, nil
}

func (m *mgrSvcActions) deleteService(name string) error {
	if m.svc == nil {
		return errors.New("install: service not open")
	}
	return m.svc.Delete()
}
