// scheduler.go carries the §3.1 Linux scheduler detection and the §4.1
// Scheduler seam for the non-systemd schedulers (Stage S3). The detection
// order is BINDING, first match wins:
//
//  1. systemd user session  — the existing env probe (UserSystemdAvailable),
//     unchanged in production;
//  2. runit user supervision — an own-uid runsvdir whose cmdline names a
//     service dir, AND sv on PATH;
//  3. OpenRC user session   — an own-uid openrc-user OR `rc-status --user`
//     exiting 0 (OpenRC ≥ 0.60; older releases fall through);
//  4. s6 user supervision   — an own-uid s6-svscan whose scandir IS its
//     /proc cwd (s6-svscan scans the current directory for subdirectories);
//     a root PID-1 s6-svscan does NOT qualify (no-sudo) and is surfaced as a
//     system-level note instead;
//  5. cron fallback         — crontab usable (`crontab -l` exit 0 or
//     "no crontab for user");
//  6. foreground            — none of the above.
//
// Everything runs as the current user: /proc is scanned for processes of the
// CURRENT uid only, and no scheduler here ever elevates. The proc scanner is
// an injected seam (ProcFS — defined at the consumer per the go-design
// ruling) so tests run against fixture trees, hermetic, never the real
// /proc. Detection ALSO scans for an existing assay-watch registration in
// ANY scheduler (HeldByAny): two schedulers both launching waves is the W5
// stampede class, and the CLI refuses the double install loudly.

package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// The Scheduler seam (§4.1) — one implementation per scheduler. The types are
// the platform-generic aliases (launchd.go); the CLI consumer defines its own
// lowercase interface over the same shapes.
// ---------------------------------------------------------------------------

// Scheduler is the per-scheduler lifecycle surface (§4.1): detection,
// install/uninstall, honest status, and the double-install refusal input.
// Every implementation pins its own command surface to an exact allowlist.
type Scheduler interface {
	Name() string
	Available() (bool, string)
	Install(spec SchedulerInstallSpec) (Result, error)
	Uninstall(spec SchedulerUninstallSpec) (UninstallResult, error)
	Status() (SchedulerStatus, error)
	HeldRegistration() (bool, string)
}

// The scheduler names as they appear in detection results, refusal messages,
// and status output — one spelling each, defined once.
const (
	SchedulerSystemd    = "systemd-user"
	SchedulerRunit      = "runit"
	SchedulerOpenRC     = "openrc-user"
	SchedulerS6         = "s6"
	SchedulerCron       = "cron"
	SchedulerForeground = "foreground"
)

// ---------------------------------------------------------------------------
// ProcFS — the /proc seam Detect consumes (defined at the consumer per the
// go-design ruling). Production reads the real /proc; tests hand fixture
// trees — hermetic by construction.
// ---------------------------------------------------------------------------

// ProcFS is the read-only process-table seam: numeric pid directory names,
// the per-pid file readers (comm/cmdline/status), and the cwd symlink.
type ProcFS interface {
	ProcIDs() ([]string, error)
	ReadProcFile(pid, name string) (string, error) // trimmed of \n and \x00 padding
	ProcCwd(pid string) (string, error)
}

// osProcFS is the production ProcFS over a root directory (the real /proc;
// the parameter keeps tests injectable through the same code path).
type osProcFS struct{ root string }

// NewOSProcFS is the production seam instance reading the real /proc.
func NewOSProcFS() ProcFS { //nolint:ireturn // the seam is an interface by design (fixture trees swap the impl)
	return osProcFS{root: "/proc"}
}

// newFixtureProcFS points the same reader at a fixture tree (tests only).
func newFixtureProcFS(root string) ProcFS { //nolint:ireturn // the seam is an interface by design
	return osProcFS{root: root}
}

// ProcIDs lists the numeric entries under the root (skips /proc's non-pid
// entries: sys, uptime, self, ...).
func (f osProcFS) ProcIDs() ([]string, error) {
	entries, err := os.ReadDir(f.root)
	if err != nil {
		return nil, fmt.Errorf("scheduler: scan %s: %w", f.root, err)
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if numeric(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	return ids, nil
}

// ReadProcFile reads root/<pid>/<name> trimmed of newlines and NUL padding
// (comm ends with \n; cmdline is \x00-separated).
func (f osProcFS) ReadProcFile(pid, name string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(f.root, pid, name))
	if err != nil {
		return "", err
	}
	return strings.Trim(string(raw), "\n\x00"), nil
}

// ProcCwd resolves root/<pid>/cwd.
func (f osProcFS) ProcCwd(pid string) (string, error) {
	return os.Readlink(filepath.Join(f.root, pid, "cwd"))
}

// numeric reports whether s is a bare digit run (a pid directory name).
func numeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// splitCmdline splits a /proc cmdline payload on its \x00 separators.
func splitCmdline(raw string) []string {
	var argv []string
	for p := range strings.SplitSeq(raw, "\x00") {
		if p != "" {
			argv = append(argv, p)
		}
	}
	return argv
}

// procUID extracts the owner uid from /proc/<pid>/status (the real uid —
// the first field of the `Uid:` line, whose order is real, effective, saved,
// filesystem; real == effective for every realistic scheduler, and real
// excludes a setuid'd helper — desirable for own-user detection).
func procUID(fs ProcFS, pid string) (int, error) {
	status, err := fs.ReadProcFile(pid, "status")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "Uid:" {
			uid, err := strconv.Atoi(fields[1])
			if err != nil {
				return 0, fmt.Errorf("scheduler: parse Uid of pid %s: %w", pid, err)
			}
			return uid, nil
		}
	}
	return 0, fmt.Errorf("scheduler: pid %s status carries no Uid line", pid)
}

// procEntry is one scanned own-uid process.
type procEntry struct {
	pid     string
	comm    string
	cmdline []string
	cwd     string // "" when the cwd link is unreadable (raced exit)
}

// scanOwnProcesses returns every process owned by the CURRENT uid (§3.1:
// system schedulers are root-owned and must never match).
func scanOwnProcesses(fs ProcFS) []procEntry {
	ids, err := fs.ProcIDs()
	if err != nil {
		return nil // an unreadable process table detects nothing — the caller falls through
	}
	uid := os.Getuid()
	var out []procEntry
	for _, id := range ids {
		puid, err := procUID(fs, id)
		if err != nil || puid != uid {
			continue
		}
		comm, err := fs.ReadProcFile(id, "comm")
		if err != nil {
			continue
		}
		line, err := fs.ReadProcFile(id, "cmdline")
		if err != nil {
			continue
		}
		cwd, _ := fs.ProcCwd(id)
		out = append(out, procEntry{pid: id, comm: comm, cmdline: splitCmdline(line), cwd: cwd})
	}
	return out
}

// ---------------------------------------------------------------------------
// Executors — the executor factory Detect consumes (§4.1 `Detect(proc,
// exec executorFactory)`). Production wires every field with the
// allowlist-checked executor of its scheduler; tests replace fields with
// recorders and scripted probes — detection stays fully hermetic.
// ---------------------------------------------------------------------------

// Executors is the per-scheduler executor factory Detect consumes — the
// §4.1 `exec executorFactory` parameter. Production wires every field with
// the allowlist-checked executor of its scheduler (ProductionExecutors);
// tests replace fields with recorders and scripted probes.
type Executors struct {
	// Home is the user home for the default artifact dirs ("" = resolved
	// from os.UserHomeDir at use time). Tests pin a fixture home.
	Home string

	// SystemdProbe is the §3.1.1 probe — production keeps the existing
	// UserSystemdAvailable behavior unchanged.
	SystemdProbe func() error
	// Systemd is the systemctl seam (install.go allowlist) and SystemdUnitDir
	// the user unit dir the registration scan inspects.
	Systemd        Executor
	SystemdUnitDir string

	// Runit is the sv seam (§3.2 allowlist); SvOnPath the §3.1.2 PATH check.
	Runit    SvExecutor
	SvOnPath func() bool

	// OpenRC is the rc-update/rc-service seam (§3.2 allowlist);
	// RCStatusProbe the §3.1.3 `rc-status --user` exit-0 fallback probe.
	OpenRC        OpenRCExecutor
	RCStatusProbe func() error

	// S6 is the s6-svc / s6-svscanctl / s6-svstat seam (§3.2 allowlist plus
	// the verified live-stop shape).
	S6 S6Executor

	// Cron is the crontab seam; CronUsable the §3.1.5 usability probe
	// (`crontab -l` exit 0 or "no crontab for user").
	Cron       CronExecutor
	CronUsable func() error
}

// ProductionExecutors wires the production factory over unitDir (the systemd
// user unit dir the CLI knows from its --unit-dir flag). Home resolves at
// use time.
func ProductionExecutors(unitDir string) *Executors {
	return &Executors{
		SystemdProbe:   UserSystemdAvailable,
		Systemd:        SystemctlExecutor{},
		SystemdUnitDir: unitDir,
		Runit:          RunitExecutor{},
		SvOnPath:       func() bool { _, err := exec.LookPath("sv"); return err == nil },
		OpenRC:         OpenRCExecutorImpl{},
		RCStatusProbe:  probeRCStatusUser,
		S6:             S6ExecutorImpl{},
		Cron:           CronExecutorImpl{},
		CronUsable:     func() error { return cronUsable(CronExecutorImpl{}) },
	}
}

// home resolves the user home (Executors.Home when pinned, else the OS
// answer — a resolution failure is loud).
func home(e *Executors) (string, error) {
	if e.Home != "" {
		return e.Home, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("scheduler: resolve home dir: %w", err)
	}
	return h, nil
}

// ---------------------------------------------------------------------------
// Detect — §3.1, BINDING order, first match wins
// ---------------------------------------------------------------------------

// Detect returns the scheduler that owns this host per the §3.1 order. The
// order is binding: systemd user session → runit → OpenRC user → s6 → cron →
// foreground. System-level (root-owned) schedulers never match — assay never
// elevates.
// Detect's return type is the §4.1 seam — an interface by design (one
// implementation per scheduler), hence the ireturn exemption.
func Detect(proc ProcFS, exec *Executors) Scheduler { //nolint:ireturn // §4.1 seam
	// 1. systemd user session — the existing probe, behavior unchanged.
	if exec.SystemdProbe != nil && exec.SystemdProbe() == nil {
		return &systemdUserScheduler{
			exec:         exec.Systemd,
			unitDir:      exec.SystemdUnitDir,
			systemdProbe: exec.SystemdProbe,
		}
	}
	// 2. runit user supervision.
	if dir := detectRunitServiceDir(proc, exec); dir != "" {
		return NewRunitScheduler(exec.Runit, dir)
	}
	// 3. OpenRC user session (own-uid openrc-user, or rc-status --user = 0).
	if ownsProcessNamed(proc, "openrc-user") || (exec.RCStatusProbe != nil && exec.RCStatusProbe() == nil) {
		return NewOpenRCScheduler(exec.OpenRC, "")
	}
	// 4. s6 user supervision (own-uid s6-svscan; scandir = its cwd).
	if scanDir := detectS6ScanDir(proc); scanDir != "" {
		return NewS6Scheduler(exec.S6, scanDir)
	}
	// 5. cron fallback (crontab usable).
	if exec.CronUsable != nil && exec.CronUsable() == nil {
		return NewCronScheduler(exec.Cron)
	}
	// 6. foreground — always matched last.
	return &ForegroundScheduler{}
}

// detectRunitServiceDir finds an own-uid runsvdir and resolves its service
// directory from the process cmdline. runsvdir(8) usage is
// `runsvdir [-L logfile] dir` — -L CONSUMES the next argument (the logfile),
// so option parsing is value-aware, not prefix-only. The dir argument is
// resolved against the process cwd when relative. "" = no runit detection
// (no own-uid runsvdir, or sv missing from PATH — §3.1.2 requires both).
func detectRunitServiceDir(proc ProcFS, exec *Executors) string {
	if exec.SvOnPath != nil && !exec.SvOnPath() {
		return ""
	}
	for _, p := range scanOwnProcesses(proc) {
		if !strings.HasPrefix(p.comm, "runsvdir") {
			continue
		}
		// A zombie's /proc cmdline is EMPTY while comm is retained — skip it
		// (a runsvdir with no dir argument cannot name a service dir anyway);
		// slicing nil[1:] would panic (P2-1, S3 review).
		if len(p.cmdline) < 2 {
			continue
		}
		argv := p.cmdline[1:] // skip argv[0]
		for i := 0; i < len(argv); i++ {
			arg := argv[i]
			if arg == "-L" {
				i++ // the logfile value is consumed — it is never a service dir
				continue
			}
			if strings.HasPrefix(arg, "-") {
				continue // value-less options carry no dir
			}
			if filepath.IsAbs(arg) {
				return filepath.Clean(arg)
			}
			if p.cwd != "" {
				return filepath.Clean(filepath.Join(p.cwd, arg))
			}
		}
	}
	return ""
}

// detectS6ScanDir finds an own-uid s6-svscan and returns ITS cwd — the
// scandir (s6-svscan(1): the scanner scans the current directory for
// subdirectories, which must be service directories). Root-owned s6
// processes never match (own-uid filter). "" = no user s6.
func detectS6ScanDir(proc ProcFS) string {
	for _, p := range scanOwnProcesses(proc) {
		if strings.HasPrefix(p.comm, "s6-svscan") && p.cwd != "" {
			return p.cwd
		}
	}
	return ""
}

// ownsProcessNamed reports whether an own-uid process carries comm.
func ownsProcessNamed(proc ProcFS, comm string) bool {
	for _, p := range scanOwnProcesses(proc) {
		if p.comm == comm {
			return true
		}
	}
	return false
}

// SystemLevelS6Note is the §3.1.4 honest note for a ROOT-owned s6-svscan
// (typically PID 1 under a system s6 init): user install unavailable without
// elevation — recorded in status, never gating anything. "" = no system s6.
func SystemLevelS6Note(proc ProcFS) string {
	ids, err := proc.ProcIDs()
	if err != nil {
		return ""
	}
	for _, id := range ids {
		uid, err := procUID(proc, id)
		if err != nil || uid != 0 {
			continue
		}
		comm, err := proc.ReadProcFile(id, "comm")
		if err != nil || !strings.HasPrefix(comm, "s6-svscan") {
			continue
		}
		return "s6 detected at system level (pid " + id + ", root-owned scandir); " +
			"user install unavailable (no elevation) — assay never uses sudo"
	}
	return ""
}

// ---------------------------------------------------------------------------
// HeldByAny — the cross-scheduler registration scan (§3.1 end): installing
// under scheduler A while scheduler B holds assay-watch is refused by the
// CLI (two schedulers launching waves = the W5 stampede class).
// ---------------------------------------------------------------------------

// HeldByAny scans every known scheduler for an existing assay-watch
// registration and returns the holder's name + artifact location. The scan
// order is deterministic (systemd → runit → openrc → s6 → cron) so refusal
// messages are stable. s6 is only scannable when a live own-uid scanner
// exists (its scandir convention is never invented).
func HeldByAny(proc ProcFS, exec *Executors) (string, string, bool) {
	// systemd: the unit file in the user unit dir.
	if exec.SystemdUnitDir != "" {
		p := filepath.Join(exec.SystemdUnitDir, WatchService)
		if _, err := os.Stat(p); err == nil {
			return SchedulerSystemd, p, true
		}
	}
	// runit: the detected service dir, else the default ~/service convention
	// (a leftover dir re-enables at the next runsvdir start — loud beats
	// silent). Dot-prefixed dirs are skipped by runsvdir → not a registration.
	h, err := home(exec)
	if err == nil {
		dir := detectRunitServiceDir(proc, exec)
		if dir == "" {
			dir = filepath.Join(h, "service")
		}
		if dir != "" {
			p := filepath.Join(dir, "assay-watch")
			if st, serr := os.Stat(p); serr == nil && st.IsDir() {
				return SchedulerRunit, p, true
			}
		}
	}
	// OpenRC: the user script in ${XDG_CONFIG_HOME:-~/.config}/rc/init.d.
	if h != "" {
		p := filepath.Join(openrcDefaultInitDir(os.Getenv("XDG_CONFIG_HOME"), h), "assay-watch")
		if _, err := os.Stat(p); err == nil {
			return SchedulerOpenRC, p, true
		}
	}
	// s6: only with a live own-uid scanner (scandir = its cwd).
	if scanDir := detectS6ScanDir(proc); scanDir != "" {
		p := filepath.Join(scanDir, "assay-watch")
		if _, err := os.Stat(p); err == nil {
			return SchedulerS6, p, true
		}
	}
	// cron: the marked @reboot line in the user crontab.
	if exec.Cron != nil && crontabHoldsMarker(exec.Cron) {
		return SchedulerCron, "user crontab (@reboot assay-watch)", true
	}
	return "", "", false
}

// ---------------------------------------------------------------------------
// systemdUserScheduler — the §3.1.1 adapter: Detect's first match wraps the
// EXISTING install path (the CLI keeps its byte-identical generic systemd
// flow; the adapter exists so Detect returns a Scheduler and the
// cross-scheduler scan can ask systemd).
// ---------------------------------------------------------------------------

type systemdUserScheduler struct {
	exec         Executor
	unitDir      string
	systemdProbe func() error
}

// Name implements the Scheduler seam.
func (s *systemdUserScheduler) Name() string { return SchedulerSystemd }

// Available reports the §3.1.1 probe result.
func (s *systemdUserScheduler) Available() (bool, string) {
	if s.systemdProbe == nil {
		return false, "no systemd probe wired"
	}
	if err := s.systemdProbe(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// Install delegates to the package Install — the exact systemd flow the CLI
// generic path drives (byte-identical surface: same Options, same executor).
func (s *systemdUserScheduler) Install(spec SchedulerInstallSpec) (Result, error) {
	return Install(Options{
		BinDir:            spec.BinDir,
		UnitDir:           s.unitDir,
		RunningBinary:     spec.RunningBinary,
		ConfigPath:        spec.ConfigPath,
		DefaultConfigPath: spec.DefaultConfigPath,
		DataDir:           spec.DataDir,
		Exec:              s.exec,
	})
}

// Uninstall delegates to the package Uninstall (same unit dir + executor).
func (s *systemdUserScheduler) Uninstall(spec SchedulerUninstallSpec) (UninstallResult, error) {
	return Uninstall(UninstallOptions{
		UnitDir:            s.unitDir,
		Exec:               s.exec,
		ManagedCoreDataDir: spec.DataDir,
		PurgeConfigPath:    spec.PurgeConfigPath,
		PurgeDataDir:       spec.PurgeDataDir,
	})
}

// Status reads the registration from disk (the same evidence the CLI status
// section shows): the unit file present = registered; the wants symlink =
// enabled. No systemctl is-active runs (not in the allowlist) — the note
// names the supervision contract instead of guessing a live state.
func (s *systemdUserScheduler) Status() (SchedulerStatus, error) {
	if s.unitDir == "" {
		return SchedulerStatus{Note: "no unit dir known — run `assay install`"}, nil
	}
	unitPath := filepath.Join(s.unitDir, WatchService)
	if _, err := os.Stat(unitPath); err != nil {
		//nolint:nilerr // the stat failure IS the answer: not registered — an honest status, not an error
		return SchedulerStatus{
			Active: false,
			Note:   "unit not rendered (" + unitPath + " — run `assay install`)",
		}, nil
	}
	enabled := false
	for _, wants := range []string{"default.target.wants", "multi-user.target.wants"} {
		if _, err := os.Stat(filepath.Join(s.unitDir, wants, WatchService)); err == nil {
			enabled = true
			break
		}
	}
	if !enabled {
		return SchedulerStatus{
			Active: true,
			Note:   "unit rendered but not enabled — run `assay install` to enable",
		}, nil
	}
	return SchedulerStatus{
		Active: true,
		Note:   "systemd user unit (Restart=always, RestartSec=5; hang detection: sd_notify watchdog)",
	}, nil
}

// HeldRegistration reports the unit file presence — the same registration
// evidence the filesystem-based scan uses.
func (s *systemdUserScheduler) HeldRegistration() (bool, string) {
	if s.unitDir == "" {
		return false, ""
	}
	p := filepath.Join(s.unitDir, WatchService)
	if _, err := os.Stat(p); err != nil {
		return false, ""
	}
	return true, p
}

// ---------------------------------------------------------------------------
// ForegroundScheduler — §3.1.6: nothing detected. Install still copies the
// binary and materializes the config; the CLI prints the exact
// foreground-run instructions. --no-scheduler skips even that (generic path).
// ---------------------------------------------------------------------------

// ForegroundScheduler is the last-resort scheduler: no supervision, no
// activation, honest about it.
type ForegroundScheduler struct{}

// Name implements the Scheduler seam.
func (*ForegroundScheduler) Name() string { return SchedulerForeground }

// Available is always true — foreground is what remains when nothing else
// matches.
func (*ForegroundScheduler) Available() (bool, string) { return true, "" }

// Install copies the binary and materializes the default config (§3.1.6)
// without rendering or activating anything.
func (*ForegroundScheduler) Install(spec SchedulerInstallSpec) (Result, error) {
	res := Result{}
	binPath, err := copyBinary(spec.RunningBinary, spec.BinDir)
	if err != nil {
		return res, err
	}
	res.BinaryPath = binPath
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
	res.ServiceNote = "no scheduler detected — run `assay watch` in the foreground " +
		"(no supervision: no crash restart; the daemon runs until it exits)"
	return res, nil
}

// Uninstall removes the managed core and honors purge — no scheduler
// artifacts exist to disable.
func (*ForegroundScheduler) Uninstall(spec SchedulerUninstallSpec) (UninstallResult, error) {
	res := UninstallResult{}
	coreRemoved, err := removeManagedCore(spec.DataDir)
	if err != nil {
		return res, err
	}
	res.CoreRemoved = coreRemoved
	for _, purge := range []string{spec.PurgeConfigPath, spec.PurgeDataDir} {
		if purge == "" {
			continue
		}
		if err := os.RemoveAll(purge); err != nil {
			return res, fmt.Errorf("uninstall: purge %s: %w", purge, err)
		}
		res.Purged = append(res.Purged, purge)
	}
	return res, nil
}

// Status reports the honest foreground posture.
func (*ForegroundScheduler) Status() (SchedulerStatus, error) {
	return SchedulerStatus{
		Active: false,
		Note:   "no scheduler — run `assay watch` in the foreground (no supervision)",
	}, nil
}

// HeldRegistration is always false — the foreground mode registers nothing.
func (*ForegroundScheduler) HeldRegistration() (bool, string) { return false, "" }

// ---------------------------------------------------------------------------
// Shared run-script content (§3.2 — runit and s6 use the exact same
// contract): `#!/bin/sh` + `exec <abs binary> watch [-c <abs config>]` with
// the log redirects under <data>/logs/. Paths are double-quoted; a
// quote-hostile path is refused BEFORE anything is written.
// ---------------------------------------------------------------------------

// runScriptContent renders the run script bytes. configPath == "" renders
// plain `watch` (default-location install — the daemon reads the default
// config location).
func runScriptContent(binaryPath, configPath, dataDir string) ([]byte, error) {
	line, err := runScriptLine(binaryPath, configPath, dataDir)
	if err != nil {
		return nil, err
	}
	return []byte("#!/bin/sh\n" + line + "\n"), nil
}

// runScriptLine is the single exec line.
func runScriptLine(binaryPath, configPath, dataDir string) (string, error) {
	for field, p := range map[string]string{
		"BinaryPath": binaryPath,
		"DataDir":    dataDir,
	} {
		if strings.ContainsAny(p, "\"$`\\\n") {
			return "", fmt.Errorf("install: %s %q contains a quote-hostile character "+
				"(\", $, backtick, backslash, or newline) — the line lands inside double quotes "+
				"in an sh script, where $ and backtick expand and a backslash eats the next "+
				"character; choose a path without these characters", field, p)
		}
	}
	args := "watch"
	if configPath != "" {
		if strings.ContainsAny(configPath, "\"$`\\\n") {
			return "", fmt.Errorf("install: ConfigPath %q contains a quote-hostile character "+
				"(\", $, backtick, backslash, or newline) — the line lands inside double quotes "+
				"in an sh script, where $ and backtick expand and a backslash eats the next "+
				"character; choose a path without these characters", configPath)
		}
		args = `watch -c "` + configPath + `"`
	}
	return `exec "` + binaryPath + `" ` + args +
		` 2>>"` + filepath.Join(dataDir, "logs", "watch.err.log") + `"` +
		` 1>>"` + filepath.Join(dataDir, "logs", "watch.out.log") + `"`, nil
}

// materializeForSpec is the scheduler-neutral default-config materialization
// (explicit -c installs skip; present files are kept, never overwritten).
func materializeForSpec(spec SchedulerInstallSpec, res *Result) error {
	if spec.ConfigPath != "" || spec.DefaultConfigPath == "" {
		return nil
	}
	created, err := MaterializeDefaultConfig(spec.DefaultConfigPath, spec.DataDir)
	if err != nil {
		return err
	}
	if created {
		res.ConfigWritten = spec.DefaultConfigPath
	} else {
		res.ConfigKept = spec.DefaultConfigPath
	}
	return nil
}

// ensureLogsDir creates <data>/logs (the log redirects need the parent).
func ensureLogsDir(dataDir string) error {
	dir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("install: create log dir %s: %w", dir, err)
	}
	return nil
}

// loudProbeFailure wraps a failed bounded verify with the scheduler name,
// the failed command, and the exact manual line (owner UX rule).
func loudProbeFailure(scheduler, cmd, manual string, attempts int, err error) error {
	return fmt.Errorf("install: %s activation not verified after %d probes: %w\n"+
		"failed command: %s\n(run by hand: %s)", scheduler, attempts, err, cmd, manual)
}

// schedulerVerifyInterval/Attempts are the bounded activation-verify
// settings (§3.3): 20 × 500ms — the runsvdir rescan runs every five seconds,
// so the window must span at least two scans. Tests shrink both fields
// directly (the launchd pattern; the launchd constants keep their names).
const (
	schedulerVerifyInterval = 500 * time.Millisecond
	schedulerVerifyAttempts = 20
)
