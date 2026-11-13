// Package core implements the self-held core manager (the 2026-11-10
// pivot): the watch daemon is the xray child's DIRECT parent (D1) and owns
// spawn, supervise, health and rollback for the long-lived
// `xray run -c <data>/rendered/live.json` process.
//
// Contracts:
//   - Singleton (S3): one manager per data dir, guarded by an exclusive
//     flock on <data>/core.lock; a second manager refuses with
//     ErrDaemonHoldsCore (same process AND cross-process — the kernel
//     holds the lock).
//   - Crash supervision (G1): Supervise starts the between-waves loop —
//     a child exiting without a manager-driven stop is logged loud and
//     revived on a bounded, capped-exponential backoff; supervision
//     restarts feed NO D8 strikes (C3: strikes move only through
//     RecordHealth).
//   - Bootstrap (S2): EnsureRunning spawns the child when none runs, and
//     ADOPTS a core left running by a dead daemon through the pidfile (A2:
//     a daemon restart must not leave the core dead, and must never
//     double-spawn onto a live one). Callers pass a ctx that outlives the
//     daemon when the child should survive daemon death (A2) — the exec
//     path kills the child on ctx cancellation.
//   - Health: Healthy dials the socks inbound (127.0.0.1:socks_port, the
//     D2 binding constant) and pulls one outbound fetch through it.
//   - Rollback (D8): K = [core].rollback_strikes consecutive failed health
//     checks restore the newest <data>/backups/config.json.bak-<ts>, gate
//     it with `run -test` on the managed binary, restart the core and log
//     the loud line; a healthy check resets the counter.
//   - Child stdio is inherited into the daemon's stdout (S7: long-lived
//     child, no buffer capture — the stream lands in the unit journal; a
//     bounded tail is kept solely for boot-death diagnostics).
//   - Exec safety: every child carries a WaitDelay (the M-3 landmine — a
//     killed child's inherited pipes must never block Wait forever).
package core

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"assay/internal/config"
	"assay/internal/platform"
)

// Geometry constants — code-owned, NOT knobs (the owner's standing ruling:
// supervision politeness is not operator-facing configuration, and no knob
// gets a floor/ceiling). The values mirror the proven checker
// temp-instance geometry.
const (
	// bootBound is the spawn-to-readiness budget: the child must bind the
	// socks inbound within it (the real binary parses and binds in ~100ms).
	bootBound = 10 * time.Second
	// bootPollEvery is the readiness and adopted-kill poll interval.
	bootPollEvery = 150 * time.Millisecond
	// bootDialTimeout is one readiness-poll dial budget.
	bootDialTimeout = 400 * time.Millisecond
	// killWaitDelay bounds exec.Wait after a kill: lingering inherited
	// pipes held by grandchildren release the parent instead of hanging it
	// (the WaitDelay-safe exec path this task is required to use).
	killWaitDelay = 5 * time.Second
	// healthTimeout bounds the whole Healthy probe (dial + SOCKS5 CONNECT +
	// one outbound fetch).
	healthTimeout = 10 * time.Second
	// testGateTimeout bounds the rollback's `run -test` child (mirrors
	// config.DefaultTestTimeout).
	testGateTimeout = 30 * time.Second
	// childTailMax is the bounded stdio tail kept for boot-death
	// diagnostics. S7 keeps the STREAM itself unbuffered — the tail is a
	// diagnostics sidecar, not the output path.
	childTailMax = 8 * 1024
	// defaultHealthURL is Healthy's outbound fetch target (one fetch
	// through the pool): the codebase's established tunnel-alive gate
	// endpoint (204 contract, GreatFire-clean). Tests override the
	// unexported healthURL with a loopback httptest server.
	defaultHealthURL = "http://cp.cloudflare.com/generate_204"
)

// PIDFileName is the pidfile name inside the data dir (Alive() for status;
// A2 adoption across daemon restarts). Exported: the status core block
// (internal/cli) observes the same file cross-process — one file-name
// contract, one definition.
const PIDFileName = "core.pid"

// Crash-supervision geometry (G1, between waves) — code-owned, NOT knobs
// (the owner's standing ruling: supervision politeness is not operator-
// facing configuration). The backoff is a capped exponential: a crash
// storm revives at start/2x/4x/… up to the cap; a child that stayed alive
// for crashStableAfter resets the ladder. Vars, not consts: the test suite
// shortens them to keep the supervision loop hermetic and fast.
var (
	// crashBackoffStart is the first revive delay after a crash.
	crashBackoffStart = 500 * time.Millisecond
	// crashBackoffCap is the maximum revive delay (bounded revive cadence).
	crashBackoffCap = 30 * time.Second
	// crashStableAfter is the uptime that resets the backoff ladder: a
	// child that lived this long before dying is treated as a fresh crash,
	// not a continuation of a crash storm.
	crashStableAfter = 90 * time.Second
	// adoptedStopPoll bounds the post-SIGKILL liveness poll for an ADOPTED
	// (non-child) pid. Production value = killWaitDelay; a test seam var
	// (T2 review M-2) so the post-poll truth branch is observable without a
	// real D-state process.
	adoptedStopPoll = killWaitDelay
	// superviseAdoptedPoll is the crash-supervisor's liveness cadence for an
	// ADOPTED core (not our child — no reaper signal; watched by polling).
	superviseAdoptedPoll = 2 * time.Second
)

// managedAssetDirRel is the managed asset dir relative to the data dir
// (S6: geosite-style routes resolve assets there at spawn; the
// managed-core download task materializes it). A var, not a const:
// filepath.Join is not a constant expression.
var managedAssetDirRel = filepath.Join("share", "xray")

// Manager is the daemon-owned core supervisor. All child-state transitions
// (spawn/stop/restart/rollback) are serialized by mu; Healthy is lock-free
// (it probes the port, not the manager's state). Create with NewManager —
// the zero value is not usable.
type Manager struct {
	mu sync.Mutex

	bin       string // resolved SINGLE binary knob (S1) — mirrors CoreXrayBin
	override  string // the raw [core].xray_bin override ("" = resolved order)
	source    BinarySource
	dataDir   string
	livePath  string
	lockPath  string
	pidPath   string
	backupDir string
	socksPort int
	strikeK   int

	log      io.Writer
	lockFile *os.File

	// Child state — guarded by mu. cmd is this session's child; adoptedPID
	// is a core adopted from the pidfile (A2); exactly one is set when a
	// core is running. generation increments on every successful child
	// start (the crash supervisor's token for "the child I was watching");
	// deliberateStop is set by every manager-driven stop (Stop, Restart,
	// rollback) so the supervisor never reads a deliberate exit as a crash.
	cmd            *exec.Cmd
	waitOnce       sync.Once
	done           chan struct{} // closed by the wait goroutine after Wait returns
	waitErr        error         // valid after <-done (channel close = happens-before)
	job            *childJob     // windows containment job (ADDENDUM §2); nil on unix
	adoptedPID     int
	strikes        int           // consecutive failed health checks (D8)
	generation     int           // increments on every child start (supervisor token)
	deliberateStop bool          // a manager-driven stop/restart is in flight
	spawnedAt      time.Time     // when the current child started (backoff reset)
	crashBackoff   time.Duration // the supervisor's current revive delay

	// superviseOnce guards Supervise: the loop starts at most once per
	// manager (the daemon calls it; a second call is a no-op).
	superviseOnce sync.Once

	// inertInfoLogged gates the S5 one-time INFO on the inert auto-update
	// path (an overridden [core].xray_bin) — one loud line per manager
	// lifetime, never per-wave noise.
	inertInfoLogged bool

	// healthURL is the outbound fetch target of Healthy
	// (defaultHealthURL; tests point it at a loopback server).
	healthURL string

	// stderrTail forwards child stdio into log (S7) and keeps a bounded
	// tail for boot-death diagnostics.
	stderrTail *tailWriter
}

// NewManager takes the singleton flock for dataDir (S3) and returns the
// manager. A second manager over the same data dir fails with
// ErrDaemonHoldsCore. The binary knob resolves exactly like
// config.CoreXrayBin — the owner-ruling order (override → user-local
// → system-preexisting → the user-local install target); the equality is
// guard-pinned by a test because NewManager receives CoreConfig + dataDir,
// not the whole Config. The binding is probed and recorded once here
// (version, floor warning, provenance), and re-detected per wave by
// AutoUpdate's reattach. A nil log defaults to os.Stdout (the daemon's
// stdout IS the journal).
func NewManager(cfg config.CoreConfig, dataDir string, log io.Writer) (*Manager, error) {
	if dataDir == "" {
		return nil, errors.New("core: dataDir is empty — the manager cannot take its singleton lock")
	}
	if log == nil {
		log = os.Stdout
	}
	//nolint:gosec // G703: the data dir comes from the owner's config, which is
	// the trust root by construction — there is no fixed path to fall back to
	// (the whole manager is scoped to the configured data dir), and the
	// caller validates non-empty (above). No loader-level alternative exists.
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("core: data dir %s: %w", dataDir, err)
	}
	lockFile, err := acquireCoreLock(dataDir)
	if err != nil {
		return nil, err
	}
	bin := config.ResolveCoreXrayBin(cfg.XrayBin, dataDir)
	socksPort := cfg.SocksPort
	if socksPort <= 0 {
		socksPort = config.DefaultCoreSocksPort
	}
	strikeK := cfg.RollbackStrikes
	if strikeK <= 0 {
		strikeK = config.DefaultCoreRollbackStrikes
	}
	m := &Manager{
		bin:        bin,
		override:   cfg.XrayBin,
		source:     classifyBinarySource(cfg.XrayBin, bin),
		dataDir:    dataDir,
		livePath:   filepath.Join(dataDir, "rendered", "live.json"),
		lockPath:   filepath.Join(dataDir, coreLockName),
		pidPath:    filepath.Join(dataDir, PIDFileName),
		backupDir:  filepath.Join(dataDir, "backups"),
		socksPort:  socksPort,
		strikeK:    strikeK,
		log:        log,
		lockFile:   lockFile,
		healthURL:  defaultHealthURL,
		stderrTail: newTailWriter(log, childTailMax),
	}
	// The health-state mirror: the D8 STREAK lives in the process that
	// counts it (S3 — the lock guarantees no other manager is counting), so
	// a fresh manager resets it. The rollback record is DISK HISTORY — the
	// restore really happened — and must survive daemon restarts (the
	// status core block observes exactly that cross-process): this is
	// create-if-absent with a streak-only reset, never an unconditional
	// wipe. A corrupt file degrades to the fresh mirror (the next write
	// replaces damaged content either way).
	if existing, rerr := ReadHealthState(dataDir); rerr != nil || existing == nil {
		if err := writeHealthStateFile(dataDir, &HealthState{}); err != nil {
			_, _ = fmt.Fprintf(log, "WARNING: core: reset health state: %v\n", err)
		}
	} else {
		existing.Strikes = 0
		existing.LastHealthy = false
		existing.LastError = ""
		if err := writeHealthStateFile(dataDir, existing); err != nil {
			_, _ = fmt.Fprintf(log, "WARNING: core: reset health state: %v\n", err)
		}
	}
	// The binding probe: version, floor warning, provenance — once per
	// manager lifetime (the per-wave re-detection is reattach). The pending
	// state (no binary anywhere) binds the install target silently.
	m.mu.Lock()
	m.applyBindingLocked(m.source, m.bin)
	m.mu.Unlock()
	_, _ = fmt.Fprintf(log, "core: manager holds the singleton lock (%s) — binary %s, "+
		"socks 127.0.0.1:%d, rollback strikes %d\n", m.lockPath, bin, socksPort, strikeK)
	return m, nil
}

// EnsureRunning spawns the core child when none is running (bootstrap per
// S2) and adopts one left running by a previous daemon (A2). When this
// session's child is already alive it is a no-op.
func (m *Manager) EnsureRunning(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureRunningLocked(ctx)
}

// Restart stops and starts the core around a swapped live.json: the
// activate stage (the activate-rework task) replaces the live config, then
// Restart brings the child back up ON the new file. If the new config is
// broken, the boot fails loud and no child runs until the next
// EnsureRunning or rollback.
func (m *Manager) Restart(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.stopLocked(); err != nil {
		return fmt.Errorf("core: restart stop leg: %w", err)
	}
	return m.ensureRunningLocked(ctx)
}

// Stop kills the core child by its exact PID and reaps it (WaitDelay-safe:
// lingering inherited pipes can never hang the caller). Idempotent.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked()
}

// Supervise starts the between-waves crash-supervision loop (G1): the
// daemon's manager watches its child; a child exiting WITHOUT a
// manager-driven stop (a crash — non-Stop exit) is logged loud and revived
// after a bounded, capped-exponential backoff (crashBackoffStart doubling
// up to crashBackoffCap; an uptime of crashStableAfter resets the ladder).
// The supervision restarts feed NO D8 strikes — the strike counter moves
// only through RecordHealth (activation-health-driven, C3). When no child
// runs (a failed bootstrap, a failed revive), the loop retries the spawn on
// the same ladder — the supervisor is the between-waves keep-alive. The
// loop ends when stop closes; the child itself is stopped only by Stop.
// Idempotent: the first call wins, later calls are no-ops.
func (m *Manager) Supervise(stop <-chan struct{}) {
	m.superviseOnce.Do(func() {
		go m.superviseLoop(stop)
	})
}

// superviseLoop is the G1 body. mu is taken only for snapshots and for the
// spawn/revive legs — never held across the wait or the backoff sleep (a
// rollback or an activate Restart must never block on the supervisor).
func (m *Manager) superviseLoop(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}

		m.mu.Lock()
		if !m.childAliveLocked() {
			// No child running: retry the spawn on the backoff ladder.
			delay := m.advanceBackoffLocked(0)
			m.mu.Unlock()
			if !sleepBackoff(stop, delay) {
				return
			}
			if err := m.revive(); err != nil {
				_, _ = fmt.Fprintf(m.log, "core: crash supervision restart failed: %v (retrying with backoff)\n", err)
			}
			continue
		}
		if m.adoptedPID != 0 {
			// An ADOPTED core is not our child: no reaper signal exists
			// (m.done may still be the PREVIOUS session child's closed
			// channel — waiting on it would spin hot). Watch it by polling
			// its liveness instead; a dead adopted pid falls into the
			// no-child branch above and is revived as a fresh spawn.
			m.mu.Unlock()
			if !sleepBackoff(stop, superviseAdoptedPoll) {
				return
			}
			continue
		}
		done := m.done
		gen := m.generation
		spawnedAt := m.spawnedAt
		m.mu.Unlock()

		select {
		case <-stop:
			return
		case <-done: // the child exited (Wait returned; waitErr is set)
		}

		m.mu.Lock()
		crashed := m.generation == gen && !m.deliberateStop
		lived := time.Since(spawnedAt)
		waitErr := m.waitErr
		if !crashed {
			// A manager-driven stop/restart/rollback replaced or removed
			// the child while we waited — not a crash; keep watching.
			m.mu.Unlock()
			continue
		}
		delay := m.advanceBackoffLocked(lived)
		m.mu.Unlock()

		_, _ = fmt.Fprintf(m.log, "core: child exited unexpectedly (crash supervision): %v — restart in %s\n",
			waitErr, delay)
		if !sleepBackoff(stop, delay) {
			return
		}
		if err := m.revive(); err != nil {
			_, _ = fmt.Fprintf(m.log, "core: crash supervision restart failed: %v (retrying with backoff)\n", err)
		}
	}
}

// revive is the supervisor's spawn leg: EnsureRunning under a non-canceling
// ctx (C4 — the revived child must outlive wave cancellation exactly like
// every other lifecycle call).
func (m *Manager) revive() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureRunningLocked(context.Background())
}

// advanceBackoffLocked returns the CURRENT revive delay and advances the
// ladder. A child that lived at least crashStableAfter resets the ladder to
// the start value (a fresh crash, not a crash storm); the returned delay is
// never below crashBackoffStart and the stored next delay never exceeds
// crashBackoffCap.
func (m *Manager) advanceBackoffLocked(lived time.Duration) time.Duration {
	if lived >= crashStableAfter {
		m.crashBackoff = 0
	}
	delay := max(m.crashBackoff, crashBackoffStart)
	if next := delay * 2; next > crashBackoffCap {
		m.crashBackoff = crashBackoffCap
	} else {
		m.crashBackoff = next
	}
	return delay
}

// sleepBackoff waits delay, aborting early when stop closes (true = the
// full delay elapsed, false = supervision is shutting down).
func sleepBackoff(stop <-chan struct{}, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-stop:
		return false
	case <-timer.C:
		return true
	}
}

// Healthy probes the running core: the socks inbound must answer on
// loopback (D2 binding constant) and one outbound fetch must succeed
// through it. Errors returned here feed the D8 strike counter via
// RecordHealth.
func (m *Manager) Healthy(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: bootDialTimeout}).DialContext(ctx, "tcp", m.socksAddr())
	if err != nil {
		return fmt.Errorf("core: health leg 1 — socks %s unreachable: %w", m.socksAddr(), err)
	}
	defer func() { _ = conn.Close() }()
	// Bound the whole leg 2 (handshake + CONNECT + fetch) at the socket
	// level from the probe's deadline, then run it.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// Leg 2 on the same connection: SOCKS5 handshake, CONNECT, one HTTP GET.
	return fetchThroughSocks(ctx, conn, m.healthURL)
}

// Alive reports whether a core process is running for this data dir:
// this session's child (or an adopted pid), else a live pidfile pid —
// the pidfile+liveness contract the status command consumes.
func (m *Manager) Alive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.childAliveLocked() {
		return true
	}
	pid := m.readPIDFile()
	return pid > 0 && PIDAlive(pid)
}

// Release drops the singleton flock WITHOUT stopping any core — the one-shot
// wave's teardown (fix I-1). A child the wave spawned or adopted keeps
// running (A2: a wave never orphans a live core; the pidfile is left for the
// daemon to adopt). The daemon never calls this — its manager holds the lock
// for its whole lifetime (S3) and stops the child explicitly on shutdown.
// (This is the exported lock-surrender seam the T2 review's M-4 flagged.)
//
// Contrast with the unexported release(): that one STOPS the child first
// (full teardown); Release is deliberately lock-only.
func (m *Manager) Release() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lockFile != nil {
		_ = unlockCoreFile(m.lockFile)
		_ = m.lockFile.Close()
		m.lockFile = nil
	}
}

// release stops any child and drops the singleton flock (test hygiene and
// the daemon-shutdown seam; process death would release the lock anyway).
func (m *Manager) release() {
	_ = m.Stop()
	if m.lockFile != nil {
		_ = unlockCoreFile(m.lockFile)
		_ = m.lockFile.Close()
		m.lockFile = nil
	}
}

// ensureRunningLocked is EnsureRunning under mu.
func (m *Manager) ensureRunningLocked(ctx context.Context) error {
	// childAliveLocked only means "not reaped yet": between a hard kill
	// (SIGKILL after a manual daemon kill — the T4-I-1 shape b) and the
	// reaper's Wait() completing, the handle is still open while the child
	// is a zombie that will never serve. Treating that window as "alive"
	// made the candidate-missing revive a no-op on exactly the hosts whose
	// scheduling lost the race (darwin CI: "Condition never satisfied", run
	// 43330792666). A live child is one that is serving (a mid-boot child
	// is unobservable here: spawnLocked awaits readiness under m.mu, so no
	// concurrent EnsureRunning can run during boot).
	if m.childAliveLocked() && m.portServing() {
		return nil
	}
	// A2 adoption: children are reparented, not killed, when the daemon
	// dies. A pidfile pid that is alive AND serving the socks inbound is
	// our core — adopt it, never double-spawn onto it.
	if pid := m.readPIDFile(); pid > 0 && PIDAlive(pid) {
		if m.portServing() {
			m.adoptedPID = pid
			_, _ = fmt.Fprintf(m.log, "core: adopted running core pid %d (left by a previous daemon)\n", pid)
			return nil
		}
		m.clearPIDFile()
		_, _ = fmt.Fprintf(m.log, "core: stale pidfile (pid %d alive but not serving the socks inbound) — removed\n", pid)
	}
	m.adoptedPID = 0
	return m.spawnLocked(ctx)
}

// spawnLocked execs the child per S7: `xray run -c <data>/rendered/live.json`,
// stdio inherited into the daemon's stdout, WaitDelay-safe exec path,
// readiness = the socks inbound accepting.
func (m *Manager) spawnLocked(ctx context.Context) error {
	if _, err := os.Stat(m.livePath); err != nil {
		return fmt.Errorf("core: live config %s missing — nothing to run "+
			"(render/bootstrap must write it first): %w", m.livePath, err)
	}
	//nolint:gosec // the binary comes from the owner's [core].xray_bin — the config file IS the trust root
	cmd := exec.CommandContext(ctx, m.bin, "run", "-c", m.livePath)
	// ADDENDUM §2 (windows): the child runs in its own process group so the
	// stop ladder can CTRL_BREAK it alone. No-op on unix (byte-identical).
	configureChildSpawn(cmd)
	cmd.Env = m.childEnv()
	cmd.WaitDelay = killWaitDelay
	cmd.Stdout = m.stderrTail
	cmd.Stderr = m.stderrTail
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("core: start %s run -c %s: %w", m.bin, m.livePath, err)
	}
	m.cmd = cmd
	m.done = nil
	m.waitErr = nil
	m.waitOnce = sync.Once{}
	m.generation++
	m.spawnedAt = time.Now()
	m.deliberateStop = false
	_ = m.waitDone() // start the reaper now; Stop and readiness share its signal
	// ADDENDUM §2 (windows): assign the child to the kill-on-close Job
	// Object — daemon death never orphans the child. A containment failure
	// fails the spawn loud (the child is killed; nothing runs uncontained).
	job, jerr := attachChildJob(cmd.Process)
	if jerr != nil {
		_ = m.cmd.Process.Kill()
		<-m.waitDone()
		m.cmd = nil
		return fmt.Errorf("core: attach the core child to the containment job object: %w "+
			"(a child outside the job could outlive the daemon — refusing to run it uncontained)", jerr)
	}
	m.job = job
	if err := m.writePIDFile(cmd.Process.Pid); err != nil {
		_ = m.cmd.Process.Kill()
		<-m.waitDone()
		m.releaseJobLocked()
		m.cmd = nil
		return fmt.Errorf("core: write pidfile after spawn: %w", err)
	}
	if err := m.awaitBoot(ctx); err != nil {
		_ = m.cmd.Process.Kill()
		<-m.waitDone()
		m.releaseJobLocked()
		m.cmd = nil
		m.clearPIDFile()
		return err
	}
	_, _ = fmt.Fprintf(m.log, "core: spawned pid %d (%s run -c %s)\n",
		cmd.Process.Pid, m.bin, m.livePath)
	return nil
}

// awaitBoot polls the socks inbound until it accepts (the child binds only
// after the config parses), failing fast when the child exits — bounded by
// bootBound, never a hang.
func (m *Manager) awaitBoot(ctx context.Context) error {
	deadline := time.After(bootBound)
	tick := time.NewTicker(bootPollEvery)
	defer tick.Stop()
	for {
		select {
		case <-m.waitDone(): // child died during boot; waitErr is set
			return fmt.Errorf("core: child exited during startup: %w\n%s", m.waitErr, m.stderrTail.String())
		case <-ctx.Done():
			return fmt.Errorf("core: spawn canceled: %w", ctx.Err())
		case <-deadline:
			return fmt.Errorf("core: socks inbound %s not ready within %s (child stdio tail):\n%s",
				m.socksAddr(), bootBound, m.stderrTail.String())
		case <-tick.C:
			if m.portServing() {
				return nil
			}
		}
	}
}

// releaseJobLocked drops the containment job handle (ADDENDUM §2: the
// kill-on-close limit makes this the final containment act on windows; a
// nil/no-op job on unix). Nil-safe.
func (m *Manager) releaseJobLocked() {
	if m.job != nil {
		m.job.release()
		m.job = nil
	}
}

// stopLocked stops whatever core this manager owns: the session child goes
// through the per-OS stop ladder (unix: the byte-identical kill+reap
// two-liner; windows: CTRL_BREAK → bounded wait → TerminateProcess,
// ADDENDUM §2); an adopted pid is SIGKILLed and liveness-polled (a
// non-child cannot be Waited — and was never in our job/process group).
// Idempotent. Every entry sets deliberateStop first — the crash supervisor
// reads a subsequent child exit as a deliberate stop, never as a crash.
func (m *Manager) stopLocked() error {
	m.deliberateStop = true
	switch {
	case m.cmd != nil:
		pid := m.cmd.Process.Pid
		if err := m.stopSessionChildLocked(); err != nil {
			return err
		}
		m.cmd = nil
		m.clearPIDFile()
		_, _ = fmt.Fprintf(m.log, "core: stopped pid %d\n", pid)
	case m.adoptedPID != 0:
		pid := m.adoptedPID
		// An adopted core that died between adoption and Stop is a benign
		// race: unix signals it as ESRCH, windows as platform.ErrProcessGone
		// (OpenProcess ERROR_INVALID_PARAMETER on a dead pid) — both ignored.
		if err := platform.KillProcessForce(pid); err != nil &&
			!errors.Is(err, syscall.ESRCH) && !errors.Is(err, platform.ErrProcessGone) {
			return fmt.Errorf("core: kill adopted pid %d: %w", pid, err)
		}
		deadline := time.Now().Add(adoptedStopPoll)
		for time.Now().Before(deadline) && PIDAlive(pid) {
			time.Sleep(bootPollEvery)
		}
		m.adoptedPID = 0
		m.clearPIDFile()
		// The POST-poll truth (T2 review M-2): a pid that survived the
		// SIGKILL poll (D-state/zombie class) is reported as such — never
		// as a clean stop.
		if PIDAlive(pid) {
			_, _ = fmt.Fprintf(m.log, "core: adopted pid %d still alive after the SIGKILL poll "+
				"(unreapable — likely D-state/zombie); it was NOT cleanly stopped\n", pid)
		} else {
			_, _ = fmt.Fprintf(m.log, "core: stopped adopted pid %d\n", pid)
		}
	default:
		// Nothing running — Stop is idempotent.
	}
	return nil
}

// childAliveLocked reports whether the manager currently owns a running
// core. The reaper's done-close signal is the truth source for the session
// child (a crash window between process death and Wait returning reads as
// alive for microseconds — the next call corrects it).
func (m *Manager) childAliveLocked() bool {
	if m.adoptedPID != 0 {
		return PIDAlive(m.adoptedPID)
	}
	if m.cmd == nil {
		return false
	}
	select {
	case <-m.waitDone():
		return false
	default:
		return true
	}
}

// waitDone reaps the child exactly once and closes done when Wait returns.
// The completion signal is a channel CLOSE, so it stays observable by every
// waiter forever (the C1 landmine: a drained one-shot value left Close
// blocked forever and leaked the child).
func (m *Manager) waitDone() <-chan struct{} {
	m.waitOnce.Do(func() {
		m.done = make(chan struct{})
		go func() {
			if m.cmd != nil {
				m.waitErr = m.cmd.Wait()
			}
			close(m.done)
		}()
	})
	return m.done
}

// socksAddr is the D2 binding constant joined with the socks port.
func (m *Manager) socksAddr() string {
	return net.JoinHostPort(config.CoreBindAddress, strconv.Itoa(m.socksPort))
}

// portServing reports whether something accepts on the socks inbound right
// now (readiness probe and adoption discriminator).
func (m *Manager) portServing() bool {
	conn, err := (&net.Dialer{Timeout: bootDialTimeout}).Dial("tcp", m.socksAddr())
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// childEnv strips ambient proxy variables (L5: nothing the core does may
// silently ride the live client) and wires the managed asset dir at spawn
// for the ASSAY-OWNED binaries only (S6 — user-local and the pending
// install target; their geoip/geosite assets live in <data>/share/xray).
// An override and a pre-existing system core resolve their own assets.
func (m *Manager) childEnv() []string {
	env := dropProxyEnv(os.Environ())
	if m.source == SourceUserLocal || m.source == "" {
		env = append(env, "XRAY_LOCATION_ASSET="+filepath.Join(m.dataDir, managedAssetDirRel))
	}
	return env
}

// dropProxyEnv strips the six canonical proxy variables from a child
// environment (the checker precedent, per-entry exact prefixes so ambient
// ZCODE_HTTP_PROXY-style harness variables survive).
func dropProxyEnv(env []string) []string {
	out := env[:0]
	for _, e := range env {
		upper := strings.ToUpper(e)
		if strings.HasPrefix(upper, "HTTP_PROXY=") || strings.HasPrefix(upper, "HTTPS_PROXY=") ||
			strings.HasPrefix(upper, "ALL_PROXY=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

// writePIDFile records the child's PID for Alive() and A2 adoption.
func (m *Manager) writePIDFile(pid int) error {
	return os.WriteFile(m.pidPath, []byte(strconv.Itoa(pid)+"\n"), 0o600)
}

// readPIDFile returns the pidfile's pid, 0 when absent or malformed (a
// malformed pidfile is not a supervision failure — it only disables
// adoption and status).
func (m *Manager) readPIDFile() int {
	raw, err := os.ReadFile(m.pidPath)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0
	}
	return pid
}

// clearPIDFile removes the pidfile; a missing file is the normal
// already-clean case, anything else is loud.
func (m *Manager) clearPIDFile() {
	if err := os.Remove(m.pidPath); err != nil && !os.IsNotExist(err) {
		_, _ = fmt.Fprintf(m.log, "core: pidfile remove failed: %v\n", err)
	}
}

// PIDAlive is the liveness probe for pidfile pids (signal 0 on unix via the
// platform seam): ESRCH = dead, EPERM = alive but not ours (counted alive —
// the status contract). Exported: the status core block (internal/cli)
// reuses the same pidfile-liveness contract instead of a second definition.
func PIDAlive(pid int) bool {
	return platform.ProcessAlive(pid)
}

// fetchThroughSocks performs health leg 2 on an already-dialed socks
// inbound: RFC 1928 no-auth handshake, CONNECT to the URL's host:port,
// then one plain HTTP GET (the health fetch is plain HTTP by contract —
// generate_204 needs no TLS; a status below 400 is healthy).
func fetchThroughSocks(ctx context.Context, conn net.Conn, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("core: health fetch URL %s: %w", rawURL, err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			return fmt.Errorf("core: health fetch URL %s: https targets are not "+
				"supported by the probe (plain HTTP contract)", rawURL)
		}
		port = "80"
	}
	if err := socksHandshake(conn); err != nil {
		return fmt.Errorf("core: health leg 2 — socks handshake: %w", err)
	}
	if err := socksConnect(conn, host, port); err != nil {
		return fmt.Errorf("core: health leg 2 — outbound connect to %s: %w",
			net.JoinHostPort(host, port), err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("core: health fetch request: %w", err)
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("core: health leg 2 — outbound fetch write: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("core: health leg 2 — outbound fetch: no HTTP response: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("core: health leg 2 — outbound fetch returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// socksHandshake is the RFC 1928 method negotiation (no auth).
func socksHandshake(conn net.Conn) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("unexpected greeting reply %#x/%#x", reply[0], reply[1])
	}
	return nil
}

// socksConnect issues the CONNECT request and validates the reply.
func socksConnect(conn net.Conn, host, port string) error {
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return fmt.Errorf("bad port %q", port)
	}
	var req []byte
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append([]byte{0x05, 0x01, 0x00, 0x01}, ip.To4()...)
	} else if ip != nil {
		req = append([]byte{0x05, 0x01, 0x00, 0x04}, ip.To16()...)
	} else {
		if len(host) > 255 {
			return errors.New("host too long for ATYP 3")
		}
		//nolint:gosec // G115: the length is guarded to ≤255 two lines above
		req = append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	}
	req = append(req, byte(p>>8), byte(p&0xff))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("refused (reply 0x%02x)", head[1])
	}
	return skipBoundAddr(conn, head[3])
}

// skipBoundAddr drains the reply's BND.ADDR/BND.PORT per its ATYP.
func skipBoundAddr(conn net.Conn, atyp byte) error {
	switch atyp {
	case 0x01:
		_, err := io.CopyN(io.Discard, conn, 4+2)
		return err
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		_, err := io.CopyN(io.Discard, conn, int64(l[0])+2)
		return err
	case 0x04:
		_, err := io.CopyN(io.Discard, conn, 16+2)
		return err
	default:
		return fmt.Errorf("bad reply atyp %#x", atyp)
	}
}

// tailWriter forwards every write into the daemon's log (S7: the child's
// stdio streams into the journal unbuffered) while keeping a bounded
// mutex-guarded tail for boot-death diagnostics. The forward is always the
// FULL write — the bound clips only the retained copy (the last max bytes),
// never the journal stream (review I-1). The mutex is load-bearing:
// os/exec streams stdio from its own goroutine while readiness and Stop
// snapshot the tail (the checker C2 data-race class).
type tailWriter struct {
	mu   sync.Mutex
	log  io.Writer
	tail []byte
	max  int
}

func newTailWriter(log io.Writer, limit int) *tailWriter {
	return &tailWriter{log: log, max: limit}
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.log.Write(p)
	// Retain at most the last max bytes for inspection; the forwarded
	// write above carried every byte of p regardless.
	w.tail = append(w.tail, p...)
	if over := len(w.tail) - w.max; over > 0 {
		w.tail = append(w.tail[:0], w.tail[over:]...)
	}
	return n, err
}

// String snapshots the bounded tail safely against the exec copy goroutine.
func (w *tailWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.tail)
}
