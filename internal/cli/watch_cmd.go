package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"assay/internal/config"
	"assay/internal/core"
	"assay/internal/plugins"
	"assay/internal/render"
	"assay/internal/sdnotify"
	"assay/internal/selfwatchdog"
	"assay/internal/store"
	"assay/internal/watchdog"

	"github.com/spf13/cobra"
)

// newWatchCommand is the W10 daemon entry: fsnotify watchdog on the plugins
// dir + the wave scheduler ([maintain].refresh_interval / speedtest_interval)
// reusing the exact maintainStages runners. SIGINT/SIGTERM finish the current
// stage, flush, and exit 0. The pre-pivot restart executor the activate
// stage used to carry (byte-pinned two-command allowlist in internal/restart)
// was REMOVED with the external mode (D3) — since the self-held-core pivot
// the daemon's core lifecycle is its own child process, not a systemctl
// call. Scheduling still lives here; this file itself carries no
// process-spawning surface of any kind.
func newWatchCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "watch",
		Short: "Daemon: hot-reload the plugin registry and run maintain waves on schedule",
		Long: `Long-running daemon (systemd unit: assay-watch.service, Restart=always):

  - fsnotify watchdog on [plugins].dir — add/modify of a .lua hot-swaps it
    into the registry (a broken file keeps the previous version active with
    a loud error), removal disables the source on the fly;
  - refresh wave every [maintain].refresh_interval (default 1h) and
    speedtest wave every [maintain].speedtest_interval (default 168h; a
    speedtest-due tick covers the refresh) — the same fetch→…→activate
    stages as ` + "`assay maintain`" + `, reusing the one wave
    implementation; "0s" disables the speedtest wave entirely (round-8:
    refresh waves stay probe-only — probe.speedtest defaults off);
  - the stats poll runs inside every wave (existing stage cadence);
  - broken-plugin waves continue with the healthy plugins (loud per-plugin
    errors); a single plugin run is additionally bounded by
    [plugins].run_timeout (a hanging plugin is abandoned loud, the wave
    proceeds);
  - configless boot (no -c, no home/cwd config) is supported: the daemon
    runs from the built-in defaults with the plugins dir under the XDG data
    dir (~/.local/share/assay/plugins); the render/activate stages fail
    loud at their boundary each wave (logged once per wave) while every
    other stage keeps working — the same wave-continues semantics as a
    broken plugin;
  - under the Type=notify unit the daemon sends READY=1 on start and pings
    WATCHDOG=1 every WatchdogSec/2 — a wedged daemon stops pinging and
    systemd kills + restarts it; without NOTIFY_SOCKET (no systemd) this is
    a no-op;
  - SIGINT/SIGTERM: finish the current stage, flush, exit 0. The activate
    stage is the one exception to "finish the STAGE": once replace begins,
    the replace→restart→health sequence runs to completion as one
    non-interruptible step (a checkpoint between replace and restart would
    orphan the live client — new config on disk, old config running, no
    restart issued). The unit's TimeoutStopSec=1800 gives systemd the
    matching patience for a mid-wave stop instead of SIGKILLing at 90s.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			return runWatch(cmd.OutOrStdout(), res.Config, defaultWatchDeps())
		},
	}
}

// waveRunner is one maintain wave: the daemon's seam over
// runMaintainGraceful with its own fetch-stage binding.
type waveRunner func(cfg *config.Config, opts maintainOptions, between func() bool) error

// watchDeps is the daemon's injection seam: tests replace the watchdog
// starter, the clock, the timer channel, and the signal source; production
// wires the real ones.
type watchDeps struct {
	startWatchdog func(dir string, log io.Writer) (*plugins.Registry, io.Closer, error)
	signals       <-chan os.Signal
	now           func() time.Time
	// after arms the scheduler wait and returns the timer channel plus a
	// stop func — the re-arm path must stop the superseded timer (audit
	// P3-10: a lingering time.After timer is GC-immune until it fires).
	after func(d time.Duration) (<-chan time.Time, func())
	// sdNotify runs the sd_notify(3) handshake: READY=1 plus the watchdog
	// pinger when NOTIFY_SOCKET/WATCHDOG_USEC are present (systemd
	// Type=notify + WatchdogSec), a logged no-op otherwise. Returns the stop
	// func (always non-nil). A hung daemon stops pinging → systemd kills and
	// restarts the unit — the honest backstop for hang classes the
	// per-plugin run timeout cannot see.
	sdNotify func(out io.Writer) (stop func())
	// selfWatch is the self-watchdog transport (ADDENDUM §1): darwin runs
	// the internal heartbeat supervisor (internal/selfwatchdog) — the daemon
	// beats at every coordination-loop progress point and, on a missed
	// threshold, the transport fires onMiss: the daemon's CLEAN self-exit
	// through the same graceful-stop seam SIGTERM uses, after which launchd
	// KeepAlive restarts the agent. Inactive on other GOOS (linux keeps the
	// sd_notify transport exclusively — byte-identical linux behavior) EXCEPT
	// the windows service context, which runs the same transport (clean
	// self-exit → SCM recovery actions restart; see newServiceWatchDeps).
	// Returns the beat feed, the stop func, and whether the transport is
	// active (active=true additionally gets the daemon to run an idle tick
	// into the scheduler loop so idle periods beat too).
	selfWatch func(out io.Writer, threshold time.Duration, onMiss func()) (beat func(), stop func(), active bool)
	// selfExit performs the transport's terminal step (production os.Exit;
	// tests record). Code 0 = clean exit.
	selfExit func(code int)
	// restartNote names the transport's restart mechanism in the miss log
	// line (the ADDENDUM §1 honesty contract): "" = the darwin default
	// (launchd KeepAlive); the windows service context names the SCM
	// recovery actions. Never printed on linux (the transport is inactive).
	restartNote string
	// serviceHooks is the windows service transport (§2.2.2/§2.2.3): Wired
	// closes when wiring completes (the svc handler reports Running right
	// after); StopRequest is the svc.Stop feed into the SAME graceful-stop
	// seam the signals use. Nil on every other path — nil keeps the select
	// case inert (linux behavior byte-identical).
	serviceHooks *serviceWiring
}

func defaultWatchDeps() watchDeps {
	return watchDeps{
		startWatchdog: func(dir string, log io.Writer) (*plugins.Registry, io.Closer, error) {
			reg, w, err := watchdog.Start(dir, log)
			if err != nil {
				return nil, nil, err
			}
			return reg, w, nil
		},
		signals: signalChannel(),
		now:     time.Now,
		after: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTimer(d)
			return t.C, func() { t.Stop() }
		},
		sdNotify: func(out io.Writer) func() {
			return sdnotify.Watch(context.Background(), out)
		},
		selfWatch: productionSelfWatch,
		selfExit:  os.Exit,
	}
}

// The self-watchdog transport pacing constants (code-owned, not knobs — the
// supervision-politeness ruling; the ADDENDUM §1 pacing loop analog of the
// unit's WatchdogSec/2 contract).
const (
	// selfWatchTickInterval is the idle tick the scheduler loop waits on
	// alongside the wave timers: every tick is a heartbeat (the loop reached
	// its select), so idle periods beat at 60s — far under threshold/2.
	selfWatchTickInterval = 60 * time.Second
	// selfExitGrace bounds the miss action's wait for the scheduler to
	// unwind through the graceful-stop seam before the clean exit fires
	// anyway (a WEDGED loop — the reason we are here — will not unwind).
	selfExitGrace = 30 * time.Second
)

// productionSelfWatch is the GOOS transport selector: darwin runs the
// internal heartbeat supervisor; every other GOOS keeps the sd_notify
// transport exclusively (the supervisor does not run on linux — the
// byte-identical-linux binding) and returns a safe no-op beat.
func productionSelfWatch(out io.Writer, threshold time.Duration, onMiss func()) (func(), func(), bool) {
	if runtime.GOOS != "darwin" {
		_ = out // no transport log on non-darwin — silence IS the off-state (sdnotify logs its own)
		return func() {}, func() {}, false
	}
	sup := selfwatchdog.Start(threshold, onMiss, time.Now, time.After)
	return sup.Beat, sup.Stop, true
}

// signalChannel is split out so the daemon never starts real signal
// delivery in tests.
var signalChannel = func() <-chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	return sigs
}

// waveScheduler owns the tick loop: the earliest of the two due instants
// arms the timer; a speedtest-due tick covers the refresh (the speedtest
// wave IS the full maintain wave with -S). Every wave re-arms from the
// moment it STARTED, so periods are exact regardless of wave duration
// (a wave that outlives its interval fires the next due wave immediately —
// catch-up, never drift). Waves never overlap: the loop is serial.
//
// speedtestInterval == 0 (round-8: [maintain].speedtest_interval = "0s")
// DISABLES the speedtest wave entirely: the loop schedules refresh waves
// only, forever — the owner's «выключи» made real at the schedule level.
type waveScheduler struct {
	cfg               *config.Config
	refreshInterval   time.Duration
	speedtestInterval time.Duration
	runWave           waveRunner
	deps              watchDeps
	out               io.Writer

	// Self-watchdog feeds (ADDENDUM §1): beat records one coordination-loop
	// heartbeat (nil-safe — no transport on linux); heartbeatTick is the
	// idle tick the run loop selects on (nil = never fires — no transport).
	beat          func()
	heartbeatTick <-chan time.Time

	// Self-update state (shared with the binary watcher when present).
	restartPending   atomic.Bool
	restartArmed     atomic.Bool
	restartWaves     int
	restartRequested atomic.Bool

	exePath           string
	selfWatcher       *binarySelfWatcher
	selfUpdateEnabled bool

	lastWaveCompletedAt time.Time
	onRestart           func(string)
}

type waveKind int

const (
	waveRefresh waveKind = iota
	waveSpeedtest
)

// run drives the schedule until stop closes. The FIRST refresh wave runs
// immediately at startup (daemon start = fresh data now; systemd's old
// OnBootSec role). Wave failures are loud but never kill the daemon — the
// schedule re-arms and the next wave retries.
//
//nolint:gocognit,cyclop // serial scheduler loop; complexity inherent
func (s *waveScheduler) run(stop <-chan struct{}, between func() bool) []waveKind {
	speedtestEnabled := s.speedtestInterval > 0
	if speedtestEnabled {
		outf(s.out, "watch: scheduler armed — refresh every %s, speedtest every %s\n",
			s.refreshInterval, s.speedtestInterval)
	} else {
		outf(s.out, "watch: scheduler armed — refresh every %s, speedtest disabled "+
			"([maintain].speedtest_interval = 0s — no speedtest waves)\n", s.refreshInterval)
	}
	var ran []waveKind
	// Re-arm anchor: the wave's START instant. Anchoring at completion let
	// every wave's duration shift the whole schedule later (drift); from
	// the start, the period between wave STARTS is exactly the interval.
	start := s.deps.now()
	combinedBetween := func() bool {
		if s.beat != nil {
			s.beat() // a stage boundary ran — coordination-loop progress
		}
		if between != nil && between() {
			return true
		}
		if s.restartPending.Load() && s.restartWaves > 3 {
			return true
		}
		return false
	}
	if err := s.runWave(s.cfg, maintainOptions{}, combinedBetween); err != nil {
		outf(s.out, "WARNING: initial wave failed: %v (the schedule re-arms — continuing)\n", err)
	}
	ran = append(ran, waveRefresh)
	s.lastWaveCompletedAt = s.deps.now()
	if s.beat != nil {
		s.beat() // the initial wave completed
	}
	if s.checkSelfUpdate() {
		return ran
	}
	nextRefresh := start.Add(s.refreshInterval)
	nextSpeedtest := start.Add(s.speedtestInterval)
	if !speedtestEnabled {
		// Zero the anchor: the due computation below treats it as absent —
		// no speedtest wave is ever scheduled.
		nextSpeedtest = time.Time{}
	}
	for {
		due := nextRefresh
		if !nextSpeedtest.IsZero() && nextSpeedtest.Before(due) {
			due = nextSpeedtest
		}
		wait := max(due.Sub(s.deps.now()), 0)
		timerC, stopTimer := s.deps.after(wait)
		select {
		case <-stop:
			stopTimer()
			return ran
		case <-timerC:
			if s.beat != nil {
				s.beat() // the loop woke for a due wave
			}
		case <-s.heartbeatTick:
			// Idle tick: the loop reached its select — the strongest idle
			// heartbeat there is. Stop the superseded timer and re-arm
			// (P3-10: the old timer must not linger armed until it fires).
			stopTimer()
			if s.beat != nil {
				s.beat()
			}
			continue
		}
		now := s.deps.now()
		refreshDue := !now.Before(nextRefresh)
		speedtestDue := !nextSpeedtest.IsZero() && !now.Before(nextSpeedtest)
		switch {
		case speedtestDue:
			start := s.deps.now()
			if err := s.runWave(s.cfg, maintainOptions{speedtest: true}, combinedBetween); err != nil {
				outf(s.out, "WARNING: speedtest wave failed: %v (the schedule re-arms — continuing)\n", err)
			}
			ran = append(ran, waveSpeedtest)
			nextSpeedtest = start.Add(s.speedtestInterval)
			nextRefresh = start.Add(s.refreshInterval)
			s.lastWaveCompletedAt = s.deps.now()
			if s.beat != nil {
				s.beat() // the speedtest wave completed
			}
			if s.checkSelfUpdate() {
				return ran
			}
		case refreshDue:
			start := s.deps.now()
			if err := s.runWave(s.cfg, maintainOptions{}, combinedBetween); err != nil {
				outf(s.out, "WARNING: refresh wave failed: %v (the schedule re-arms — continuing)\n", err)
			}
			ran = append(ran, waveRefresh)
			nextRefresh = start.Add(s.refreshInterval)
			s.lastWaveCompletedAt = s.deps.now()
			if s.beat != nil {
				s.beat() // the refresh wave completed
			}
			if s.checkSelfUpdate() {
				return ran
			}
		}
	}
}

// ensureBootstrapLiveConfig writes the D7 bootstrap live config when the
// core's live artifact does not exist yet (S2: the daemon spawns a bootstrap
// core at start, and the spawn needs the artifact). An existing live.json is
// last-good (or a prior bootstrap) and is kept — A4/D7: never regress a
// configured core to the fail-closed posture by overwriting it.
func ensureBootstrapLiveConfig(out io.Writer, cfg *config.Config, p paths) error {
	if _, err := os.Stat(ownLivePath(p)); err == nil {
		return nil
	}
	own, warnings, err := render.RenderOwnConfig(nil, cfg.Core, toRenderRoutes(cfg.Render.PoolRoutes),
		nil, nil, ownRenderKnobs(cfg))
	if err != nil {
		return fmt.Errorf("render bootstrap core config: %w", err)
	}
	for _, b := range warnings {
		outf(out, "WARNING: %s\n", b)
	}
	if err := os.MkdirAll(filepath.Join(p.dataDir, "rendered"), 0o750); err != nil {
		return err
	}
	if err := store.WriteFileAtomic(ownLivePath(p), func(f *os.File) error {
		_, err := f.Write(own)
		return err
	}); err != nil {
		return err
	}
	outf(out, "watch: bootstrap core config written (empty pool fail-closed — catch-all → block) → %s\n",
		ownLivePath(p))
	return nil
}

// wireDaemonCore builds the daemon's manager, ensures the bootstrap live
// config, and spawns/adopts the core (the S2 ordering: manager → bootstrap
// config → EnsureRunning). The bootstrap legs degrade loud-NONFATAL per the
// bootstrap-degradation closure: a transient boot race heals; a persistent
// failure (e.g. the managed binary is absent) exhausts the retry budget and
// lands on the loud non-fatal WARNING — the crash supervisor keeps retrying
// on its own bounded ladder, and the waves retry through auto-update. The
// spawn ctx is deliberately NON-canceling (C4): only the explicit Stop on
// the shutdown path may kill this child. A MANAGER failure stays fatal
// (nothing works without the data dir + the singleton lock, T4 review M-4).
func wireDaemonCore(out io.Writer, cfg *config.Config, p paths) (*core.Manager, error) {
	mgr, err := core.NewManager(cfg.Core, p.dataDir, out)
	if err != nil {
		return nil, fmt.Errorf("watch: core manager: %w", err)
	}
	if err := ensureBootstrapLiveConfig(out, cfg, p); err != nil {
		outf(out, "WARNING: watch: bootstrap core config: %v (daemon stays up; the waves retry)\n", err)
	}
	if berr := bootstrapCoreWithRetries(out, mgr.EnsureRunning, bootstrapAttempts,
		func(d time.Duration) { time.Sleep(d) }); berr != nil {
		outf(out, "WARNING: watch: bootstrap core: %v (daemon stays up; the waves retry "+
			"and the crash supervisor revives)\n", berr)
	}
	return mgr, nil
}

// startSelfUpdateWatcher arms the binary-change watcher on the scheduler
// (the self-update restart path) and returns its closer for the caller to
// defer for the daemon's lifetime. A start failure is loud but non-fatal —
// the daemon keeps running without self-update (the honest degraded state),
// reported with a nil closer.
func startSelfUpdateWatcher(
	out io.Writer, cfg *config.Config, sched *waveScheduler, exeDir, exeBase, exe string,
) func() {
	bw, werr := startBinarySelfWatcherWith(
		exeDir, exeBase,
		&sched.restartPending, &sched.restartArmed,
		out, cfg.SelfUpdate.CheckInterval.Duration, exe,
	)
	if werr != nil {
		outf(out, "WARNING: self-update watcher failed to start: %v\n", werr)
		return nil
	}
	sched.selfWatcher = bw
	return bw.close
}

// closeServiceWired fires the §2.2.2 wired handshake: the svc handler
// reports Running the moment this closes. Nil-safe — the unix deps carry
// no service hooks and this is a no-op (byte-identical behavior).
func closeServiceWired(deps watchDeps) {
	if hooks := deps.serviceHooks; hooks != nil && hooks.Wired != nil {
		close(hooks.Wired)
	}
}

// runWatch wires the daemon: watchdog → shared registry → core manager
// (bootstrap spawn per S2) → scheduler with a between-stage shutdown
// checkpoint → signal-driven graceful stop (exit 0).
//
// S2 ordering: the core manager takes the singleton flock, the bootstrap
// live config is ensured, and EnsureRunning has spawned/adopted the core
// BEFORE the sd_notify handshake — READY=1 fires only once the bootstrap
// core is reachable. The child runs under a NON-canceling ctx (C4: the exec
// path kills the child on ctx cancellation) and is stopped explicitly on
// the SIGTERM shutdown (A2: a daemon restart never leaves the core dead —
// the pidfile lets the next daemon adopt it).
func runWatch(out io.Writer, cfg *config.Config, deps watchDeps) error {
	// The daemon's lifetime channel: the crash supervisor and the scheduler
	// both watch it; SIGTERM closes it after the current stage finishes.
	stop := make(chan struct{})
	dir := config.ExpandHome(cfg.Plugins.Dir)
	reg, closer, err := deps.startWatchdog(dir, out)
	if err != nil {
		return fmt.Errorf("watch: start watchdog on %s: %w", dir, err)
	}
	defer func() { _ = closer.Close() }()

	// The core manager: the daemon owns the singleton flock for its whole
	// lifetime (S3) — a second daemon fails loud here and the unit restarts.
	// The BOOTSTRAP, by contrast, degrades loud-but-nonfatal (the same
	// wave-continues contract as the configless stages): a missing managed
	// binary logs its WARNING and the daemon stays up (an unwritable data
	// dir is NOT that case — it fails NewManager HARD right above, since
	// nothing works without the data dir; T4 review M-4). The waves retry
	// the core through every wave's activate stage: revive on a last-good
	// live config, Restart on a candidate (T4-I-1) — and the crash
	// supervisor revives independently of the waves (G1).
	p := newPaths(cfg)
	mgr, err := wireDaemonCore(out, cfg, p)
	if err != nil {
		return err
	}

	// G1: the between-waves crash supervision. The loop dies with the
	// daemon's stop channel; the child itself is stopped only by the
	// explicit Stop on the shutdown path below.
	mgr.Supervise(stop)

	stopSdNotify := deps.sdNotify(out)
	defer stopSdNotify()

	// Resolve the running binary path once (fail loud if it cannot be
	// determined — no guessing).
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("watch: resolve executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("watch: eval symlinks for executable: %w", err)
	}
	exeDir := filepath.Dir(exe)
	exeBase := filepath.Base(exe)

	// The waves share the watchdog-maintained registry: the fetch stage
	// snapshots it once at wave start, so a mid-wave hot-reload never
	// disturbs the running wave (the registry's snapshot contract). The
	// fetch runner is swapped through the W4 stages seam — no duplicated
	// pipeline logic; every other stage is the exact production runner.
	// The enrichment seam gets the SAME registry (F1): the MinLivePercent
	// breaker lands on the long-lived watchdog registry and actually
	// disables plugins across waves. The activate stage gets the daemon's
	// manager (T4): the D8 strike counter accumulates across waves, and the
	// one-shot flock refusal can never fire against the daemon's own lock.
	//
	// The wave runners receive the self-watchdog beat through the closure
	// variables the transport wiring fills in below (ADDENDUM §1) — closures
	// capture by reference, so the runners pick the transport up once it is
	// wired.
	beat := func() {}
	runWave := func(cfg *config.Config, opts maintainOptions, between func() bool) error {
		// The daemon's ONE manager flows into every core-touching stage via
		// defaultMaintainStages (fix I-1): the D8 strike counter accumulates
		// across waves and the S5 inert INFO stays one-time.
		stages := defaultMaintainStages(opts, mgr)
		stages.fetch = func(c *cobra.Command, cc *config.Config) error {
			_, err := runFetchWith(c, cc, reg, beat)
			return err
		}
		stages.pluginStatsEnrich = func(c *cobra.Command, cc *config.Config) error {
			return runPluginStatsEnrichment(c, cc, reg)
		}
		// The probe stage carries the same beat feed (per batch / per
		// single-node job) — the probe stage is the longest legitimate
		// in-wave beat gap.
		stages.probe = func(c *cobra.Command, cc *config.Config) error {
			return runProbe(c, cc, 0, opts.speedtest, beat)
		}
		return runMaintainGraceful(out, cfg, opts, stages, between)
	}

	var shutdown atomic.Bool
	// The graceful-stop seam, exactly-once: SIGTERM and the self-watchdog
	// miss BOTH land here (a double close of stop would panic), and the core
	// stop is equally once-only — both paths may race to it.
	requestStop := sync.OnceFunc(func() {
		shutdown.Store(true)
		close(stop)
	})
	stopCore := sync.OnceFunc(func() {
		// C4/A2: the core is stopped EXPLICITLY on the daemon shutdown (the
		// child never dies via ctx cancellation). A stop failure is loud but
		// must not mask the clean shutdown — the pidfile and the flock die
		// with the process either way.
		if serr := mgr.Stop(); serr != nil {
			outf(out, "watch: core stop failed: %v\n", serr)
		}
		// Release the singleton lock handle too: production freed it via
		// process exit; an embedded run (tests) lives on, and windows cannot
		// remove an open file — the leaked core.lock failed TempDir cleanup
		// (run 43330792666). Lock-only: the child was already stopped above.
		mgr.Release()
	})
	between := shutdown.Load
	sched := &waveScheduler{
		cfg:             cfg,
		refreshInterval: cfg.Maintain.RefreshInterval.Duration,
		// Round-8 tri-state: nil/0 → the speedtest wave is disabled entirely.
		speedtestInterval: cfg.Maintain.SpeedtestWavePeriod(),
		runWave:           runWave,
		deps:              deps,
		out:               out,
		exePath:           exe,
		selfUpdateEnabled: cfg.SelfUpdate.Enabled,
	}
	// Self-update watcher (binary change detection) — started alongside the
	// plugin watchdog when enabled (loud non-fatal on failure); the closer
	// rides runWatch's lifetime.
	if cfg.SelfUpdate.Enabled {
		if closeWatcher := startSelfUpdateWatcher(out, cfg, sched, exeDir, exeBase, exe); closeWatcher != nil {
			defer closeWatcher()
		}
	}

	sched.onRestart = func(reason string) {
		outf(out, "watch: %s — graceful self-restart\n", reason)
	}
	schedDone := make(chan struct{})

	// The self-watchdog transport (ADDENDUM §1): on darwin the supervisor
	// paces at threshold/2; a missed threshold fires the miss action — the
	// SAME graceful-stop seam SIGTERM uses (requestStop), a best-effort core
	// stop (a wedged loop never BLOCKS the exit on the child stop — the
	// child is stopped best-effort and answered by pidfile adoption (A2) on
	// unix / Job Object containment on windows), a bounded wait for the
	// unwind, and a CLEAN exit 0 that launchd KeepAlive answers with a
	// restart. The mechanism is named loudly — status output states it the
	// same way.
	// The transport wiring happens HERE (after sched exists) — the wave
	// runners capture the beat variable by reference and pick the transport
	// up. The idle tick lives inside the scheduler (the helper sets
	// sched.heartbeatTick); its channel has exactly one receiver.
	transportBeat, _, stopTransport := startSelfWatchTransport(
		deps, out, sched, schedDone, requestStop, stopCore)
	defer stopTransport()
	beat = transportBeat
	// The wired handshake (§2.2.2): the service context reports Running to
	// the SCM right AFTER the wiring — before the scheduler goroutine (and
	// its immediate first wave) starts, never gated on it. Nil on unix.
	closeServiceWired(deps)
	// PANIC POLICY (audit P3-9): a panic in this goroutine crashes the whole
	// process loudly — Go semantics — and every deployment transport answers a
	// crash with a restart (systemd Restart=always / launchd KeepAlive / the
	// SCM recovery actions) BY DESIGN. No recover here: a recover could mask a
	// corrupted-state crash-loop the supervisor surfaces honestly.
	go func() {
		_ = sched.run(stop, between)
		close(schedDone)
	}()

	outf(out, "watch: plugin watchdog live on %s (%d plugins loaded)\n", dir, reg.Len())
	if cfg.SelfUpdate.Enabled {
		outf(out, "watch: self-update enabled — watching %s\n", exe)
	}
	// The service stop transport (§2.2.3): the windows svc handler feeds
	// svc.Stop|svc.Shutdown through it — the SAME graceful-stop seam the
	// signals use below. A nil channel in a select case is never ready, so
	// the unix path is byte-identical with the pre-service behavior.
	var svcStop <-chan struct{}
	if deps.serviceHooks != nil {
		svcStop = deps.serviceHooks.StopRequest
	}
	// finishGraceful is the shared shutdown sequence (§2.2.3 — ONE seam,
	// three feeds land here with the same unwinding): reason line →
	// requestStop → armed second-signal force exit (P3-11) → scheduler
	// unwind → explicit core stop → clean shutdown.
	finishGraceful := func(reason string) error {
		outln(out, reason)
		requestStop()
		releaseForceExit := armSecondSignalForceExit(out, deps.signals, deps.selfExit)
		defer releaseForceExit()
		<-schedDone
		stopCore()
		outln(out, "watch: clean shutdown")
		return nil
	}
	select {
	case <-schedDone:
		if sched.restartRequested.Load() {
			_ = sdnotify.Stopping()
			return nil
		}
		return nil
	case <-svcStop:
		return finishGraceful("watch: windows service stop — finishing the current stage, then exiting")
	case sig := <-deps.signals:
		return finishGraceful(fmt.Sprintf("watch: %v — finishing the current stage, then exiting", sig))
	}
}

// armSecondSignalForceExit arms the second-signal force exit (audit P3-11)
// for the duration of a graceful stop: during finishGraceful's wait for
// the unwind — hours on a legitimately finishing mid-stage stop — a second
// SIGTERM/SIGINT previously buffered unread (signalChannel cap 1) and a
// supervisor-less `assay watch` was interruptible only by SIGKILL. From
// the moment this arms, the next signal (including one already buffered
// during the stage) forces the exit loud. Safe mid-stage by the A2
// contract: adoption + last-good semantics recover on the next start. The
// exit goes through the deps.selfExit seam — the production os.Exit rides
// it, and tests record instead of exiting. release() disarms without
// forcing (the normal unwind completed): the disarm is a full handshake —
// release closes force AND waits for the watcher to leave the select, so
// once release returns a released watcher can never act on a late signal
// (a bare close(force) leaves the goroutine parked with both select cases
// ready, and Go resolves a multi-ready select randomly — the watcher could
// still force an exit after the normal unwind completed).
func armSecondSignalForceExit(out io.Writer, signals <-chan os.Signal, selfExit func(int)) func() {
	force := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-force:
		case sig := <-signals:
			outf(out, "watch: %v — forcing exit (a graceful stop is already in flight; "+
				"adoption (A2) / last-good semantics recover on the next start)\n", sig)
			selfExit(1)
		}
	}()
	return func() {
		close(force)
		<-done
	}
}

// startSelfWatchTransport wires the self-watchdog transport (ADDENDUM §1):
// it starts the transport with the code-owned threshold and the miss action,
// and — when the transport is active — fills the scheduler's beat feed and
// creates the idle tick the run loop selects on. Returns the beat, the tick
// channel (nil = no transport), and the transport's stop func (always
// non-nil; the caller defers it).
func startSelfWatchTransport(
	deps watchDeps, out io.Writer, sched *waveScheduler, schedDone <-chan struct{},
	requestStop, stopCore func(),
) (func(), <-chan time.Time, func()) {
	if deps.selfWatch == nil {
		return func() {}, nil, func() {}
	}
	// The restart mechanism line (ADDENDUM §1 honesty contract): the darwin
	// default when unset, the SCM recovery actions in the service context.
	note := deps.restartNote
	if note == "" {
		note = "launchd KeepAlive restarts the agent; mechanism: self-watchdog → KeepAlive restart"
	}
	miss := selfWatchMiss(out, schedDone, requestStop, stopCore, deps.selfExit, note)
	transportBeat, stopTransport, active := deps.selfWatch(out, selfwatchdog.Threshold, miss)
	stop := func() { stopTransport() }
	if !active {
		return func() {}, nil, stop
	}
	// The ticker's channel is consumed by EXACTLY one receiver — the
	// scheduler run loop's select case — so every idle tick beats.
	ticker := time.NewTicker(selfWatchTickInterval)
	stop = func() {
		ticker.Stop()
		stopTransport()
	}
	sched.beat = transportBeat
	sched.heartbeatTick = ticker.C
	return transportBeat, ticker.C, stop
}

// selfWatchMiss builds the miss action of the self-watchdog transport
// (ADDENDUM §1): the SAME graceful-stop seam SIGTERM uses (requestStop), a
// best-effort core stop (a wedged loop never BLOCKS the exit on the child
// stop — the child is stopped best-effort and answered by pidfile adoption
// (A2) on unix / Job Object containment on windows; audit P3-7: the child
// CAN briefly outlive the daemon — that is the design, the old wording
// promised too much), a bounded wait for the unwind, and a CLEAN exit 0
// that the platform's supervisor answers with a restart (launchd KeepAlive
// / the Windows SCM recovery actions — restartNote names the mechanism
// loudly).
func selfWatchMiss(
	out io.Writer, schedDone <-chan struct{}, requestStop, stopCore func(), selfExit func(int), restartNote string,
) func() {
	return func() {
		outf(out, "watch: self-watchdog: no daemon progress for %s — clean self-exit "+
			"(%s)\n", selfwatchdog.Threshold, restartNote)
		requestStop()
		// Best-effort child stop — never block the exit on a wedged unwind.
		// PANIC POLICY (audit P3-9): a panic in this goroutine crashes the whole
		// process loudly — Go semantics — and every deployment transport answers a
		// crash with a restart (systemd Restart=always / launchd KeepAlive / the
		// SCM recovery actions) BY DESIGN. No recover here: a recover could mask a
		// corrupted-state crash-loop the supervisor surfaces honestly.
		go stopCore()
		select {
		case <-schedDone:
		case <-time.After(selfExitGrace):
			// The loop is wedged (the reason this transport exists) —
			// the grace expires and the clean exit fires anyway.
		}
		outln(out, "watch: clean self-exit (code 0)")
		selfExit(0)
	}
}

// bootstrapAttempts is the daemon's bootstrap retry budget (the
// bootstrap-degradation closure): a failing bootstrap EnsureRunning retries
// with a doubling backoff before degrading to the loud non-fatal state.
// Code-owned, not a knob (supervision politeness is not operator-facing
// configuration — the owner's standing ruling).
const bootstrapAttempts = 3

// bootstrapCoreWithRetries is the daemon's bootstrap step: it calls ensure
// up to N times with a doubling backoff (1s, 2s, … — transient boot races
// heal; a persistent failure exhausts the budget fast), every failed
// attempt is loud, and the LAST error surfaces to the caller (which prints
// the non-fatal WARNING). The retry outcome is loud either way.
func bootstrapCoreWithRetries(
	out io.Writer, ensure func(context.Context) error, attempts int, wait func(time.Duration),
) error {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		err := ensure(context.Background())
		if err == nil {
			return nil
		}
		lastErr = err
		outf(out, "watch: bootstrap attempt %d/%d failed: %v\n", attempt, attempts, err)
		if attempt < attempts {
			wait(time.Duration(attempt) * time.Second)
		}
	}
	return fmt.Errorf("bootstrap failed after %d attempts: %w", attempts, lastErr)
}

// checkSelfUpdate is called at every wave boundary. It promotes a pending
// binary change to an armed restart (after verification) and, once armed or
// escalated past 3 waves, triggers a graceful self-restart. Returns true when
// a restart was triggered (caller should stop the loop).
func (s *waveScheduler) checkSelfUpdate() bool {
	if !s.restartPending.Load() {
		s.restartWaves = 0
		return false
	}
	s.restartWaves++
	// Verify (stat-stability + per-OS exec magic) once.
	if !s.restartArmed.Load() && s.exePath != "" {
		if ok, reason := verifyBinary(s.exePath); ok {
			s.restartArmed.Store(true)
		} else if reason != "" {
			outf(s.out, "self-update: binary not yet armed (%s) — waiting\n", reason)
		}
	}
	armed := s.restartArmed.Load()
	escalated := s.restartWaves > 3
	if !armed && !escalated {
		outf(s.out, "self-update: restart pending (wave %d/3) — waiting for verification/escalation\n", s.restartWaves)
		return false
	}
	if escalated && !armed {
		outf(s.out, "self-update: escalation — pending for %d waves, forcing restart\n", s.restartWaves)
	}
	outf(s.out, "binary updated on disk, restarting\n")
	s.restartRequested.Store(true)
	if s.onRestart != nil {
		s.onRestart("binary updated on disk")
	}
	return true
}
