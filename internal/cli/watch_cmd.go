package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/plugins"
	"public_vpn/internal/sdnotify"
	"public_vpn/internal/watchdog"

	"github.com/spf13/cobra"
)

// newWatchCommand is the W10 daemon entry: fsnotify watchdog on the plugins
// dir + the wave scheduler ([maintain].refresh_interval / speedtest_interval)
// reusing the exact maintainStages runners. SIGINT/SIGTERM finish the current
// stage, flush, and exit 0. Since W13 the daemon's systemd surface is
// exactly the restart executor the activate stage carries (byte-pinned
// two-command allowlist in internal/restart) — scheduling still lives here;
// this file itself carries no process-spawning surface of any kind.
func newWatchCommand(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "watch",
		Short: "Daemon: hot-reload the plugin registry and run maintain waves on schedule",
		Long: `Long-running daemon (systemd unit: publicvpn-watch.service, Restart=always):

  - fsnotify watchdog on [plugins].dir — add/modify of a .lua hot-swaps it
    into the registry (a broken file keeps the previous version active with
    a loud error), removal disables the source on the fly;
  - refresh wave every [maintain].refresh_interval (default 1h) and
    speedtest wave every [maintain].speedtest_interval — the same
    fetch→…→activate stages as ` + "`publicvpn maintain`" + `, reusing the
    one wave implementation; a speedtest-due tick covers the refresh;
  - the stats poll runs inside every wave (existing stage cadence);
  - broken-plugin waves continue with the healthy plugins (loud per-plugin
    errors); a single plugin run is additionally bounded by
    [plugins].run_timeout (a hanging plugin is abandoned loud, the wave
    proceeds);
  - configless boot (no -c, no home/cwd config) is supported: the daemon
    runs from the built-in defaults with the plugins dir under the XDG data
    dir (~/.local/share/publicvpn/plugins); the render/activate stages fail
    loud at their boundary each wave (logged once per wave) while every
    other stage keeps working — the same wave-continues semantics as a
    broken plugin;
  - under the Type=notify unit the daemon sends READY=1 on start and pings
    WATCHDOG=1 every WatchdogSec/2 — a wedged daemon stops pinging and
    systemd kills + restarts it; without NOTIFY_SOCKET (no systemd) this is
    a no-op;
  - SIGINT/SIGTERM: finish the current stage, flush, exit 0.`,
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
	after         func(time.Duration) <-chan time.Time
	// sdNotify runs the sd_notify(3) handshake: READY=1 plus the watchdog
	// pinger when NOTIFY_SOCKET/WATCHDOG_USEC are present (systemd
	// Type=notify + WatchdogSec), a logged no-op otherwise. Returns the stop
	// func (always non-nil). A hung daemon stops pinging → systemd kills and
	// restarts the unit — the honest backstop for hang classes the
	// per-plugin run timeout cannot see.
	sdNotify func(out io.Writer) (stop func())
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
		after:   time.After,
		sdNotify: func(out io.Writer) func() {
			return sdnotify.Watch(context.Background(), out)
		},
	}
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
type waveScheduler struct {
	cfg               *config.Config
	refreshInterval   time.Duration
	speedtestInterval time.Duration
	runWave           waveRunner
	deps              watchDeps
	out               io.Writer
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
func (s *waveScheduler) run(stop <-chan struct{}, between func() bool) []waveKind {
	outf(s.out, "watch: scheduler armed — refresh every %s, speedtest every %s\n",
		s.refreshInterval, s.speedtestInterval)
	var ran []waveKind
	// Re-arm anchor: the wave's START instant. Anchoring at completion let
	// every wave's duration shift the whole schedule later (drift); from
	// the start, the period between wave STARTS is exactly the interval.
	start := s.deps.now()
	if err := s.runWave(s.cfg, maintainOptions{}, between); err != nil {
		outf(s.out, "WARNING: initial wave failed: %v (the schedule re-arms — continuing)\n", err)
	}
	ran = append(ran, waveRefresh)
	nextRefresh := start.Add(s.refreshInterval)
	nextSpeedtest := start.Add(s.speedtestInterval)
	for {
		due := nextRefresh
		if nextSpeedtest.Before(due) {
			due = nextSpeedtest
		}
		wait := max(due.Sub(s.deps.now()), 0)
		timer := s.deps.after(wait)
		select {
		case <-stop:
			return ran
		case <-timer:
		}
		now := s.deps.now()
		refreshDue := !now.Before(nextRefresh)
		speedtestDue := !now.Before(nextSpeedtest)
		switch {
		case speedtestDue:
			start := s.deps.now()
			if err := s.runWave(s.cfg, maintainOptions{speedtest: true}, between); err != nil {
				outf(s.out, "WARNING: speedtest wave failed: %v (the schedule re-arms — continuing)\n", err)
			}
			ran = append(ran, waveSpeedtest)
			nextSpeedtest = start.Add(s.speedtestInterval)
			nextRefresh = start.Add(s.refreshInterval)
		case refreshDue:
			start := s.deps.now()
			if err := s.runWave(s.cfg, maintainOptions{}, between); err != nil {
				outf(s.out, "WARNING: refresh wave failed: %v (the schedule re-arms — continuing)\n", err)
			}
			ran = append(ran, waveRefresh)
			nextRefresh = start.Add(s.refreshInterval)
		}
	}
}

// runWatch wires the daemon: watchdog → shared registry → scheduler with a
// between-stage shutdown checkpoint → signal-driven graceful stop (exit 0).
// The sd_notify handshake (READY=1 + WatchdogSec pings) starts before the
// first wave: under the Type=notify unit systemd holds the start until
// READY=1, and the pinger must be live from the very beginning.
func runWatch(out io.Writer, cfg *config.Config, deps watchDeps) error {
	dir := config.ExpandHome(cfg.Plugins.Dir)
	reg, closer, err := deps.startWatchdog(dir, out)
	if err != nil {
		return fmt.Errorf("watch: start watchdog on %s: %w", dir, err)
	}
	defer func() { _ = closer.Close() }()

	stopSdNotify := deps.sdNotify(out)
	defer stopSdNotify()

	// The waves share the watchdog-maintained registry: the fetch stage
	// snapshots it once at wave start, so a mid-wave hot-reload never
	// disturbs the running wave (the registry's snapshot contract). The
	// fetch runner is swapped through the W4 stages seam — no duplicated
	// pipeline logic; every other stage is the exact production runner.
	runWave := func(cfg *config.Config, opts maintainOptions, between func() bool) error {
		stages := defaultMaintainStages(opts)
		stages.fetch = func(c *cobra.Command, cc *config.Config) error {
			return runFetchWith(c, cc, reg)
		}
		return runMaintainGraceful(out, cfg, opts, stages, between)
	}

	var shutdown atomic.Bool
	between := shutdown.Load
	stop := make(chan struct{})
	sched := &waveScheduler{
		cfg:               cfg,
		refreshInterval:   cfg.Maintain.RefreshInterval.Duration,
		speedtestInterval: cfg.Maintain.SpeedtestInterval.Duration,
		runWave:           runWave,
		deps:              deps,
		out:               out,
	}
	schedDone := make(chan struct{})
	go func() {
		_ = sched.run(stop, between)
		close(schedDone)
	}()

	outf(out, "watch: plugin watchdog live on %s (%d plugins loaded)\n", dir, reg.Len())
	select {
	case <-schedDone:
		return nil
	case sig := <-deps.signals:
		outf(out, "watch: %v — finishing the current stage, then exiting\n", sig)
		shutdown.Store(true)
		close(stop)
		<-schedDone
		outln(out, "watch: clean shutdown")
		return nil
	}
}
