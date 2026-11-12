// The windows service context's daemon seam (plan §2.2.2/§2.2.3/§2.2.5/
// §2.2.6 + ADDENDUM §1). Everything here is GOOS-neutral: the real svc/mgr
// wiring lives in cmd/assay (//go:build windows) and the file log sink in
// internal/platform, but the transport semantics — the ONE graceful-stop
// seam with a second feed, the wired handshake, the self-watchdog transport
// with the SCM recovery note, and the fail-closed SYSTEM-profile refusal —
// are pinned by the locally-runnable suite in this package.

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"assay/internal/config"
	"assay/internal/install"
	"assay/internal/platform"
	"assay/internal/selfwatchdog"
)

// serviceWiring is the windows service transport into runWatch (§2.2.2):
// Wired is closed the moment the daemon finished wiring — the svc handler
// reports Running right after it (never after the first wave);
// StopRequest is the svc.Stop|svc.Shutdown feed into the SAME graceful-stop
// seam the unix SIGTERM/SIGINT signals consume (§2.2.3 — one mechanism, two
// transports). Nil on every other path: linux behavior is byte-identical.
type serviceWiring struct {
	Wired       chan<- struct{}
	StopRequest <-chan struct{}
}

// serviceRestartNote is the ADDENDUM §1 mechanism line the windows service
// context reports for the self-watchdog miss (launchd KeepAlive is the
// darwin transport; the SCM recovery actions are the windows one).
const serviceRestartNote = "Windows SCM recovery actions restart the service; " +
	"mechanism: self-watchdog → SCM recovery-actions restart"

// serviceSelfWatch is the service transport: the internal heartbeat
// supervisor ALWAYS runs in the service context (clean self-exit → SCM
// recovery actions restart), regardless of GOOS — the same clock-seam shape
// the darwin transport uses. Only the windows service entrypoint calls it;
// linux never sees it.
func serviceSelfWatch(out io.Writer, threshold time.Duration, onMiss func()) (func(), func(), bool) {
	_ = out // no transport log — the miss action itself logs the mechanism
	sup := selfwatchdog.Start(threshold, onMiss, time.Now, time.After)
	return sup.Beat, sup.Stop, true
}

// newServiceWatchDeps assembles the daemon deps for the service context:
// default deps + the service transport hooks + the always-active
// self-watchdog transport with the SCM recovery note (ADDENDUM §1).
func newServiceWatchDeps(wired chan<- struct{}, stopRequest <-chan struct{}) watchDeps {
	deps := defaultWatchDeps()
	deps.serviceHooks = &serviceWiring{Wired: wired, StopRequest: stopRequest}
	deps.selfWatch = serviceSelfWatch
	deps.restartNote = serviceRestartNote
	return deps
}

// ParseServiceArgs parses the registered service arguments (§2.2.4/§2.2.5).
// The SCM delivers the service name followed by the registered arguments
// (x/sys windows/svc/service.go), so the contract is exactly
// `assay watch [-c <abs config>]` — anything else refuses loudly instead
// of being silently mis-read. An absent -c is legal HERE (the §2.2.5
// refusal applies downstream, in resolveServiceConfig) so a hand-created
// -c-less service produces the actionable refusal rather than an arg error;
// an explicit EMPTY -c value refuses at this gate instead — an empty string
// is a malformed value, not an absent one.
func ParseServiceArgs(args []string) (string, error) {
	if len(args) < 2 || args[0] != install.WinSvcName {
		return "", fmt.Errorf("service arguments %v are malformed — the assay service runs "+
			"`watch [-c <abs config>]` only (the SCM delivers the service name first)", args)
	}
	if args[1] != "watch" {
		return "", fmt.Errorf("service verb %q is not `watch` — the assay service runs "+
			"`watch [-c <abs config>]` only", args[1])
	}
	switch len(args) {
	case 2:
		return "", nil
	case 4:
		// An explicit `-c ""` is an EMPTY value, not an absent one: it
		// refuses at this same malformed-args gate instead of silently
		// downgrading to the default-resolution path (the §2.2.5 SYSTEM
		// profile check is for the absent case, not the empty one).
		if (args[2] == "-c" || args[2] == "--config") && args[3] != "" {
			return args[3], nil
		}
	}
	return "", fmt.Errorf("service arguments %v are malformed — the assay service runs "+
		"`watch [-c <abs config>]` only", args)
}

// RunWatchService is the windows service context's daemon entry (the svc
// handler calls it): resolve the config (explicit -c from the service
// arguments, or the §2.2.5-refused default resolution), open the file log
// sink (§2.2.6 — service stdout goes nowhere), and run the daemon with the
// service transport wired. The returned error fails the service (SCM
// recovery actions apply).
func RunWatchService(out io.Writer, explicitCfg string, wired chan<- struct{}, stopRequest <-chan struct{}) error {
	res, err := resolveServiceConfig(explicitCfg)
	if err != nil {
		// Pre-sink diagnostics: a service's stderr goes nowhere, so the
		// handler's failure exit code carries the refusal; this copy helps
		// console-debug runs. The daemon-side logging starts only after the
		// sink exists — the refusal happens BEFORE anything is created
		// (§2.2.5 fail-closed posture).
		_, _ = fmt.Fprintf(out, "watch: service start refused: %v\n", err)
		return err
	}
	sink, err := serviceLogSink(res.Config.DataDir)
	if err != nil {
		_, _ = fmt.Fprintf(out, "watch: open the service log sink: %v\n", err)
		return fmt.Errorf("watch: open the service log sink: %w", err)
	}
	defer func() { _ = sink.Close() }()
	reportConfigSource(sink, res)
	return runWatch(sink, res.Config, newServiceWatchDeps(wired, stopRequest))
}

// resolveServiceConfig resolves the service context's config: explicit -c
// wins (the installer embeds the absolute path, §2.2.5); a default
// resolution is checked against the SYSTEM profile and REFUSED fail-closed
// when it would silently create and use the SYSTEM's data dir.
func resolveServiceConfig(explicit string) (*config.Resolved, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	res, err := config.Resolve(explicit, home, cwd)
	if err != nil {
		return nil, err
	}
	if explicit == "" {
		if msg := serviceDefaultDirRefusal(runtime.GOOS, res.Config.DataDir); msg != "" {
			return nil, errors.New(msg)
		}
	}
	return res, nil
}

// serviceDefaultDirRefusal is the §2.2.5 fail-closed refusal check: on
// windows, a default-resolution data dir under the SYSTEM profile produces
// the loud refusal naming both fixes; any other GOOS or a real user dir
// passes ("" = no refusal). goos is a parameter so the suite pins the
// windows behavior from linux (the S0 table-driven pattern).
func serviceDefaultDirRefusal(goos, dataDir string) string {
	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = os.Getenv("WINDIR")
	}
	profile := platform.SystemProfilePrefix(goos, windir)
	return install.ServiceDefaultDataDirRefusal(dataDir, profile)
}
