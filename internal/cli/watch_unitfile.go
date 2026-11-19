package cli

// The incident-#3 detector (2026-11-12 watchdog-kill): the unit file
// vanished from disk while the loaded unit kept running — every healthy
// sd_notify ping was then rejected ("reception is disabled"), the watchdog
// SIGABRT'd the daemon, and Restart=always stood by POWERLESS (nothing on
// disk to restart from). The daemon cannot fix systemd's loaded state and
// must not reinstall itself (the install allowlist is owner-invoked — no
// self-install), but it CAN see the precondition: does its own unit file
// still exist? Detection only — one loud line per check that finds the
// file missing turns the silent-death state into a flagged one the owner
// can act on (re-run `assay install`).

import (
	"io"
	"os"
	"path/filepath"
	"runtime"

	"assay/internal/config"
	"assay/internal/install"
)

// unitFileGuard checks the daemon's own unit file presence. stat is the
// seam (production os.Stat; tests inject) — the check is one stat per
// invocation: once at daemon startup and once per due wave (bounded, cheap,
// never a ticker).
type unitFileGuard struct {
	out  io.Writer
	path string                            // "" = the platform has no unit file (check inactive)
	stat func(string) (os.FileInfo, error) // seam
}

// check performs one presence check: silence when the unit file is there,
// ONE loud line when it is not (or when its presence cannot be confirmed —
// a stat error hides the same state a missing file does).
func (g *unitFileGuard) check() {
	if g == nil || g.path == "" {
		return
	}
	_, err := g.stat(g.path)
	if err == nil {
		return
	}
	if !os.IsNotExist(err) {
		outf(g.out, "WARNING: watch: cannot confirm the unit file %s on disk (%v) — "+
			"%s will not restart this daemon if the file is missing; re-run assay install\n",
			g.path, err, unitFileSupervisorName())
		return
	}
	outf(g.out, "WARNING: watch: unit file %s missing on disk — "+
		"%s will not restart this daemon; re-run assay install\n",
		g.path, unitFileSupervisorName())
}

// resolveDaemonUnitPath resolves the daemon's own unit file path per OS —
// the same artifact `assay install` renders at the same default location
// (the systemd user unit on linux, the launchd agent plist on darwin);
// "" on platforms with no unit file behind the daemon (windows: the SCM
// registration is not a file the daemon can stat).
func resolveDaemonUnitPath() string {
	switch runtime.GOOS {
	case "linux":
		return filepath.Join(config.ExpandHome("~/.config/systemd/user"), install.WatchService)
	case "darwin":
		return filepath.Join(config.ExpandHome("~/Library/LaunchAgents"), install.LaunchdPlistName)
	default:
		return ""
	}
}

// unitFileSupervisorName names the restart mechanism the missing file
// disarms (per-OS excellence: the mechanism is named, not generic).
func unitFileSupervisorName() string {
	switch runtime.GOOS {
	case "darwin":
		return "launchd"
	case "linux":
		return "systemd"
	default:
		return "the service manager"
	}
}
