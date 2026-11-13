# Cross-platform acceptance — owner-manual checklist

CI proves the compile matrix, the unit behavior, and the native/container
legs (qemu-user, Rosetta 2, WOW64, the arm64 runner, the launchctl/SCM/
scheduler containers). Five things still need a real OS session no runner
provides — the items below are the plan's OWN list (Stage S5). Each states
its prerequisites, the exact steps, and what to observe. Every manual
command here already runs inside `assay install` / `assay status` /
`assay uninstall`; the manual pass exists to verify the product honestly,
not to work around it.

## 1. macOS — launchd agent survives logout/login

**Prerequisites:** a real Mac (Apple Silicon or Intel), a release tarball
plus `checksums.txt`, a terminal.

- [ ] Verify the archive (`shasum -a 256 -c checksums.txt`, or compare the
      single line), then clear Gatekeeper quarantine:
      `xattr -dr com.apple.quarantine ./assay`.
- [ ] `./assay install` — observe: it prints the launchd flow; the plist
      exists at `~/Library/LaunchAgents/assay-watch.plist` with mode `0600`
      (`ls -l`); `launchctl print gui/$(id -u)/assay-watch` reports
      `state = running` with a pid; the managed core downloaded to
      `<data>/bin/xray` (Apple Silicon gets the native arm64 asset).
- [ ] `./assay status` — observe the launchd note: `KeepAlive restart on
      exit; hang detection: self-watchdog → KeepAlive restart`.
- [ ] **The acceptance point:** log out and log back in. Without any manual
      action, `launchctl print gui/$(id -u)/assay-watch` must again report
      `state = running` (a new pid — `RunAtLoad` starts the agent at login),
      and `<data>/logs/watch.out.log` must show a fresh daemon boot.
- [ ] Crash parity: `kill -9 <pid>` the watch process — KeepAlive restarts
      it within the `ThrottleInterval=5` window (a new pid in
      `launchctl print`).
- [ ] `./assay uninstall` — observe the bootout, the plist removal, and
      `launchctl print gui/$(id -u)/assay-watch` now failing (not
      registered).

## 2. Windows — desktop install, service lifecycle, PATH

**Prerequisites:** a real Windows 10/11 desktop (x64 or arm64), the release
zip plus `checksums.txt`, an Administrator terminal.

- [ ] Verify the zip (`sha256sum -c checksums.txt` in Git Bash, or compare
      `Get-FileHash -Algorithm SHA256` output), then unblock the file
      (right-click → Properties → Unblock) to skip the SmartScreen friction
      documented in the README.
- [ ] In an **Administrator** PowerShell: `.\assay.exe install` — observe
      the install summary; `Get-Service assay` shows `Running` /
      `Automatic` with display name `assay watch daemon`; `sc.exe qfailure
      assay` shows the recovery action `RESTART -- Delay = 5000` with reset
      period `86400`.
- [ ] `.\assay.exe status` from a **normal** (non-admin) shell — observe it
      still reports your data dir under `%LOCALAPPDATA%\assay`; the service
      note names `recovery: ServiceRestart after 5s` and the
      self-watchdog transport.
- [ ] PATH: in a fresh non-admin shell, bare `assay` is NOT on PATH (the
      installer never edits it silently). Run the documented line
      (`[Environment]::SetEnvironmentVariable("Path", $env:Path +
      ";%LOCALAPPDATA%\assay\bin", "User")`), open a NEW terminal, and
      observe `assay` now resolves.
- [ ] Upgrade ordering: place a rebuilt `assay.exe` and re-run
      `.\assay.exe install` — observe the stop → replace → start sequence
      succeed (the running-image lock is handled by the tool, never a
      locked-file error).
- [ ] `.\assay.exe uninstall` from the elevated shell — observe stop →
      poll Stopped → delete; `Get-Service assay` now errors (service
      gone). `<data>` is kept unless `--purge`.

## 3. runit — real Void/Artix box

**Prerequisites:** a Void Linux or Artix host running runit, `sv` and
`runit` packages installed, your user services dir convention (`~/service`
by default — start it with `runsvdir ~/service &` if your session does not
already run one).

- [ ] `./assay install` — observe the runit detection; the service dir
      `<service-dir>/assay-watch/` with a `run` script at mode `0755`
      (`ls -l`); within runsvdir's ≤ 5-second rescan,
      `sv status <service-dir>/assay-watch` exits 0.
- [ ] `./assay status` — observe the honest runit note: restart-on-exit
      with a 1-second backoff, logs unrotated.
- [ ] Crash parity: `kill -9` the `assay watch` process — runsv reruns
      `./run` within about a second (a new pid in `sv status` output).
- [ ] `./assay uninstall` — observe `sv stop` then the service dir removal;
      `sv status <service-dir>/assay-watch` now fails (no live runsv).
- [ ] Re-run `./assay install` and confirm re-registration is clean
      (idempotent re-install).

## 4. OpenRC user — login-cycle distro

**Prerequisites:** a distro with OpenRC ≥ 0.60 user services wired at
login (`openrc-user` via `pam_openrc`; `XDG_RUNTIME_DIR` set), a terminal.

- [ ] After a fresh login, verify the user session exists:
      `rc-status --user` exits 0.
- [ ] `./assay install` — observe the openrc-user detection; the script at
      `~/.config/rc/init.d/assay-watch` with mode `0755`;
      `rc-service --user assay-watch status` reports started.
- [ ] `./assay status` — observe the honest caveat: user services run while
      the session lives; no lingering without root.
- [ ] **The acceptance point:** log out and back in — the service comes
      back with the session (`rc-service --user assay-watch status`
      reports started again).
- [ ] Crash parity: `kill -9` the watch process — `supervise-daemon`
      restarts it (`rc-service --user assay-watch status` shows started
      with a fresh pid).
- [ ] `./assay uninstall` — observe stop → `rc-update --user del assay-watch
      default` → script removal.

## 5. fsnotify plugin hot-reload — darwin and windows

**Prerequisites:** items 1/2 completed (agent/service running), one working
`.lua` source already in the plugins dir. fsnotify rides FSEvents/kqueue on
darwin and ReadDirectoryChangesW on windows — no CI leg exercises real FS
events, which is exactly why this item is owner-manual (plan §5.18). Run
the same five steps on both platforms; the daemon's log is
`<data>/logs/watch.out.log` (+ `watch.err.log`) under launchd and
`<data>/logs/watch.log` under the Windows service.

- [ ] Drop a NEW valid plugin file into `<data>/plugins/` while the daemon
      runs — observe the hot-load journal line
      (`plugin <id> loaded — source active (hot-added)`) without any
      restart, and the next wave fetching from the new source.
- [ ] Edit that file (change its URL) — observe the reload picking up the
      edit on the following wave.
- [ ] Remove/rename the file — observe the plugin leaving the registry
      loudly.
- [ ] Drop a broken `.lua` — observe the loud plugin-attributed error line
      and the wave continuing with the healthy sources (the circuit
      breaker counts it).
- [ ] Confirm no restart was needed at any step (`assay status` uptime
      unchanged).
