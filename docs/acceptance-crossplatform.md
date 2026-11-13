# Cross-platform acceptance — owner-manual checklist

CI proves the compile matrix, the unit behavior, and the native/container
legs (qemu-user, Rosetta 2, WOW64, the arm64 runner, the launchctl/SCM/
scheduler containers). Five things still need a real OS session no runner
provides — the items below are the plan's OWN list (Stage S5). Each states
its prerequisites, the exact steps, and what to observe. Every manual
command here already runs inside `assay install` / `assay status` /
`assay uninstall`; the manual pass exists to verify the product honestly,
not to work around it.

## Results — 2026-11-13 docker acceptance pass

A docker pass ran every docker-runnable step on 2026-11-13 with the
release-identical binary built at the accepted commit (0bfdf93) inside
disposable containers: debian:trixie for the runit and foreground legs,
alpine:edge (OpenRC 0.63.2) for the OpenRC leg, each with a temporary
config inside the container and the managed ports pointed outside the
production band. The per-item result lines below carry the captured
evidence. Items needing a real OS session stay owner-manual and cite
their CI legs: the four linux scheduler container legs and the darwin
launchctl end-to-end leg are green in run 43396722388 and re-verified
green at 0bfdf93 in run 43414096837; the v0.2.0-rc1 release matrix (all
five platform targets) is green in run 43406511045.

The pass found and root-caused one product defect that the CI legs
cannot see (they install configless; the defect needs an install that
materializes nothing): `install` renders the linux scheduler scripts
with an EMPTY data-dir prefix whenever nothing is materialized — an
explicit `-c` install, and ANY re-install over an existing config
(`materializeDataDir` in `internal/cli/install_cmd.go` returns "" for
both, and the empty string flows into `SchedulerInstallSpec.DataDir`
unchanged). The runit/s6 run script and the OpenRC script then carry
relative pidfile and log paths: under runit the service crash-loops
("down, want up") while `sv status` still exits 0; under OpenRC
supervise-daemon silently launches no daemon child while
`rc-service --user assay-watch status` still reports "started", and the
stop leg wedges on the missing pidfile.

## 1. macOS — launchd agent survives logout/login

**Result (2026-11-13): NOT-DOCKER-RUNNABLE — owner-manual;
CI-proven.** launchd requires a real macOS session, so the steps below
stay owner-manual. The darwin launchctl E2E leg (launchd unit tests +
launchctl end-to-end) is green in run 43396722388 and again at 0bfdf93
in run 43414096837; the darwin release targets built green in run
43406511045 (v0.2.0-rc1).

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

**Result (2026-11-13): NOT-DOCKER-RUNNABLE — owner-manual; NOT
CI-proven at the accepted commit (open defect).** The Windows SCM E2E
leg (`assay install` → SCM lifecycle) fails at 0bfdf93 with
`install: the assay service did not report Running within 60×500ms` —
five consecutive runs (43396722388, 43404313899, 43406504634,
43409302454, 43414096837), so the 30-second start budget the leg's own
parity fix granted is consumed without the service ever reaching
Running; the leg's captured status probe shows the core never started
and the install rolled the binary back. The windows unit suites, the
vet/build matrix, and windows-latest `-race` are green in the same
runs, which localizes the defect to the service-context start path; it
needs its own root-cause wave before item 2 may be treated as
CI-proven. The steps below stay owner-manual.

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

**Result (2026-11-13, docker debian:trixie, binary at 0bfdf93): SPLIT.**
PASS on the configless first install (steps 1–4 of this item): install
detects the user runsvdir, renders `assay-watch/run` at mode 0755 with
absolute log paths, and `sv status` exits 0 with a live pid within the
5-second rescan; `assay status` prints the honest runit note
(restart-on-exit, 1-second backoff, unrotated logs); `kill -9` of the
watch process is answered by runsv with a fresh pid inside the
1-second backoff (observed pid 56 → 135); uninstall stops the service
and removes the dir, and `sv status` then fails. FAIL on every install
that materializes nothing (the shared defect above): the `-c` install
and the step-5 re-install over the materialized config both render the
run script with relative log redirects, the daemon never boots
("down, want up" restart loop) while `sv status` still exits 0, and the
re-install takes a previously live daemon down. The CI container leg
covers the configless first install only; green in runs 43396722388 and
43414096837.

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

**Result (2026-11-13, docker alpine:edge / OpenRC 0.63.2, binary at
0bfdf93): SPLIT.** PASS on the configless first install for every
docker-runnable step: `rc-status --user` exits 0 once the session
skeleton a pam_openrc login creates is in place; install renders the
script at mode 0755, `sh -n` clean, and
`rc-service --user assay-watch status` reports started with the daemon
child alive; `assay status` carries the no-lingering session caveat;
`kill -9` of the watch process is answered by supervise-daemon with a
fresh pid (observed 71 → 176); uninstall stops the service, deletes the
runlevel entry, removes the script, and the follow-up status fails.
Step 4 (the login-cycle acceptance point) is NOT-DOCKER-RUNNABLE — it
needs pam_openrc at a real login — and stays owner-manual. FAIL on the
`-c` path (the shared defect above): the script's relative pidfile and
log paths leave supervise-daemon with no daemon child while status
still reports "started", and the stop leg wedges on the missing pidfile
(the executor's bounded stop path engages; the 30-minute parity poll
was not waited out inside the container — a healthy-service stop is the
design target, not this state). The CI container leg proves script
validity on the configless path only; green in runs 43396722388 and
43414096837.

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

**Result (2026-11-13, docker debian:trixie, foreground daemon with the
managed core, linux inotify backend): PASS — all five steps.** Dropping
a new valid plugin produced `plugin accept2 loaded — source active
(hot-added)` within seconds of the write and the next wave fetched from
it; editing the file reloaded it (remove + hot-added pair) and the
following wave picked up the edited content (1 → 2 nodes); removing it
logged `plugin accept2 removed — source disabled` and the wave continued
without the source; a deliberately broken `.lua` failed loud and
plugin-attributed (`WARNING: plugin broken reload FAILED …`) with the
healthy sources untouched; the daemon pid stayed constant and the core
uptime kept accumulating across four waves — no restart at any step.
The darwin (FSEvents/kqueue) and windows (ReadDirectoryChangesW)
variants below stay owner-manual: they require items 1/2 completed on
real machines.

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
