# Cross-platform landmines

The behaviors behind assay's cross-platform error messages, distilled from
the campaign risk register (implementation plan §5, risks 1–8, 18–19).
The owner-UX rule that governs all of them: every failure is loud and
carries the exact command line to run by hand — nothing here is silent,
and no command in these notes is invented; each one is what the tool
prints or what the README documents.

## 1. The Windows service runs as LocalSystem

Its `%USERPROFILE%`/`%LOCALAPPDATA%` are the **SYSTEM** profile, not
yours. A service started without `-c` would resolve a data dir under
`C:\Windows\System32\config\systemprofile\...` — assay refuses that
loudly before anything is created, naming both fixes. `assay install`
therefore ALWAYS embeds your absolute config path into the service
command line. Never hand-create the service without `-c`.

## 2. Windows PATH precedence — cwd wins in cmd.exe

cmd.exe resolves bare commands against the **current directory first**.
A planted `assay.exe`/`xray.exe` in a directory you cd into would shadow
a PATH lookup. Assay never adds the current directory to any resolution
chain and its executors use absolute paths only. In scripts, run
installed tools by absolute path; add `%LOCALAPPDATA%\assay\bin` to PATH
only via the documented PowerShell line (the installer never edits PATH
silently).

## 3. launchd agents get a minimal environment

No `XDG_*`, no shell profile — environment inheritance cannot be relied
on under launchd (and the Windows service environment is the SYSTEM
profile's, same conclusion). Assay resolves everything from absolute
paths plus the config file; nothing may depend on shell env. If you
move your config, reinstall (`assay install -c <abs path>`) rather than
expecting an env var to carry it.

## 4. Signals: SIGTERM exists on unix only

One graceful-stop seam serves both transports: SIGTERM/SIGINT on unix,
`svc.Stop` on Windows. `os.Interrupt` on Windows means console ctrl
events in interactive contexts only — never in services. The managed
xray child on Windows stops through the graceful ladder (CTRL_BREAK to
its own process group → bounded wait → TerminateProcess last resort)
inside a Job Object; unix keeps the hard kill + reap for the core
child. Force-killing the service (`taskkill /F` on `assay.exe`) skips
the graceful drain — use `assay uninstall` or the SCM Stop.

## 5. One instance per host: locks, not pidfiles

The daemon holds an exclusive one-shot lock (`flock` on unix,
`LockFileEx` on Windows); a second instance refuses immediately. The
`assay-watch.pid` file you may see on OpenRC belongs to
supervise-daemon/openrc-run (their backgrounding contract), not to
assay — do not treat its presence or absence as assay state.

## 6. Atomic replace: not atomic on Windows

Same-dir temp + rename is atomic on unix; `os.Rename` on Windows is
not, and a running exe locks its own image — so windows install
upgrades always stop the service → replace → start, and a freshly
written exe can be transiently locked by antivirus (bounded retry,
then a loud failure). If an upgrade reports a locked file after the
bounded retries, stop the service by hand (`sc.exe stop assay`) and
re-run `assay install`.

## 7. Self-update verifies the executable magic per OS

ELF (`\x7fELF`) on linux, Mach-O on darwin, PE (`MZ`) on Windows. A
truncated, corrupted, or wrong-architecture binary fails the verify
loudly instead of replacing a good one — if you see that error, the
download is bad; re-fetch and re-verify against `checksums.txt`.

## 8. The launchd plist must stay 0600

Apple requires LaunchAgent plists at mode 600/400 owned by the user;
assay writes `0600` and launchd refuses anything else. If `assay
install` on macOS reports a load refusal, do not "fix" permissions to
0644 — that is the refusal class, not a remedy.

## 9. Plugin hot-reload is real-FS-event dependent (§5.18)

fsnotify rides FSEvents/kqueue (darwin) and ReadDirectoryChangesW
(Windows); no CI leg exercises real filesystem events, so the
behavior is proven by the owner-manual acceptance item (see
`docs/acceptance-crossplatform.md`, item 5). On network mounts event
delivery can be absent — keep the plugins dir on a local filesystem.

## 10. Unsigned binaries: quarantine and SmartScreen (§5.19)

Downloaded release binaries trip macOS Gatekeeper quarantine and
Windows SmartScreen; assay ships no code-signing. The trust anchor is
`checksums.txt` from the release (`sha256sum -c checksums.txt`; the
release footer contract). Then clear the friction once:
`xattr -dr com.apple.quarantine ./assay` on macOS, Properties →
Unblock (or More info → Run anyway) on Windows. Never bypass the
checksum verify to "save time" — it is the only integrity contract an
unsigned download has.
