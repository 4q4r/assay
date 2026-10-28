# systemd user unit (template)

This file is the **single source of truth** for the publicvpn systemd user
unit. It is a Go text template — `publicvpn install` embeds it (`go:embed`),
renders the placeholders (binary path, config path), writes it to
`~/.config/systemd/user/`, and enables the daemon. You normally never touch
systemd yourself:

```bash
go build -o publicvpn ./cmd/publicvpn
./publicvpn install -c /absolute/path/to/config.toml
```

- `public_vpn-watch.service` — the long-running **watch daemon** (W10):
  fsnotify watchdog on the plugins dir (new provider = new .lua file, no
  rebuild) plus the wave scheduler — refresh waves every
  `[maintain].refresh_interval` (default 1h), speedtest waves every
  `[maintain].speedtest_interval`, stats poll inside every wave,
  activate-if-changed behind the `-test` gate. `Restart=always` brings a
  crashed daemon back in 5s.

## Scheduling mechanics

There are **no timers** anymore: the daemon re-arms each wave from the
moment the previous one completes, so waves can never overlap, and the
intervals are read from the config **live** — a period change is a config
edit plus `systemctl --user restart public_vpn-watch.service`, never a
re-install. The W5 timer units (`public_vpn-refresh/speedtest.*`) are
retired: `install` disables and removes them automatically when they are
still on disk (waves must fire from exactly one scheduler).

## What install executes

Exactly two `systemctl --user` calls, pinned to an internal allowlist (no
restart of anything, no other units, ever):

```bash
systemctl --user daemon-reload
systemctl --user enable --now public_vpn-watch.service
```

(A legacy-timer `disable --now` runs first, only when the old units are
still present.) `uninstall` runs the symmetric disables and removes every
known unit file (`--purge` also removes the config + data dir; default keeps
user data). Hosts without a user systemd session: `publicvpn install
--no-systemd` copies the binary only and skips the unit.

## Journald cheatsheet

```bash
# Follow the daemon live (watchdog reloads + wave output).
journalctl --user -u public_vpn-watch.service -f

# Last restart's full output.
journalctl --user -u public_vpn-watch.service -n 200

# Daemon state: active since, restarts.
systemctl --user status public_vpn-watch.service
```

If the daemon should keep running after logout, enable lingering:

```bash
sudo loginctl enable-linger whoami
```
