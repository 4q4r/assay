# systemd user units (templates)

These four files are the **single source of truth** for the publicvpn systemd
user units. They are Go text templates — `publicvpn install` embeds them
(`go:embed`), renders the placeholders (binary path, config path, recheck
periods from `[maintain]`), writes them to `~/.config/systemd/user/`, and
enables the timers. You normally never touch systemd yourself:

```bash
go build -o publicvpn ./cmd/publicvpn
./publicvpn install -c /absolute/path/to/config.toml
```

- `public_vpn-refresh.timer` + `.service` — the full refresh wave
  (fetch → parse → filter → probe → geo → stats → prune → select → render →
  activate-if-changed) every `[maintain].refresh_interval` (default 6h).
- `public_vpn-speedtest.timer` + `.service` — the same wave weekly
  (`[maintain].speedtest_interval`, default 168h), with the slow `-S`
  throughput measurement in the probe stage.

## Timer mechanics

The timers use `OnBootSec` + `OnUnitActiveSec` — **not** `OnCalendar` — so the
period is whatever duration your config carries (90m, 8h, 10d): the timer
re-arms N after each completed wave, which also means waves can never overlap.
`Persistent=true` replays a missed wave after sleep or downtime.

**Changing a period:** edit `[maintain].refresh_interval` /
`[maintain].speedtest_interval` in the config, then re-run
`publicvpn install -c <config>` (idempotent — it re-renders the units,
daemon-reloads, and re-enables). `publicvpn status` flags a mismatch between
the configured and the installed periods.

## What install executes

Exactly two `systemctl --user` calls, pinned to an internal allowlist (no
restart, no other units, ever):

```bash
systemctl --user daemon-reload
systemctl --user enable --now public_vpn-refresh.timer public_vpn-speedtest.timer
```

`uninstall` runs the symmetric `disable --now` and removes the four unit
files (`--purge` also removes the config + data dir; default keeps user
data). Hosts without a user systemd session: `publicvpn install
--no-systemd` copies the binary only and skips the timers.

## Journald cheatsheet

```bash
# Follow the refresh wave live.
journalctl --user -u public_vpn-refresh.service -f

# Last run's full output (waves are oneshot — one journal session per run).
journalctl --user -u public_vpn-refresh.service -n 200

# Speedtest wave output.
journalctl --user -u public_vpn-speedtest.service -n 200

# Timer state: when did it last run, when is the next fire?
systemctl --user list-timers 'public_vpn-*'

# Manually fire a wave right now (same as running publicvpn maintain).
systemctl --user start public_vpn-refresh.service
```

If the timers should keep running after logout, enable lingering:

```bash
sudo loginctl enable-linger whoami
```
