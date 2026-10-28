# systemd user timers

This project ships **repo files only** — nothing here installs, enables, or
talks to systemd. You (the operator) copy them into your user manager:

- `systemd/public_vpn-refresh.timer` + `.service` — the full refresh wave
  every 6 hours (fetch → parse → filter → probe → geo → stats → prune →
  select → render → activate-if-changed).
- `systemd/public_vpn-speedtest.timer` + `.service` — the same wave weekly,
  with the slow `-S` throughput measurement in the probe stage.

## Install

Build the binary first (`go build -o publicvpn ./cmd/publicvpn` in the repo
root), then:

```bash
mkdir -p ~/.config/systemd/user
cp /home/user/projects/public_vpn/systemd/public_vpn-*.service \
   /home/user/projects/public_vpn/systemd/public_vpn-*.timer \
   ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now public_vpn-refresh.timer public_vpn-speedtest.timer
```

If the timers should keep running after logout, enable lingering:

```bash
sudo loginctl enable-linger whoami
```

The units reference `%h/projects/public_vpn` (your home). If the repo lives
elsewhere, fix the paths in the copied units — the repo copies stay untouched.

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

`Persistent=true` replays a missed wave after sleep or downtime, so a laptop
that wakes on Monday still gets its speedtest wave.
