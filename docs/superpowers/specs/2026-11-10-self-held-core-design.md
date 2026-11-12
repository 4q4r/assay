# Design: assay self-held core (independent xray process + own proxies)

Status: FINAL DRAFT — builder check (9 questions) settled; owner decisions D1–D8
binding. Awaiting owner approval to start waves. Supersedes the external-client
activation story (`render` into a foreign xray-raw config + `systemctl` restart)
for the publication pivot.

> AMENDED 2026-11-12 (owner rulings 2026-11-11 + 2026-11-12: «xray стоит
> ставить системно всегда когда его нет», then «запись в локал не требует
> судо»): the core-binary resolution, install target and auto-update
> semantics changed from the managed `<data>/bin/xray` story to the
> user-local story below. S1, S5 and D4 carry the amended wording in place
> (marked AMENDED); the original D4 text above is superseded by its
> amendment.

## Intent and why

assay today manages a FOREIGN client: it renders the selected pool into the
owner's hand-edited xray-raw config and restarts that systemd unit. A public
user has no such client to hand over — the product must be self-contained:
`assay install` → daemon runs → the user gets working local proxy inbounds
backed by the verified node pool. The owner's own laptop keeps xray-raw as the
primary client and consumes the pool through ONE forwarded proxy outbound.

## Goals

- G1: assay owns a long-lived xray core process: spawn at daemon start, watch,
  restart on activate-if-changed and on crash, health-check (socks reachable +
  outbound dial), bounded rollback on persistent runtime failure — no foreign
  systemd units involved.
- G2: the rendered live config is assay's OWN artifact (own inbounds, own
  routing, own observatory, own stats port) — never another client's file.
- G3: `assay install` is a complete user bootstrap: binary + unit + config +
  xray core download (sha-verified) + bootstrap core spawn.
- G4: core auto-update (configurable, default ON, managed core only) + manual
  `assay xray-update`.
- G5: the owner's laptop migrates to the same product shape: xray-raw restored
  to a clean hand-managed base + one outbound pointing at assay's socks inbound.

## Non-goals

- N1: no multi-user/auth surface (bind 127.0.0.1 by default; LAN exposure is a
  later explicit decision).
- N2: no provider roster (bring-your-own-sources stands).
- N3: no transport for the user's own client besides the local inbounds (no
  TUN, no system proxy management).
- N4: no Windows/macOS packaging in this pivot (Linux + systemd user units).

## Anti-goals (what would make this a failure)

- A1: any code path that writes another client's config file or restarts a
  foreign systemd unit (the old external mode must be REMOVED, not hidden).
- A2: the daemon holding the core hostage: a daemon restart must not leave the
  core dead.
- A3: silent core downloads: every download sha-verified and logged loudly.
- A4: unproxied traffic leakage: an empty pool NEVER routes to `direct`.

## Owner decisions (binding)

- D1 (Q1a): the watch daemon is the core process's direct parent. One unit
  (`assay-watch.service`); no `assay-core.service`. The daemon restarts the
  core on activate-if-changed and supervises it between waves; `Restart=always`
  on the unit covers daemon death, and the daemon re-spawns the core on start
  if absent.
- D2 (Q2): inbounds = socks5 + http, bound 127.0.0.1 by default, ports
  configurable. Per-country socks ports (port base + one socks inbound per
  alive-country balancer, tags `in-<cc>`) ship as a configurable option,
  default off.
- D3 (Q3): the external mode is REMOVED entirely — render has one target (the
  own live config), activate knows one lifecycle (own core). The foreign-config
  template seam, the foreign-unit restart allowlist, and their tests die.
- D4 (Q4, AMENDED 2026-11-12): the core binary lives USER-LOCAL at
  `~/.local/bin/xray` — user-writable, no elevation anywhere («запись в локал
  не требует судо»). With no binary present, `install` downloads the release
  (sha-verified) and installs it ATOMICALLY there, keeping the previous
  binary as `~/.local/bin/xray.previous` through every swap for instant
  binary-level rollback, and prints a one-time loud PATH note
  (`~/.local/bin` precedes `/usr/bin` on PATH, so assay's copy shadows any
  later apt-installed xray — the duplicate-core concern is solved by PATH
  precedence). Core auto-update stays configurable, defaults ON, checked
  each maintenance wave by the WATCHER (`[core].update_interval`, default
  24h); `assay xray-update` stays as the manual path. A different binary may
  be pointed at via `[core].xray_bin` for users who prefer it (auto-update
  inert there per S5).
- D5 (Q5): the owner's xray-raw migration starts from the CURRENT live config:
  the hand core (direct/block/fox-proxy/proxy-0/proxy-1, `best_rtt` leastLoad
  balancer, the owner's routing rules) is intact inside it — the migration
  strips the assay-added pool layer (pool-* outbounds, pool_* balancers, pool
  routes, pool observatory block) and adds ONE socks outbound → assay's socks
  inbound. The pool layer then lives only in assay's own core.
- D6 (Q6): this document is the design of record; implementation follows as
  waves after owner approval.
- D7 (round-2 Q-A): empty-pool posture is FAIL-CLOSED — the bootstrap config's
  catch-all routes to `block` (never `direct`); once a pool has been activated
  at least once, an empty-pool wave KEEPS the last-good live config (loud
  per-wave line naming the state; core keeps running on it). The pool never
  becomes unreachable-by-regression.
- D8 (round-2 Q-B): self-healing rollback — `[core].rollback_strikes`
  (default 3, configurable): K consecutive failed post-activation health
  checks → auto-restore the newest pre-activate dated backup → `-test` gate →
  core restart → loud journal line naming the rollback; strikes reset on a
  healthy check. Report-only details (per-check errors) stay in the journal.

## Builder-check settlements (binding, from the 9-question check)

- S1 (Q1, AMENDED 2026-11-12): `[core].xray_bin` is the SINGLE binary knob —
  the probe/check temp-instance fleets, the batch pre-filter, the activation
  `-test` gate, the D8 rollback gate and the core manager resolve it in the
  owner-ruling order: (1) the explicit override; (2) an EXISTING user-local
  `~/.local/bin/xray` — assay's OWN binary, bound and UPDATABLE; (3) an
  EXISTING system xray (`/usr/local/bin/xray`, `/usr/bin/xray` — first
  match) bound AS FOUND (auto-update inert; a below-floor core warns LOUD
  and non-blocking — the owner's 26.3.27 bound core is the expected case,
  and the W19 adaptive observatory interval already caps the probe rate);
  (4) none of the above → the user-local install target (the next
  resolution fills it). `[activate].xray_bin` retires. `install` guarantees
  a usable binary exists before the first wave. Render goldens track the
  core version. The resolution provenance (`binary_source`:
  `override | user-local | system-preexisting`, plus `binary_path` and
  `binary_version`) is written to `<data>/core-state.json` on every
  resolution change and rendered by `assay status`.
- S2 (Q3): readiness = Option B — the daemon spawns a bootstrap core at start
  (bootstrap config: empty-pool posture per D7), READY=1 fires once that core
  is reachable; each wave re-renders and restarts on activate-if-changed.
  No TimeoutStartSec change needed (spawn is fast; the wave is not on the
  start path).
- S3 (Q4): the core manager takes a singleton file lock (flock, data dir).
  A one-shot `assay activate` refuses loud when the daemon holds the lock
  ("the daemon owns the core — use the unit or `assay watch`") and spawns
  transiently only when no daemon holds it.
- S4 (Q6): the retired/re-homed knob list is enumerated below; the config
  loader treats retired keys as parse-and-warn (loud per-key migration line,
  daemon never refuses to start on a retired key). Enumeration:
  `[activate].target` → retire (defaults pointing at ~/projects/xray-raw die);
  `[activate].xray_bin` → re-home to `[core].xray_bin` (S1);
  `[activate].asset_dir` → retire (managed core dir owns assets; unzipFlat
  wiring moves to the core manager);
  `[activate].service_name` → retire (D3);
  `[render].template` → retire (own config fully generated);
  `[render].output_dir` → retire (fixed `<data>/rendered/live.json`);
  `[render].stats_port` → re-home to `[core].api_port` (default 15491);
  `[render].pool_inbound_tags` → retire (inbound tags are generated);
  `[render].pool_routes` → KEPT, re-homed under `[render]` unchanged (see S6);
  `[maintain].auto_restart` → retire (core restart is the core manager's job).
- S5 (Q8, AMENDED 2026-11-12): auto-update ON applies to the ASSAY-OWNED
  USER-LOCAL core only — deliberate reversal of the xray-raw frozen-core
  ruling, scoped to the binary assay itself installed at
  `~/.local/bin/xray`. A bound PRE-EXISTING system core and an explicit
  `[core].xray_bin` override make auto-update inert with a one-time loud
  INFO line. The W5 runbook restates that xray-raw's core is NEVER touched
  by assay.
- S6 (Q7): domain→balancer trust-wall routes survive in the own config
  (`[render].pool_routes` re-homed semantics unchanged: only these
  destinations may reach the pool, matched against the GENERATED inbound
  tags), placed above the catch-all; `check`'s RECOMMENDATION block re-points
  its output at the re-homed knob. Geosite-style routes get
  XRAY_LOCATION_ASSET wired to the managed asset dir at spawn.
- S7 (Q9): the generated config's log block = `loglevel: warning`,
  `access: none` by default (this machine's 272k-lines/8h journald-flood
  history), with a `[core].loglevel` knob; the core child's stderr is
  inherited into the assay-watch unit journal (long-lived child, no buffer
  capture); documented in W4.

## Architecture

### Process model

`assay watch` (assay-watch.service) spawns `xray run -c <data>/rendered/live.json`
as a child at start (bootstrap config per D7) and re-spawns/restarts it via the
core manager: start (if not running), stop, restart (activate-if-changed),
crash supervision (child exit → loud log + restart with backoff), shutdown
(daemon stop → graceful core stop via the existing WaitDelay-safe exec path),
singleton flock (S3). The daemon's READY=1 (Type=notify) fires once the
bootstrap core is reachable (S2).

### Config surface

New `[core]` section (TOML, repo-local config only — no env):

- `xray_bin` — path to the core binary; default = the owner-ruling
  resolution (user-local `~/.local/bin/xray` → existing system xray → the
  user-local install target; S1 as amended; auto-update inert for a system
  or overridden binary, S5 as amended).
- `auto_update` — bool, default true (D4 as amended; the assay-owned
  user-local binary only per S5).
- `update_interval` — duration, default "24h"; checked each maintenance wave.
- `socks_port` / `http_port` — defaults 10810/10811 (do NOT collide with the
  owner's xray-raw 10808/10809; config.example documents the distinction).
- `api_port` — default 15491 (owner's xray-raw keeps 15490).
- `per_country_inbounds` — bool, default false (D2 option): port base + one
  socks inbound per alive-country balancer, tags `in-<cc>`.
- `rollback_strikes` — int, default 3 (D8).
- `loglevel` — string, default "warning" (S7).

Retired/re-homed: see S4 enumeration. Retired keys parse-and-warn (S4); the
daemon never fails to start on them.

### Render target (own live config)

One rendered artifact per wave: `<data>/rendered/live.json`. Structure:
inbounds (socks/http [per-country]), outbounds (direct/block + pool), routing
(domain policy rules per S6 above the catch-all; catch-all → `pool_all`
leastLoad when a pool exists, → `block` in the bootstrap/empty-pool posture per
D7; pool routes only when per-country is on), balancers (as today), observatory
(in-client coverage of pool balancers), stats/API on `api_port`. Activation
gate unchanged: `xray run -test` before replace, dated backup, replace, core
restart, health check (socks dial + one balanced outbound fetch), loud diff
summary; failed health checks feed the D8 strike counter.

### Install / core lifecycle

`assay install` (configless or -c): binary self-copy, config materialize 0600
never-overwrite, unit write, THEN core bootstrap per the owner-ruling order:
an existing user-local or system binary is bound (no download; the system one
warns non-blocking below the floor); with neither, the matching release asset
(GitHub XTLS/Xray-core, linux-amd64 default) downloads, sha256-verifies
against the release checksums, and installs ATOMICALLY to `~/.local/bin/xray`
(user-writable — no elevation anywhere; the previous binary is preserved as
`~/.local/bin/xray.previous`; the release assets materialize in
`<data>/share/xray` and the spawn wires `XRAY_LOCATION_ASSET` there for the
assay-owned binaries). Auto-update (watcher stage): each wave re-runs the
binary resolution first (per-wave re-detection), then — for the assay-owned
user-local binary only — checks the latest release (respecting
`update_interval` and the floor), stages, verifies, atomic swap (keeping the
previous binary), core restart — all logged; failures never break the wave.

GRACEFUL MIGRATION (owner requirement 2026-11-12): the binary swap itself is
an atomic rename — zero downtime at the file level. For the CORE cutover the
chosen option is (a): the proven stop+start restart (~1-3s gap — the
documented downtime budget). Option (b), a true zero-downtime SO_REUSEPORT
handoff, is NOT achievable on Xray-core 26.x: the SockoptObject exposes NO
reuseport field (verified against the sockopt reference,
xtls.github.io/config/transports/sockopt.html — mark/tcpMaxSeg/tcpFastOpen/
tproxy/tcpcongestion/customSockopt etc. only; `customSockopt` can set raw
socket options but there is no listen-fd handoff or drain mechanism between
xray processes), so two live cores cannot share the inbound safely. The
binary-level rollback mirrors the config-level D8: K consecutive failed
health checks restore `~/.local/bin/xray.previous` over the binary FIRST
(atomic rename), then the `-test` gate, config restore and restart run on
the known-good binary; loud journal lines at every step. Manual:
`assay xray-update` (same surface, forced). Uninstall: remove unit + binaries
+ (opt-in) data dir.

### CLI surface changes

`render` / `activate` re-targeted (own config; activate refuses loud under the
daemon's flock per S3, spawns transiently only daemon-less); `watch` gains the
core manager; `install`/`uninstall`/`xray-update` as above; `status` gains core
state (PID, version, uptime, inbounds, strike count); `check`/`list`/`fetch`/
`parse`/`filter`/`probe`/`select`/`maintain` behaviorally unchanged (S1 rewires
their binary resolution).

## Migration runbook (owner laptop, W5)

1. Deploy new binary; stop assay-watch (activations into xray-raw cease).
2. Rebuild the clean xray-raw config from the live one: keep
   direct/block/fox-proxy/proxy-0/proxy-1, `best_rtt` balancer, the owner's
   routing rules and inbounds; drop every `pool-*` outbound, `pool_*` balancer,
   pool route, pool observatory subject, and the assay stats block; add one
   socks outbound `assay-pool` → 127.0.0.1:10810; add one routing rule above
   the catch-all routing the desired markers through `assay-pool` (owner picks
   the markers — default none, all traffic stays on Germans until he opts in).
   `xray run -test` gate + dated backup, restart xray-raw, health check.
   xray-raw's core binary is NEVER touched by assay (S5 restated).
3. Start assay-watch (own-core mode): bootstrap core spawn (D7 posture) +
   first wave; verify socks 10810 alive through a pool node and `assay status`
   core block.
4. Verify the owner's box end-to-end (Germans default unchanged; assay pool
   reachable on demand).

## Waves

- W1 core-manager + own render target: `[core]` config surface, core manager
  package (flock, spawn/supervise/restart/health/rollback per D7/D8), render
  re-target (own inbounds + routing + D7 posture), activate rework (S3), tests
  (dynamic repro: core child lifecycle, strike→rollback).
- W2 install + core lifecycle: download/sha/atomic-install, auto-update path
  (S5), `xray-update` rework, uninstall, tests.
- W3 external-mode removal: template seam, foreign-restart allowlist, S4
  retire/re-home list, parse-and-warn loader contract, test rewrite,
  grep-exhaustive zero-remnant acceptance.
- W4 docs: README standalone story, config.example, DESIGN sync.
- W5 owner-laptop migration (runbook above) + deploy.
- W6 re-publication: flip public after owner reviews the product README.

## What's left to the builder

- Exact package layout for the core manager (internal/core) and its seams.
- Release-asset naming/parsing for the core download (verified against
  XTLS/Xray-core release manifests at implementation time).
- Test seams for child-process supervision (hermetic fake binary pattern
  already exists for temp instances — reuse).
- Log/journal line grammar for the core lifecycle (match existing style).
- The 26.3.27 frozen-core landmine (observatory busy-loop pre-#6666) applies
  to the managed core: pin the minimum known-good core version for the
  observatory shapes assay renders; auto-update respects the floor.
