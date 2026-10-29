# 🌍 public_vpn

<div align="center">

## 🛰️ public_vpn — a geo-diverse location pool for your xray client

*Fetch, probe, geo-enrich, rank, render, and maintain a pool of third-party public proxy nodes — explicitly routed, never your default route.*

[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Tests](https://img.shields.io/badge/tests-520-brightgreen?style=for-the-badge&logo=go&logoColor=white)](#-testing)
[![xray-core](https://img.shields.io/badge/xray--core-26.3.27-red?style=for-the-badge)](https://github.com/XTLS/Xray-core)
[![Plugins](https://img.shields.io/badge/sources-Lua%20plugins-blue?style=for-the-badge)](#-lua-plugins-the-source-ingest-layer)
[![Daemon](https://img.shields.io/badge/daemon-publicvpn%20watch-teal?style=for-the-badge)](#-the-watch-daemon)
[![Lint](https://img.shields.io/badge/golangci--lint-0%20issues-success?style=for-the-badge)](.golangci.yml)

[🚀 Quick Start](#-quick-start) · [🗺️ Pipeline](#️-pipeline) · [🧭 maintain](#-what-happens-on-maintain) · [📦 install](#-self-install--uninstall) · [🔒 Security](#-security-model) · [⚙️ Configuration](#️-configuration) · [📖 Design](DESIGN.md)

</div>

---

## 📑 Table of Contents

- [✨ What It Does](#-what-it-does)
- [🗺️ Pipeline](#️-pipeline)
- [🔌 Link & Transport Support](#-link--transport-support)
- [🧭 What Happens on `maintain`](#-what-happens-on-maintain)
- [🧩 Lua plugins (the source-ingest layer)](#-lua-plugins-the-source-ingest-layer)
- [👀 Pool inventory (`list`)](#-pool-inventory-list)
- [🌍 Site check (`check`)](#-site-check-check)
- [🛰️ Exit-geo self-report (W11 + W16 HTTPS rung)](#️-exit-geo-self-report-w11--w16-https-rung)
- [⚖️ Pool balancers (W16)](#️-pool-balancers-w16)
- [📂 Project Structure](#-project-structure)
- [🚀 Requirements](#-requirements)
- [⚡ Quick Start](#-quick-start)
- [📦 Self-install / uninstall](#-self-install--uninstall)
- [⏱️ The watch daemon](#️-the-watch-daemon)
- [🔒 Security Model](#-security-model)
- [⚠️ Landmine Warnings](#️-landmine-warnings)
- [⚙️ Configuration](#️-configuration)
- [📋 Config resolution (`-c` is optional)](#️-config-resolution--c-is-optional)
- [✅ Testing](#-testing)
- [🗺️ Roadmap](#️-roadmap)

## ✨ What It Does

`publicvpn` is a single-binary Go pipeline that keeps a **cold base** (`geo-base.jsonl`: country / city / ASN / ISP per node) of hundreds of third-party public proxy nodes and promotes a small **active core** (20–25, expandable to 40 for city coverage) into your xray client config. Every stream-based pool outbound carries the owner-mandated hardening (`sockopt.tcpMaxSeg: 1440`, TLS fingerprint `firefox`; hysteria2 outbounds are QUIC/UDP and carry the fingerprint without the TCP-only clamp), every link parameter passes through **1:1** — nothing is rewritten behind your back.

**The pool never becomes the default route.** It participates only in routing rules you explicitly configure (`[render.pool_routes]`); everything else — including the catch-all — stays on your own nodes. Empty location → traffic dropped (block), never direct: every pool balancer carries `fallbackTag: "block"`, so a location with no healthy candidate blackholes instead of falling back.

## 🔌 Link & Transport Support

The render surface targets **your pinned core (xray 26.3.27)** — every field name and every "removed" verdict below is verified against both the real binary (`xray run -test`) and the tagged Xray-core source. Links carrying a transport this core cannot express **fail the render loud with the param named** — never a silent rewrite (L9).

| Link `type=` | Rendered as | Notes |
| :-- | :-- | :-- |
| `tcp` / `raw` | `tcp` + `tcpSettings` | `headerType=http` renders the http-obfs request block (`host`/`path` from the link); other header types refused loud |
| `ws` / `websocket` | `ws` + `wsSettings` | `path`, independent `host` (the deprecated `headers.Host` spelling is not emitted), `ed` appended into the path query (that is where the core reads it), `ehs` accepted only as the fixed `Sec-WebSocket-Protocol` |
| `httpupgrade` | `httpupgradeSettings` | `path`, `host`, same `ed`-in-path mechanics |
| `grpc` | `grpcSettings` | `serviceName`; `mode=multi` → `multiMode` (deprecated transport — the core warns but accepts) |
| `kcp` / `mkcp` | `kcp` (maximally bare — **no `kcpSettings` block is rendered at all**) | **`seed`/`headerType` are build-fatal on 26.3.27** — the mKCP header/seed feature was removed (migrated upstream to finalmask/mkcp-original/mkcp-aes128gcm), so a link carrying either key fails the render loud; any other kcp-namespaced param lands in the drop report |
| `xhttp` / `splithttp` | `xhttp` + `xhttpSettings` | `mode`, `path`, `host`, and an `extra` JSON-object passthrough (validated) |
| `http` / `h2` / `h3` | **refused loud** | the HTTP/2 transport was removed from 26.3.27 (→ XHTTP stream-one) |
| `quic` | **refused loud** | removed from 26.3.27 (→ XHTTP stream-one H3) |
| *(scheme)* `hysteria2` / `hy2` | `hysteria` outbound (version 2) + `hysteriaSettings` | a real hysteria2 client exists in 26.3.27 (verified against the binary + tagged source): `security=tls` renders unconditionally (the QUIC dialer refuses to run without it), the credential rides `hysteriaSettings.auth`, `sni`/`pinSHA256`/`ech` map 1:1 to `tlsSettings` (`pinnedPeerCertSha256`/`echConfigList`), fingerprint `firefox` applies, and **no `tcpMaxSeg`** renders (TCP-gated upstream; QUIC dials UDP). `obfs`/`obfs-password` (salamander) **fail the render loud** — the core has no salamander. Port-hopping links (`:123,5000-6000`) are malformed at parse. |

Security layers: `none` (no TLS settings rendered), `tls` (`sni`→`serverName`, `alpn`, `fp` overridden to `firefox`), `reality` (`pbk`/`sid`/`spx`/`pqv`→`mldsa65Verify`, fingerprint `firefox`; only with `tcp`/`xhttp`/`grpc` — the core's own restriction, enforced at render time).

Protocols: `vless`, `vmess` (incl. the JSON vocabulary: `net`/`type`/`host`/`path`/`scy`/`aid`, header datum preserved), `trojan`, **`ss`**, and **`hysteria2`** (with its documented `hy2://` alias) — parsed always, **accepted only when allowlisted** in `[filter].protocols` (default `vless,vmess,trojan`; ss and hysteria2 are opt-in). Shadowsocks renders as a `shadowsocks` outbound (`servers[0]` with `method`/`password` 1:1); SIP003 **plugin params cannot render** — the 26.3.27 shadowsocks outbound has no plugin support — so an ss link carrying `plugin=` fails the render loud. hysteria v1 links (`hysteria://`) stay rejected at parse: the core only speaks hysteria2 (version 2).

## 🗺️ Pipeline

```mermaid
flowchart LR
    A["🌐 fetch"] --> B["📜 parse"] --> C["🛡️ filter"]
    C --> D["🩺 probe"]
    D --> E["🌍 geo"]
    E --> F["📊 stats"]
    F --> G["✂️ prune"]
    G --> H["🏆 select"]
    H --> I["📝 render"]
    I --> J{"⚡ rendered ≠ live?"}
    J -- "no" --> K["✔ no changes"]
    J -- "yes" --> L["🧪 xray -test gate"]
    L -- "fail" --> M["🛑 abort, live untouched"]
    L -- "pass" --> N["💾 backup + atomic activate"]
```

| Stage | Binary | What it owns |
| :-- | :-- | :-- |
| 🌐 fetch | `publicvpn fetch` | run the **Lua source plugins** (W10): each plugin fetches and iterates, hands raw links to Go; the results land in the cache + manifest exactly like the old file downloads — parse/dedupe are untouched |
| 📜 parse | `publicvpn parse` | base64/URI decode of `vless\|vmess\|trojan\|ss\|hysteria2(hy2)`, normalize, dedupe by identity hash |
| 🛡️ filter | `publicvpn filter` | `[filter].protocols` allowlist (default `vless,vmess,trojan`), keep `reality\|tls` only, drop `allowInsecure` (policy knob), drop private hosts, per-source caps |
| 🩺 probe | `publicvpn probe` | out-of-band `xray-knife`: liveness, RTT, tunnel exit IP (D8), optional `-S` speedtest |
| 🌍 geo | `publicvpn geo` | **W11 per-node self-report + W16 HTTPS rung**: every alive node asks geo endpoints through its own tunnel (exit-truth geo; the old aggregate batch clamp is retired) |
| 📊 stats | `maintain` sub-step | `xray api statsquery` poll → per-outbound uplink/downlink into the cold base |
| ✂️ prune | `maintain` sub-step | dead/ttl-stale-orphan removal with a `.bak-<ts>` backup |
| 🏆 select | `publicvpn select` | rank (alive → checks → speed), per-group cap K (unknown-geo nodes share one `unknown` group — W16), soft cap N with city expansion (D7) |
| 📝 render | `publicvpn render` | template + pool outbounds + balancers (country / city / `pool_unknown` / `pool_all`) + Plan A observatory, L1-gated |
| ⚡ activate | `publicvpn activate` | `-test` gate → date-stamped backup → atomic replace. **Never restarts the service.** |

## 🧭 What Happens on `maintain`

One `publicvpn maintain` invocation runs the whole refresh wave end-to-end:

1. **fetch** — resolve current source paths and download changed files into the cache.
2. **parse** — decode the cached bodies into normalized node records.
3. **filter** — apply the ingest security filter; the survivors are the wave's reference set.
4. **probe** — out-of-band xray-knife liveness + exit-IP discovery (skipped by `--skip-probe`).
5. **geo** — per-node in-tunnel self-report: every alive node asks ip-api through its own tunnel (fallback = DoH view; skipped together with probe).
6. **stats** — poll `xray api statsquery -pattern "outbound>>>pool-" -reset=true` on `127.0.0.1:<stats_port>` and fold the per-outbound byte deltas into `geo-base.jsonl`. Failures are classified: before your first activation (target lacks the rendered api/stats block, or the endpoint refuses connections) you get an **INFO** — *"stats will be available after the first activation + service restart; skipping accounting this wave"* — never a warning. A reachable endpoint that responds unexpectedly is a **WARNING** (accounting must not block node refresh). A fold/write failure into the geo-base **fails the wave loud** — traffic data loss is never silent. CLOSED RULING (owner, round-7 M1): a strict/stats-fatal mode was rejected — stats poll failures are warning-class and **never** fail a wave; the write-loss LOUD exception (data integrity) is the only carve-out, and it stays.
7. **prune** — remove records that are dead beyond `[maintain].prune_dead_after` (default 48h) or that rank's TTL already refuses *and* whose source dropped; every removal pass leaves `geo-base.jsonl.bak-<ts>` next to the store.
8. **select** — re-rank from the cold base; rank's TTL freshness gate drops stale-alive records on its own, so `--skip-probe` waves reselect safely from cold data.
9. **render** — rebuild the full client config (template + pool + balancers + observatory, stats/policy ensured).
10. **activate-if-changed** — if the rendered bytes equal the live config: `no changes`, nothing touched, nothing restarted. Otherwise the W3 activate path runs: `xray run -test` gate → date-stamped backup → atomic replace → **auto-restart (W13)** — the daemon restarts the live client itself (`systemctl --user restart xray-raw.service`, exactly once per real activation) and then runs the post-restart health check (`is-active` + the socks port from the activated config). `[maintain].auto_restart` defaults to **true** (hands-off — zero manual restarts ever); an explicit `false` restores the old semantics: the command prints the restart hint instead. A failed restart or a failed health check is **loud** (the wave completes as `DONE_WITH restart-failure` / `DONE_WITH health-failure` — the gated new config is already on disk; the report names the backup to restore from, and nothing is auto-restored).

`--no-activate` stops after the render+diff. `--speedtest` adds the throughput measurement explicitly (it is **on by default since W10** — every wave carries `-S` speed data). The daemonized form of this wave is [`publicvpn watch`](#️-the-watch-daemon).

## 🧩 Lua plugins (the source-ingest layer)

Since W10 the sources are **Lua plugins**, not config tables. Every `.lua` file in `[plugins].dir` is one source: it fetches and iterates, hands raw links to Go as `publicvpn.node` records, and Go keeps owning URI normalization, parsing, rejection counting, and dedupe (the same `parse`/`filter` pipeline as before — plugins only discover). The runtime is [gopher-lua](https://github.com/yuin/gopher-lua) (pure-Go Lua 5.1, no cgo).

**Lifecycle:** the built-in plugins — `matin`, `epodonios`, `radikal`, `haker` (the four former Go-discovered sources) and `stintikvpn` (the network-API reference plugin) — materialize into the plugins dir on **first run only**. Owner edits and removals persist (delete the whole dir to restore all defaults). A plugin file present = source **active**; remove or rename it (e.g. `haker.lua.off`) to disable. The `publicvpn watch` daemon hot-reloads the dir: a new provider is a new `.lua` file — no rebuild, no restart.

**Plugin contract:** the chunk itself must stay side-effect-free and RETURN its discover `function() → nodes`. All fetching happens inside that function (the load-time check runs the chunk with the network surface loud-disabled — a plugin doing work in the chunk fails the load with a clear error).

### Plugin circuit breaker (`[plugins].max_consecutive_failures`)

A plugin whose run keeps failing is auto-disabled instead of failing every wave forever (owner spec: «автоотключение неотвечающих плагинов, 5 ошибок по дефолту отключают его»):

- A **failure event** is a run-timeout abandonment or a loud run error. A **successful run resets** the plugin's consecutive-failure counter to zero.
- After `max_consecutive_failures` consecutive failures (default **5**) the plugin is **auto-disabled**: the wave logs `plugin <id> DISABLED after N consecutive failures (breaker limit N)` loud, and the plugin is **excluded from subsequent wave snapshots**.
- The counter also resets (and a disabled plugin is **re-enabled**) when the plugin **file is edited** — the watchdog reload = you touched it = fresh chance. Removing the file clears the state too.
- `0` = **unlimited**: the breaker is off, plugins are never auto-disabled (owner no-floor ruling — the counter still accumulates for observability).
- **Where the state lives:** in the plugin registry. A one-shot run (`publicvpn fetch`) gets a fresh registry per process — and each plugin runs at most once per wave, so at any limit **≥ 2** a one-shot wave can never trip the breaker by itself (an explicit `max_consecutive_failures = 1` is the exception: it trips on the very first failure, one-shot wave included). The `watch` daemon shares its watchdog-maintained registry across waves, so counts and disables **persist for the daemon's lifetime**. There is no state file by design: a daemon restart is deliberately a fresh chance (you restart after fixing plugin files; a systemd WatchdogSec restart behaves the same).
- Every wave lists currently disabled plugins: `breaker: N plugin(s) disabled — <ids> (a file edit reloads and re-enables)`.

### Host API reference

| Function | Signature | Notes |
| :-- | :-- | :-- |
| `publicvpn.node` | `node{ raw, source?, remark?, scheme?, host?, port? }` | **`raw` is REQUIRED** (a share link) — Go owns parsing. `source` regroups the node under another source id (`[filter].source_cap` granularity; default = the plugin id). `remark` names the node when the link has no fragment. `scheme`/`host`/`port` are optional pre-parse hints (validated, reported; the parsed URI always wins). `port` must be 1–65535 when present. |
| `publicvpn.http` | `http{ url, method?, headers?, body?, timeout?, max_redirects?, max_body_bytes? } → { status, headers, body }` | Defaults: `GET`, 30s timeout, 10 redirects, 8 MiB body cap. Non-2xx is a **value**, not an error — plugins decide. Network errors and body-cap overruns fail loud. Multi-value headers join with `", "`. **Proxy=nil by construction** (landmine L5 — plugin traffic never rides your own VPN). |
| `publicvpn.github_files` | `github_files{ repo, include?, manifest? } → { path, content }[]` | The D9 discovery helper (GitHub contents API, or `manifest` + raw downloads; mirrors via `[fetch].api_base`/`raw_base`, token via `[fetch].github_token`). A truncated tree listing or zero include matches fails loud. |
| `publicvpn.base64` | `encode(s)`, `decode(s)` | `encode` = standard. `decode` accepts std + URL-safe alphabets, padding optional (mirrors the parser's flexible decode). |
| `publicvpn.json` | `decode(s) → table`, `encode(t) → string` | Objects ⇄ tables, arrays ⇄ sequences; decode errors fail loud. |
| `publicvpn.log` | `log(a, b, …)` | One prefixed line into the stage/daemon log. (`print` is stripped — the sandbox has no stdout.) |

**Sandbox:** the Lua state opens only `base`, `string`, `table`, `math` — **no `os`, no `io`, no `package`, no `debug`**; `dofile`/`loadfile`/`print`/`require`/`module`/`newproxy` are stripped from `_G`. Plugins are trusted local code, but the callable surface is exactly the table above — touching `os` or `io` fails loud with the documented nil-index error. The sandbox bounds the *callable surface*, not the *compute*: CPU and memory inside a plugin are unbounded by design — see the [Security Model](#-security-model) for the runtime caps around that (run timeout → abandonment, `Restart=always`, `WatchdogSec`).

> ⚠️ **gopher-lua v1.1.2 VM bug:** a `for … in (fn() .. "x"):gmatch(…)` loop — an *inline call-chain expression* feeding the iterator — panics with a nil dereference (even for pure-stdlib `pcall` results). Assign the loop text to a local first, then iterate. All built-in plugins follow this; `TestGopherLuaInlineGmatchWorkaround` pins it.

### Minimal plugin

```lua
-- mysource.lua — drop into ~/.local/share/publicvpn/plugins/, done.
local REPO = "Owner/v2ray-configs"
local INCLUDE = { "sub/vless.txt" }

local function body_lines(body)
  local trimmed = body:gsub("^%s+", ""):gsub("%s+$", "")
  if trimmed:find("://", 1, true) then return body end
  local ok, decoded = pcall(publicvpn.base64.decode, trimmed)
  if ok and decoded:find("://", 1, true) then return decoded end
  return body
end

local function collect()
  local nodes = {}
  for _, file in ipairs(publicvpn.github_files{ repo = REPO, include = INCLUDE }) do
    local text = body_lines(file.content) .. "\n"   -- assign BEFORE gmatch (see VM note)
    for line in text:gmatch("([^\r\n]*)\n") do
      line = line:gsub("^%s+", ""):gsub("%s+$", "")
      if line ~= "" and not line:find("^#") and not line:find("^//") then
        nodes[#nodes + 1] = publicvpn.node{ raw = line }
      end
    end
  end
  return nodes
end

return collect
```

### The StintikVPN reference plugin (network API walkthrough)

`stintikvpn.lua` is the full-flexibility demo — plain HTTP + JSON, no GitHub helper:

1. `publicvpn.http{ url = DATA_URL }` fetches `https://raw.githubusercontent.com/Stintik-123/StintikVPN/main/docs/data.json` (the curated-subscription index; non-200 → loud `error()`).
2. `publicvpn.json.decode` parses it; the loop iterates `data.subscriptions`.
3. Each subscription URL is nested-fetched **under `pcall`** — one dead upstream is logged (`publicvpn.log`) and skipped, the rest still land (the pipeline's per-plugin continuation handles the rest).
4. Every candidate line becomes `publicvpn.node{ raw = line, remark = sub.id }`.

Run it against the real upstreams (documented live test): `env -u http_proxy -u https_proxy go test -tags live -run TestLive ./internal/plugins/`.

## 👀 Pool inventory (`list`)

```bash
publicvpn list                 # active core by country: flag, code+name, nodes, alive, median RTT
publicvpn list --cities --all  # + indented city sub-rows (D5 view) + the cold base section
```

Read-only display over the data `status`/`check` already use (selection + probe results + geo-base) — countries ordered by node count, liveness from the latest probe wave, `--cities` expands multi-city countries, `--all` appends the cold base grouped the same way. Unknown-geo nodes in the selection render as their own `🏳 unknown` row, and the `balancers:` line names the routing targets the current selection will produce (W16: `pool_all`, country balancers, `pool_unknown` when present). Colors follow the same `auto`/`NO_COLOR`/`--no-color` contract as `check`; the table reuses the check renderer (one table implementation in the repo).

### `--json` (machine-readable twin)

`publicvpn list --json` prints exactly **one JSON document** on stdout — no human config-source line, no table banners, no color codes (the W12 provenance lives inside it as the `config` object). The data is the same the table renders, same aggregation and ordering (the city sub-rows obey the table's suppression rule; the W16 unknown row and the `balancers:` line data serialize as structured fields), and is **pinned byte-for-byte by a golden test**. Schema:

| Field | Type | Meaning |
| :-- | :-- | :-- |
| `generated_at` | string (RFC 3339) | the selection's generation timestamp |
| `config` | `{source, path?}` | W12 provenance: the resolved config source (`path` omitted when configless) |
| `selection` | `{path, nodes}` | the selection file read and its node count |
| `countries[]` | array | the active core grouped by country, table sort order; unknown-geo nodes form their own entry with `code` `""`, `name` `"unknown"`, flag `🏳` (the same row the table renders) |
| `countries[].code` | string | ISO 3166-1 alpha-2, upper case; `""` = the unknown-geo pseudo-group (not an ISO code) |
| `countries[].name` / `.flag` | string | English short name / flag emoji (`"unknown"` / `🏳` for the unknown group) |
| `countries[].nodes` / `.alive` | int | node count / alive count (latest probe wave truth) |
| `countries[].median_rtt_ms` | number | median RTT of nodes with a positive RTT (`0` when none) |
| `countries[].cities[]` | array, `--cities` only | city sub-rows (`city`, `nodes`, `alive`, `median_rtt_ms`) — the exact rows the table renders (a single-city country gets none); omitted without `--cities` |
| `cold_base` | object, `--all` only | `{path, records, countries[]}` — the cold base grouped the same way |
| `balancers[]` | array | the structured W16 routing targets (`pool_all` / `pool_<cc>` / `pool_unknown` with `nodes` counts) — the data behind the table's `balancers:` line, same aggregation |

## 🌍 Site check (`check`)

```bash
publicvpn check nyaa.si https://speed.cloudflare.com/__down?bytes=25000000 --top 10
publicvpn check nyaa.si --countries NL,DE --attempts 3 --save reports/nyaa.json
```

For picky sites that open only from specific countries/cities/ASNs, `check` answers **"в каких странах/городах лучше держать матчинг-рулы"**: it drives the URL through EVERY pool node — each through its own **temporary single-node xray instance** (managed binary, socks inbound on a free `127.0.0.1:18xxx` port, the node's outbound built by the same `render.BuildOutbound` the live renderer uses **with the same hardening** — `tcp_max_seg` emitted mandatorily and the TLS fingerprint applied, straight from `[render]`) — and ranks the pool by how well each location actually serves the site. Resolution happens at the **exit** (`socks5h` semantics: hostnames ride the tunnel, never pre-resolved locally), and a supplementary `dns.google/resolve` query **through the tunnel** reports the IPs the exit's resolver sees (labeled `doh-via-exit`).

- **Per-attempt diagnostics** via `httptrace`: connect, TLS handshake (explicit probe, negotiated version reported), TTFB, total ms, bytes, avg speed — plus the full redirect chain and final URL.
- **Blockpages are classified, never silently successful**: `403/451/429/5xx` → `blocked-http`; a tiny 2xx body carrying a known block signature (Cloudflare `error code: 1015/1020`, Imperva, "Access Denied"…) → `blocked-page`. A node failing TLS for the target is a **distinct failure class** (`tls-fail`).
- **Geo summary + recommendation**: per-URL table over nodes, then country and city groups with success rate / median / avg ms / avg speed, and an explicit **recommendation block** — best countries/cities for matching rules for THIS url (feed the winners into `[render.pool_routes]`).
- **Read-only by construction**: the cold base and the live client are never touched, nothing is rendered or activated, all dialing is out-of-band. Liveness comes from the last probe wave — a staleness hint prints when the data is older than `[geo].ttl`.

| Flag | Default | Meaning |
| :-- | :-- | :-- |
| `--countries` | *(all)* | comma-separated ISO codes to filter the pool |
| `--limit` | `0` (all alive, ceiling 60) | max nodes to test |
| `--attempts` | `3` | HTTP attempts per node per URL |
| `--timeout` | `15s` | per-request timeout |
| `--top` | `10` | geo-summary/recommendation rows per block |
| `--concurrency` | `4` | parallel temp xray instances (each is a full process — keep modest) |
| `--with-dead` | off | include nodes not alive in the last probe |
| `--color` | `auto` | `auto` (colorize only on a terminal) / `always` / `never`; `NO_COLOR` forces auto off |
| `--no-color` | off | deprecated-friendly alias for `--color=never` (wins over a conflicting `--color`) |
| `--save` | *(none)* | write the JSON report under the data dir (relative path) or at an absolute path |

## 🛰️ Exit-geo self-report (W11 + W16 HTTPS rung)

The geo stage asks **every alive node about itself through its own tunnel** — no batch lookups, no shared rate budget:

1. The wave stands up ONE temporary single-node xray instance per alive node (the same `render.BuildOutbound`-hardened infrastructure the `check` stage uses: socks inbound on a free `127.0.0.1:18xxx` port, mandatory `tcp_max_seg`, TLS fingerprint; booted under the same serialized port-handout mutex, killed by exact PID). Every rung of the ladder below rides that SAME instance.
2. **Rung 1 — plain-HTTP ip-api self-report.** Through the instance it issues `GET http://ip-api.com/json/` — **no ip parameter**, so ip-api answers *"who is asking"*. The response is that node's exit geo (country / city / ISP / AS / proxy / hosting), observed through its own tunnel: the strongest possible D8 exit-truth evidence.
3. **Why the old limit disappeared in principle:** the batch era POSTed exit-IP groups from this box's one source IP against a 15 requests/min clamp. The self-report's requests originate from thousands of DISTINCT node exit IPs — each carries its own 45 req/min single-endpoint budget, and those budgets never pool. The retired batch knobs (`[geo].endpoint`, `[geo].batch_size`, `[geo].per_minute`) fail config load with a loud migration error naming the replacement. A small politeness pacing (≈10 request starts/s across the wave) remains — every external request start on every rung takes a pacer slot; courtesy toward nodes and the geo endpoints, not a rate-limit honor. ip-api's free tier stays **HTTP-only, non-commercial** — personal use of public geo data satisfies it.
4. **Rung 2 — HTTPS self-geo (W16).** A rung-1 failure (reset / timeout / non-200 / `status=fail`) retries as `GET [geo].https_url` — default `https://ipinfo.io/json`, **keyless and TLS-only**, so an exit that blocks plain HTTP wholesale is rescued here (the class W11 could only offer the resolver-network DoH view). Same no-aggregate argument: ipinfo's free tier is limited per source IP, and every node is its own source; the ToS is personal-use — same footing as ip-api. The knob is a plain string: ANY https endpoint is accepted verbatim (structural https check only, no allowlist). **Field honesty:** the ipinfo free tier has no separate ISP field and no proxy/hosting flags — those are stored **empty**, with the `self-report-https` provenance marker naming the evidence class (an empty flag is never presented as a measured "not a proxy"); the composite `org` field (`AS24940 Hetzner Online GmbH`) splits honestly into `asn` + `asname`. Country / city / ip map 1:1 (field surface verified live 2026-10-29); the reported `ip` is treated as the freshest exit truth exactly like ip-api's `query`, churn logged loud.
5. **Rung 3 — DoH fallback.** Both self-geo rungs failing retries as the through-tunnel **DoH view**: `o-o.myaddr.l.google.com` TXT via `[geo].doh_url` (default `https://dns.google/resolve`) reveals the exit network's own DNS resolver IP, and the ip-api single-IP lookup of THAT IP rides the same tunnel — still a per-node source. Honest limitation: for exits behind big anycast public resolvers the fallback describes the resolver-operator's network — exactly what the provenance marker makes visible (and why rung 2 exists).
6. **Rung 4 — unknown (never a dropped node).** If every rung fails, the node keeps its record, stays usable, its previous geo evidence is preserved (store blank-fold), and the **unknown** class is reported loud in the wave log. Unknown-geo nodes are not wasted: they enter the selection under the `unknown` cap group and render into the `pool_unknown` balancer (below).
7. **Provenance in the cold base:** every record carries `geo_source` — `self-report` (the node's own ip-api answer), `self-report-https` (the node's own ipinfo answer, W16), `doh-fallback` (the indirect DoH view), or empty (no evidence) — so evidence quality is always visible next to the fields it describes. A self-report whose IP differs from the probe wave's exit IP (exit churn) wins the record with the freshest tunnel truth and prints a loud churn line.

## ⚖️ Pool balancers (W16)

The renderer emits a leastLoad balancer per location — plus two W16 targets — and **every one of them carries `fallbackTag: "block"`** (a location with no healthy candidate blackholes instead of falling back — the W9 security invariant, not a knob):

| Balancer | Selector | When it renders | Use case |
| :-- | :-- | :-- | :-- |
| `pool_<cc>` | `pool-<cc>-` | ≥1 node from that country selected | per-country routing (D5: leastLoad quality guarantee) |
| `pool_<cc>_<city>` | explicit tags | ≥2 live nodes in one city | city override (D5; single-node cities route by direct tag) |
| `pool_unknown` | `pool-xx-` | ≥1 unknown-geo node selected | the unknown-geo pseudo-location — nodes whose geo evidence failed stay usable and routable |
| `pool_all` | `pool-` | always, with ≥1 pool node | the **whole-pool** balancer: one route target spanning every country and the unknown group |

Unknown-geo nodes keep the D5 tag grammar intact with the `xx` pseudo-code (`pool-xx-NN` — not an ISO code, never confusable with a country); the grouping happens at render time over resolved geo presence, and the cold-base schema is untouched. Their cap treatment is symmetric: `unknown` acts as a cap group exactly like a country (D7 K applies). All four balancer kinds select only observatory-covered outbounds (the Plan A observatory's `pool-` prefix covers every pool tag — leastLoad ignores uncovered nodes), and `[render.pool_routes]` accepts all of them plus direct `pool-<cc>-NN` / `pool-xx-NN` tags — anything else fails the render loud (D6). `publicvpn list` shows the same picture: unknown nodes render as a `🏳 unknown` row, and a `balancers:` line names the targets the current selection will produce.

## 📂 Project Structure

```text
public_vpn/
├── cmd/publicvpn/          # main.go — cobra root wiring
├── internal/
│   ├── cli/                # command tree + maintain orchestration (stage seam) + watch daemon + install/uninstall + list
│   ├── config/             # strict-decode TOML (unknown keys fail loud), no env vars
│   ├── model/              # Node, GeoRecord (§5 cold-base schema), tag contracts (D5/D6)
│   ├── fetch/              # D9 dynamic discovery + raw downloads (L5 proxy-stripped) — now the plugins' github_files engine
│   ├── plugins/            # W10 Lua source plugins: gopher-lua sandbox, host API, registry, embedded defaults
│   ├── watchdog/           # W10 fsnotify hot-reload of the plugins dir (last-good semantics)
│   ├── parse/              # base64/link decoding (vless/vmess/trojan/ss) → normalized Node
│   ├── filter/             # ingest security filter (protocols allowlist + insecure policy)
│   ├── probe/              # xray-knife out-of-band runner (L5)
│   ├── geo/                # W11+W16 per-node self-report ladder (ip-api → HTTPS → DoH → unknown)
│   ├── checker/            # W8 site-to-location check: temp xray instances, socks5h client, blockpage classifier, geo summary
│   ├── stats/              # W4 statsquery poll + byte folding (L7-tolerant)
│   ├── prune/              # W4 dead/ttl-stale-orphan rules (reuses rank freshness)
│   ├── rank/               # select stage: ranking, caps D7, pool tags
│   ├── render/             # W3/W5/W16 renderer: transports, country/city/unknown/all balancers, L1 gate
│   ├── activate/           # -test gate + backup + atomic replace (never restarts)
│   ├── install/            # W5 self-install: binary copy, unit rendering, allowlisted systemctl seam
│   └── store/              # JSONL cold base, probe log, selection — all writes atomic
├── systemd/                # the watch-daemon unit TEMPLATE (single source of truth, go:embed'd by install) + embed.go
├── config.example.toml     # sanitized template (defaults + schema comments); real config.toml stays local, gitignored
└── DESIGN.md               # full design: decisions D1–D11, landmines, resource budget
```

## 🚀 Requirements

- **Go ≥ 1.27** to build (`go build -o publicvpn ./cmd/publicvpn`).
- **xray-core 26.3.27** present locally (the `-test` gate and the stats API both exec it; do **not** upgrade the core — L11).
- **xray-knife ≥ v10.1.0** on `PATH` or `[probe].path` for the probe stage.
- A working xray client config to use as the render template (read-only reference — the renderer never writes your template).

## ⚡ Quick Start

1. **Create `config.toml`** — start from [`config.example.toml`](config.example.toml) (sanitized defaults + schema comments; the real config is gitignored): copy it, set `data_dir` and your real `template`/`target` paths, review the `[plugins]` dir (the built-in Lua sources materialize there on first run — see [Lua plugins](#-lua-plugins-the-source-ingest-layer)), and declare your pool routes under `[[render.pool_routes]]` (D2: no routes → the pool is built but carries nothing; a route target is a rendered `pool_*` balancer or a direct `pool-<cc>-NN` outbound tag for single-node cities, D5). The config is **optional**: without it every data stage runs configless on built-in defaults (see [Config resolution](#️-config-resolution--c-is-optional)) — the file is required for `render`/`activate` and for `install`.
2. **`publicvpn fetch`** — run the Lua source plugins and cache their raw links.
3. **`publicvpn parse`** — decode the cached bodies into normalized node records.
4. **`publicvpn filter`** — apply the ingest security filter (reality/tls only); the survivors are the wave's reference set.
5. **`publicvpn probe`** — out-of-band liveness + exit-IP wave (add `--speedtest` for the weekly-style throughput measurement).
6. **`publicvpn geo`** — per-node self-report of the exit geo into the cold base.
7. **`publicvpn select`** — rank and cap the active set.
8. **`publicvpn render`** — render the full client config into `rendered/config.json`.
9. **`publicvpn activate`** — `-test` gate, backup, atomic replace of `[activate].target`, then restart your client when you are ready (`systemctl --user restart xray-raw.service` — the binary prints this hint, it never restarts by itself).
10. **`publicvpn maintain`** — from now on, one command — or the [`publicvpn watch` daemon](#️-the-watch-daemon) installed by `publicvpn install` — does the whole wave on schedule, activating only on real diffs.

## 📦 Self-install / uninstall

`publicvpn install` turns the machine you run it on into a maintained node:

1. **Binary** — copies the RUNNING binary (`os.Executable`) to `--bin-dir` (default `~/.local/bin`) as `publicvpn`: atomic write (temp → fsync → rename), mode `0755`. Re-running after a rebuild **is** the self-upgrade flow.
2. **Unit** — renders the **watch-daemon unit** from the repo template (`systemd/public_vpn-watch.service`, single source of truth via `go:embed`) into `--unit-dir` (default `~/.config/systemd/user`). `ExecStart` is `<installed binary> watch -c <the config path you passed>`; the unit carries `Restart=always` (a crashed daemon is back in 5s). Path rules unchanged: `--bin-dir` and `--config` may **not** contain whitespace (systemd argv-splits `ExecStart=`), while `--unit-dir` may (verified with `systemd-analyze verify`); only the manager's real search path is discovered by `daemon-reload` — a custom unit dir elsewhere needs `XDG_CONFIG_HOME` or symlinks.
3. **Legacy-timer migration (W5 → W10)** — if the old `public_vpn-refresh/speedtest` timer units are still on disk from a previous install, install **disables and removes them automatically** (a stale timer would fire waves concurrently with the daemon and stampede the probe origin). Zero owner steps; `status` flags leftover legacy units with a `LEGACY:` hint.
4. **Activation** — `systemctl --user daemon-reload`, then `enable --now public_vpn-watch.service`, pinned to an internal allowlist (no restarts of anything, no other units, ever — install never touches the live client; the daemon's only systemd surface is the W13 restart executor, see [Security Model](#-security-model)).

**The installed binary does not self-update.** `git pull` changes the source, not `~/.local/bin/publicvpn` — after pulling a new `main`, rebuild and re-install (`publicvpn install` = self-copy of the running binary), then `systemctl --user restart public_vpn-watch.service` so the daemon unit loads the new code. `publicvpn status` flags exactly this drift: a `STALE:` line appears whenever the running binary's content differs from the installed one.

```bash
go build -o publicvpn ./cmd/publicvpn
./publicvpn install                              # uses ~/.config/publicvpn/config.toml when it exists
./publicvpn install -c /absolute/path/to/config.toml   # explicit path wins; must exist
```

- **The config resolves install-style** (the unit embeds its path): explicit `-c` wins; else the home default `~/.config/publicvpn/config.toml` when present; otherwise install fails loud with guidance. The cwd default (`./config.toml`) is deliberately ignored by install — a daemon unit must reference a stable location. The rendered unit carries the resolved absolute path.
- **install never creates or moves config files** — the unit references the resolved path; keep that file in place.
- **No user systemd session?** install fails loud with an actionable message; pass `--no-systemd` to copy the binary only (unit skipped, documented in the output).
- **`publicvpn uninstall`** — the symmetric teardown: disables the daemon (and any legacy timers still present) → removes every known unit file (current + the W5-era names) → `daemon-reload` → report. User data (config, data dir, installed binary) is **kept by default**; `--purge` (explicit, destructive) also removes the config file and `[data_dir]` — and nothing else, in particular nothing xray-raw.
- **`publicvpn status`** — install state: installed binary, the watch unit, its enablement (read-only filesystem inspection), a `STALE:` hint when the running binary differs from the installed one (post-`git pull` rebuild without re-install — the exact stale-binary incident class), and a `LEGACY:` hint while old timer units survive. Detection reads the directories given via `--bin-dir` / `--unit-dir` (defaults identical to `install`: `~/.local/bin` and `~/.config/systemd/user`) — an install made with custom paths is tracked by passing the same values here (`status` keeps no state file, by design).

## ⏱️ The watch daemon

`publicvpn watch` is the long-running form of the pipeline (what `install` enables):

- **plugin watchdog** — fsnotify on `[plugins].dir`: add/modify of a `.lua` hot-swaps it into the registry (a broken file keeps the **previous version active** with a loud error naming the Lua failure); removal disables the source on the fly; `Close` is idempotent (double-close is a no-op) and a debounce callback that fires at the shutdown boundary re-checks the closed gate before touching the registry — no reload can begin after `Close` returns;
- **wave scheduler** — refresh waves every `[maintain].refresh_interval` (**default 1h since W10**), speedtest waves every `[maintain].speedtest_interval` (the speedtest tick runs the full wave with `-S` and covers the refresh); waves re-arm from completion, so they never overlap; the **first wave runs immediately** at start;
- **stats poll** — inside every wave (the existing stage cadence);
- **broken-plugin waves** — one dead provider never kills a refresh: per-plugin failures are loud, the healthy plugins carry the wave;
- **auto-restart + health check (W13)** — every gated activation restarts the live client through the byte-pinned executor and then verifies it came back (`is-active` + the socks port read from the just-activated config; a failed restart or health check is loud and names the backup — report-only, no auto-restore); `[maintain].auto_restart = false` prints the manual hint instead;
- **configless boot** — the daemon runs fine with no config file at all: data stages work from the built-in defaults (plugins dir under `~/.local/share/publicvpn/plugins`), while the render/activate stages fail loud at their boundary once per wave and the schedule keeps re-arming — the same wave-continues semantics as a broken plugin; stats accounting logs an INFO and skips;
- **graceful shutdown** — `SIGINT`/`SIGTERM` finish the current stage, flush, exit `0` (the unit's `Restart=always` is for crashes, not for config reloads).

```toml
[maintain]
refresh_interval = "1h"     # refresh wave recheck (W10 default 1h, floor 5m)
speedtest_interval = "168h" # speedtest wave recheck (default 168h = weekly, floor 5m)
```

**Changing a period or the plugins dir is a config edit + `systemctl --user restart public_vpn-watch.service`** — the daemon reads the config live; no re-install. Values below the 5-minute floor fail config validation loud.

## 🔒 Security Model

- **Every node operator is a man-in-the-middle by design.** They see your DNS queries, inner SNI, timing, and traffic volumes. REALITY's `pbk` proves the operator to you — it proves nothing about the operator to you.
- **Disposable traffic only.** The pool exists for geo-diversity: scraping, region checks, location-specific services. Logins, banking, and anything identity-bearing stay off it — your own nodes remain the default transport for everything else.
- **The trust wall is structural, not advisory.** Pool traffic reaches only `[render.pool_routes]` destinations; the template's existing rules (RU-direct, SMTP-block, torrent-direct) keep precedence, so the pool can never carry them even by mistake.
- **Ingest hygiene is a hard filter.** `allowInsecure=1` links, non-TLS transports, private/loopback hosts, and any scheme outside `[filter].protocols` never reach the cold base; forward-secrecy transports (`reality`/`tls`) only. `allow_insecure` defaults to **false** — the knob exists for explicit opt-in, but note this pinned core *removed* the `allowInsecure` feature entirely (→ `pinnedPeerCertSha256`), so an admitted link merely loses the param with a loud report entry.
- **PSK-only shadowsocks stays opt-in and second-class.** Plain `ss` (no TLS layer) is dropped by the security stance even when allowlisted; ss links carrying SIP003 `plugin=` params fail the render loud because this core cannot express them. Prefer `reality`/`tls` transports for pool nodes.
- **Fingerprint `firefox` only where a fingerprint can exist.** The client-side uTLS override applies to `tls`/`reality` settings; `security=none` has no TLS handshake, so an `fp` param there is reported in the drop report, not consumed.
- **The `-test` gate is unconditional.** A config that fails validation never replaces the live file — a crash-looping client is the one failure mode this pipeline refuses to create.
- **The daemon's systemd surface is two byte-pinned allowlist executors — nothing else.** `install` may run exactly its four pinned commands (daemon-reload, enable/disable `--now` on `public_vpn-*` units only); the W13 restart executor may run exactly `systemctl --user restart xray-raw.service` (the owner-ruled hands-off restart, once per real activation) and its read-only `is-active` verification. Any other unit, verb, flag, or scope fails loud before a process is spawned; guard tests pin the command sets byte-for-byte, the constructor call sites, and the whole-tree fact that no other production file spawns systemctl at all. Config knobs cannot widen this surface (`[activate].service_name` names the printed manual-restart hint only; the auto path is pinned to `xray-raw.service` and refuses anything else loud).
- **Lua plugins are trusted code: CPU and memory inside a plugin are unbounded by design.** The sandbox restricts *what a plugin can call* (`os`/`io`/`package`/`debug` stripped, host API capped), never *how much it can compute* — gopher-lua has no instruction-count or allocation budget, and that is the trusted-code contract, not a defense gap. The runtime caps around it: `[plugins].run_timeout` (default `120s`, explicit `0s` = unbounded) abandons a hung plugin **loud** and the wave continues with the healthy sources — the abandoned goroutine and its Lua state leak one per wave for a persistently hanging plugin (the documented detection-first trade-off; plugins are pure fetch, so nothing else is lost). A `string.rep` memory bomb crashes the whole process — the unit's `Restart=always` covers exactly that class. A daemon wedged by anything else stops its `sd_notify` watchdog pings, so systemd kills it at `WatchdogSec=300` and restarts it. The honest control for a plugin you do not trust is the one that has always existed: plugins are local files you edit — do not ship one you cannot vouch for.
- **Credentials stay local.** The rendered config and pipeline state are written `0600`; the repository ships no secrets and no pinned node URLs.

## ⚠️ Landmine Warnings

- **L1 — never render an observatory with an empty selector.** On xray-core 26.3.27 (pre-#6666) it busy-loops a CPU core; the renderer hard-refuses that shape on any pool state.
- **L4 — DNS goes through NSS.** Hostname resolution uses the system resolver; direct-to-public-DNS probing is dead on split-brain setups and must not be reintroduced.
- **L5 — strip proxy env on every network call.** The ambient `http_proxy` points at your own client; an unstripped fetch, probe, or stats dial silently tunnels through the very VPN it is measuring.
- **L6 — the ip-api aggregate clamp is retired (W11).** The batch-era clamp (≤100 IPs/POST, ≤15 batch requests/min, honor `X-Rl` or risk a 1-hour ban) applied to lookups made from THIS box's single source IP. The W11 self-report asks ip-api from EVERY node through its own tunnel — thousands of distinct source IPs, each with its own 45 req/min single-endpoint budget that never pools — so the aggregate limit is gone in principle. The retired `[geo]` batch knobs (`endpoint`, `batch_size`, `per_minute`) fail config load with a loud migration error. A small politeness pacing (~10 request starts/s across the wave) remains — courtesy, not a rate-limit honor. The free tier stays **HTTP-only and non-commercial** (personal use, public geo data — satisfied).
- The full list (L1–L12) with rationale lives in [DESIGN.md §8](DESIGN.md).

## ⚙️ Configuration

Everything lives in `config.toml` — unknown keys fail loud, there are no env-var overrides.

| Section | Owns | Notable keys |
| :-- | :-- | :-- |
| `[plugins]` | **W10: the source ingest is Lua plugins** | `dir` (default `<data_dir>/plugins`; built-ins materialize on first run; see [Lua plugins](#-lua-plugins-the-source-ingest-layer)), `run_timeout` (default `120s`, `0s` = unbounded — a plugin exceeding it is abandoned loud and the wave continues), `max_consecutive_failures` (default `5`, `0` = unlimited — the circuit breaker; see below). The old `[sources.*]` tables fail config load with a loud migration error. |
| `[fetch]` | download client (the plugins' `github_files` engine) | `timeout`, `retries`, `concurrency`, `api_base`/`raw_base` (mirrors), `github_token`; `cache_max_age` is a W5-era leftover — unused by the plugin ingest |
| `[http]` | shared HTTP client | `user_agent` — THE single pipeline User-Agent (fetch + geo) |
| `[filter]` | ingest security | `source_cap`, `protocols` (allowlist, ss + hysteria2 opt-in), `allow_insecure` (default `false`) |
| `[probe]` | xray-knife wave | `path`, `threads`, `url`, `speedtest` (**default `true` since W10** — every wave carries `-S`; `false` opts out), `check_preset`, `max_passed`, `skip_fresh_within` (skip re-probing fresh-passed nodes, `0s` = probe everything) |
| `[geo]` | W11 self-report (automatic — no knob) | `doh_url` (DoH fallback endpoint, default `https://dns.google/resolve`), `ttl`, `timeout`; the batch-era `endpoint`/`batch_size`/`per_minute` are removed and fail load loud |
| `[select]` | ranking caps (D7) | `per_country_cap`, `soft_cap`, `city_expand_threshold`, `ceiling`, `tie_band_rtt_tolerance` (city tie-break band width, default `1.2`) |
| `[render]` | client config render | `template`, `output_dir`, `stats_port`, `pool_routes`, `pool_inbound_tags` (validated against template inbounds — missing tag fails the render loud), `observatory_interval` (verbatim string, default `"60s"`), `tcp_max_seg` (mandatory on every pool outbound), `tls_fingerprint` (default `firefox`), `balancer_tolerance` (default `0.2`) |
| `[activate]` | activation | `target`, `xray_bin`, `asset_dir`, `backup_dir`, `test_timeout` (`0s` = no deadline), `service_name` (names the printed manual-restart hint; the W13 auto path is byte-pinned to `xray-raw.service`), `backup_keep` (N newest, `0` = unlimited) |
| `[maintain]` | wave schedule + the W13 auto-restart (the watch daemon reads it live) | `prune_dead_after` (default `48h`), `refresh_interval` (default **`1h`** since W10), `speedtest_interval` (default `168h`), `stats_timeout` (default `10s`), `prune_backup_keep` (`0` = unlimited), `auto_restart` (**default `true`** since W13 — the daemon restarts the live client after every gated activation and health-checks it; `false` = print the manual restart hint instead) |

**Validation policy (owner ruling, binding):** the 5-minute floor applies **ONLY** to `[maintain].refresh_interval` / `speedtest_interval` (W5, owner-approved). Every W6 knob (`cache_max_age`, `test_timeout`, `skip_fresh_within`, `stats_timeout`, `observatory_interval`, `tcp_max_seg`, `tls_fingerprint`, `balancer_tolerance`, `tie_band_rtt_tolerance`, `pool_inbound_tags`, `api_base`, `raw_base`, `user_agent`, `service_name`, `backup_keep`, `prune_backup_keep`) is **deliberately unbounded** — the only structural checks are value parsing, rejection of negative numbers (sign correctness), and the per-knob `0` semantics documented above. Values the xray core rejects fail the `-test` gate loud. Defaults preserve the pre-W6 behavior byte-for-byte.

## 📋 Config resolution (`-c` is optional)

The CLI does not require a config path. `-c/--config` is optional on every command, and exactly **one** source wins whole — there is no merging, ever. The first existing file in this order IS the configuration:

| Precedence | Source | Behavior |
| :-- | :-- | :-- |
| 1 | `-c <path>` (explicit) | wins **always**; the file must exist — a missing explicit path fails loud naming the path (no silent fall-through) |
| 2 | `~/.config/publicvpn/config.toml` | used when it exists (the home default) |
| 3 | `./config.toml` | used when it exists (keeps the repo/owner operational workflow working) |
| 4 | nothing found | **configless run** — built-in defaults (`data_dir = $XDG_DATA_HOME/publicvpn` when the env var is set to an **absolute** path — a set-but-relative value violates the XDG spec, is treated as unset, and prints a loud warning naming the violation; else `~/.local/share/publicvpn`; every other knob at its documented default; the plugins dir defaults under `data_dir`, so the embedded Lua sources materialize there on first run) |

Every command prints the resolved source as a `config:` line (`explicit -c <path>` / `home default <path>` / `cwd default <path>` / `configless (built-in defaults)`), and `status` carries the same line.

**What works without any config file** (pure defaults, out of the box): `fetch`, `parse`, `filter`, `probe`, `geo`, `select`, `check`, `list`, `status`, and the `watch` daemon's data stages. Stage commands that find no pipeline data yet fail with their normal loud "run the previous stage first" messages — that is data flow, not configuration.

**What REQUIRES a config (loud stage boundaries):**

- **`render`** needs a configured `[render].template`; **`activate`** needs a configured `[activate].target`. A configless run fails at the stage boundary — `configless mode cannot render — provide -c or a config at ~/.config/publicvpn/config.toml` (same wording for activate) — instead of silently defaulting those paths at the live client's config. Inside `maintain`/`watch` waves the boundary ends the wave loud while every earlier stage stays flushed and usable.
- **`install`** (and `uninstall --purge`) always needs a resolvable config — the daemon unit embeds the path — but resolves it install-style: explicit `-c` wins; else the **home default** when present; else loud with guidance. The **cwd default is deliberately not consulted** here: a unit must reference a stable location, never the directory the operator happened to stand in. With the home default, the unit carries the resolved absolute path.
- **`stats` accounting** (inside waves) degrades to INFO in configless mode (`no activate.target — stats accounting unavailable`) and the wave continues — accounting is never correctness.

## ✅ Testing

```bash
go test ./... -count=1        # full suite
go test -race -count=1 ./...  # race detector
golangci-lint run             # strict gate: 0 issues, caps disabled
```

The suite covers every stage with hermetic fixtures: the **W10 plugin matrix** — node-class contract (constructor/collector loudness with plugin + index attribution), the host network API over httptest (GET/POST/headers/redirect-caps/timeout/body-cap, a dynamic ambient-proxy-env test pinning **L5**), the `github_files` helper (include filters, manifest mode, truncated-tree loudness), the sandbox (os/io/require/dofile fail loud, at load-check AND at run time), defaults materialization (first-run-only; owner edits persist), watchdog hot-reload (add/modify/remove/broken-keeps-last-good, `-race`-pinned concurrent reload vs wave snapshots), the daemon scheduler (injected clock: tick order, speedtest-covers-refresh, failure survival, signal-driven clean shutdown), the StintikVPN fixture (nested fetches, per-subscription isolation) plus `live`-tagged real-source runs —: mocked-stage maintain orchestration (order, no-op-when-unchanged, failed `-test` gate), real-shaped `statsquery` responses (missing-counter tolerance included), prune boundaries and backup semantics, render golden regression (per-transport goldens **xray-validated against the real binary in the default suite**), the full W5 install matrix — unit files rendered from config intervals under a fake HOME, an injected systemctl executor (tests never execute systemd), an allowlist guard pinning the exact permitted commands, and idempotent re-install/purge semantics — and the W8 check matrix: URL normalization, blockpage classifier, aggregation/ranking math, a golden report (`--no-color`), an in-process SOCKS5 server pinning the **remote-DNS (`socks5h`) contract** behaviorally, engine integration (filters, limits, throttling, verdict classes, staleness hint), and a `live`-tagged real-xray temp-instance lifecycle test (`go test -tags live ./internal/checker/`) — plus the round-7 pins: the plugin circuit-breaker state machine (4 failures + success reset, 5 → disable, reload re-enable, unlimited mode, wave-level exclusion and loud lines), the `list --json` golden schema, the relative-`XDG_DATA_HOME` validation, watchdog `Close` idempotence and the post-close reload gate, and the gate's start-failure classification seam.

## 🗺️ Roadmap

- **VPS probe mode (D10)** — run the probe stage on a rented server and sync results back, trading home-IP footprint for infrastructure.
- **Panel-side integration** — explicitly out of scope; this pipeline is a local single-binary tool and stays one.
