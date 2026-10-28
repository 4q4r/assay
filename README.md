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
- [📂 Project Structure](#-project-structure)
- [🚀 Requirements](#-requirements)
- [⚡ Quick Start](#-quick-start)
- [📦 Self-install / uninstall](#-self-install--uninstall)
- [⏱️ The watch daemon](#️-the-watch-daemon)
- [🔒 Security Model](#-security-model)
- [⚠️ Landmine Warnings](#️-landmine-warnings)
- [⚙️ Configuration](#️-configuration)
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
| 🌍 geo | `publicvpn geo` | ip-api.com batch enrichment of exit IPs (rate-capped, L6) |
| 📊 stats | `maintain` sub-step | `xray api statsquery` poll → per-outbound uplink/downlink into the cold base |
| ✂️ prune | `maintain` sub-step | dead/ttl-stale-orphan removal with a `.bak-<ts>` backup |
| 🏆 select | `publicvpn select` | rank (alive → checks → speed), per-country cap K, soft cap N with city expansion (D7) |
| 📝 render | `publicvpn render` | template + pool outbounds + balancers + Plan A observatory, L1-gated |
| ⚡ activate | `publicvpn activate` | `-test` gate → date-stamped backup → atomic replace. **Never restarts the service.** |

## 🧭 What Happens on `maintain`

One `publicvpn maintain` invocation runs the whole refresh wave end-to-end:

1. **fetch** — resolve current source paths and download changed files into the cache.
2. **parse** — decode the cached bodies into normalized node records.
3. **filter** — apply the ingest security filter; the survivors are the wave's reference set.
4. **probe** — out-of-band xray-knife liveness + exit-IP discovery (skipped by `--skip-probe`).
5. **geo** — batch-enrich the fresh exit IPs via ip-api (skipped together with probe).
6. **stats** — poll `xray api statsquery -pattern "outbound>>>pool-" -reset=true` on `127.0.0.1:<stats_port>` and fold the per-outbound byte deltas into `geo-base.jsonl`. Failures are classified: before your first activation (target lacks the rendered api/stats block, or the endpoint refuses connections) you get an **INFO** — *"stats will be available after the first activation + service restart; skipping accounting this wave"* — never a warning. A reachable endpoint that responds unexpectedly is a **WARNING** (accounting must not block node refresh). A fold/write failure into the geo-base **fails the wave loud** — traffic data loss is never silent.
7. **prune** — remove records that are dead beyond `[maintain].prune_dead_after` (default 48h) or that rank's TTL already refuses *and* whose source dropped; every removal pass leaves `geo-base.jsonl.bak-<ts>` next to the store.
8. **select** — re-rank from the cold base; rank's TTL freshness gate drops stale-alive records on its own, so `--skip-probe` waves reselect safely from cold data.
9. **render** — rebuild the full client config (template + pool + balancers + observatory, stats/policy ensured).
10. **activate-if-changed** — if the rendered bytes equal the live config: `no changes`, nothing touched. Otherwise the W3 activate path runs: `xray run -test` gate → date-stamped backup → atomic replace. **The service is never restarted** — the command prints the restart hint for you.

`--no-activate` stops after the render+diff. `--speedtest` adds the throughput measurement explicitly (it is **on by default since W10** — every wave carries `-S` speed data). The daemonized form of this wave is [`publicvpn watch`](#️-the-watch-daemon).

## 🧩 Lua plugins (the source-ingest layer)

Since W10 the sources are **Lua plugins**, not config tables. Every `.lua` file in `[plugins].dir` is one source: it fetches and iterates, hands raw links to Go as `publicvpn.node` records, and Go keeps owning URI normalization, parsing, rejection counting, and dedupe (the same `parse`/`filter` pipeline as before — plugins only discover). The runtime is [gopher-lua](https://github.com/yuin/gopher-lua) (pure-Go Lua 5.1, no cgo).

**Lifecycle:** the built-in plugins — `matin`, `epodonios`, `radikal`, `haker` (the four former Go-discovered sources) and `stintikvpn` (the network-API reference plugin) — materialize into the plugins dir on **first run only**. Owner edits and removals persist (delete the whole dir to restore all defaults). A plugin file present = source **active**; remove or rename it (e.g. `haker.lua.off`) to disable. The `publicvpn watch` daemon hot-reloads the dir: a new provider is a new `.lua` file — no rebuild, no restart.

**Plugin contract:** the chunk itself must stay side-effect-free and RETURN its discover `function() → nodes`. All fetching happens inside that function (the load-time check runs the chunk with the network surface loud-disabled — a plugin doing work in the chunk fails the load with a clear error).

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

Read-only display over the data `status`/`check` already use (selection + probe results + geo-base) — countries ordered by node count, liveness from the latest probe wave, `--cities` expands multi-city countries, `--all` appends the cold base grouped the same way. Colors follow the same `auto`/`NO_COLOR`/`--no-color` contract as `check`; the table reuses the check renderer (one table implementation in the repo).

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
│   ├── geo/                # ip-api batch enrichment (L6 rate caps)
│   ├── checker/            # W8 site-to-location check: temp xray instances, socks5h client, blockpage classifier, geo summary
│   ├── stats/              # W4 statsquery poll + byte folding (L7-tolerant)
│   ├── prune/              # W4 dead/ttl-stale-orphan rules (reuses rank freshness)
│   ├── rank/               # select stage: ranking, caps D7, pool tags
│   ├── render/             # W3/W5 renderer: full transport surface, balancers, Plan A observatory, L1 gate
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

1. **Create `config.toml`** — start from [`config.example.toml`](config.example.toml) (sanitized defaults + schema comments; the real config is gitignored): copy it, set `data_dir` and your real `template`/`target` paths, review the `[plugins]` dir (the built-in Lua sources materialize there on first run — see [Lua plugins](#-lua-plugins-the-source-ingest-layer)), and declare your pool routes under `[[render.pool_routes]]` (D2: no routes → the pool is built but carries nothing; a route target is a rendered `pool_*` balancer or a direct `pool-<cc>-NN` outbound tag for single-node cities, D5).
2. **`publicvpn fetch`** — run the Lua source plugins and cache their raw links.
3. **`publicvpn parse`** — decode the cached bodies into normalized node records.
4. **`publicvpn filter`** — apply the ingest security filter (reality/tls only); the survivors are the wave's reference set.
5. **`publicvpn probe`** — out-of-band liveness + exit-IP wave (add `--speedtest` for the weekly-style throughput measurement).
6. **`publicvpn geo`** — enrich the exit IPs into the cold base.
7. **`publicvpn select`** — rank and cap the active set.
8. **`publicvpn render`** — render the full client config into `rendered/config.json`.
9. **`publicvpn activate`** — `-test` gate, backup, atomic replace of `[activate].target`, then restart your client when you are ready (`systemctl --user restart xray-raw.service` — the binary prints this hint, it never restarts by itself).
10. **`publicvpn maintain`** — from now on, one command — or the [`publicvpn watch` daemon](#️-the-watch-daemon) installed by `publicvpn install` — does the whole wave on schedule, activating only on real diffs.

## 📦 Self-install / uninstall

`publicvpn install` turns the machine you run it on into a maintained node:

1. **Binary** — copies the RUNNING binary (`os.Executable`) to `--bin-dir` (default `~/.local/bin`) as `publicvpn`: atomic write (temp → fsync → rename), mode `0755`. Re-running after a rebuild **is** the self-upgrade flow.
2. **Unit** — renders the **watch-daemon unit** from the repo template (`systemd/public_vpn-watch.service`, single source of truth via `go:embed`) into `--unit-dir` (default `~/.config/systemd/user`). `ExecStart` is `<installed binary> watch -c <the config path you passed>`; the unit carries `Restart=always` (a crashed daemon is back in 5s). Path rules unchanged: `--bin-dir` and `--config` may **not** contain whitespace (systemd argv-splits `ExecStart=`), while `--unit-dir` may (verified with `systemd-analyze verify`); only the manager's real search path is discovered by `daemon-reload` — a custom unit dir elsewhere needs `XDG_CONFIG_HOME` or symlinks.
3. **Legacy-timer migration (W5 → W10)** — if the old `public_vpn-refresh/speedtest` timer units are still on disk from a previous install, install **disables and removes them automatically** (a stale timer would fire waves concurrently with the daemon and stampede the probe origin). Zero owner steps; `status` flags leftover legacy units with a `LEGACY:` hint.
4. **Activation** — `systemctl --user daemon-reload`, then `enable --now public_vpn-watch.service`, pinned to an internal allowlist (no restarts of anything, no other units, ever — and the daemon itself **never** talks to systemd).

```bash
go build -o publicvpn ./cmd/publicvpn
./publicvpn install -c /absolute/path/to/config.toml   # config is required: the unit embeds its path
```

- **install never creates or moves config files** — the unit references the path you pass; keep that file in place.
- **No user systemd session?** install fails loud with an actionable message; pass `--no-systemd` to copy the binary only (unit skipped, documented in the output).
- **`publicvpn uninstall`** — the symmetric teardown: disables the daemon (and any legacy timers still present) → removes every known unit file (current + the W5-era names) → `daemon-reload` → report. User data (config, data dir, installed binary) is **kept by default**; `--purge` (explicit, destructive) also removes the config file and `[data_dir]` — and nothing else, in particular nothing xray-raw.
- **`publicvpn status`** — install state: installed binary, the watch unit, its enablement (read-only filesystem inspection), and a `LEGACY:` hint while old timer units survive. **Default dirs only:** detection reads `~/.local/bin` and `~/.config/systemd/user` — custom `--bin-dir`/`--unit-dir` installs are not tracked (`status` keeps no state file, by design).

## ⏱️ The watch daemon

`publicvpn watch` is the long-running form of the pipeline (what `install` enables):

- **plugin watchdog** — fsnotify on `[plugins].dir`: add/modify of a `.lua` hot-swaps it into the registry (a broken file keeps the **previous version active** with a loud error naming the Lua failure); removal disables the source on the fly;
- **wave scheduler** — refresh waves every `[maintain].refresh_interval` (**default 1h since W10**), speedtest waves every `[maintain].speedtest_interval` (the speedtest tick runs the full wave with `-S` and covers the refresh); waves re-arm from completion, so they never overlap; the **first wave runs immediately** at start;
- **stats poll** — inside every wave (the existing stage cadence);
- **broken-plugin waves** — one dead provider never kills a refresh: per-plugin failures are loud, the healthy plugins carry the wave;
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
- **Lua plugins are trusted code: CPU and memory inside a plugin are unbounded by design.** The sandbox restricts *what a plugin can call* (`os`/`io`/`package`/`debug` stripped, host API capped), never *how much it can compute* — gopher-lua has no instruction-count or allocation budget, and that is the trusted-code contract, not a defense gap. The runtime caps around it: `[plugins].run_timeout` (default `120s`, explicit `0s` = unbounded) abandons a hung plugin **loud** and the wave continues with the healthy sources — the abandoned goroutine and its Lua state leak one per wave for a persistently hanging plugin (the documented detection-first trade-off; plugins are pure fetch, so nothing else is lost). A `string.rep` memory bomb crashes the whole process — the unit's `Restart=always` covers exactly that class. A daemon wedged by anything else stops its `sd_notify` watchdog pings, so systemd kills it at `WatchdogSec=300` and restarts it. The honest control for a plugin you do not trust is the one that has always existed: plugins are local files you edit — do not ship one you cannot vouch for.
- **Credentials stay local.** The rendered config and pipeline state are written `0600`; the repository ships no secrets and no pinned node URLs.

## ⚠️ Landmine Warnings

- **L1 — never render an observatory with an empty selector.** On xray-core 26.3.27 (pre-#6666) it busy-loops a CPU core; the renderer hard-refuses that shape on any pool state.
- **L4 — DNS goes through NSS.** Hostname resolution uses the system resolver; direct-to-public-DNS probing is dead on split-brain setups and must not be reintroduced.
- **L5 — strip proxy env on every network call.** The ambient `http_proxy` points at your own client; an unstripped fetch, probe, or stats dial silently tunnels through the very VPN it is measuring.
- **L6 — respect ip-api's free tier.** HTTP-only endpoint, ≤100 IPs per batch, ≤15 batch requests/min; ignoring the rate headers risks a 1-hour ban for the whole pipeline.
- The full list (L1–L12) with rationale lives in [DESIGN.md §8](DESIGN.md).

## ⚙️ Configuration

Everything lives in `config.toml` — unknown keys fail loud, there are no env-var overrides.

| Section | Owns | Notable keys |
| :-- | :-- | :-- |
| `[plugins]` | **W10: the source ingest is Lua plugins** | `dir` (default `<data_dir>/plugins`; built-ins materialize on first run; see [Lua plugins](#-lua-plugins-the-source-ingest-layer)), `run_timeout` (default `120s`, `0s` = unbounded — a plugin exceeding it is abandoned loud and the wave continues). The old `[sources.*]` tables fail config load with a loud migration error. |
| `[fetch]` | download client (the plugins' `github_files` engine) | `timeout`, `retries`, `concurrency`, `api_base`/`raw_base` (mirrors), `github_token`; `cache_max_age` is a W5-era leftover — unused by the plugin ingest |
| `[http]` | shared HTTP client | `user_agent` — THE single pipeline User-Agent (fetch + geo) |
| `[filter]` | ingest security | `source_cap`, `protocols` (allowlist, ss + hysteria2 opt-in), `allow_insecure` (default `false`) |
| `[probe]` | xray-knife wave | `path`, `threads`, `url`, `speedtest` (**default `true` since W10** — every wave carries `-S`; `false` opts out), `check_preset`, `max_passed`, `skip_fresh_within` (skip re-probing fresh-passed nodes, `0s` = probe everything) |
| `[geo]` | ip-api enrichment | `endpoint`, `batch_size`, `per_minute`, `ttl` |
| `[select]` | ranking caps (D7) | `per_country_cap`, `soft_cap`, `city_expand_threshold`, `ceiling`, `tie_band_rtt_tolerance` (city tie-break band width, default `1.2`) |
| `[render]` | client config render | `template`, `output_dir`, `stats_port`, `pool_routes`, `pool_inbound_tags` (validated against template inbounds — missing tag fails the render loud), `observatory_interval` (verbatim string, default `"60s"`), `tcp_max_seg` (mandatory on every pool outbound), `tls_fingerprint` (default `firefox`), `balancer_tolerance` (default `0.2`) |
| `[activate]` | activation | `target`, `xray_bin`, `asset_dir`, `backup_dir`, `test_timeout` (`0s` = no deadline), `service_name`, `backup_keep` (N newest, `0` = unlimited) |
| `[maintain]` | wave schedule (the watch daemon reads it live) | `prune_dead_after` (default `48h`), `refresh_interval` (default **`1h`** since W10), `speedtest_interval` (default `168h`), `stats_timeout` (default `10s`), `prune_backup_keep` (`0` = unlimited) |

**Validation policy (owner ruling, binding):** the 5-minute floor applies **ONLY** to `[maintain].refresh_interval` / `speedtest_interval` (W5, owner-approved). Every W6 knob (`cache_max_age`, `test_timeout`, `skip_fresh_within`, `stats_timeout`, `observatory_interval`, `tcp_max_seg`, `tls_fingerprint`, `balancer_tolerance`, `tie_band_rtt_tolerance`, `pool_inbound_tags`, `api_base`, `raw_base`, `user_agent`, `service_name`, `backup_keep`, `prune_backup_keep`) is **deliberately unbounded** — the only structural checks are value parsing, rejection of negative numbers (sign correctness), and the per-knob `0` semantics documented above. Values the xray core rejects fail the `-test` gate loud. Defaults preserve the pre-W6 behavior byte-for-byte.

## ✅ Testing

```bash
go test ./... -count=1        # full suite
go test -race -count=1 ./...  # race detector
golangci-lint run             # strict gate: 0 issues, caps disabled
```

The suite covers every stage with hermetic fixtures: the **W10 plugin matrix** — node-class contract (constructor/collector loudness with plugin + index attribution), the host network API over httptest (GET/POST/headers/redirect-caps/timeout/body-cap, a dynamic ambient-proxy-env test pinning **L5**), the `github_files` helper (include filters, manifest mode, truncated-tree loudness), the sandbox (os/io/require/dofile fail loud, at load-check AND at run time), defaults materialization (first-run-only; owner edits persist), watchdog hot-reload (add/modify/remove/broken-keeps-last-good, `-race`-pinned concurrent reload vs wave snapshots), the daemon scheduler (injected clock: tick order, speedtest-covers-refresh, failure survival, signal-driven clean shutdown), the StintikVPN fixture (nested fetches, per-subscription isolation) plus `live`-tagged real-source runs —: mocked-stage maintain orchestration (order, no-op-when-unchanged, failed `-test` gate), real-shaped `statsquery` responses (missing-counter tolerance included), prune boundaries and backup semantics, render golden regression (per-transport goldens **xray-validated against the real binary in the default suite**), the full W5 install matrix — unit files rendered from config intervals under a fake HOME, an injected systemctl executor (tests never execute systemd), an allowlist guard pinning the exact permitted commands, and idempotent re-install/purge semantics — and the W8 check matrix: URL normalization, blockpage classifier, aggregation/ranking math, a golden report (`--no-color`), an in-process SOCKS5 server pinning the **remote-DNS (`socks5h`) contract** behaviorally, engine integration (filters, limits, throttling, verdict classes, staleness hint), and a `live`-tagged real-xray temp-instance lifecycle test (`go test -tags live ./internal/checker/`).

## 🗺️ Roadmap

- **VPS probe mode (D10)** — run the probe stage on a rented server and sync results back, trading home-IP footprint for infrastructure.
- **Panel-side integration** — explicitly out of scope; this pipeline is a local single-binary tool and stays one.
