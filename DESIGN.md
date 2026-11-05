# public_vpn — design

**Status:** DRAFT v1 (2026-10-28) — awaiting owner approval. Nothing implemented.
**Author:** controller synthesis of 3 subagent reports (StintikVPN repo analysis; Exa/GitHub internet research; live xray-raw audit), all facts URL- or disk-verified 2026-10-28.
**Live client today:** xray-core 26.3.27 (`cc66b68-dirty`), config validates OK (`xray run -test` → `Configuration OK`).

## 1. Intent

Extend the owner's laptop xray client (`~/projects/xray-raw`) with a curated pool of third-party public proxy nodes for **location diversity**, backed by a geo-base (country / city / ASN / ISP per node exit). The pool serves ONLY explicitly routed traffic. The owner's two German REALITY/XHTTP nodes remain the default transport for everything else. This project (`public_vpn`) is the pipeline: fetch → filter → probe → geo-enrich → select → render/activate → maintain.

## 2. Owner decisions (grilling rounds, 2026-10-28)

- **D1 — Deliverable:** analysis report + this design doc in `~/projects/public_vpn/`; implementation is a separate approved task.
- **D2 — Trust wall:** pool participates ONLY in explicitly configured routes. Default route and every undocumented destination stay on the Germans (`best_rtt` untouched).
- **D3 — Flexibility × compactness:** small ACTIVE core in-config + full COLD base on disk. Target ≤ 20–25 active pool outbounds; hundreds cold.
- **D4 — Geo granularity:** country + city + ASN + ISP per node (picky services may demand a specific city).
- **D5 — Selection UX (a):** per-country balancers + routing rules; **CONFIRMED by owner 2026-10-28** — two-layer scheme:
  - Country = default balancer granularity — `leastLoad` over ALL country nodes = the quality guarantee.
  - City = explicit override only: city balancer when a city has ≥2 live nodes; direct outbound tag when 1. No nesting country↔city; city balancers are generated only where they make sense.
  - Tags stay flat: `pool-<cc>-NN`; city/ASN/ISP live in geo-base metadata, never in tags. Numbers kept.
- **D6 — Namespace (owner decision, recorded in memory 2026-10-28):** the Germans' balancer `best_rtt` (selector `["proxy-"]`) and its burstObservatory coverage are **Germans-only by design** — no `costs`, no chaining, nothing third-party ever enters `proxy-*`. Pool uses the `pool-` prefix with its own coverage.
- **D7 — Coverage-first caps (owner, 2026-10-28):** country count UNLIMITED; node soft cap N=20–25; if ≥25 distinct cities are available among alive nodes, the cap EXPANDS to cover them (recommended configurable ceiling 40 for CPU safety).
- **D8 — Exit-IP geo (owner, 2026-10-28):** geo-enrichment uses the node's EXIT IP observed THROUGH the tunnel (ip-echo fetched via the node connection), never the advertised host/IP (relay/frontend ≠ exit).
- **D9 — Dynamic sources (owner, 2026-10-28):** sources auto-discovered from GitHub every wave (contents API / upstream manifests) — no hand-maintained pinned URLs; upstream reorganizations and new files propagate automatically.
- **D10 — Probe origin (owner, 2026-10-28):** local, throttled, from the owner's IP; VPS mode is a later optional flag.
- **D11 — Language (owner, 2026-10-28):** Go single binary.

## 3. Substrate — what we ingest

**StintikVPN repo verdict:** a curated *link directory*, not a node source. Zero `vless://`/`vmess://` URIs anywhere; content = 5 upstream subscription URLs + 5 Telegram MTProto links (irrelevant to xray). MIT, active (pushed 2026-10-26, 161★, 0 open issues), daily CI liveness-checking the links. **Use:** consume its upstreams directly; optionally poll its `data.json` + `dead-link` issue as a source-health signal.

**Source registry (all verified alive 2026-10-27/28):**

| id | source | cadence | why |
| :-- | :-- | :-- | :-- |
| `matin` | `MatinGhanbari/v2ray-configs` — per-protocol `vless.txt`, `all_sub.txt`, `super-sub.txt` | 15 min | no-wipe 404 semantics; `super-sub` = pre-tested best |
| `radikal` | `0xRadikal/Free-v2ray-Configs` — `secure/configs.txt` + per-protocol | 15 min | pre-filtered forward secrecy (no `allowInsecure`, no PSK-only); 404-never-empty-wipes semantics |
| `tvc` | `xtoolkit/TVC` — per-protocol files | hourly | Telegram-channel breadth (continuation of yebekhe/TVC) |

Default enabled (current, 14): `matin`, `radikal`, `stintikvpn`, `hidashimora`, `kort0881`, `au1rxx`, `barryfar`, `nirevil`, `mehdirzfx`, `mhditaheri`, `flat447`, `luxxuria`, `igareck`, `nodesradar`. `tvc` optional. **D9: URLs are NOT pinned** — the registry stores repo ids + a discovery method (GitHub contents API listing / upstream manifest files such as 0xRadikal's `index.json`); fetch resolves current raw paths at every wave, so upstream reorganizations and new split files propagate automatically. Skipping `mahdibland/V2RayAggregator` full merge (their own README warns it crashes clients). **RF reality check:** most public VLESS is `tcp+vision` — exactly the profile TSPU blocks post-handshake (net4people/bbs#546). The working subset is small; the pool is a *location* source, never a primary transport.

## 4. Pipeline

```text
fetch → parse → filter → probe → geo → select → render → activate
                                          ↑______________ maintain (timers: refresh 6h, speedtest weekly, stats poll)
```

1. **fetch** — curl each enabled source (cache, timeouts, retries). All network calls run with `env -u http_proxy -u https_proxy` (ambient-proxy landmine L5).
2. **parse** — base64-detect + decode; per-line URI parse; accept `vless|vmess|trojan|ss|hysteria2`/`hy2` (W14: ALL rendered protocols by default per the round-7 owner ruling; the `[filter].protocols` allowlist remains the acceptance policy knob, hysteria-v1, tuic and ssr stay rejected as not-xray-core/removed); normalize to internal record; dedupe key = hash(host, port, credential, transport params).
3. **filter** — keep `security=reality|tls` only; drop `allowInsecure=1|insecure=true`; drop private/loopback hosts; per-source caps.
4. **probe (out-of-band, W14 real-xray engine)** — every probed node gets a temporary single-node xray (the SAME factory the check/geo stages use, `[activate].xray_bin`): N liveness HTTP GETs through its tunnel (statuses/TTFB/total, blockpage classifier reuse), a D8 exit-IP echo through the same tunnel, and an optional configurable speedtest sample (`[probe].speedtest_url`) → `speed_bps`. Uniform coverage of EVERY rendered protocol, hysteria2 included (the knife-era "does the prober support hysteria2" question is dead — the real core is the prober). Default origin = this machine, throttled; optional VPS mode (footprint, §7). Never inside the live client.
5. **resolve + geo (exit-IP based, D8; W11 self-report redesign)** — for each ALIVE node, discover its EXIT IP through the tunnel itself (an ip-echo request fetched VIA the node connection during the probe wave), never the advertised host (relay/frontend ≠ exit). Geo enrichment is a PER-NODE SELF-REPORT: through the node's own temp xray instance (the check-stage infrastructure — one socks endpoint per node, no second instance) the stage issues `GET http://ip-api.com/json/` with no ip parameter, so ip-api answers "who is asking" and the response IS that node's exit geo (`countryCode,city,isp,as,asname,proxy,hosting`). Requests originate from thousands of distinct node IPs — the aggregate per-source batch clamp (≤100 IPs/POST, 15 req/min, X-Rl/X-Ttl) is RETIRED in principle; each node's requests carry their own 45 req/min budget, plus small politeness pacing across the wave. Free tier remains HTTP-only, non-commercial (personal use — satisfied). Failure classes fall back, never drop: reset/timeout/non-200/status=fail → through-tunnel DoH view (`o-o.myaddr.l.google.com` TXT via `[geo].doh_url`, default `https://dns.google/resolve`, reveals the exit network's resolver IP; the ip-api single-IP lookup of that IP rides the same tunnel) → if that fails too, geo unknown: the node stays usable, previous geo evidence is preserved, the class is reported loud. Every record carries `geo_source` provenance (`self-report` | `doh-fallback` | ""). DNS via NSS (`getent hosts`, NOT `dig @8.8.8.8` — split-brain landmine L4) is for dialing only, never for geo. Output: `geo-base.jsonl` (cold base), TTL 24 h.
6. **select** — rank by alive → checks → speed; country count UNLIMITED (D7); per-country cap K (default 3–5, configurable — keeps one country from hogging); global soft cap N=20–25 that EXPANDS when ≥25 distinct cities exist among alive nodes (recommended ceiling 40, configurable — CPU math §6); city-diversity tie-break; survivors → active set, everything else stays cold with probe history.
7. **render** — template (bootstrapped once from the live config) + pool outbounds + balancers + rules:
   - every pool outbound gets `sockopt.tcpMaxSeg: 1440` and `fingerprint: "firefox"` (client-side override on tls/reality settings);
   - **all link auth/transport params pass through 1:1** (`sni`, `host`, `path`, `pbk`, `sid`, `mode`, uuid/password) — never rewritten (L9; REALITY serverName must match the server's list or auth fails);
   - pool observatory: **Plan A** (preferred, verify day-one): legacy `observatory {subjectSelector:["pool-"], probeInterval:"60s", enableConcurrency:true}` COEXISTING with the existing `burstObservatory {subjectSelector:["proxy-"], 10s…}` — per-group cadence via two mechanisms. Plan B (fallback): no in-client pool observatory at all — pool routes use static outbound tags picked at render time (selection fully out-of-band). Plan C (last resort): merged selector `["proxy-","pool-"]` at 30 s — degrades Germans' failover 10 s→30 s, needs owner sign-off.
   - leastLoad pool balancers REQUIRE in-client pool coverage (L2) — Plan B replaces balancers with direct tags.
   - routing rules: owner-configured pool routes inserted AFTER existing rule 6 (private-IP direct) and BEFORE rule 7 catch-all; each carries `inboundTag:["socks-in","http-in"]`. Existing rules 1–6 (nvidia→fox, SMTP-block, torrent-direct, youtube-direct, RU-direct, private-direct) keep precedence → pool can never carry mail/torrents/RU-destined traffic even by mistake.
8. **activate** — `xray run -test -c` the rendered file; date-stamped backup of live config (`.bak-<ts>` convention); atomic replace of `xray-raw/config.json`; **never auto-restart the service** — print the restart command + diff summary for the owner.
9. **maintain (systemd user timers)** — refresh wave 6 h (fetch→…→activate-if-changed); speedtest wave weekly; `xray api statsquery -pattern "outbound>>>pool-" -reset=true` poll → per-node usage into geo-base → prune dead > 48 h.

## 5. Tag & naming contract

- Outbound tags: `pool-<cc>-NN` — `cc` = ISO-3166 alpha-2 lowercase, `NN` = stable per-country sequence (`pool-nl-01`, `pool-fr-03`).
- Country balancer: `pool_<cc>`; city balancer: `pool_<cc>_<city-slug>` only when ≥2 live nodes in that city.
- Cold-base record: `{tag, source, scheme, host, port, ip, country, city, asn, asname, isp, proxy_flag, hosting_flag, first_seen, last_seen, last_probe, rtt_ms, speed_bps, alive, bytes_up, bytes_down}`.
- Forbidden: `proxy-*` for any pool node (D6); `ipinfo` Lite has NO city (researched correction) — city comes from ip-api/GeoLite2 only.

## 6. CPU / resource budget (researched numbers)

- Idle outbounds are lazy (dialed on demand) → pool nodes cost only observatory probes.
- Probe fan-out: 20–25 pool nodes @ 60 s interval ≈ ≤0.75 probes/s worst case — comparable to today's 2 Germans @ 10 s×5 sampling. At the documented 10 s floor with 100 nodes it would be up to 50 probes/s — that is why pool cadence must be 30–60 s, never 10 s.
- The probe wave runs temp single-node xray instances out-of-band only ([activate].xray_bin; W14) — the live client is never involved.
- `loglevel: warning` steady-state (info = a line per connection, real cost at scale); `/metrics` per-entity counters available for attribution before adding knobs.
- Laptop headroom: documented pain thresholds start at 50+ outbounds on 512 MB-class hardware and 500+ concurrent probes — 20–25 active nodes on 14 GB RAM is far below all of them.
- Known core bugs shaping config: observatory busy-loops ~100 % CPU when `subjectSelector` matches NOTHING — fixed 2026-08-23 (#6666); this core is 26.3.27 (2026-03-27, pre-fix) → **never render a pool observatory whose selector can match zero tags** (generator refuses empty pool; see L1). Balancer/observatory memory leaks fixed 2024-12 (#4095) — already included.

## 7. Security model

- The node operator is a man-in-the-middle by design: sees DNS, inner SNI, timing, volumes, the real client IP; REALITY `pbk` authenticates the operator to us — it does not protect us from the operator. Hence D2: disposable traffic only, logins/banking never (SMTP is blocked pre-pool anyway).
- Link hygiene at ingest: drop `allowInsecure=1`, drop PSK-only protocols, prefer forward-secrecy transports (reality/tls) — mirrors 0xRadikal's SECURE criterion.
- Trust extends into the future: feeds can swap endpoints any hour → every wave re-filters and re-probes; nodes failing twice get pruned.
- Footprint: bulk probing = a fan-out of foreign-IP TLS dials from the home RU IP. Default = local but throttled (concurrency + probes/min caps); VPS mode (run probe stage on an own server, sync results) as an optional flag.
- Source fetches over HTTPS (raw.githubusercontent / gitverse mirror): the registry stores repo ids + a discovery method, and fetch resolves the current raw paths at every wave (D9 dynamic discovery — no pinned URLs).

## 8. Landmines

- **L1** — observatory empty-selector busy-loop on this core (pre-#6666): generator must refuse to render a pool observatory with 0 matched tags.
- **L2** — `leastLoad`/`leastPing` EXCLUDE observatory-uncovered nodes: pool balancers are only valid with in-client pool coverage (Plan A) or they select nothing.
- **L3** — multi-config `-c` merge semantics unverified → render ONE complete config; no stacking.
- **L4** — DNS split-brain on this box: resolve via NSS/`getent`; `dig @8.8.8.8` is dead.
- **L5** — ambient `http_proxy=127.0.0.1:10809` in the owner's shell: pipeline network calls run with `env -u http_proxy -u https_proxy`, or fetches/probes silently tunnel through the Germans and geo-lookups get skewed.
- **L6** — ip-api free tier: HTTP-only, 45 req/min single / 15 req/min batch, non-commercial ToS; ignore `X-Rl` → 429 + 1 h ban.
- **L7** — `xray api` traffic stats skip loopback outbounds (#3653) — fine for pool, don't use for fox-proxy accounting.
- **L8** — long-lived connections (Discord voice) pin to the outbound chosen at connect time; pool failover helps new connections only.
- **L9** — third-party link params are auth material: pass through 1:1, never normalize `sni/host/path/pbk/sid/mode`.
- **L10** — systemd unit is `Restart=always`: a bad config crash-loops the client → `-test` gate before every write + date-stamped backup.
- **L11** — owner ruling: do NOT upgrade the xray core in this project; all fixes stay config-level.
- **L12** — housekeeping note (out of scope): three orphaned `.geosite.dat.XXXXXX` temp files sit in `~/projects/xray-raw/`.

## 9. Use cases (what this buys)

- Geo-diverse disposable egress: parsing/scraping, region checks, geo-fingerprint testing.
- Location-specific services (streaming catalogs, download mirrors) via explicit routing rules.
- Manual overflow/fallback locations if the Germans degrade (explicit switch, never automatic — D2).
- Free RF-censorship telemetry: observatory/probe history shows which locations/transports survive, per day.

## 10. Non-goals

No xray core upgrade (L11). No auto-restart of the live service. No changes to Germans / fox-proxy / routing rules 1–6 / Remnawave-panel side. No GUI. No protocol allowlist expansion beyond `[filter].protocols`: `ss` and `hysteria2`/`hy2` are opt-in there (hysteria-v1, `tuic` and `ssr` stay rejected — not-xray-core / removed from the core). The pool never becomes the default route.

## 11. Implementation outline (only after design approval)

- **W1** — scaffold `public_vpn` CLI (`fetch|parse|geo|probe|select|render|activate|status`), source registry, geo-base.
- **W2** — xray-knife probe integration + select ranking.
- **W3** — render + activate with `-test` gate; day-one verification of Plan A observatory coexistence (fallback B).
- **W4** — timers, stats pruning, README (owner README standard: TOC, badges, mermaid).

**Quality gates (owner mandate 2026-10-28, binding):** latest stable Go toolchain (never downgrade); latest versions of all dependencies, each chosen best-fit and justified; lint + format at ZERO errors/warnings (gofmt/gofumpt + golangci-lint strict, .golangci.yml all-enabled, firefox-vpn-client precedent); full test matrix — unit, integration (network stages: httptest mocks by default + live tests behind explicit guards), load/benchmark (parse/select/render at 10k+ nodes), and regression (golden-file tests for rendered xray config — unexpected render diff = failure). No version pinning beyond dependency resolution. `go build`, `go vet`, `go test ./...`, lint — all clean, verbatim outputs in the report.

- All implementation via subagents; branch → PR → squash-merge (local repo until the owner authorizes a remote). **Language: Go single binary (D11, confirmed).**

## 12. Resolved owner inputs (round 2, 2026-10-28 — implementation authorized)

1. D5 two-layer selection — CONFIRMED.
2. Caps: countries unlimited; N=20–25 soft, expands for ≥25 distinct cities (ceiling 40, configurable); K=3–5 per country.
3. Country filter: none — all alive nodes, no exclude list; geo keyed on EXIT IP through-connection (D8).
4. Sources: dynamic GitHub discovery, no pinned URLs (D9).
5. Probe origin: local, throttled, owner IP (D10).
6. Language: Go (D11).
