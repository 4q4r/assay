# Self-Held Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** assay owns its xray core process and proxy inbounds — a self-contained user product — and the external-client activation mode is removed.

**Architecture:** the watch daemon spawns/supervises a long-lived `xray run` child (core manager package with flock, health checks, strike-based rollback); render generates assay's OWN live config (own inbounds, D7 fail-closed posture, re-homed pool_routes); install downloads and auto-updates the managed core.

**Tech Stack:** Go (module `assay`), gopher-lua (unchanged), systemd user units, TOML config, stretchr/testify.

**Spec:** `docs/superpowers/specs/2026-11-10-self-held-core-design.md` (D1–D8, S1–S7 — the plan argues from it; executors read both).

## Global Constraints

- Module `assay`; every gate standalone: `go build ./...` · `go vet ./...` · `golangci-lint run` (0 issues) · `go test -race -count=1 ./...` green (flake protocol: `TestBootSmokeEveryProtocolFamily` may fire under contention — rerun isolated, note it).
- Defaults verbatim: `socks_port` 10810 · `http_port` 10811 · `api_port` 15491 · `auto_update` true · `update_interval` "24h" · `rollback_strikes` 3 · `loglevel` "warning" · bind 127.0.0.1.
- Empty pool NEVER routes to `direct` (A4/D7): bootstrap catch-all → `block`; post-first-pool empty wave keeps last-good.
- Retired config keys parse-and-warn (S4) — the daemon never refuses to start on them.
- `access: none` in every generated config by default (S7 journald-flood lesson).
- Hermetic tests (no real network, no real downloads — download tests use httptest servers + fixture checksums).
- No provider roster, no slang, comment density matches the repo.
- One commit per task, conventional messages, branch `feat/self-held-core` (all tasks land on it; the controller owns push/PR/merge).

## Review Focus

1. **Empty/absent selection on ANY render path** → catch-all `block`, never `direct`; post-first-pool waves keep last-good and never regress to `block` (Task 3 tests pin both).
2. **Two managers race** (one-shot CLI vs daemon) → flock refuse loud, no second core, no port-bind race (Task 4 tests pin the refusal + lock ownership).
3. **Core binary absent/corrupt/system-overridden** → install guarantees the managed binary before the first wave; probe/check fleets and the `-test` gate resolve the SAME `[core].xray_bin`; auto-update inert with one loud INFO when overridden (Tasks 1/2/5).
4. **Legacy config files carry retired keys** → parse-and-warn per key, daemon starts, defaults applied (Task 1 tests pin the loader contract).
5. **Health-failure storms** → strike counter resets on healthy check, K-strikes rollback restores the newest pre-activate backup and passes `-test` before restart (Task 2/4 tests pin the counter and the rollback).

---

### Task 1: `[core]` config surface + retired-key parse-and-warn

**Files:**
- Modify: `internal/config/config.go` (add `CoreConfig` struct + `applyCoreDefaults` + retired-key table)
- Modify: `internal/config/resolve.go` (loader contract: retired keys warn-and-continue)
- Test: `internal/config/core_config_internal_test.go` (new)

**Interfaces:**
- Produces: `type CoreConfig struct { XrayBin string; AutoUpdate bool; UpdateInterval Duration; SocksPort, HTTPPort, APIPort int; PerCountryInbounds bool; RollbackStrikes int; Loglevel string }` on `Config` as `Config.Core CoreConfig`.
- Produces: `func (c *Config) CoreXrayBin() string` — resolves managed default `<data>/bin/xray` when the knob is empty (later tasks consume this instead of `Activate.XrayBin`).
- Produces: retired-key handling — decoding a config containing any S4-retired key (`activate.target`, `activate.xray_bin`, `activate.asset_dir`, `activate.service_name`, `render.template`, `render.output_dir`, `render.stats_port`, `render.pool_inbound_tags`, `maintain.auto_restart`) emits one loud warning line per key to the resolve warning sink and applies the re-homed value where S4 says so (`render.stats_port` → `core.api_port`; `activate.xray_bin` → `core.xray_bin`); unknown NON-retired keys keep today's strict-decode error.

- [ ] **Step 1: Write failing tests** — `TestCoreDefaultsAbsentSection` (no `[core]` in config → all defaults verbatim from Global Constraints; `CoreXrayBin()` returns `<data>/bin/xray` joined from the resolved data dir); `TestRetiredKeysParseAndWarn` (a config with all nine retired keys decodes OK, produces exactly one warning per key, `stats_port` value lands in `core.api_port`, `xray_bin` lands in `core.xray_bin`); `TestUnknownKeyStillStrict` (a truly unknown key still errors).
- [ ] **Step 2: Run** `go test ./internal/config/ -run 'TestCore|TestRetired|TestUnknown' -v` → FAIL (CoreConfig undefined).
- [ ] **Step 3: Implement** the struct, defaults, retired-key table, parse-and-warn in the decode path.
- [ ] **Step 4: Run** the same command → PASS; then `go build ./...` + `go vet ./...`.
- [ ] **Step 5: Commit** `feat: [core] config surface with retired-key parse-and-warn`.

### Task 2: core manager package (internal/core)

**Files:**
- Create: `internal/core/manager.go`, `internal/core/lock.go`, `internal/core/rollback.go`
- Test: `internal/core/manager_internal_test.go` (new; hermetic fake binary — reuse the checker temp-instance fake-xray pattern from `internal/checker/instance.go`)

**Interfaces:**
- Consumes: `config.CoreConfig` (Task 1), `CoreXrayBin()`.
- Produces: `type Manager struct`; `func NewManager(cfg config.CoreConfig, dataDir string, log io.Writer) (*Manager, error)` (takes the singleton flock or returns `ErrDaemonHoldsCore`); `func (m *Manager) EnsureRunning(ctx context.Context) error` (spawn if not running; used for bootstrap per S2); `func (m *Manager) Restart(ctx context.Context) error` (stop+start around a swapped live.json); `func (m *Manager) Stop() error`; `func (m *Manager) Healthy(ctx context.Context) error` (socks dial to `127.0.0.1:socks_port` + one outbound fetch through it); `func (m *Manager) RecordHealth(err error) (rolledBack bool)` — strike counter per D8: K=`rollback_strikes` consecutive failures → restore the NEWEST `<data>/backups/config.json.bak-<ts>` → `-test` gate via the managed binary → restart → loud line; strikes reset on healthy; `func (m *Manager) Alive() bool` (pidfile+liveness for status).
- Produces: flock constant path `<data>/core.lock`; error `ErrDaemonHoldsCore`.
- The child runs `xray run -c <data>/rendered/live.json`; stderr inherited into the daemon's stdout (S7); spawn uses the WaitDelay-safe exec path (`internal/restart` precedent).

- [ ] **Step 1: Write failing tests** — `TestManagerSpawnsAndKillsFakeCore` (fake binary sleeps; EnsureRunning → port listens → Stop → gone); `TestSingletonLockRefusesSecondManager` (second NewManager → ErrDaemonHoldsCore); `TestStrikesTriggerRollback` (fake core fails health 3× with `rollback_strikes=3` and a prepared backup dir → RecordHealth returns rolledBack=true, the backup file is live.json's content, loud rollback line in the log buffer); `TestStrikesResetOnHealthy`; `TestRollbackRunsTestGate` (a backup that fails `-test` → rollback refuses loud, keeps previous state).
- [ ] **Step 2: Run** `go test ./internal/core/ -v` → FAIL (package missing).
- [ ] **Step 3: Implement** manager/lock/rollback.
- [ ] **Step 4: Run** full package → PASS; build+vet.
- [ ] **Step 5: Commit** `feat: core manager — flock, supervise, health, strike rollback`.

### Task 3: render re-target (own live config)

**Files:**
- Modify: `internal/render/render.go` (own-target generation replaces template+pool merge)
- Modify: `internal/cli/pipeline.go` (render stage: target `<data>/rendered/live.json`; empty-pool posture per D7)
- Test: `internal/render/render_own_target_test.go` (new)

**Interfaces:**
- Consumes: `config.CoreConfig` (Task 1), selection + geo store (unchanged inputs).
- Produces: `func RenderOwnConfig(sel *model.Selection, core config.CoreConfig, poolRoutes []RouteRule) ([]byte, error)` — generates: inbounds (socks `in` + http `in-http`, per-country `in-<cc>` when enabled), outbounds (direct/block + pool), routing (S6 domain rules above catch-all; catch-all → `pool_all` when selection non-empty; → `block` in bootstrap/empty posture), balancers, observatory, log block per S7, stats on `api_port`.
- Produces: empty-pool contract — `RenderOwnConfig` with an empty selection and `bootstrap=true` renders catch-all `block`; the PIPELINE stage (`pipeline.go`) implements keep-last-good: if a previous `live.json` exists and the new selection is empty, skip the write + loud line `render: empty selection — keeping last-good core config` (test pins both layers).

- [ ] **Step 1: Write failing tests** — `TestRenderOwnBootstrapBlockCatchAll`; `TestRenderOwnFullPool` (selection with 2 nodes → pool outbounds + `pool_all` balancer + catch-all → `pool_all` + socks/http inbounds on the configured ports + log block warning/none + stats api_port); `TestRenderOwnPerCountryInbounds` (option on → `in-de`/`in-fr` inbounds bound to their balancers); `TestRenderPoolRoutesAboveCatchAll` (S6 domain rule ordering); `TestPipelineKeepsLastGoodOnEmptySelection` (pipeline-level, tmp data dir with a prior live.json).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** render package + pipeline tests → PASS; full `go test -race ./internal/render/ ./internal/cli/`.
- [ ] **Step 5: Commit** `feat: render own live config — D7 posture, per-country option, S6 routes`.

### Task 4: activate rework + watch wiring (bootstrap spawn, flock integration)

**Files:**
- Modify: `internal/cli/pipeline.go` (activate stage: `-test` via `CoreXrayBin()`, dated backup → replace `live.json` → `manager.Restart` → `Healthy`+`RecordHealth`; core manager owned by the watch daemon; S1 factory rewiring — the probe/check temp-instance fleets and batch pre-filter resolve `CoreXrayBin()` instead of `cfg.Activate.XrayBin`, pipeline.go:700/:790)
- Modify: `internal/cli/watch_cmd.go` (bootstrap spawn at start per S2; manager lifecycle on shutdown)
- Modify: `internal/cli/activate_cmd.go` if present (one-shot refuses loud under flock, transient spawn when daemon-less)
- Test: `internal/cli/activate_own_internal_test.go` (new)

**Interfaces:**
- Consumes: Tasks 1–3 (`CoreConfig`, `core.Manager`, `RenderOwnConfig`).
- Produces: the activate stage contract — `-test` gate, backup, write, restart, health, strikes; `ErrDaemonHoldsCore` surfaced to the one-shot CLI as a loud message; watch daemon: manager started before READY=1, stopped on SIGTERM (A2); probe/check factories resolve `CoreXrayBin()` (S1) — pinned by a test asserting both fleets boot the managed fake binary on a clean data dir.

- [ ] **Step 1: Write failing tests** — `TestActivateOwnWritesBackupsAndRestarts` (fake core binary; activate with a real selection → backup created, live.json replaced, Restart called, health recorded); `TestOneShotActivateRefusesUnderFlock` (daemon-style lock held → one-shot returns the loud refusal text); `TestWatchBootstrapsCoreAtStart` (watch start with empty selection → bootstrap live.json with catch-all block + core running before READY); `TestStrikeCounterFeedsRollback` (3 failed healths across activates → rollback fired via the manager).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** (reuse the existing restart/health ladder structure where the seam allows).
- [ ] **Step 4: Run** cli package + full `-race` → PASS.
- [ ] **Step 5: Commit** `feat: activate own core — bootstrap spawn, flock, strike rollback`.

### Task 5: install + managed core lifecycle

**Files:**
- Modify: `internal/install/install.go`, `internal/cli/install_cmd.go` (core bootstrap step per D4)
- Create: `internal/core/download.go` (release fetch, sha256 verify, atomic install)
- Modify: `internal/xrayupdate/xrayupdate.go` + `internal/cli/xrayupdate_cmd.go` (managed-core path; auto-update wiring into the wave; inert-when-overridden per S5)
- Modify: `internal/cli/uninstall_cmd.go` (remove managed core + opt-in data)
- Test: `internal/core/download_internal_test.go`, `internal/install/install_core_internal_test.go` (new)

**Interfaces:**
- Consumes: `config.CoreConfig` (Task 1).
- Produces: `func EnsureCoreBinary(ctx context.Context, cfg config.CoreConfig, dataDir string, log io.Writer) error` — no-op when the managed binary exists or `xray_bin` is overridden (one loud INFO per S5); else download latest release asset for the platform, sha256-verify against the release checksum file, atomic install to `<data>/bin/xray`; `func (m *Manager) AutoUpdate(ctx context.Context, cfg config.CoreConfig) error` — respects `update_interval`, staged swap + core restart, floor-version pin from the spec's frozen-core landmine note.
- Version floor: reject cores older than the observatory-safe floor documented in the spec's builder note (exact floor resolved by the implementer against XTLS release notes at build time; test with a fixture floor).

- [ ] **Step 1: Write failing tests** — `TestEnsureCoreDownloadsVerifiesAndInstalls` (httptest server serving a fixture asset + checksums; wrong checksum → loud refuse, no file; correct → atomic install); `TestEnsureCoreNoopWhenOverriddenOrPresent`; `TestAutoUpdateInertWhenOverridden` (one INFO line, no download); `TestInstallGuaranteesCoreBeforeFirstWave` (install on a clean data dir → managed binary present afterward); `TestUninstallRemovesCore` (opt-in flag).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS; build/vet/lint.
- [ ] **Step 5: Commit** `feat: managed core lifecycle — download, auto-update, uninstall`.

### Task 6: external-mode removal (S4 zero-remnant sweep)

**Files:**
- Modify/Delete: `internal/restart/` (foreign-unit allowlist executor + its guard tests die; the package keeps only what Task 4 reuses), `internal/cli/units.go` (foreign restart paths), `internal/config/config.go` (retired fields deleted from structs after the parse-and-warn table exists), `systemd/` (unit file: ExecStart unchanged — daemon only), README.md + DESIGN.md (external-mode sections removed; full docs rewrite is Task 7's scope — here only the dead-path mentions go)
- Test: update every test that pinned the removed surface (the allowlist EXACTLY-2-files guard, restart-flow tests, render template tests die with their feature)

**Interfaces:**
- Consumes: Tasks 1–5 (nothing references the removed surface anymore).
- Produces: acceptance — `git grep -n "xray-raw" -- '*.go' cmd/ systemd/` → zero; `git grep -n "template\|service_name\|pool_inbound_tags" -- 'internal/config/'` → zero struct/knob remnants (docs exempt); the S4 parse-and-warn table is the ONLY place those names exist.

- [ ] **Step 1: Write the failing acceptance** — a test `TestExternalModeSurfaceZero` in `internal/config/` asserting the grep contract above (red until removal).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Remove** the external-mode code paths + update/kill their tests.
- [ ] **Step 4: Run** full `go test -race -count=1 ./...` → PASS; acceptance test green.
- [ ] **Step 5: Commit** `feat: remove external activation mode (S4 sweep)`.

### Task 7: status core block + docs (README standalone, config.example, DESIGN)

**Files:**
- Modify: `internal/cli/status_intel.go` (core block: PID, version `xray version` output, uptime, inbounds, strike count)
- Modify: `config.example.toml` (`[core]` section with verbatim defaults + retired-key migration notes), `README.md` (Quick Start → standalone story: install downloads core, drop .lua sources, socks 10810; architecture diagram re-target), `DESIGN.md` (§ wave pipeline target + §10 non-goals sync)
- Test: `internal/cli/status_core_internal_test.go` (new)

**Interfaces:**
- Consumes: Tasks 1–6.
- Produces: `status` core block fields; docs matching shipped behavior (no invented flags — verify every documented command against `--help`).

- [ ] **Step 1: Write failing test** — `TestStatusCoreBlock` (fake core running → PID/uptime/inbounds/strikes rendered; no core → honest "core not running").
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the status core block.
- [ ] **Step 4: Rewrite the docs** (README standalone story, config.example `[core]`, DESIGN sync) — every documented command verified against `--help`.
- [ ] **Step 5: Gates** (build/vet/lint/full -race + markdownlint for README).
- [ ] **Step 6: Commit** `feat: status core block + standalone docs`.

### Task 8 (ops, no code): owner-laptop migration runbook (W5)

Executed by the controller + deploy operator AFTER Tasks 1–7 merge and a binary is built:
- [ ] Stop assay-watch; build new binary sha-verified; install.
- [ ] Rebuild clean xray-raw config from the live one per spec D5 runbook (strip pool layer, add `assay-pool` socks outbound → 127.0.0.1:10810, owner picks routing markers; `-test` gate + dated backup; restart xray-raw; health check). xray-raw's core binary untouched (S5).
- [ ] Start assay-watch (own-core mode); verify bootstrap core, first wave, socks 10810 through a pool node, `assay status` core block; verify the owner's default route stays on Germans.
- [ ] Journal evidence lines collected into the deployment report.

### Task 9 (ops): re-publication (W6)

- [ ] Owner reviews the product README on the private repo.
- [ ] On owner word: `gh repo edit 4q4r/assay --visibility public`; verify badges/topics; CodeRabbit re-engages (ruling 2026-11-05).
