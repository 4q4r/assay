# Performance Optimization Master Plan

**Project:** public_vpn (Go 1.27, xray pool manager)
**Date:** 2026-11-01
**Status:** PLANNING — awaiting owner approval before implementation
**Plan author:** orchestrator (consolidated from 5 research/planning documents)

## 1. Executive Summary

The maintain wave is probe-bound (91% of wall time) and timeout-bound on dead nodes (95% failure rate). The single largest structural waste is `skip_fresh_within`: it only skips `passed` nodes, but most alive nodes are `semi-passed`, so only ~15 of ~2,200 alive nodes are skipped per wave. The user's requested redesign replaces the per-status skip with a **"known alive" set** that is populated at wave start from the latest probe results and persists across waves — including nodes that later disappear from source lists.

**Expected aggregate impact:**
- Probe wall time: 90 min → ~30 min (3×)
- Geo wall time: 7.6 min → ~2 min (4×)
- Total wave time: 98 min → ~35 min (2.8×)
- Peak memory: 1.7 GB → ~1.0 GB (−40%)
- Render failures: 5/9 waves → 0/9 (already fixed via graceful routes)
- Alive yield: ~5-8% (KnownAlive skips slow semi-passed)

**Source documents (all in `.superpowers/sdd/2026-10-31-plugin-liveness-and-clean-balancers/`):**
1. `perf-analysis-report.md` — bottleneck analysis, optimization recommendations
2. `optimization-implementation-plan.md` — 5-track implementation plan with tasks
3. `dynamic-timeout-plan.md` — dynamic timeout calibration (p95 + EMA + adaptive window)
4. `geo-cache-plan.md` — geo cache design (hashicorp/golang-lru/v2/expirable, lease renewal, run-count KnownAlive)
5. `dynamic-concurrency-plan.md` — CPU/RAM-aware concurrency (5 waves A-E)
6. `dynamic-cache-sizing-plan.md` — adaptive cache sizing (SizingEngine, ReuseCap)
7. `method-benchmark-report.md` — method comparison, 429 accounting, batch capacity

## 2. Memory Consulted

- `~/.config/opencode/MEMORY.md` (full index)
- `~/.config/opencode/memory/projects/public_vpn.md` (full project contract)
- `~/.config/opencode/memory/topics/workflow.md` (subagent mandates, plan-before-start rule)
- `~/.config/opencode/memory/topics/workflow-git-pr.md` (branch→PR→squash pipeline)
- `~/.config/opencode/memory/topics/stack-and-tools.md` (toolchain gates)
- `~/.config/opencode/memory/topics/environment-infra.md` (xray/remnawave infra)

## 3. Global Constraints (unchanged)

- No external dependencies beyond current `go.mod` (ask before adding).
- One config file, one storage mode, no fallback chains.
- The `-test` gate is non-negotiable; a failed gate leaves the live config untouched.
- Never auto-restart `xray-raw.service`.
- Owner-facing docs (`README.md`, `config.example.toml`) updated in the same change.
- All quality gates: gofmt, gofumpt, golangci-lint, go vet, go build, go test -race, markdownlint at zero.
- Branch → PR → squash-merge pipeline. No direct push to main.
- Subagent mandates: background:true, specialized agent types only (no `general`), fresh session per task, memory mandate in every brief.

## 4. Wave Structure

### Wave 0: Config Tuning (no code, immediate effect)
**Owner actions only — no subagent needed.**

| # | Action | Config change | Expected impact |
|---|--------|--------------|-----------------|
| 0.1 | Enable skip_fresh_within | `skip_fresh_within = "1h"` | Skip recently-probed passed nodes |
| 0.2 | Lower probe timeout | `probe.timeout = "8s"` | 8s sweet spot (165 alive in 30 min) |
| 0.3 | Lower geo timeout | `geo.timeout = "8s"` | Faster geo failures |
| 0.4 | Raise geo concurrency | `geo.self_report_concurrency = 8` (already 8, raise to 16) | Halve geo wall time |
| 0.5 | Lower probe attempts | `probe.attempts = 2` (from 3) | 33% fewer HTTP GETs |
| 0.6 | Increase refresh_interval | `maintain.refresh_interval = "2h"` | Halve daily resource use |

**Status:** Partially done (skip_fresh_within=1h, probe.timeout=10s, geo.timeout=10s, self_report_concurrency=8). Need to adjust timeout to 8s and attempts to 2.

### Wave 1: Render Robustness + Config Reconciliation
**Smallest change, eliminates wave waste immediately. Depends on: nothing.**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 1.1 | `internal/render/render.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (xray routing) | Skip missing balancers with loud warning instead of aborting render. Add `BlockedRoutes` to `Result`. |
| 1.2 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Config reconciliation at wave start: log which configured pool_routes balancers have no live country. |
| 1.3 | `internal/render/*_test.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Update tests: render with missing balancer completes with warning. |

**Subagent:** backend-architect (standard model)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp
**MCP:** context7 (xray routing docs), exa (docs)
**Depends on:** nothing (can run in parallel with Wave 2)
**Review:** task reviewer after each, final review at end

### Wave 2: Known-Alive Tracking Redesign
**Largest impact on probe time. Depends on: Wave 1 (config reconciliation).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 2.1 | `internal/model/node.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Add `KnownAliveRecord{Key, Host, Link, LastSeen, LastStatus, AliveStreak, AliveWaveSeq}`. |
| 2.2 | `internal/store/` | backend-architect | brainstorming, grilling, build-with-exa | — | New `known-alive.jsonl` store: ReadKnownAlive, WriteKnownAlive, PruneKnownAlive. |
| 2.3 | `internal/probe/probe.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go concurrency) | Replace `freshSkipSet` with `knownAliveSkipSet` (skips semi-passed + passed within TTL). Add `KnownAlive` field to `Options`. |
| 2.4 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `runProbe`: load KnownAlive from disk at wave start, pass to Options; after probe, write updated set (merge new alive + prune TTL-expired). Orphan retention with TTL decay. |
| 2.5 | `internal/rank/rank.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `collectCandidates`: consult KnownAlive as fallback liveness source for cold-base path. |
| 2.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit + integration + race tests. |

**Subagent:** backend-architect (standard model for 2.1-2.5, most capable for 2.6 integration tests)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go concurrency, file I/O), exa (docs)
**Depends on:** Wave 1 (config reconciliation for orphan logging)
**Review:** task reviewer after each, final review at end

### Wave 3: Concurrency Model Improvements
**Halves boot count, reduces memory. Depends on: nothing (independent).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 3.1 | `internal/config/config.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `DefaultProbeBatchSize` 10→20; `DefaultProbeThreads` 32→12. New knobs: `probe.batch_size`, `probe.batch_concurrency`, `probe.threads` (already exist, verify defaults). |
| 3.2 | `internal/checker/instance.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Widen port band 18500–18799 → 18500–18999 (500 ports). Update constants. |
| 3.3 | `internal/probe/probe.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go sync) | Verify `runBatchJobs` uses config batch_size. No code change if already wired. |
| 3.4 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Port allocation 12×20=240, no collision. Batch of 20 boots one xray. |

**Subagent:** backend-architect (standard model)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go sync, net), exa (docs)
**Depends on:** nothing (can run in parallel with Wave 2)
**Review:** task reviewer after each, final review at end

### Wave 4: Geo Enrichment Optimization
**Raises geo success rate from 47% to ~70%+. Depends on: Wave 2 (KnownAlive for exit IP cache).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 4.1 | `internal/config/config.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `GeoConfig.SelfReportConcurrency` default 8 (raise from 4). `GeoConfig.Timeout` default 8s. New: `ExitIPEchoURL` (already added in geo-fix). New: `MaxTTL` (cap for rate-limit sleep, default 30s). |
| 4.2 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go http, net) | `reportAll` uses SelfReportConcurrency. `Run` caps maxTTL sleep at Cfg.MaxTTL. New rung 0: MaxMind offline lookup before tunnel (if DB path configured). New rung 5: HTTPS echo via exit-IP echo URL after DoH fallback. |
| 4.3 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `runGeo` passes MaxMind path, exit-IP echo URL. In-wave geo cache by exit IP (from geo-fix). |
| 4.4 | `internal/model/node.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `FlagsVerified` already added (geo-fix). Verify integration. |
| 4.5 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | MaxMind lookup unit test. maxTTL cap unit test. Geo wave integration test. |

**Subagent:** backend-architect (standard model for 4.1-4.4, most capable for 4.5)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go http, net, file I/O), exa (MaxMind docs, ipinfo docs)
**Depends on:** Wave 2 (KnownAlive for exit IP cache)
**Review:** task reviewer after each, final review at end

### Wave 5: Dynamic Timeout Calibration
**Self-learning timeout adjustment. Depends on: Wave 2 (KnownAlive provides RTT data).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 5.1 | `internal/probe/probe.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go time, context) | Add `ObservedRTTMs []float64` and `TimedOutCount int` to probe outcome aggregation. Compute p95 + 1s margin. |
| 5.2 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go time, context) | Add `RequestRTTMs []float64` and `TimedOutCount int` to `geo.Summary`. |
| 5.3 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | After probe/geo stage: compute calibrated timeout, persist to `<dataDir>/timeout-calibration.json`, apply to next wave's `cfg`. |
| 5.4 | `internal/config/config.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Add `ProbeConfig.CalibrationEnabled bool` (default true), `ProbeConfig.CalibrationBase float64`, `ProbeConfig.CalibrationMargin float64`. |
| 5.5 | `internal/cli/status.go` (or pipeline.go) | backend-architect | brainstorming, grilling, build-with-exa | — | Display calibrated timeout in `publicvpn status` (compact block). |
| 5.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit: p95 computation, EMA, hysteresis, safety rails. Integration: calibrated timeout changes across waves. |

**Subagent:** backend-architect (standard model for 5.1-5.5, most capable for 5.6)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go time, context, file I/O), exa (adaptive timeout research)
**Depends on:** Wave 2 (KnownAlive provides RTT data for calibration)
**Review:** task reviewer after each, final review at end

### Wave 6: Dynamic Concurrency (CPU/RAM-aware)
**Auto-distribute concurrency within owner-set limits. Depends on: Wave 3 (batch_size config).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 6.1 | `internal/config/config.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Add `MaxCPUCores int`, `MaxRAMMB int`, `HeadroomPct int` to a new `ResourceConfig` (or extend existing). Defaults: 0 = auto-detect (runtime.NumCPU, system RAM). |
| 6.2 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Wave-start resource budget calculation: `min(ram_budget, cpu_budget, port_budget)`. Apply to probe (threads, batch_size) and geo (concurrency). |
| 6.3 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | In-wave adaptation: every 5s check memory pressure (>85% → reduce 25%), CPU idle → increase, port exhaustion → pressure. |
| 6.4 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Inter-wave EMA: persist per-stage cost to `stage-stats.jsonl`, adjust base concurrency for next wave. |
| 6.5 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Use dynamic concurrency instead of fixed `SelfReportConcurrency`. |
| 6.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit: budget calculation, adaptation logic. Integration: wave with resource limits completes. |

**Subagent:** backend-architect (standard model for 6.1-6.5, most capable for 6.6)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go runtime, sync, time), exa (resource-aware scheduling research)
**Depends on:** Wave 3 (batch_size config)
**Review:** task reviewer after each, final review at end

### Wave 7: Dynamic Cache Sizing
**Adaptive cache capacity based on memory, input, providers. Depends on: Wave 4 (geo cache).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 7.1 | `internal/geo/` (new file) | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go runtime) | `SizingEngine` with `RecomputeCap` — combines memory ceiling + input size + provider class. |
| 7.2 | `internal/geo/` | backend-architect | brainstorming, grilling, build-with-exa | — | Decision ladder: memory breach → shrink; input growth → grow; hit rate <70% + headroom → grow 25%; eviction <5% + headroom → shrink 15%; memory pressure >85% → shrink 20%; cooldown if resized last wave; else hold. |
| 7.3 | `internal/geo/` | backend-architect | brainstorming, grilling, build-with-exa | — | `CacheStats` extension: Capacity, MemoryBytes, HitRate, EvictionRate, MemoryPressure, ProviderClass, LastResizeReason, LastResizeWave, ResizeCount. |
| 7.4 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit: ReuseCap logic, provider classification, decision ladder. |

**Subagent:** backend-architect (standard model for 7.1-7.3, most capable for 7.4)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go runtime, memory), exa (dynamic cache sizing research)
**Depends on:** Wave 4 (geo cache must exist first)
**Review:** task reviewer after each, final review at end

### Wave 8: Geo Cache Implementation
**Exit-IP → hosting/proxy cache with lease renewal. Depends on: Wave 7 (sizing).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 8.1 | `internal/model/node.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Add `FlagsVerified bool` to GeoRecord (already done in geo-fix). Add `AliveWaveSeq int`, `AliveStreak int` for run-count KnownAlive. |
| 8.2 | `internal/geo/` (new file) | backend-architect | brainstorming, grilling, build-with-exa | context7 (hashicorp/golang-lru) | `ExitGeoCache` — hot in-memory, 16 shards, LRU per shard, TTL with renewal. `touch()` on hit. Rehydrate from geo-base.jsonl. |
| 8.3 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Replace `Reporter.cache`/`cacheMu` with `ExitGeoCache`. Add in-wave cache by exit IP. |
| 8.4 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `runGeo` constructs + rehydrates cache. `runProbe` increments wave seq. |
| 8.5 | `internal/store/` | backend-architect | brainstorming, grilling, build-with-exa | — | `wave-state.json` (single field: currentWaveSeq). Read/increment/persist. |
| 8.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit: cache hit/miss, renewal, eviction, rehydration. Integration: wave with cache. |

**Subagent:** backend-architect (standard model for 8.1-8.5, most capable for 8.6)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (hashicorp/golang-lru, Go sync, file I/O), exa (cache design research)
**Depends on:** Wave 7 (sizing)
**Review:** task reviewer after each, final review at end

### Wave 9: Dynamic Timeout Calibration
**Self-learning timeout adjustment. Depends on: Wave 2 (KnownAlive provides RTT data).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 9.1 | `internal/probe/probe.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go time, context) | Add `ObservedRTTMs []float64` and `TimedOutCount int` to probe outcome aggregation. Compute p95 + 1s margin. |
| 9.2 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go time, context) | Add `RequestRTTMs []float64` and `TimedOutCount int` to `geo.Summary`. |
| 9.3 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | After probe/geo stage: compute calibrated timeout, persist to `<dataDir>/timeout-calibration.json`, apply to next wave's `cfg`. |
| 9.4 | `internal/config/config.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Add `ProbeConfig.CalibrationEnabled bool` (default true), `ProbeConfig.CalibrationBase float64`, `ProbeConfig.CalibrationMargin float64`. Per-city granularity support. |
| 9.5 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Display calibrated timeout in `publicvpn status` (compact block: current, base, floor/ceiling, CV, wave count, slowest 3 regions). |
| 9.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit: p95 computation, EMA, hysteresis, safety rails, adaptive window. Integration: calibrated timeout changes across waves. |

**Subagent:** backend-architect (standard model for 9.1-9.5, most capable for 9.6)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go time, context, file I/O), exa (adaptive timeout research)
**Depends on:** Wave 2 (KnownAlive provides RTT data for calibration)
**Review:** task reviewer after each, final review at end

### Wave 10: Final Integration and Quality Gates

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 10.1 | All | backend-architect | brainstorming, grilling, build-with-exa, code-reviewer | — | Full build, vet, test -race, golangci-lint, markdownlint. |
| 10.2 | All | backend-architect | brainstorming, grilling, build-with-exa | — | Manual verification: `publicvpn status`, `publicvpn list`, `publicvpn list -v`. |
| 10.3 | README.md, config.example.toml | technical-writer | brainstorming, grilling, build-with-exa | — | Update docs with new knobs and features. |

**Subagent:** backend-architect (most capable for review), technical-writer for docs
**Skills:** brainstorming, grilling, build-with-exa, code-reviewer, requesting-code-review
**MCP:** context7, exa
**Depends on:** All waves complete
**Review:** final whole-branch review

## 5. Dependency Graph

```
Wave 0 (config tuning) ──┐
Wave 1 (render robustness) ──┤
Wave 3 (concurrency) ──┤──→ Wave 10 (final)
Wave 2 (KnownAlive) ──┤
Wave 4 (geo enrichment) ──┤──→ Wave 8 (geo cache)
Wave 5 (dynamic timeout) ──┤
Wave 6 (dynamic concurrency) ──┤
Wave 7 (cache sizing) ──┘
```

**Parallelization opportunities:**
- Wave 0, 1, 3 can run in parallel (disjoint files).
- Wave 2 depends on Wave 1 (config reconciliation).
- Wave 4 depends on Wave 2 (KnownAlive for exit IP cache).
- Wave 5 depends on Wave 2 (RTT data).
- Wave 6 depends on Wave 3 (batch_size config).
- Wave 7 depends on Wave 4 (geo cache must exist).
- Wave 8 depends on Wave 7 (sizing).
- Wave 9 depends on Wave 2 (RTT data).
- Wave 10 depends on all.

**Recommended execution order:**
1. Wave 0 (immediate, config-only)
2. Wave 1 + Wave 3 (parallel, disjoint files)
3. Wave 2 (depends on Wave 1)
4. Wave 4 + Wave 5 + Wave 6 (parallel after Wave 2/3)
5. Wave 7 (after Wave 4)
6. Wave 8 (after Wave 7)
7. Wave 9 (after Wave 2)
8. Wave 10 (final)

## 6. Subagent Assignment Summary

| Wave | Agent type | Model | Skills required | MCP required |
|------|-----------|-------|----------------|-------------|
| 0 | (owner, no code) | — | — | — |
| 1 | backend-architect | opencode-go/beam-free#max | brainstorming, grilling, build-with-exa, context7-mcp | context7, exa |
| 2 | backend-architect | opencode-go/beam-free#max | brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development | context7, exa |
| 3 | backend-architect | opencode-go/beam-free#max | brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development | context7, exa |
| 4 | backend-architect | opencode-go/beam-free#max | brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development | context7, exa |
| 5 | backend-architect | opencode-go/beam-free#max | brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development | context7, exa |
| 6 | backend-architect | opencode-go/beam-free#max | brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development | context7, exa |
| 7 | backend-architect | opencode-go/beam-free#max | brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development | context7, exa |
| 8 | backend-architect | opencode-go/beam-free#max | brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development | context7, exa |
| 9 | backend-architect | opencode-go/beam-free#max | brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development | context7, exa |
| 10 | backend-architect + technical-writer | opencode-go/beam-free#max | brainstorming, grilling, build-with-exa, code-reviewer, requesting-code-review | context7, exa |

**Every subagent dispatch must include:**
- The memory mandate (read MEMORY.md + topics + projects/public_vpn.md)
- The no-subagents contract (implementer never dispatches subagents)
- The report file path and report contract
- The relevant brief file path
- The global constraints from this plan

**Task briefs:** Use `bash scripts/task-brief PLAN_FILE N` to extract task text to a uniquely named file. Never make a subagent read the whole plan file.

**Review:** After each task, dispatch a task reviewer (task-reviewer-prompt.md) with the brief, report, and review package. After all tasks in a wave, dispatch a final code reviewer (code-reviewer.md) on the most capable model.

## 7. Owner Decisions Needed (from all plans)

| # | Decision | Options | Recommendation |
|---|----------|---------|----------------|
| 1 | Per-region timeout ladder | IR/CN/RU/TR=12s, DE/NL/US/FR=6s | Adopt as proposed |
| 2 | MaxMind provisioning | Provide license key + DB path, or decline | Owner declined ("не просил MaxMind") — exclude |
| 3 | refresh_interval | 1h (current) or 2h | 2h (halves daily resource use) |
| 4 | KnownAlive TTL | 2h (proposed) | Replace with run-count (N=3 waves) per owner |
| 5 | attempts | 3 → 2 | Accept (33% fewer HTTP GETs) |
| 6 | Per-city vs per-region timeouts | per-city, per-region, global | Per-region primary, global fallback (per-city statistically unsound) |
| 7 | Show calibrated timeout in status | yes/no | Yes (compact block) |
| 8 | Dynamic calibration enabled by default | yes/no | Yes (safe by construction) |
| 9 | Dynamic history size | fixed N or adaptive | Adaptive window [3,50] + adaptive α (CV-driven) |
| 10 | Library for geo-cache | hashicorp/golang-lru/v2/expirable | Confirmed |
| 11 | Cache size cap | fixed or dynamic | Dynamic (SizingEngine, memory-aware) |
| 12 | Concurrency model | fixed or dynamic (CPU/RAM) | Dynamic (owner sets max CPU/RAM, system auto-distributes) |
| 13 | MaxMind in geo enrichment | include or exclude | Exclude (owner: "не просил максмайнд") |
| 14 | pool_routes reconciliation | change to pool_all/unknown or keep | Owner said "не трогать" but waves fail at render; graceful routes fix (→ block) already implemented |

## 8. Risk Assessment (consolidated)

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Stale liveness data from KnownAlive | Medium | Medium | Run-count (3 waves) + geo.ttl freshness gate in rank |
| False negatives from lower timeout | Medium | Medium | Per-region overrides, semi-passed preserved, controlled A/B |
| xray can't handle 20 concurrent inbounds | Low | High | xray run -test gate; revert to 10 if fail |
| Port band exhaustion | Low | High | Widen to 500 ports; monitor allocation |
| Memory regression from larger batches | Low | Medium | Threads drop to 12; peak comparable or lower |
| Render skips a needed route, traffic drops | Medium | Medium | Loud warning + config reconciliation at wave start |
| Dynamic concurrency oscillation | Low | Medium | EMA smoothing, hysteresis, cooldown |
| Cache sizing thrashing | Low | Medium | Hysteresis (10%), cooldown if resized last wave |

## 9. Definition of Done

- [ ] All 10 waves implemented and tested.
- [ ] `go build ./...`, `go vet ./...`, `gofmt -l .`, `golangci-lint run ./...` all pass (0 issues).
- [ ] `go test -race -count=1 ./...` passes (checker flake resolved or documented).
- [ ] Probe wall time reduced from ~90 min to ~30 min.
- [ ] Geo wall time reduced from ~7.6 min to ~2 min.
- [ ] Total wave time reduced from ~98 min to ~35 min.
- [ ] Peak memory reduced from ~1.7 GB to ~1.0 GB.
- [ ] Render failures eliminated (0/9 waves).
- [ ] Manual verification: `publicvpn status`, `publicvpn list`, `publicvpn list -v`.
- [ ] README.md and config.example.toml updated.
- [ ] All reports written and ledger updated.
- [ ] Final whole-branch review clean.

## 10. Sources Consulted

### Research documents (in `.superpowers/sdd/2026-10-31-plugin-liveness-and-clean-balancers/`)
1. `perf-analysis-report.md` — bottleneck analysis, optimization recommendations (322 lines)
2. `optimization-implementation-plan.md` — 5-track implementation plan
3. `dynamic-timeout-plan.md` — dynamic timeout calibration (p95 + EMA + adaptive window)
4. `geo-cache-plan.md` — geo cache design (hashicorp/golang-lru/v2/expirable, lease renewal, run-count KnownAlive)
5. `dynamic-concurrency-plan.md` — CPU/RAM-aware concurrency (5 waves A-E)
6. `dynamic-cache-sizing-plan.md` — adaptive cache sizing (SizingEngine, ReuseCap)
7. `method-benchmark-report.md` — method comparison, 429 accounting, batch capacity
8. `wave-timing-report.md` — 88 min wave breakdown
9. `wave-monitor-1..5-report.md` — 5 waves documented
10. `geo-research-report.md` — unknown locations + exit IP detection (171 lines)
11. `self-update-research-report.md` — auto-restart mechanisms
12. `instant-apply-plan-review.md` — instant config apply review (7 findings)
13. `graceful-routes-report.md` — graceful pool route handling

### Context7 libraries studied
- `/fsnotify/fsnotify` — file watching, atomic-save parent-dir pattern
- `/xtls/xray-core` (v26.3.27) — observatory API, core constraints
- `/hashicorp/golang-lru` — LRU + expirable cache, renewal-on-Add
- `/dgraph-io/ristretto` — TinyLFU admission, SampledLFU eviction
- `/allegro/bigcache` — off-heap cache, LifeWindow/CleanWindow
- Go stdlib: sync.RWMutex, sync.Map, runtime.MemStats, GOMEMLIMIT, context.WithTimeout, time.Timer

### Web research (cloakbrowser, humanize=true, careful)
- `jasonwong1991/easy_proxies` — proxy pool manager, health-check + failover
- `kutovoys/xray-checker` — per-node liveness with cooldown blacklist
- Adaptive timeout management (IEEE reference)
- IP geo caching patterns (Flyriver, Weaviate GOMEMLIMIT)

### Memory consulted
- `~/.config/opencode/MEMORY.md` (full index)
- `~/.config/opencode/memory/projects/public_vpn.md` (full project contract)
- `~/.config/opencode/memory/topics/workflow.md` (subagent mandates, plan-before-start rule)
- `~/.config/opencode/memory/topics/workflow-git-pr.md` (branch→PR→squash pipeline)
- `~/.config/opencode/memory/topics/stack-and-tools.md` (toolchain gates)
- `~/.config/opencode/memory/topics/environment-infra.md` (xray/remnawave infra)