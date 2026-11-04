# Disk I/O and Full Optimization Master Plan

**Project:** public_vpn (Go 1.27, xray pool manager)
**Date:** 2026-11-02
**Status:** PLANNING — awaiting owner approval before implementation
**Plan author:** orchestrator (consolidated from perf-analysis-report.md, disk-io-analysis-report.md, and all prior research/planning documents)

## 1. Executive Summary

The maintain wave is probe-bound (91% of wall time) and network-bound on dead nodes. Disk I/O is NOT the wall-time bottleneck (daemon writes ~6 KB/s), but two real problems exist:

1. **Unbounded `probe-results.jsonl`** (361 MB, 1.1M records) — re-read 4-5× per wave → 1.4-1.8 GB redundant reads/wave.
2. **Non-atomic `rendered/config.json`** — `os.WriteFile` (no temp+rename, no fsync) — the one true durability hazard.

Additionally, the dynamic planning review found **6 subsystems, only 2 wired** — sizing engine, adaptation, and inter-wave EMA are dead code. The user wants everything wired, tested, and verified.

**Expected aggregate impact (all tracks combined):**
- Probe wall time: 90 min → ~30 min (3×)
- Total wave time: 98 min → ~35 min (2.8×)
- Peak memory: 1.7 GB → ~1.0 GB (−40%)
- Render failures: 5/9 → 0/9 (already fixed)
- Disk I/O: 1.4 GB redundant reads/wave → ~5 MB
- Durability: rendered config becomes atomic+synced

## 2. Source Documents

All in `.superpowers/sdd/2026-10-31-plugin-liveness-and-clean-balancers/`:
1. `perf-analysis-report.md` — bottleneck analysis, optimization recommendations (322 lines)
2. `disk-io-analysis-report.md` — disk I/O analysis, RAM vs disk recommendations
3. `optimization-implementation-plan.md` — 5-track implementation plan (Waves 1-10)
4. `dynamic-timeout-plan.md` — dynamic timeout calibration
5. `geo-cache-plan.md` — geo cache design (hashicorp/golang-lru/v2/expirable)
6. `dynamic-concurrency-plan.md` — CPU/RAM-aware concurrency
7. `dynamic-cache-sizing-plan.md` — adaptive cache sizing (SizingEngine)
8. `method-benchmark-report.md` — method comparison, 429 accounting
9. `dynamic-planning-review.md` — feedback loop analysis, dead code audit
10. `instant-apply-plan-review.md` — instant config apply review
11. `graceful-routes-report.md` — graceful pool route handling
12. `wave-timing-report.md` — 88 min wave breakdown
13. `wave-monitor-1..6-report.md` — 6 waves documented

## 3. Global Constraints

- No external dependencies beyond current `go.mod` (ask before adding).
- One config file, one storage mode, no fallback chains.
- The `-test` gate is non-negotiable; a failed gate leaves the live config untouched.
- Never auto-restart `xray-raw.service`.
- Owner-facing docs (`README.md`, `config.example.toml`) updated in the same change.
- All quality gates: gofmt, gofumpt, golangci-lint, go vet, go build, go test -race, markdownlint at zero.
- Branch → PR → squash-merge pipeline. No direct push to main.
- Subagent mandates: background:true, specialized agent types only (no `general`), fresh session per task, memory mandate in every brief.
- **Plan-before-start rule:** show plan to owner and get confirmation before starting. (Recorded in global memory 2026-11-01.)

## 4. Wave Structure

### Wave 0: Config Tuning (no code, immediate effect)
**Owner actions only — no subagent needed.**

| # | Action | Config change | Expected impact |
|---|--------|--------------|-----------------|
| 0.1 | Enable skip_fresh_within | `skip_fresh_within = "1h"` | ✅ Already done |
| 0.2 | Probe timeout | `probe.timeout = "8s"` | ✅ Already done (was 10s, now 8s) |
| 0.3 | Geo timeout | `geo.timeout = "10s"` | ✅ Already done |
| 0.4 | Geo concurrency | `geo.self_report_concurrency = 8` | ✅ Already done |
| 0.5 | Probe attempts | `probe.attempts = 2` | ✅ Already done |
| 0.6 | Refresh interval | `maintain.refresh_interval = "2h"` | ✅ Already done |

**Status:** ✅ COMPLETE (all applied in prior sessions).

### Wave 1: Disk I/O Fixes (durability + performance)
**Smallest, highest-impact. Depends on: nothing.**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 1.1 | `internal/render/render.go` | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | context7 (xray config) | Make rendered config atomic: replace `os.WriteFile` with `writeFileAtomic` (temp+Sync+rename). Add fsync. |
| 1.2 | `internal/store/store.go` | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Compact `probe-results.jsonl`: store only latest-per-key instead of append-only. Reduce 361 MB → ~5 MB. |
| 1.3 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Drop fsync from intermediate writes (nodes.jsonl, filtered.jsonl). Keep atomic rename. |
| 1.4 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Move `probe-work/` temp configs to tmpfs (`/tmp/opencode/probe-work/` or `os.MkdirTemp`). |
| 1.5 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Fix silently dead stage-stats path: loud warning if `RecordStageStat` fails. |
| 1.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Tests for atomic render, probe-results compaction, tmpfs probe-work. |

**Subagent:** backend-architect (standard model for 1.1-1.5, most capable for 1.6)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go file I/O, os package), exa (tmpfs best practices)
**Depends on:** nothing (can run in parallel with Wave 2)
**Review:** task reviewer after each, final review at end

### Wave 2: Wire Dead Code (sizing + adaptation + EMA)
**Connects implemented-but-unused code. Depends on: nothing (independent).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 2.1 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go sync) | Wire `SizingEngine` into `runGeo`: call `RecomputeCap`, apply via `exitCache.Resize(newCap)`, log resize decision. |
| 2.2 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Wire `AdaptConcurrency` into wave: 5s ticker, memory pressure → reduce 25%, CPU idle → increase, port exhaustion → pressure. |
| 2.3 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Wire `RecordStageStat` + `AdjustBaseConcurrency`: persist per-stage costs to `stage-stats.jsonl`, inter-wave EMA. |
| 2.4 | `internal/cli/resource_budget.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Fix `ComputeConcurrencyBudget`: scalar `min()` → boot-serialization-aware budget. |
| 2.5 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Wiring tests: sizing engine called, adaptation called, stage stats recorded. |

**Subagent:** backend-architect (standard model for 2.1-2.4, most capable for 2.5)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go sync, time, runtime), exa (concurrency patterns)
**Depends on:** nothing (can run in parallel with Wave 1)
**Review:** task reviewer after each, final review at end

### Wave 3: KnownAlive Tracking Redesign
**Run-count based, survives source removal. Depends on: Wave 1 (config reconciliation).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 3.1 | `internal/model/node.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Add `KnownAliveRecord{Key, Host, Link, LastSeen, LastStatus, AliveStreak, AliveWaveSeq}`. |
| 3.2 | `internal/store/` | backend-architect | brainstorming, grilling, build-with-exa | — | New `known-alive.jsonl` store: ReadKnownAlive, WriteKnownAlive, PruneKnownAlive (run-count based). |
| 3.3 | `internal/probe/probe.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go concurrency) | Replace `freshSkipSet` with `knownAliveSkipSet` (skips semi-passed + passed). Add `KnownAlive` field to `Options`. |
| 3.4 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Load KnownAlive at wave start, write updated set after probe. Orphan retention with run-count decay. |
| 3.5 | `internal/rank/rank.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `collectCandidates`: consult KnownAlive as fallback liveness source. |
| 3.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit + integration + race tests. |

**Subagent:** backend-architect (standard model for 3.1-3.5, most capable for 3.6)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go concurrency, file I/O), exa (docs)
**Depends on:** Wave 1 (config reconciliation for orphan logging)
**Review:** task reviewer after each, final review at end

### Wave 4: Geo Enrichment Optimization
**Raises geo success rate from 47% to ~70%+. Depends on: Wave 3 (KnownAlive for exit IP cache).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 4.1 | `internal/config/config.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `GeoConfig.SelfReportConcurrency` default 8 (already done). `GeoConfig.Timeout` default 8s (already done). New: `ExitIPEchoURL` (already done). New: `MaxTTL` (cap for rate-limit sleep, default 30s). |
| 4.2 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go http, net) | `reportAll` uses SelfReportConcurrency. `Run` caps maxTTL sleep at Cfg.MaxTTL. New rung 5: HTTPS echo via exit-IP echo URL. In-wave geo cache by exit IP. |
| 4.3 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `runGeo` passes exit-IP echo URL. Verify in-wave cache wired. |
| 4.4 | `internal/model/node.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `FlagsVerified` already added. Verify integration. |
| 4.5 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | maxTTL cap unit test. Geo wave integration test. |

**Subagent:** backend-architect (standard model for 4.1-4.4, most capable for 4.5)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go http, net, file I/O), exa (ipinfo docs, HTTPS echo services)
**Depends on:** Wave 3 (KnownAlive for exit IP cache)
**Review:** task reviewer after each, final review at end

### Wave 5: Dynamic Timeout Calibration
**Self-learning timeout adjustment. Depends on: Wave 3 (KnownAlive RTT data).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 5.1 | `internal/probe/probe.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go time, context) | Add `ObservedRTTMs []float64` and `TimedOutCount int` to probe outcome aggregation. Compute p95 + 1s margin. |
| 5.2 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go time, context) | Add `RequestRTTMs []float64` and `TimedOutCount int` to `geo.Summary`. |
| 5.3 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | After probe/geo stage: compute calibrated timeout, persist to `timeout-calibration.json`, apply to next wave's `cfg`. |
| 5.4 | `internal/config/config.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Add `CalibrationEnabled bool` (default true), `CalibrationBase float64`, `CalibrationMargin float64`. Per-region granularity. |
| 5.5 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Display calibrated timeout in `status` (compact block). |
| 5.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit + integration tests. |

**Subagent:** backend-architect (standard model for 5.1-5.5, most capable for 5.6)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go time, context, file I/O), exa (adaptive timeout research)
**Depends on:** Wave 3 (KnownAlive RTT data)
**Review:** task reviewer after each, final review at end

### Wave 6: Dynamic Concurrency (CPU/RAM-aware)
**Auto-distribute concurrency within owner-set limits. Depends on: Wave 1 (batch_size config).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 6.1 | `internal/config/config.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Add `MaxCPUCores int`, `MaxRAMMB int`, `HeadroomPct int` to `ResourceConfig`. Defaults: 0 = auto-detect. |
| 6.2 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Wave-start budget: `min(ram_budget, cpu_budget, port_budget)`. Apply to probe and geo. |
| 6.3 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | In-wave adaptation: 5s check, memory pressure → reduce 25%, CPU idle → increase. |
| 6.4 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Inter-wave EMA: persist per-stage cost to `stage-stats.jsonl`, adjust base concurrency. |
| 6.5 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Use dynamic concurrency instead of fixed SelfReportConcurrency. |
| 6.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit + integration tests. |

**Subagent:** backend-architect (standard model for 6.1-6.5, most capable for 6.6)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go runtime, sync, time), exa (resource-aware scheduling research)
**Depends on:** Wave 1 (batch_size config)
**Review:** task reviewer after each, final review at end

### Wave 7: Dynamic Cache Sizing
**Adaptive cache capacity. Depends on: Wave 4 (geo cache).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 7.1 | `internal/geo/` (new file) | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go runtime) | `SizingEngine` with `RecomputeCap` — memory + input + provider class. |
| 7.2 | `internal/geo/` | backend-architect | brainstorming, grilling, build-with-exa | — | Decision ladder: memory breach → shrink; input growth → grow; hit rate <70% + headroom → grow 25%; eviction <5% + headroom → shrink 15%; memory pressure >85% → shrink 20%; cooldown; else hold. |
| 7.3 | `internal/geo/` | backend-architect | brainstorming, grilling, build-with-exa | — | `CacheStats` extension: Capacity, MemoryBytes, HitRate, EvictionRate, MemoryPressure, ProviderClass, LastResizeReason, LastResizeWave, ResizeCount. |
| 7.4 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit tests. |

**Subagent:** backend-architect (standard model for 7.1-7.3, most capable for 7.4)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go runtime, memory), exa (dynamic cache sizing research)
**Depends on:** Wave 4 (geo cache must exist first)
**Review:** task reviewer after each, final review at end

### Wave 8: Geo Cache Implementation
**Exit-IP → hosting/proxy cache with lease renewal. Depends on: Wave 7 (sizing).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 8.1 | `internal/model/node.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Add `AliveWaveSeq int`, `AliveStreak int` to GeoRecord. `FlagsVerified` already added. |
| 8.2 | `internal/geo/` (new file) | backend-architect | brainstorming, grilling, build-with-exa | context7 (hashicorp/golang-lru) | `ExitGeoCache`: 16 shards, LRU per shard, TTL with renewal. `touch()` on hit. Rehydrate from geo-base.jsonl. |
| 8.3 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Replace `Reporter.cache`/`cacheMu` with `ExitGeoCache`. In-wave cache by exit IP. |
| 8.4 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | `runGeo` constructs + rehydrates cache. `runProbe` increments wave seq. |
| 8.5 | `internal/store/` | backend-architect | brainstorming, grilling, build-with-exa | — | `wave-state.json` (currentWaveSeq). Read/increment/persist. |
| 8.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit + integration tests. |

**Subagent:** backend-architect (standard model for 8.1-8.5, most capable for 8.6)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (hashicorp/golang-lru, Go sync, file I/O), exa (cache design research)
**Depends on:** Wave 7 (sizing)
**Review:** task reviewer after each, final review at end

### Wave 9: Dynamic Timeout Calibration
**Self-learning timeout adjustment. Depends on: Wave 3 (KnownAlive RTT data).**

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 9.1 | `internal/probe/probe.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go time, context) | Add `ObservedRTTMs []float64`, `TimedOutCount int`. Compute p95 + 1s margin. |
| 9.2 | `internal/geo/geo.go` | backend-architect | brainstorming, grilling, build-with-exa | context7 (Go time, context) | Add `RequestRTTMs []float64`, `TimedOutCount int` to `geo.Summary`. |
| 9.3 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | After probe/geo: compute calibrated timeout, persist to `timeout-calibration.json`, apply to next wave. |
| 9.4 | `internal/config/config.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Add `CalibrationEnabled bool` (default true), `CalibrationBase float64`, `CalibrationMargin float64`. Per-city granularity. |
| 9.5 | `internal/cli/pipeline.go` | backend-architect | brainstorming, grilling, build-with-exa | — | Display calibrated timeout in `status`. |
| 9.6 | Tests | backend-architect | brainstorming, grilling, build-with-exa, test-driven-development | — | Unit + integration tests. |

**Subagent:** backend-architect (standard model for 9.1-9.5, most capable for 9.6)
**Skills:** brainstorming, grilling, build-with-exa, context7-mcp, test-driven-development
**MCP:** context7 (Go time, context, file I/O), exa (adaptive timeout research)
**Depends on:** Wave 3 (KnownAlive RTT data)
**Review:** task reviewer after each, final review at end

### Wave 10: Final Integration and Quality Gates

| Task | Files | Agent | Skills | MCP | Description |
|------|-------|-------|--------|-----|-------------|
| 10.1 | All | backend-architect | brainstorming, grilling, build-with-exa, code-reviewer | — | Full gate run. Fix new issues. |
| 10.2 | All | backend-architect | brainstorming, grilling, build-with-exa | — | Manual verification: status, list, list -v, list --cities. |
| 10.3 | README.md, config.example.toml | technical-writer | brainstorming, grilling, build-with-exa | — | Update docs. |

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

**Parallelization:**
- Wave 0, 1, 3 can run in parallel (disjoint files).
- Wave 2 depends on Wave 1.
- Wave 4, 5, 6 depend on Wave 2/3.
- Wave 7 depends on Wave 4.
- Wave 8 depends on Wave 7.
- Wave 9 depends on Wave 2.
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

**Task briefs:** Use `bash scripts/task-brief PLAN_FILE N` to extract task text. Never make a subagent read the whole plan file.

**Review:** After each task, dispatch a task reviewer (task-reviewer-prompt.md) with the brief, report, and review package. After all tasks in a wave, dispatch a final code reviewer (code-reviewer.md) on the most capable available model.

## 7. Owner Decisions Needed

| # | Decision | Recommendation |
|---|----------|----------------|
| 1 | Per-region timeout ladder (IR/CN/RU/TR=12s, DE/NL/US/FR=6s) | Adopt as proposed |
| 2 | MaxMind provisioning | Exclude (owner: "не просил MaxMind") |
| 3 | refresh_interval | 2h |
| 4 | KnownAlive TTL → run-count (N=3 waves) | Adopt |
| 5 | attempts 3→2 | Accept |
| 6 | Per-city vs per-region timeouts | Per-region primary, global fallback |
| 7 | Show calibrated timeout in status | Yes |
| 8 | Dynamic calibration enabled by default | Yes |
| 9 | Dynamic history size | Adaptive window [3,50] + adaptive α |
| 10 | Library for geo-cache | hashicorp/golang-lru/v2/expirable (confirmed) |
| 11 | Cache size cap | Dynamic (SizingEngine, memory-aware) |
| 12 | Concurrency model | Dynamic (CPU/RAM constraints) |
| 13 | MaxMind in geo enrichment | Exclude |
| 14 | pool_routes reconciliation | Graceful → block (already implemented) |

## 8. Definition of Done

- [ ] All 10 waves implemented and tested.
- [ ] `go build ./...`, `go vet ./...`, `gofmt -l .`, `golangci-lint run ./...` all pass (0 issues).
- [ ] `go test -race -count=1 ./...` passes.
- [ ] Probe wall time reduced from ~90 min to ~30 min.
- [ ] Geo wall time reduced from ~7.6 min to ~2 min.
- [ ] Total wave time reduced from ~98 min to ~35 min.
- [ ] Peak memory reduced from ~1.7 GB to ~1.0 GB.
- [ ] Render failures eliminated (0/9 waves).
- [ ] Manual verification: `publicvpn status`, `publicvpn list`, `publicvpn list -v`.
- [ ] README.md and config.example.toml updated.
- [ ] All reports written and ledger updated.
- [ ] Final whole-branch review clean.

## 9. Sources Consulted

### Research documents (in `.superpowers/sdd/2026-10-31-plugin-liveness-and-clean-balancers/`)
1. `perf-analysis-report.md` — bottleneck analysis (322 lines)
2. `optimization-implementation-plan.md` — 5-track implementation plan
3. `dynamic-timeout-plan.md` — dynamic timeout calibration
4. `geo-cache-plan.md` — geo cache design
5. `dynamic-concurrency-plan.md` — CPU/RAM-aware concurrency
6. `dynamic-cache-sizing-plan.md` — adaptive cache sizing
7. `method-benchmark-report.md` — method comparison, 429 accounting
8. `wave-timing-report.md` — 88 min wave breakdown
9. `wave-monitor-1..6-report.md` — 6 waves documented
10. `geo-research-report.md` — unknown locations + exit IP detection
11. `self-update-research-report.md` — auto-restart mechanisms
12. `instant-apply-plan-review.md` — instant config apply review
13. `graceful-routes-report.md` — graceful pool route handling
14. `dynamic-planning-review.md` — feedback loop analysis, dead code audit
15. `disk-io-analysis-report.md` — disk I/O analysis

### Context7 libraries studied
- `/fsnotify/fsnotify`, `/xtls/xray-core`, `/hashicorp/golang-lru`, `/dgraph-io/ristretto`, `/allegro/bigcache`
- Go stdlib: sync.RWMutex, sync.Map, runtime.MemStats, GOMEMLIMIT, context.WithTimeout, time.Timer

### Web research (cloakbrowser, humanize=true, careful)
- `jasonwong1991/easy_proxies`, `kutovoys/xray-checker`
- Adaptive timeout management (IEEE reference)
- IP geo caching patterns (Flyriver, Weaviate GOMEMLIMIT)
- Dynamic cache sizing (Flyriver adaptive cache sizing)
- Resource-aware scheduling (PostgreSQL work_mem, make/ninja)

### Memory consulted
- `~/.config/opencode/MEMORY.md` (full index)
- `~/.config/opencode/memory/projects/public_vpn.md` (full project contract)
- `~/.config/opencode/memory/topics/workflow.md` (subagent mandates, plan-before-start rule)
- `~/.config/opencode/memory/topics/workflow-git-pr.md` (branch→PR→squash pipeline)
- `~/.config/opencode/memory/topics/stack-and-tools.md` (toolchain gates)
- `~/.config/opencode/memory/topics/environment-infra.md` (xray/remnawave infra)