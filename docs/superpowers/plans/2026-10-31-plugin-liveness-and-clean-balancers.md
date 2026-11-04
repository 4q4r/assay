# Plugin Liveness & Clean Balancers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add plugin liveness monitoring with per-plugin stats in status, configurable duplicate/live thresholds that auto-disable plugins, and clean/all balancer separation for countries and cities.

**Architecture:** 
- Extend `PluginsConfig` with duplicate/live threshold knobs
- Add plugin stats tracking in registry and fetch wave
- Extend status command with plugin liveness section
- Add circuit-breaker-like threshold checking in fetch wave
- Modify render to create clean/all balancer pairs per country/city
- Add `select.only_clean` config to filter only clean IPs

**Tech Stack:** Go 1.27.3, gopher-lua v2, existing internal packages

**Spec:** User objective in session context

## Global Constraints
- No external dependencies beyond current go.mod
- All quality gates must pass: gofmt, gofumpt, golangci-lint, go vet, go build, go test -race, markdownlint
- Follow existing patterns: chips for status, chips for config knobs, no range bounds on knobs
- Config knobs: nil/unset = default, explicit "0s"/0 = unbounded/disabled, negative = structurally invalid
- W19 unbounded select semantics preserved
- GeoRecord has `ProxyFlag` and `HostingFlag` for clean determination

## Review Focus
1. **Plugin stats accuracy** — per-plugin live count, duplicate count (bidirectional), hosting/proxy flag distribution
2. **Threshold enforcement** — plugin auto-disabled when thresholds violated, re-enabled on file edit
3. **Balancer separation** — clean balancer only gets nodes with `!HostingFlag && !ProxyFlag`; all balancer gets all
4. **only_clean filter** — when enabled, only clean balancers rendered, no all balancers
5. **Status display** — plugin liveness section shows correct aggregated data

---

### Task 1: Add Plugin Threshold Config to PluginsConfig

**Files:**
- Modify: `internal/config/config.go` (PluginsConfig struct, applyPluginsDefaults, validate)

**Interfaces:**
- Produces: `PluginsConfig.MaxDuplicatePercent *float64`, `PluginsConfig.MinLivePercent *float64` with defaults nil (unset = disabled)

- [ ] **Step 1: Write failing test** in `internal/config/config_test.go`
```go
func TestPluginsConfigThresholds(t *testing.T) {
    // Test nil defaults, explicit 0, positive values, validation
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `go test -v -run TestPluginsConfigThresholds ./internal/config/`

- [ ] **Step 3: Implement config fields**
Add to `PluginsConfig`:
```go
MaxDuplicatePercent *float64 `toml:"max_duplicate_percent"`
MinLivePercent      *float64 `toml:"min_live_percent"`
```
In `applyPluginsDefaults`: nil stays nil (disabled by default)
In `validate`: if set, must be >= 0 (no upper bound per owner ruling)

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

---

### Task 2: Track Plugin Stats in Fetch Wave

**Files:**
- Modify: `internal/cli/pipeline.go` (runAllPlugins, new stats tracking)
- Add: `internal/plugins/stats.go` (PluginStats struct and methods)

**Interfaces:**
- Consumes: `plugins.Registry`, fetch wave plugin results
- Produces: `PluginStats` per plugin with live count, total nodes, duplicate count, hosting/proxy breakdown

- [ ] **Step 1: Write failing test** in `internal/plugins/stats_test.go`
```go
func TestPluginStatsCollection(t *testing.T) {
    // Test stats aggregation from plugin nodes
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement PluginStats**
```go
type PluginStats struct {
    PluginID       string
    TotalNodes     int
    LiveNodes      int
    DuplicateCount int  // bidirectional: nodes with same key from other plugins
    HostingCount   int
    ProxyCount     int
    CleanCount     int  // !hosting && !proxy
}
```
Track during `runAllPlugins` - count nodes per plugin, cross-reference keys for duplicates, use GeoRecord for hosting/proxy flags

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

---

### Task 3: Add Plugin Liveness Section to Status Command

**Files:**
- Modify: `internal/cli/pipeline.go` (runStatus, add printPluginLivenessStatus)
- Modify: `internal/cli/status_color_internal_test.go` (test new section)

**Interfaces:**
- Consumes: `PluginStats` from registry, geo-base for hosting/proxy flags
- Produces: Status output section with per-plugin stats

- [ ] **Step 1: Write failing test** in `internal/cli/status_color_internal_test.go`
```go
func TestStatusPluginLiveness(t *testing.T) {
    // Test plugin liveness section appears with correct format
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement printPluginLivenessStatus**
Show: plugin name, total nodes, live nodes, live %, duplicate count, duplicate %, hosting %, proxy %, clean %, status (OK/WARNING/DISABLED)
Threshold violations highlighted

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

---

### Task 4: Implement Threshold Enforcement in Fetch Wave

**Files:**
- Modify: `internal/cli/pipeline.go` (runAllPlugins threshold checking)
- Use: `plugins.Registry.RecordFailure` for auto-disable on threshold violation

**Interfaces:**
- Consumes: `PluginsConfig.MaxDuplicatePercent`, `PluginsConfig.MinLivePercent`, `PluginStats`
- Produces: Plugin disabled in registry when thresholds violated

- [ ] **Step 1: Write failing test** in `internal/cli/pipeline_internal_test.go`
```go
func TestPluginThresholdAutoDisable(t *testing.T) {
    // Test plugin disabled when duplicate% > max or live% < min
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement threshold checking**
After each plugin run in `runAllPlugins`:
- Calculate duplicate% = duplicateCount / totalNodes * 100
- Calculate live% = liveNodes / totalNodes * 100
- If MaxDuplicatePercent set and duplicate% > threshold: RecordFailure (disable)
- If MinLivePercent set and live% < threshold: RecordFailure (disable)
- Log loud warning with exact values

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

---

### Task 5: Add Clean/All Balancer Separation in Render

**Files:**
- Modify: `internal/render/render.go` (buildBalancers function)
- Modify: `internal/model/node.go` (add CleanBalancerTag functions)

**Interfaces:**
- Consumes: `Selection` with GeoRecord flags, config flag for clean-only mode
- Produces: Two balancer sets per country/city (clean + all)

- [ ] **Step 1: Write failing test** in `internal/render/render_test.go`
```go
func TestCleanAndAllBalancers(t *testing.T) {
    // Test clean balancer only gets clean nodes, all gets all
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement balancer separation**
In `buildBalancers`:
- Split nodes by country: cleanNodes (hosting=false && proxy=false) and allNodes
- For each country with cleanNodes >= 2: render clean country balancer (tag: `pool_<cc>_clean`)
- For each country with allNodes >= 2: render all country balancer (tag: `pool_<cc>`)
- Same for city balancers: `pool_<cc>_<city>_clean` and `pool_<cc>_<city>`
- pool_all always rendered (all nodes); add pool_all_clean when clean nodes exist

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

---

### Task 6: Add only_clean Select/Render Config

**Files:**
- Modify: `internal/config/config.go` (SelectConfig or RenderConfig with OnlyClean bool)
- Modify: `internal/render/render.go` (respect OnlyClean flag)
- Modify: `internal/rank/rank.go` (filter selection to clean only when enabled)

**Interfaces:**
- Consumes: `SelectConfig.OnlyClean *bool` (nil = unset = false, explicit true = filter)
- Produces: Selection/render with only clean nodes

- [ ] **Step 1: Write failing test** in `internal/render/render_test.go` and `internal/rank/rank_test.go`
```go
func TestOnlyCleanFilter(t *testing.T) {
    // Test only clean nodes selected and rendered
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement OnlyClean**
In config: `OnlyClean *bool` in SelectConfig, default nil (false)
In rank: filter candidates to `!HostingFlag && !ProxyFlag` when enabled
In render: when OnlyClean=true, skip all-balancers, only render clean balancers

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

---

### Task 7: Integration Tests and Quality Gates

**Files:**
- Modify: existing tests as needed
- Run: all quality gates

- [ ] **Step 1: Run all tests** `go test -race -count=1 ./...`

- [ ] **Step 2: Run quality gates** `gofmt`, `gofumpt`, `golangci-lint`, `go vet`, `go build`, `markdownlint`

- [ ] **Step 3: Manual verification** - run status command, verify output

- [ ] **Step 4: Commit final changes**
---

## Follow-up plan (deferred, separate authorization)

**Instant config apply** — `docs/superpowers/plans/2026-10-31-instant-config-apply.md`.
A policy-only config change (e.g. a new `render.pool_routes` entry) must reach the live xray
config within seconds, mid-wave, through the unchanged `xray -test` gate — instead of waiting
for `probe` + `geo` (hours on 2026-10-31). Also fixes stale `selection.json` breaking manual
`render` (`selected node … has no node record`).
