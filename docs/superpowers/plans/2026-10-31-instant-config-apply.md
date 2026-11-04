# Instant Config Apply — deferred plan

> **Status:** DEFERRED (recorded 2026-10-31, not started).
> **Agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.
> Track steps with `- [ ]`. Do not start without an explicit go from the owner.

**Owner request (2026-10-31, verbatim):**
> «сделать потом моментальное применение (чтобы как конфиг обновлялся вписывался в текущий конфиг еще до его обновления (не ломая текущую проверку, но применяясь моментально))»

## Problem

A pure config edit — a new `[[render.pool_routes]]` entry, a threshold knob, a balancer
switch — only reaches the live client config `~/projects/xray-raw/config.json` at the very
end of a maintain wave: `fetch → parse → filter → probe → geo → stats → prune → select →
render → activate`.

`probe` + `geo` dominate. Measured on 2026-10-31: probe 16:04→17:43 (1795/45257 alive),
geo 17:44→18:0x+ with per-node timeouts of 10–30 s. A one-line routing change therefore
waited **hours** even though it depends only on `selection.json` + `filtered.jsonl`, both
of which were already on disk and unchanged.

Concrete trigger: adding `geosite:stripe → pool_sg_singapore` at 17:49 could not be
activated until the wave's own render stage.

## Goal

A config-only change is applied to the live xray config **within seconds/one render**, using
the already-available selection + filtered records, while:

1. **The gate is never bypassed.** `xray run -test` (with `XRAY_LOCATION_ASSET`) must pass on
   the newly rendered config before the atomic replace. No "fast path" flag that skips it.
2. **No restart.** Same contract as today: backup → atomic replace → printed restart hint,
   `xray-raw.service` never touched automatically.
3. **No race with a running wave.** The fast path and the maintain wave must never render /
   activate concurrently (single writer, file lock or equivalent).
4. **No silent divergence.** Whatever the fast path writes must be exactly what the next full
   wave would write given the same selection — otherwise the next activate flip-flops.

## Design sketch

### A. Split render into two layers

The rendered config has two dependency classes:

- **Data layer** — `outbounds` (one per selected node) + `observatory` interval. Depends on
  the *node records* (transport params) and selection. Changes only when probe/geo/select run.
- **Policy layer** — `routing.rules` (including `pool_routes`), `routing.balancers`
  (country/city/clean/all tags), `api`/stats, `policy`. Depends on the selection **tags and
  geo verdict flags** only, plus config knobs.

`pool_routes`, `balancer_tolerance`, `select.only_clean`, plugin thresholds and route knobs
live entirely in the policy layer. That is what makes the fast path possible: re-derive the
policy layer from the cached selection and splat it into the **currently live** config,
keeping the live data layer byte-identical.

Two implementation options, decide in Task 1 with measurements:

- **Option 1 (preferred): policy-only re-render.** Load the live config as the base,
  `stripPoolArtifacts` its policy layer, rebuild rules/balancers from `selection.json` +
  `filtered.jsonl` (or from the live outbound tags, which is even cheaper and immune to a
  stale selection), keep its `outbounds` untouched, run the gate, activate.
- **Option 2: full re-render from cached selection** (today's `render`, just triggered early).
  Simpler, but re-emits ~900 outbounds and still breaks on a stale selection (see C).

### B. Trigger

`publicvpn watch` watches `config.toml` (mtime + content hash) alongside the plugin dir it
already hot-reloads. On change:

- debounce (owner edits save-then-save; wait ~2 s),
- classify the change: policy-only vs data-affecting,
- policy-only → fast path (A); data-affecting (probe/geo/select/filter knobs) → do nothing,
  the next wave picks it up,
- log exactly which keys changed and which path was taken.

Explicit command too: `publicvpn apply` (policy-only) so it can be run by hand without the
daemon, mirroring `render`/`activate` as separate steps today.

### C. Stale selection must not be a hard failure

Today `render` fails loud:
`render: selected node 98a5ee93709a6cee (tag pool-xx-04) has no node record` — `selection.json`
(16:03) still referenced a node that the next filter pass (16:04) no longer kept. This kills
every manual `render`/`check` between waves and would kill the fast path too.

Fix: render should treat a selected node with no record as **dropped from this render** with a
loud per-node warning and a summary count, not a fatal error — or, for the fast path, work
from the live outbound tags so no record lookup is needed at all. Decide in Task 2; keep a
fatal mode behind an explicit flag if the "no silent drop" doctrine demands it for the full
wave (`L9` spirit: refuse the drop unless it is accounted for and reported).

## Tasks

### Task 1: Decide the mechanism (measure, do not guess)

- [ ] Write down the exact current policy-layer surface (`routing.rules`, `routing.balancers`,
  `api`, `policy`, `observatory`) and prove which config knobs touch only that surface.
- [ ] Prototype Option 1 and Option 2 on a copy of the data dir; time both; diff the output
  against a full-wave render for the same selection (must be byte-identical).
- [ ] Record the decision + evidence in this file.

### Task 2: Policy-only re-render

- [ ] `internal/render`: entry point that takes the live config + selection (or live outbound
  tags) and rebuilds only rules/balancers, preserving every outbound byte-for-byte.
- [ ] Tests: adding a `pool_routes` entry changes exactly one rule and zero outbounds; removing
  it restores the previous bytes; a `pool_routes` target that does not exist still fails loud
  (D6 unchanged).
- [ ] `select.only_clean` flip in the fast path re-emits the balancer set (clean-only vs
  clean+all) without touching outbounds.

### Task 3: Stale-selection handling

- [ ] Reproduce the 16:03/16:04 case in a fixture.
- [ ] Apply the decided behaviour from (C) with loud accounting; test both modes.
- [ ] Prove manual `render` works mid-wave again.

### Task 4: `apply` command + watch trigger

- [ ] `publicvpn apply`: load config → policy re-render → `xray -test` gate → backup →
  atomic replace → restart hint. Nothing else.
- [ ] `watch`: config mtime/hash detection, debounce, policy-vs-data classification, single
  writer lock shared with the maintain wave.
- [ ] Negative tests: gate failure leaves the live config untouched; concurrent wave + apply
  never interleave; unchanged config never re-activates (idempotent).

### Task 5: Quality gate + live verification

- [ ] `gofmt`, `gofumpt`, `golangci-lint`, `go vet`, `go build`, `go test -race -count=1 ./...`,
  `markdownlint` — zero.
- [ ] Live: edit a `pool_routes` entry, observe apply within seconds, confirm the diff in
  `~/projects/xray-raw/config.json` is exactly the expected rule, confirm `xray -test` ran and
  passed, confirm the daemon did not restart the service.

## Definition of done

- A `pool_routes`-only config change reaches the live config in seconds, mid-wave, with the
  `xray -test` gate green and no service restart.
- The change is idempotent and does not fight the next full wave's render.
- Data-affecting config changes are explicitly classified and deferred to the wave, with a log
  line saying so.
- Stale selection no longer blocks manual render/apply.

## Global constraints (unchanged from the parent plan)

- No external dependencies beyond `go.mod`.
- One config file, one storage mode, no fallback chains.
- The `-test` gate is non-negotiable; a failed gate must leave the live config untouched.
- Never auto-restart `xray-raw.service`.
- Owner-facing docs (`README.md`, `config.example.toml`) updated in the same change.
