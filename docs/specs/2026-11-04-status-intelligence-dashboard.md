# `assay status` — Provider Intelligence Dashboard: UI/UX Design Spec

**Status:** Design Spec (Code-Verified) — 0 code modifications in this phase.
**Target:** Transform `assay status` from a plain debug log into an intelligent decision dashboard for evaluating, pruning, and optimizing node sources/plugins (Lua plugins).

---

## 1. Terminal Screen Layouts (ASCII Mockups)

All screens leverage the existing single-styling owner in `internal/ui` (lipgloss v2, ANSI-256 traffic lights 46/214/196, dim tree glyphs, table borders).

### 1.1 Standard View (`assay status`)

```
assay pipeline status
config: local-share default ~/.local/share/assay/config.toml
data dir: /home/<user>/.local/share/assay

┌─ Pipeline Funnel ─────────────────────────────────────────────────────────┐
│ Fetched       14,208  [███████████████████████████ 100.0%]                │
│ Filtered       9,412  [███████████████████           66.2%]                │
│ Probed         9,412  [███████████████████           66.2%]                │
│ Alive          5,642  [███████████                   39.7%]                │
│ Geo Clean      4,218  [████████                      29.7%]                │
│ Selected         222  [                             1.6%]                  │
└───────────────────────────────────────────────────────────────────────────┘

┌─ Global Quality & Pool Distribution ──────────────────────────────────────┐
│ Clean (Residential)   3,120 nodes (74.0%)                                │
│ Datacenter/Hosting    1,098 nodes (26.0%)                                │
│ Regional Breakdown:                                                       │
│   EU  48.2% ██████████████████████                                       │
│   NA  22.4% ████████████                                                 │
│   APAC 18.1% █████████                                                   │
│   RU   8.6% █████                                                        │
│   Other 2.7% ██                                                          │
└───────────────────────────────────────────────────────────────────────────┘

┌─ Provider Intelligence ───────────────────────────────────────────────────┐
│ Provider          Parsed Alive (Now / 24h Avg) Clean Unique Primary      │
│                             ▂▃▅▆▇  ▂▄▆█         %     %     Overlap    │
│ matin-ghanbari     4,210   82 (45.2%)  70 (39.1%)  ▂▃▅▅▆▇  41.2% 88.4%  │
│ epodonios           2,800  45 (16.1%)  60 (21.4%)  ▄▅▆▆▇▇  22.0% 76.2%  │
│ 0xradikal           1,900  28 (14.7%)  40 (21.1%)  ▂▃▃▄▅▅  28.9% 91.5%  │
│ haker23378-netizen  1,800  15 (8.3%)   12 (6.7%)   ▃▃▃▄▄▅  11.8% 95.2%  │
└───────────────────────────────────────────────────────────────────────────┘

install:  installed binary: ~/.local/bin/assay
service:  enabled active (daemon)
```

### 1.2 Verbose / Overlap View (`assay status --overlap` or `status -v`)

```
...
┌─ Provider Intelligence ───────────────────────────────────────────────────┐
│ ... (compact view) ...                                                   │
└───────────────────────────────────────────────────────────────────────────┘

┌─ Provider Overlap Inspection (Pairwise) ──────────────────────────────────┐
│ Matrix shows overlap percentage of shared node identities:                │
│               matin  epod  0xrad  haker                                     │
│ matin-ghan    100%   82%    12%    8%                                     │
│ epodonios      82%  100%    45%   22%                                     │
│ 0xradikal      12%   45%   100%   15%                                     │
│ haker23378      8%   22%    15%  100%                                     │
│                                                                        │
│ Pruning Recommendations:                                                 │
│  1. epodonios shares 82% of its nodes with matin-ghanbari.               │
│     If matin-ghanbari has higher liveness/latency, consider pruning     │
│     epodonios unless its unique nodes (18%) cover distinct regions.     │
│  2. 0xradikal has 91.5% unique nodes — KEEP (low overlap, high yield). │
│  3. haker23378-netizen overlaps > 90% with matin-ghanbari & 0xradikal.  │
│     Impact is minimal if removed — candidate for disabling.              │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component & Data Models

### 2.1 Pipeline Funnel (Section 1)
*   **Source:** Stages from `fetch` (manifest) → `filter` (`filtered.jsonl`) → `probe` (`probe-results.jsonl`) → `alive` → `geo clean` (`geo-base.jsonl`) → `select` (`selection.json`).
*   **Layout:** Single-line proportional horizontal bar `[███████ 66.2%]`.
*   **Glyph:** `█` filled, `░` dim (dim 240 tree style).

### 2.2 Global Quality & Pool Distribution (Section 2)
*   **Residential/Hosting Ratio:** Aggregated from all geo-clean nodes (`HostingFlag` vs clean).
*   **Regional Breakdown:** Aggregated `Country` ISO codes from active selection or geo base.

### 2.3 Provider Intelligence Table (Section 3)
Built using the existing `ui.Table` component (lipgloss NormalBorder, dim 238 borders, bold 99 headers, right-aligned numeric columns).

| Column | Width | Alignment | Semantics / Content |
| :--- | :--- | :--- | :--- |
| **Provider** | 20 | Left | `st.PluginID` from `PluginStats` |
| **Parsed** | 10 | Right | `st.TotalNodes` |
| **Alive (Now / 24h Avg)** | 14 | Right | Current wave: `st.LiveNodes` (%). 24h avg derived from historical `probe-results.jsonl` or rolling window. Includes sparkline glyph. |
| **Sparkline / Trend** | 8 | Center | 6-point rolling window of alive counts, rendered as `▂▃▅▆▇` |
| **Clean %** | 8 | Right | `st.CleanCount / st.TotalNodes` |
| **Unique %** | 8 | Right | `(TotalNodes - DuplicateCount) / TotalNodes` |
| **Primary Overlap** | 14 | Left | Top pairwise overlap partners, e.g., `'mostly with X [82%], Y [45%]'` |
| **Verdict** | 10 | Center | Traffic-light badge: `OK` (green), `WARN` (amber), `DROP` (red) |

---

## 3. Color & Accessibility Rules

### 3.1 Traffic Light Hierarchy
*   **Green (ANSI 256: 46):** High liveness (> 60%), clean ratio (> 70%), OK verdict.
*   **Amber (ANSI 256: 214):** Moderate liveness (30%–60%), overlapping nodes, Warning verdict.
*   **Red (ANSI 256: 196):** Low liveness (< 30%), 100% redundant, Drop verdict.

### 3.2 Layout Rules
*   **Alignment:** Use `ui.Column` with `Right: true` for all numeric metrics (Parsed, Alive, Clean %, Unique %).
*   **Glyph Fallbacks (NO_COLOR / ASCII mode):**
    *   Sparklines: `[---|===+###]` instead of `▂▃▅▆▇`
    *   Bars: `[=========>    ]` instead of `[███████]`
    *   Verdicts: `[OK]` / `[!!]` / `[XX]` instead of colored backgrounds.
*   **Width Guard:** Provider names truncate with `…` if > 20 chars. Long overlap lists truncate at top 2 partners.

---

## 4. Machine-Readable JSON Schema (`--json`)

When `assay status --json` is executed, the dashboard is bypassed in favor of a structured JSON dump:

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-11-04T14:32:15Z",
  "config_source": "local-share default /home/<user>/.local/share/assay/config.toml",
  "pipeline": {
    "fetched": 14208,
    "filtered": 9412,
    "probed": 9412,
    "alive": 5642,
    "geo_clean": 4218,
    "selected": 222
  },
  "global_quality": {
    "residential_pct": 74.0,
    "hosting_pct": 26.0,
    "regional": [
      { "code": "EU", "pct": 48.2 },
      { "code": "NA", "pct": 22.4 },
      { "code": "APAC", "pct": 18.1 },
      { "code": "RU", "pct": 8.6 }
    ]
  },
  "providers": [
    {
      "id": "matin-ghanbari",
      "total_parsed": 4210,
      "alive_current": 82,
      "alive_24h_avg": 70,
      "alive_pct": 45.2,
      "clean_pct": 41.2,
      "unique_pct": 88.4,
      "sparkline": [12, 15, 18, 22, 28, 30],
      "overlaps": [
        { "with": "epodonios", "pct": 82.0 },
        { "with": "0xradikal", "pct": 12.0 }
      ],
      "verdict": "OK"
    }
  ],
  "overlap_matrix": [
    { "a": "matin-ghanbari", "b": "epodonios", "shared_pct": 82.0 }
  ],
  "recommendations": [
    "Prune 'epodonios' (82% overlap with matin-ghanbari, higher latency).",
    "Keep '0xradikal' (91.5% unique nodes, excellent geo spread)."
  ]
}
```

---

## 5. Integration Recommendations for `internal/cli/pipeline.go`

Current file: `internal/cli/pipeline.go` (lines 2095–2400+).
Current helper: `printPluginLivenessStatus(out io.Writer, p paths, cfg *config.Config, color bool)`.

### 5.1 Recommended File & Function Refactor
1.  **Create `internal/cli/status_intel.go`**:
    *   Move `printPluginLivenessStatus`, `printStageCounts`, `printGeoStatus` into `status_intel.go`.
    *   Add `printPipelineFunnel`, `printGlobalQuality`, `printOverlapMatrix` in `status_intel.go`.
2.  **Extend `runStatus`** in `pipeline.go`:
    *   Introduce `statusFlags` struct (`Verbose`, `JSON`, `Overlap`).
    *   Update `newStatusCommand` in `pipeline.go` to bind `--json`, `--overlap` (or `-v`) flags.
    *   Call `printPipelineFunnel(out, p, color)` and `printGlobalQuality(out, p, color)` before `printPluginLivenessStatus`.
    *   When `--json` is set, call `emitStatusJSON(out, res, p)`.
3.  **Enrich `internal/plugins/stats.go`**:
    *   Add `OverlapPartners map[string]int` and `SparklineHistory []int` to `PluginStats` to support the dashboard without re-computing graph traversals at render time.
