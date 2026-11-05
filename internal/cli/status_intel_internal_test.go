// Phase 4 status intelligence dashboard tests: verdict-threshold bands
// (table-driven), the --json machine-readable contract (field names, order,
// round-trip), the --overlap composition, NO_COLOR / plain-ASCII fallbacks
// (sparkline ladder " ..--==#", funnel bars "=-", verdicts [OK]/[!!]/[XX]),
// cold-start rendering, and the provider table's alignment stability.

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"public_vpn/internal/plugins"
	"public_vpn/internal/stats"
	"public_vpn/internal/ui"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statusIntelFixture builds a data dir with an ENRICHED manifest (post-
// upgrade shape), provider history, and a Phase-1 geo base — the "warm"
// state every dashboard element fills in for.
func statusIntelFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "run", "systemd"), 0o755))

	cfgPath := filepath.Join(home, "config.toml")
	body := "data_dir = " + quotePath(filepath.Join(home, "data")) + `

[maintain]
refresh_interval = "6h"
speedtest_interval = "168h"

[plugins]
max_duplicate_percent = 20.0
min_live_percent = 50.0
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))

	dataDir := filepath.Join(home, "data")
	cacheDir := filepath.Join(dataDir, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o750))

	// Funnel inputs: fetched 3 → filtered 2 → probed 3 (2 alive) → geo clean 1 → selected 2.
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "nodes.jsonl"),
		[]byte("{\"raw\":\"a\"}\n{\"raw\":\"b\"}\n{\"raw\":\"c\"}\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "filtered.jsonl"),
		[]byte("{\"raw\":\"a\"}\n{\"raw\":\"b\"}\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "probe-results.jsonl"),
		[]byte("{\"key\":\"k1\",\"host\":\"h1\",\"alive\":true,\"checked_at\":\"2026-11-04T10:00:00Z\"}\n"+
			"{\"key\":\"k2\",\"host\":\"h2\",\"alive\":true,\"checked_at\":\"2026-11-04T10:00:00Z\"}\n"+
			"{\"key\":\"k3\",\"host\":\"h3\",\"alive\":false,\"checked_at\":\"2026-11-04T10:00:00Z\"}\n"), 0o600))
	// geo base: two records with Phase-1 evidence (one clean residential
	// with unlock data, one hosting), one legacy record (no evidence).
	geo := "{\"scheme\":\"vless\",\"host\":\"a.example\",\"port\":443,\"country\":\"de\",\"alive\":true," +
		"\"risk_score\":12,\"is_residential\":true,\"ip_type\":\"Residential\"," +
		"\"media_unlocks\":{\"chatgpt\":\"yes\",\"netflix\":\"full\",\"youtube_region\":\"de\",\"checked_at\":\"2026-11-04T09:00:00Z\"}}\n" +
		"{\"scheme\":\"vless\",\"host\":\"b.example\",\"port\":443,\"country\":\"nl\",\"alive\":false," +
		"\"risk_score\":70,\"is_hosting\":true,\"ip_type\":\"DataCenter\"}\n" +
		"{\"scheme\":\"vmess\",\"host\":\"c.example\",\"port\":443,\"country\":\"\",\"alive\":false}\n"
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "geo-base.jsonl"), []byte(geo), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "selection.json"),
		[]byte("{\"cap_applied\":2,\"nodes\":[{\"tag\":\"pool-de-01\",\"key\":\"k1\",\"country\":\"de\"},"+
			"{\"tag\":\"pool-nl-01\",\"key\":\"k2\",\"country\":\"nl\"}]}"), 0o600))

	// Manifest: enriched stats + overlap matrix (Go-default field names, the
	// runtime wire shape).
	manifest := map[string]any{
		"fetched_at": "2026-11-04T12:00:00Z",
		"sources":    map[string]any{},
		"plugin_stats": []map[string]any{
			{
				"PluginID": "plugin_a", "TotalNodes": 100, "LiveNodes": 80,
				"DuplicateCount": 10, "HostingCount": 30, "ProxyCount": 20, "CleanCount": 50,
				// Post-F6 enrichment always records the geo-classified count:
				// the honest clean share is Clean/Classified (50/100 = 50%).
				"ClassifiedCount": 100,
				"UnlockCount":     12, "UniqueYield": 88.0,
				"TopOverlaps": []map[string]any{
					{"plugin_id": "plugin_b_redundant", "percent": 12.0},
				},
			},
			{
				"PluginID": "plugin_b_redundant", "TotalNodes": 50, "LiveNodes": 5,
				"DuplicateCount": 25, "HostingCount": 10, "ProxyCount": 5, "CleanCount": 35,
				"ClassifiedCount": 50,
				"UniqueYield":     8.0,
				"TopOverlaps": []map[string]any{
					{"plugin_id": "plugin_a", "percent": 82.0},
				},
			},
		},
		"plugin_overlap": map[string]any{
			"sets": map[string]any{"plugin_a": 90, "plugin_b_redundant": 46},
			"cells": map[string]any{
				"plugin_a":           map[string]any{"plugin_a": 100.0, "plugin_b_redundant": 12.0},
				"plugin_b_redundant": map[string]any{"plugin_a": 82.0, "plugin_b_redundant": 100.0},
			},
		},
	}
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "manifest.json"),
		mustMarshalJSON(t, manifest), 0o600))

	// Provider history: plugin_a has 6 waves inside the trailing 24h window
	// with rates 0..100% (exercises the whole sparkline ladder).
	hist := stats.ProviderHistory{Providers: map[string]*stats.ProviderSeries{}}
	series := &stats.ProviderSeries{}
	base := time.Now().UTC().Truncate(time.Hour).Add(-6 * time.Hour)
	lives := []int{0, 20, 40, 60, 80, 100}
	for i, live := range lives {
		ts := base.Add(time.Duration(i) * time.Hour)
		stats.UpdateSeries(series, stats.WaveSnapshot{Timestamp: ts.Unix(), Total: 100, Live: live}, ts)
	}
	hist.Providers["plugin_a"] = series
	require.NoError(t, stats.WriteProviderHistory(
		filepath.Join(dataDir, providerHistoryFile), &hist))
	return cfgPath
}

func quotePath(p string) string { return "\"" + p + "\"" }

// runStatusCaptured executes the full status path with the REAL command
// surface (flags registered by newStatusCommand) while pinning the config
// resolution through the explicit seam.
func runStatusCaptured(t *testing.T, cfgPath string, setFlags func(*cobra.Command)) string {
	t.Helper()
	cmd := newStatusCommand(&cfgPath)
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	if setFlags != nil {
		setFlags(cmd)
	}
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
	return out.String()
}

// ---------------------------------------------------------------------------
// Verdict bands
// ---------------------------------------------------------------------------

// TestProviderVerdictBands pins the spec §3.1 traffic-light bands and the
// worst-class-wins rule at the exact boundaries.
func TestProviderVerdictBands(t *testing.T) {
	tests := []struct {
		name      string
		alive     float64
		clean     float64
		unique    float64
		want      string
		wantColor string
	}{
		{"all green", 80, 90, 88, verdictOK, ui.Green},
		{"alive at green boundary", 60, 90, 88, verdictOK, ui.Green},
		{"alive just below green", 59.9, 90, 88, verdictWarn, ui.Amber},
		{"alive amber band", 45, 90, 88, verdictWarn, ui.Amber},
		{"alive at amber floor", 30, 90, 88, verdictWarn, ui.Amber},
		{"alive red", 29.9, 90, 88, verdictDrop, ui.Red},
		{"clean at green boundary", 80, 70, 88, verdictOK, ui.Green},
		{"clean just below green", 80, 69.9, 88, verdictWarn, ui.Amber},
		{"clean red", 80, 39.9, 88, verdictDrop, ui.Red},
		{"unique at green boundary", 80, 90, 40, verdictOK, ui.Green},
		{"unique amber", 80, 90, 39.9, verdictWarn, ui.Amber},
		{"unique red is redundant", 80, 90, 14.9, verdictDrop, ui.Red},
		{"worst wins: red alive beats amber clean", 10, 50, 88, verdictDrop, ui.Red},
		{"worst wins: amber unique beats green alive", 90, 90, 20, verdictWarn, ui.Amber},
		{"zero everything drops", 0, 0, 0, verdictDrop, ui.Red},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			word, color := providerVerdict(tt.alive, tt.clean, tt.unique)
			assert.Equal(t, tt.want, word)
			assert.Equal(t, tt.wantColor, color)
		})
	}
}

// ---------------------------------------------------------------------------
// Flags surface
// ---------------------------------------------------------------------------

func TestStatusCommandCarriesIntelFlags(t *testing.T) {
	cfgPath := ""
	cmd := newStatusCommand(&cfgPath)
	require.NotNil(t, cmd.Flags().Lookup("json"), "status carries --json")
	overlap := cmd.Flags().Lookup("overlap")
	require.NotNil(t, overlap, "status carries --overlap")
	assert.Equal(t, "v", overlap.Shorthand, "-v is the overlap shorthand (no conflict on status)")

	bare := &cobra.Command{}
	jsonOut, ov := statusOutputFlags(bare)
	assert.False(t, jsonOut, "a bare command renders the dashboard")
	assert.False(t, ov, "a bare command has no overlap view")
}

// ---------------------------------------------------------------------------
// Cold start (the live tree's pre-upgrade shape)
// ---------------------------------------------------------------------------

// statusColdFixture keeps the manifest zero-enriched (the pre-upgrade
// binary's shape), no provider history, no overlap matrix, no geo base.
func statusColdFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "run", "systemd"), 0o755))
	cfgPath := filepath.Join(home, "config.toml")
	body := "data_dir = " + quotePath(filepath.Join(home, "data")) + `

[maintain]
refresh_interval = "6h"
speedtest_interval = "168h"
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))

	dataDir := filepath.Join(home, "data")
	cacheDir := filepath.Join(dataDir, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "nodes.jsonl"), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "filtered.jsonl"), []byte(""), 0o600))
	manifest := map[string]any{
		"fetched_at": "2026-11-04T12:00:00Z",
		"sources":    map[string]any{},
		"plugin_stats": []map[string]any{
			{"PluginID": "barryfar", "TotalNodes": 18110, "LiveNodes": 0,
				"DuplicateCount": 394, "HostingCount": 0, "ProxyCount": 0, "CleanCount": 0},
		},
	}
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "manifest.json"),
		mustMarshalJSON(t, manifest), 0o600))
	// provider-history.json / geo-base.jsonl / probe-results / selection
	// deliberately absent — the cold start.
	return cfgPath
}

func TestStatusDashboardColdStart(t *testing.T) {
	cfgPath := statusColdFixture(t)
	s := runStatusCaptured(t, cfgPath, nil)

	assert.Contains(t, s, "provider intelligence", "the table section renders")
	assert.Contains(t, s, "calibrating", "no history → the calibrating note")
	assert.Contains(t, s, "n/a", "no enrichment → pending cells")
	assert.Contains(t, s, "liveness/quality columns fill after the plugin-stats enrichment pass",
		"the pending note names the missing pass")
	assert.Contains(t, s, "no ip-quality evidence yet", "quality cold start is explicit")
	assert.Contains(t, s, "no unlock evidence yet", "media cold start is explicit")
	assert.NotContains(t, s, "provider overlap inspection",
		"the matrix view is --overlap-only")
	assert.NotContains(t, s, "\x1b[", "plain mode: zero ANSI")
	assert.Contains(t, s, "0.0%", "an all-zero funnel renders empty shares")

	// --overlap renders the cold-start matrix note instead of a fabricated matrix.
	sOverlap := runStatusCaptured(t, cfgPath, func(cmd *cobra.Command) {
		require.NoError(t, cmd.Flags().Set("overlap", "true"))
	})
	assert.Contains(t, sOverlap, "matrix not computed yet", "cold overlap is explicit")
	assert.Contains(t, sOverlap, "no strong pruning signal", "advice stays silent without data")
}

// TestStatusJSONColdStartValid pins that --json emits a VALID document even
// on the pre-upgrade tree: verdict NONE, empty sparkline, empty matrix.
func TestStatusJSONColdStartValid(t *testing.T) {
	cfgPath := statusColdFixture(t)
	out := &bytes.Buffer{}
	cmd := newStatusCommand(&cfgPath)
	cmd.SetOut(out)
	require.NoError(t, cmd.Flags().Set("json", "true"))
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))

	var doc statusJSONDoc
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc), "the cold-start payload must parse")
	assert.Equal(t, "1.0", doc.SchemaVersion)
	require.NotEmpty(t, doc.Providers)
	assert.Equal(t, verdictNone, doc.Providers[0].Verdict)
	assert.Empty(t, doc.Providers[0].Sparkline)
	assert.Empty(t, doc.Providers[0].Overlaps)
	assert.Empty(t, doc.OverlapMatrix)
	assert.Empty(t, doc.Recommendations)
	assert.Equal(t, 0, doc.Pipeline.Fetched)
	assert.NotContains(t, out.String(), "\x1b[", "JSON is color-independent")
}

// ---------------------------------------------------------------------------
// Warm dashboard rendering
// ---------------------------------------------------------------------------

func TestStatusDashboardWarm(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	s := runStatusCaptured(t, cfgPath, nil)

	// New sections.
	assert.Contains(t, s, "pipeline funnel")
	assert.Contains(t, s, "global quality & pool distribution")
	assert.Contains(t, s, "media & unlock summary")
	assert.Contains(t, s, "provider intelligence")

	// Funnel annotations (fetched 3 → filtered 2 → probed 3 → alive 2 →
	// geo clean 1 → selected 2).
	assert.Contains(t, s, "-1 filter policy")
	assert.Contains(t, s, "+1 accumulated store (latest-per-key)")
	assert.Contains(t, s, "66.7%", "filtered share of fetched")

	// Quality (2 classified: 1 clean residential de, 1 hosting nl; 1 legacy ignored).
	assert.Contains(t, s, "2 classified — clean 1 (50.0%), hosting 1 (50.0%), proxy 0 (0.0%)")
	assert.Contains(t, s, "50.0% clean-residential (1 of 2 classified)")
	assert.Contains(t, s, "2 tagged, 1 unknown — top: de 1, nl 1")

	// Media (one checked record).
	assert.Contains(t, s, "1 exits probed — chatgpt yes 1, netflix full 1")
	assert.Contains(t, s, "youtube: 1 unlocked across de, 0 blocked")
	assert.Contains(t, s, "mean risk 12.0",
		"risk folds only scored (unlock-checked) exits — legacy zeros never drag the mean")

	// Provider table warm cells: sparkline spans the full ladder, trend is
	// strongly up.
	assert.Contains(t, s, "80 (80.0%)", "current alive cell")
	assert.Contains(t, s, "50.0%", "24h volume-weighted average")
	assert.Contains(t, s, " .--=#", "the sparkline renders (plain mode → pinned ASCII ladder)")
	assert.Contains(t, s, "↑", "the strong up trend arrow")
	assert.Contains(t, s, "plugin_b_re… 12%", "the overlap cell caps partner labels")
	assert.Contains(t, s, "plugin_a 82%", "the owning row renders the full partner id")
	assert.Contains(t, s, "OK", "verdict words render")

	// Legacy chips keep their exact bytes.
	assert.Contains(t, s, "plugin plugin_a: total=100 live=80 (80.0%) dup=10 (10.0%)"+
		" hosting=30 (30.0%) proxy=20 (20.0%) clean=50 (50.0%) status=OK")
}

// TestProviderCleanPercentClassifiedOnlyFlip pins F6's WARN-vs-DROP flip
// scenario (owner ruling 2026-11-04): alive-but-ungeo'd nodes once counted
// as clean against the pre-filter TotalNodes denominator, landing honest
// providers in the wrong verdict band. Post-fix, the clean share is
// CleanCount/ClassifiedCount — classified-only numerator AND denominator
// (mirroring the phase1Evidence gate).
func TestProviderCleanPercentClassifiedOnlyFlip(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name           string
		stats          plugins.PluginStats
		oldCleanCount  int // what the pre-fix fold would have counted as clean
		wantCleanPct   float64
		wantOldVerdict string // what Clean/TotalNodes would have said
		wantVerdict    string // the honest classified-only verdict
	}{
		{
			name: "alive-but-ungeo'd dilution: old WARN flips to DROP",
			// 10 alive nodes; 5 with geo records, ALL hosting; 5 never
			// geo'd. Old math folded the 5 ungeo'd into clean → 50% → WARN.
			// Honest math: 0 of 5 classified are clean → 0% → DROP.
			stats:          plugins.PluginStats{PluginID: "p", TotalNodes: 10, LiveNodes: 10, CleanCount: 0, HostingCount: 5, ClassifiedCount: 5, UniqueYield: 88},
			oldCleanCount:  5,
			wantCleanPct:   0,
			wantOldVerdict: verdictWarn,
			wantVerdict:    verdictDrop,
		},
		{
			name: "hosting-free provider no longer dilutes: old DROP flips to OK",
			// 10 alive nodes; 2 with geo records, both clean; 8 never
			// geo'd. Old math: 2/10 = 20% → DROP. Honest math: 2/2 = 100%
			// → the clean band is green.
			stats:          plugins.PluginStats{PluginID: "q", TotalNodes: 10, LiveNodes: 10, CleanCount: 2, ClassifiedCount: 2, UniqueYield: 88},
			oldCleanCount:  2,
			wantCleanPct:   100,
			wantOldVerdict: verdictDrop,
			wantVerdict:    verdictOK,
		},
		{
			name: "nothing geo-classified: clean share is 0 (unknown), never fabricated",
			// 7 alive nodes, none ever geo'd. Old math folded ALL of them
			// into clean (oldClean=7) → a fabricated 100% → OK. Honest
			// math: nothing classified → 0% → the no-evidence score.
			stats:          plugins.PluginStats{PluginID: "r", TotalNodes: 7, LiveNodes: 7, CleanCount: 0, ClassifiedCount: 0, UniqueYield: 88},
			oldCleanCount:  7,
			wantCleanPct:   0,
			wantOldVerdict: verdictOK,
			wantVerdict:    verdictDrop,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &fetchManifest{PluginStats: []plugins.PluginStats{tc.stats}}
			rows := buildProviderRows(m, &stats.ProviderHistory{Providers: map[string]*stats.ProviderSeries{}}, now)
			require.Len(t, rows, 1)
			row := rows[0]
			assert.True(t, row.enriched, "live evidence present → the row is enriched")
			assert.InDelta(t, tc.wantCleanPct, row.cleanPct, 1e-9, "clean%% is classified-only")
			// The old math really did land in the other band — the flip is
			// real, not a test artifact.
			oldPct := float64(tc.oldCleanCount) * 100 / float64(tc.stats.TotalNodes)
			oldVerdict, _ := providerVerdict(float64(tc.stats.LiveNodes)*100/float64(tc.stats.TotalNodes), oldPct, tc.stats.UniqueYield)
			assert.Equal(t, tc.wantOldVerdict, oldVerdict, "the pre-fix math must disagree (the flip is real)")
			assert.Equal(t, tc.wantVerdict, row.verdict, "the honest classified-only verdict")
		})
	}
}

func TestStatusDashboardOverlapView(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	s := runStatusCaptured(t, cfgPath, func(cmd *cobra.Command) {
		require.NoError(t, cmd.Flags().Set("overlap", "true"))
	})
	assert.Contains(t, s, "provider overlap inspection")
	assert.Contains(t, s, "100%", "the diagonal is pinned at 100")
	assert.Contains(t, s, "12%", "the a→b overlap share")
	assert.Contains(t, s, "82%", "the b→a overlap share")
	// Pruning advice from the enriched rows: plugin_b_redundant has 8% unique
	// and 82% overlap with plugin_a.
	assert.Contains(t, s, "prune candidate 'plugin_b_redundant': only 8.0% unique — 82% shared with plugin_a")
}

// TestStatusTableAlignmentStability pins the M3 contract on the new tables:
// every line inside one bordered box has the SAME rune width — rows never
// wrap, never collide.
func TestStatusTableAlignmentStability(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	s := runStatusCaptured(t, cfgPath, nil)

	blocks := make([][]int, 0, 2)
	var cur []int
	for line := range strings.SplitSeq(s, "\n") {
		switch {
		case strings.HasPrefix(line, "┌"):
			cur = append(cur[:0], len([]rune(line)))
		case cur != nil && (strings.HasPrefix(line, "│") || strings.HasPrefix(line, "└")):
			cur = append(cur, len([]rune(line)))
			if strings.HasPrefix(line, "└") {
				blocks = append(blocks, cur)
				cur = nil
			}
		}
	}
	require.Len(t, blocks, 2, "the dashboard renders the funnel and provider tables")
	for bi, block := range blocks {
		for i, w := range block {
			assert.Equal(t, block[0], w, "table %d line %d must align with its border box", bi, i)
		}
	}
}

// ---------------------------------------------------------------------------
// NO_COLOR / plain-ASCII fallbacks (pinned ladders)
// ---------------------------------------------------------------------------

func TestStatusDashboardASCIIFallbacks(t *testing.T) {
	cfgPath := statusIntelFixture(t)

	t.Run("plain mode (buffer = color off)", func(t *testing.T) {
		s := runStatusCaptured(t, cfgPath, nil)
		assert.NotContains(t, s, "\x1b[", "zero ANSI")
		assert.NotContains(t, s, "▂", "the unicode sparkline ladder is replaced")
		assert.Contains(t, s, " .--=#", "the pinned ASCII sparkline ladder renders")
		assert.Contains(t, s, "--", "mid-ladder ASCII glyphs render")
		assert.Contains(t, s, " 33.3%", "funnel bars use the =/- ASCII ladder")
		assert.Contains(t, s, "[!!]", "verdicts render as pinned ASCII words")
		assert.Contains(t, s, "[XX]", "the DROP verdict renders as ASCII")
	})

	t.Run("--color=always renders unicode + colored verdicts", func(t *testing.T) {
		s := runStatusCaptured(t, cfgPath, func(cmd *cobra.Command) {
			require.NoError(t, cmd.Flags().Set("color", "always"))
		})
		assert.Contains(t, s, "\x1b[", "color on")
		assert.Contains(t, s, "▂", "unicode sparkline under color")
		assert.Contains(t, s, "38;5;46", "OK verdict is traffic-light green")
		assert.Contains(t, s, "38;5;214", "WARN verdict is amber (plugin_a's clean% sits in the amber band)")
		assert.Contains(t, s, "38;5;196", "DROP verdict is red")
		assert.NotContains(t, s, "[OK]", "ASCII verdict words are the plain-mode fallback only")
	})

	t.Run("deterministic across runs", func(t *testing.T) {
		a := runStatusCaptured(t, cfgPath, nil)
		b := runStatusCaptured(t, cfgPath, nil)
		assert.Equal(t, a, b, "two runs render identically (no wall-clock bytes in the text view)")
	})
}

// ---------------------------------------------------------------------------
// JSON contract
// ---------------------------------------------------------------------------

// TestStatusJSONGolden pins the full schema: field names, order, and values
// against the fixture — the machine-readable twin of the dashboard.
func TestStatusJSONGolden(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	out := &bytes.Buffer{}
	cmd := newStatusCommand(&cfgPath)
	cmd.SetOut(out)
	require.NoError(t, cmd.Flags().Set("json", "true"))
	require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
	s := out.String()

	// Field order pins (encoding/json emits struct order).
	pairs := []string{
		`"schema_version"`, `"generated_at"`, `"config_source"`, `"pipeline"`,
		`"global_quality"`, `"providers"`, `"overlap_matrix"`, `"recommendations"`,
	}
	pos := -1
	for _, p := range pairs {
		i := strings.Index(s, p)
		require.Greater(t, i, pos, "%s must appear in schema order", p)
		pos = i
	}

	var doc statusJSONDoc
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc))

	// Key-set pin: the top level carries exactly the documented schema.
	var raw map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &raw))
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	assert.Equal(t, []string{
		"config_source", "generated_at", "global_quality", "overlap_matrix",
		"pipeline", "providers", "recommendations", "schema_version",
	}, keys, "the top-level key set is exactly the schema")

	assert.Equal(t, "1.0", doc.SchemaVersion)
	_, err := time.Parse(time.RFC3339, doc.GeneratedAt)
	require.NoError(t, err, "generated_at is RFC3339")
	assert.Contains(t, doc.ConfigSource, "config.toml", "the provenance rides along")

	assert.Equal(t, statusJSONPipeline{
		Fetched: 3, Filtered: 2, Probed: 3, Alive: 2, GeoClean: 1, Selected: 2,
	}, doc.Pipeline)

	// Quality: 2 classified (1 residential), regions de/nl/unknown.
	assert.InDelta(t, 50.0, doc.GlobalQuality.ResidentialPct, 1e-9)
	assert.InDelta(t, 50.0, doc.GlobalQuality.HostingPct, 1e-9)
	assert.Equal(t, []statusJSONRegion{
		{Code: "de", Pct: 33.333333},
		{Code: "nl", Pct: 33.333333},
		{Code: "unknown", Pct: 33.333333},
	}, doc.GlobalQuality.Regional)

	// Providers: sorted by id, full metric set.
	require.Len(t, doc.Providers, 2)
	a, b := doc.Providers[0], doc.Providers[1]
	assert.Equal(t, "plugin_a", a.ID)
	assert.Equal(t, 100, a.TotalParsed)
	assert.Equal(t, 80, a.AliveCurrent)
	assert.InDelta(t, 50.0, a.Alive24hAvg, 1e-9, "24h avg comes from stats.WeightedLiveness")
	assert.InDelta(t, 80.0, a.AlivePct, 1e-9)
	assert.InDelta(t, 50.0, a.CleanPct, 1e-9)
	assert.InDelta(t, 88.0, a.UniquePct, 1e-9)
	assert.Equal(t, []float64{0, 20, 40, 60, 80, 100}, a.Sparkline,
		"sparkline is the rate history in percent")
	assert.Equal(t, []statusJSONPair{{With: "plugin_b_redundant", Pct: 12}}, a.Overlaps)
	assert.Equal(t, verdictWarn, a.Verdict,
		"plugin_a's clean% (50) sits in the amber band — worst class wins")

	assert.Equal(t, "plugin_b_redundant", b.ID)
	assert.InDelta(t, 10.0, b.AlivePct, 1e-9)
	assert.Equal(t, verdictDrop, b.Verdict, "10% alive < 30 → DROP")
	assert.Empty(t, b.Sparkline, "no history for plugin_b_redundant")

	// Recommendations mirror the pruning bands (keep advice sorted after the
	// prune candidate by top-overlap share).
	assert.Equal(t, []string{
		"prune candidate 'plugin_b_redundant': only 8.0% unique — 82% shared with plugin_a",
		"keep 'plugin_a': 88.0% unique nodes (low overlap, high yield)",
	}, doc.Recommendations)

	// Overlap matrix: upper triangle of the sorted ids.
	require.Len(t, doc.OverlapMatrix, 1)
	assert.Equal(t, statusJSONOverlap{A: "plugin_a", B: "plugin_b_redundant", SharedPct: 12},
		doc.OverlapMatrix[0])

	assert.NotContains(t, s, "\x1b[", "JSON output is color-independent")
}

// TestStatusJSONOverlapComposition pins that both flags compose: --json
// --overlap emits the SAME JSON document (the matrix is always included).
func TestStatusJSONOverlapComposition(t *testing.T) {
	cfgPath := statusIntelFixture(t)
	run := func(overlap bool) string {
		out := &bytes.Buffer{}
		cmd := newStatusCommand(&cfgPath)
		cmd.SetOut(out)
		require.NoError(t, cmd.Flags().Set("json", "true"))
		if overlap {
			require.NoError(t, cmd.Flags().Set("overlap", "true"))
		}
		require.NoError(t, runStatus(cmd, explicitResolved(t, cfgPath)))
		return out.String()
	}
	assert.Equal(t, run(false), run(true),
		"--overlap must not change the JSON payload (the matrix is always part of it)")
}

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

func TestStatusIntelFormatters(t *testing.T) {
	assert.Equal(t, "14,208", formatCount(14208))
	assert.Equal(t, "1,380,072", formatCount(1380072))
	assert.Equal(t, "999", formatCount(999))
	assert.Equal(t, "0", formatCount(0))

	assert.Equal(t, "short", truncateName("short", 20))
	assert.Equal(t, "exactly-twenty-chars", truncateName("exactly-twenty-chars", 20))
	trunc := truncateName("a-very-long-provider-name-here", 20)
	assert.Len(t, []rune(trunc), 20)
	assert.True(t, strings.HasSuffix(trunc, "…"), "truncation uses an ellipsis")

	assert.Equal(t, strings.Repeat("█", 20)+" 100.0%", funnelBar(100, true))
	assert.Equal(t, strings.Repeat("░", 20)+" 0.0%", funnelBar(0, true))
	assert.Equal(t, strings.Repeat("=", 6)+strings.Repeat("-", 14)+" 33.3%",
		funnelBar(33.3, false))
	assert.Equal(t, strings.Repeat("=", 19)+strings.Repeat("-", 1)+" 99.9%", funnelBar(99.9, false))
	assert.Equal(t, strings.Repeat("-", 20)+" 0.4%", funnelBar(0.4, false))

	assert.Equal(t, " ..--==#", asciiSparklineString(stats.SparklineGlyphs))
	assert.Equal(t, ".-=", asciiSparklineString("▂▄▆"))

	assert.Equal(t, "blocked 12 / yes 40", formatVocab(map[string]int{"blocked": 12, "yes": 40}),
		"vocab counters render key-sorted (deterministic)")
	assert.Equal(t, "no data", formatVocab(map[string]int{}))
}
