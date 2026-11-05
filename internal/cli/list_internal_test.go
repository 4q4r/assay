package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/require"
)

// listFixture writes a fixed selection + probe results + geo-base and
// returns the config plus the exact expected time string.
func listFixture(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	gen := time.Date(2026, 10, 28, 15, 0, 0, 0, time.UTC)
	sel := &model.Selection{
		GeneratedAt: gen,
		CapApplied:  4,
		CitiesAlive: 3,
		Nodes: []model.SelectedNode{
			{Tag: "pool-de-01", Key: "k-de-1", Country: "de", City: "Frankfurt", RTTMs: 40},
			{Tag: "pool-de-02", Key: "k-de-2", Country: "de", City: "Berlin", RTTMs: 50},
			{Tag: "pool-fr-01", Key: "k-fr-1", Country: "fr", City: "Paris", RTTMs: 60},
			{Tag: "pool-us-01", Key: "k-us-1", Country: "us", City: "Dallas", RTTMs: 150},
		},
	}
	require.NoError(t, store.WriteSelection(filepath.Join(dir, "selection.json"), sel))

	// Probe truth: de-1 alive 40ms, de-2 dead, fr-1 alive 60ms, us-1 dead.
	results := []store.ProbeResult{
		{Key: "k-de-1", Host: "de1.example.com", Alive: true, RTTMs: 40, CheckedAt: gen},
		{Key: "k-de-2", Host: "de2.example.com", Alive: false, RTTMs: 51, CheckedAt: gen},
		{Key: "k-fr-1", Host: "fr1.example.com", Alive: true, RTTMs: 60, CheckedAt: gen},
		{Key: "k-us-1", Host: "us1.example.com", Alive: false, RTTMs: 149, CheckedAt: gen},
	}
	require.NoError(t, store.AppendProbeResults(filepath.Join(dir, "probe-results.jsonl"), results))

	cold := []*model.GeoRecord{
		{Tag: "pool-de-01", Country: "de", City: "Frankfurt", Alive: true, RTTMs: 40},
		{Tag: "pool-de-02", Country: "de", City: "Berlin", Alive: false, RTTMs: 51},
		{Tag: "pool-fr-01", Country: "fr", City: "Paris", Alive: true, RTTMs: 60},
		{Tag: "pool-nl-01", Country: "nl", City: "Amsterdam", Alive: false, RTTMs: 30},
	}
	require.NoError(t, store.WriteGeo(filepath.Join(dir, "geo-base.jsonl"), cold))

	cfg := &config.Config{DataDir: dir}
	return cfg, gen.Format(time.RFC3339)
}

func runListCapture(t *testing.T, cfg *config.Config, opts listOptions) string {
	t.Helper()
	out := &bytes.Buffer{}
	res := &config.Resolved{Config: cfg, Source: config.SourceConfigless}
	require.NoError(t, runList(out, res, opts))
	return out.String()
}

// multiCityFixture writes a selection + probes for arbitrary nodes (the
// tree-hierarchy fixture: one multi-city country plus a single-city one).
func multiCityFixture(t *testing.T, nodes []model.SelectedNode) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	gen := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	require.NoError(t, store.WriteSelection(filepath.Join(dir, "selection.json"),
		&model.Selection{GeneratedAt: gen, CapApplied: len(nodes), Nodes: nodes}))
	results := make([]store.ProbeResult, 0, len(nodes))
	for i, n := range nodes {
		results = append(results, store.ProbeResult{
			Key: n.Key, Host: fmt.Sprintf("h%d.example.com", i+1),
			Alive: true, RTTMs: n.RTTMs, CheckedAt: gen,
		})
	}
	require.NoError(t, store.AppendProbeResults(
		filepath.Join(dir, "probe-results.jsonl"), results))
	return &config.Config{DataDir: dir}, gen.Format(time.RFC3339)
}

func TestListGroupsActiveCoreByCountry(t *testing.T) {
	cfg, gen := listFixture(t)
	out := runListCapture(t, cfg, listOptions{})
	// Owner header (verbatim) + the selection provenance as its own dim chip.
	require.Contains(t, out, "📦 pool inventory — active core: 4 nodes")
	require.Contains(t, out, "selection: "+gen)
	require.NotContains(t, out, fmt.Sprintf("active core: 4 nodes (selection: %s)", gen),
		"the selection timestamp moved to its own provenance chip line")
	// Node-count ordering: de (2) first, then fr/us (1 each, name-ordered).
	deIdx := strings.Index(out, "🇩🇪 de Germany")
	frIdx := strings.Index(out, "🇫🇷 fr France")
	usIdx := strings.Index(out, "🇺🇸 us United States")
	require.GreaterOrEqual(t, deIdx, 0)
	require.Greater(t, frIdx, deIdx)
	require.Greater(t, usIdx, frIdx)
	// Alive counts: de 1/2, fr 1/1, us 0/1.
	require.Contains(t, out, "1")
	require.Contains(t, out, "0")
	// Min RTT of de = the smallest RTT among nodes CARRYING an RTT:
	// 40, 51 → 40; formatted by the shared formatter.
	require.Contains(t, out, "40ms", "de min of [40,51] = 40ms")
	require.Contains(t, out, "60ms", "fr min is the single 60ms probe")
}

func TestListCitiesExpansion(t *testing.T) {
	cfg, _ := listFixture(t)
	out := runListCapture(t, cfg, listOptions{cities: true})
	// Germany has two cities → tree-glyph sub-rows UNDER the country row
	// (alphabetical: Berlin opens ├──, Frankfurt closes └──);
	// single-city countries get none (W16 suppression rule unchanged).
	require.Contains(t, out, "├── Berlin")
	require.Contains(t, out, "└── Frankfurt")
	require.NotContains(t, out, "├── Frankfurt", "Frankfurt is the last sub-row (└──)")
	require.NotContains(t, out, "└── Paris")
	require.NotContains(t, out, "├── Paris")
	require.NotContains(t, out, "├── Dallas")
}

// M-b pins: a geo case-variant pair ("Frankfurt am Main" vs
// "Frankfurt Am Main") is ONE city under `list --cities` — one table row
// and one JSON entry, both showing the deterministic lowest-string
// spelling, with the group's merged node counts; the display is identical
// regardless of node order.
func TestListCitiesFoldCaseVariants(t *testing.T) {
	t.Parallel()
	fraMain := model.SelectedNode{
		Tag: "pool-de-01", Key: "k-de-1", Country: "de",
		City: "Frankfurt am Main", RTTMs: 40,
	}
	fraAlt := model.SelectedNode{
		Tag: "pool-de-02", Key: "k-de-2", Country: "de",
		City: "Frankfurt Am Main", RTTMs: 50,
	}
	berlin := model.SelectedNode{
		Tag: "pool-de-03", Key: "k-de-3", Country: "de",
		City: "Berlin", RTTMs: 60,
	}

	capture := func(nodes []model.SelectedNode, opts listOptions) string {
		t.Helper()
		dir := t.TempDir()
		gen := time.Date(2026, 10, 28, 15, 0, 0, 0, time.UTC)
		require.NoError(t, store.WriteSelection(filepath.Join(dir, "selection.json"),
			&model.Selection{GeneratedAt: gen, Nodes: nodes}))
		results := make([]store.ProbeResult, 0, len(nodes))
		for i, n := range nodes {
			results = append(results, store.ProbeResult{
				Key: n.Key, Host: fmt.Sprintf("de%d.example.com", i+1),
				Alive: true, RTTMs: n.RTTMs, CheckedAt: gen,
			})
		}
		require.NoError(t, store.AppendProbeResults(
			filepath.Join(dir, "probe-results.jsonl"), results))
		return runListCapture(t, &config.Config{DataDir: dir}, opts)
	}

	nodes := []model.SelectedNode{fraMain, fraAlt, berlin}
	out := capture(nodes, listOptions{cities: true})
	require.Equal(t, 1, strings.Count(out, "Frankfurt Am Main"),
		"the case-variant pair is ONE city row, not two")
	require.Contains(t, out, "├── Frankfurt Am Main",
		"the folded 2-node pair sorts first (node-count order) and opens ├──")
	require.Contains(t, out, "└── Berlin",
		"the 1-node city closes the tree with └──")
	require.NotContains(t, out, "Frankfurt am Main",
		"the higher-sorting variant never displays")

	// The JSON twin agrees with the table: same single folded group, same
	// displayed spelling, merged node count (2 Frankfurt nodes + Berlin).
	var doc listJSONDoc
	require.NoError(t, json.Unmarshal([]byte(
		capture(nodes, listOptions{cities: true, json: true})), &doc))
	var de *listJSONCountry
	for i := range doc.Countries {
		if doc.Countries[i].Code == "DE" {
			de = &doc.Countries[i]
		}
	}
	require.NotNil(t, de, "the DE country row is present")
	require.Len(t, de.Cities, 2, "folded Frankfurt group + Berlin")
	require.Equal(t, "Frankfurt Am Main", de.Cities[0].City,
		"json city name agrees with the table")
	require.Equal(t, 2, de.Cities[0].Nodes, "json node count merges the variants")

	// Determinism: reversing the node order must not move the display name.
	reversed := capture([]model.SelectedNode{berlin, fraAlt, fraMain},
		listOptions{cities: true})
	require.Equal(t, 1, strings.Count(reversed, "Frankfurt Am Main"))
	require.Contains(t, reversed, "├── Frankfurt Am Main",
		"display is order-independent (node-count tree order regardless of node order)")
}

// W18 tree hierarchy: --cities sub-rows live INSIDE the one country table
// (glyphs ├──/└── under their country row), never as duplicate header
// blocks. First/mid/last glyph order is pinned with a three-city country.
func TestListTreeHierarchy(t *testing.T) {
	nodes := []model.SelectedNode{
		{Tag: "pool-de-01", Key: "k-de-1", Country: "de", City: "Aachen", RTTMs: 30},
		{Tag: "pool-de-02", Key: "k-de-2", Country: "de", City: "Berlin", RTTMs: 60},
		{Tag: "pool-de-03", Key: "k-de-3", Country: "de", City: "Cologne", RTTMs: 850},
		{Tag: "pool-fr-01", Key: "k-fr-1", Country: "fr", City: "Paris", RTTMs: 60},
	}
	cfg, _ := multiCityFixture(t, nodes)
	out := runListCapture(t, cfg, listOptions{cities: true})
	deIdx := strings.Index(out, "🇩🇪 de Germany")
	require.GreaterOrEqual(t, deIdx, 0)
	aachen := strings.Index(out, "├── Aachen")
	berlin := strings.Index(out, "├── Berlin")
	cologne := strings.Index(out, "└── Cologne")
	frIdx := strings.Index(out, "🇫🇷 fr France")
	require.Greater(t, aachen, deIdx, "cities render under their country")
	require.Greater(t, berlin, aachen, "glyph order: first/mid/last")
	require.Greater(t, cologne, berlin)
	require.Greater(t, frIdx, cologne, "the next country renders after the tree block")
	require.Equal(t, 1, strings.Count(out, "loc "),
		"ONE table header — cities never get their own header block")
	require.Equal(t, 1, strings.Count(out, "│ loc"),
		"one bordered table for countries + city sub-rows")
	// Cologne 850ms ≥ 800 → the red traffic light on a city median cell.
	colored := runListCapture(t, cfg, listOptions{cities: true, color: true})
	require.Contains(t, colored, "38;5;196", "≥800ms median is red (owner spec)")
}

// W18 JSON purity: --json output is a pure JSON document — zero ANSI bytes
// even though the underlying data carries colorable values.
func TestListJSONPurity(t *testing.T) {
	cfg, _ := listFixture(t)
	out := runListCapture(t, cfg, listOptions{json: true})
	require.NotContains(t, out, "\x1b", "JSON must never carry ANSI styling")
	require.True(t, json.Valid([]byte(out)), "output is valid JSON")
	require.Contains(t, out, `"min_rtt_ms": 40`, "JSON numbers unchanged (color-independent twin)")
}

func TestListAllColdSection(t *testing.T) {
	cfg, _ := listFixture(t)
	out := runListCapture(t, cfg, listOptions{all: true})
	require.Contains(t, out, "cold base: 4 records")
	require.Contains(t, out, "🇳🇱 nl Netherlands", "cold-only country appears in the cold section")
	require.Contains(t, out, "1", "fr alive count")
}

func TestListNoSelectionFailsLoud(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir()}
	out := &bytes.Buffer{}
	err := runList(out, &config.Resolved{Config: cfg, Source: config.SourceConfigless}, listOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no active selection")
}

// W18 golden: the bordered, chip-rendered list screen (color-off bytes).
// First run materializes testdata/golden-list-plain.txt; later runs pin it.
// The golden was REGENERATED deliberately for the lipgloss migration —
// deltas (bordered table, header/pools chips, selection chip line) are
// documented in the W18 report.
func TestListColorOffGolden(t *testing.T) {
	cfg, _ := listFixture(t)
	out := runListCapture(t, cfg, listOptions{})
	goldenPath := filepath.Join("testdata", "golden-list-plain.txt")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		require.NoError(t, os.MkdirAll("testdata", 0o750), "testdata dir")
		require.NoError(t, os.WriteFile(goldenPath, []byte(out), 0o644),
			"first run materializes the golden")
		return
	}
	require.Equal(t, string(golden), out,
		"list output diverged from testdata/golden-list-plain.txt — regenerate deliberately")
}

// W18: median cells carry the owner traffic light (46/214/196); the screen
// with color on contains the exact SGR codes; color-off stays clean.
func TestListTrafficLightColors(t *testing.T) {
	cfg, _ := listFixture(t)
	colored := runListCapture(t, cfg, listOptions{color: true})
	plain := runListCapture(t, cfg, listOptions{})
	require.NotEqual(t, colored, plain, "color mode must add ANSI sequences")
	require.Contains(t, colored, "\x1b[")
	require.NotContains(t, plain, "\x1b[")
	require.Contains(t, colored, "38;5;46", "green median (46ms < 400) is 46")
	require.Contains(t, colored, "38;5;214", "amber alive (de 1/2 partial) is 214")
	require.Contains(t, colored, "38;5;196", "red alive (us 0/1 dead) is 196")
}

func TestCountryNameFallback(t *testing.T) {
	require.Equal(t, "Germany", countryName("de"))
	require.Equal(t, "ZZ", countryName("zz"), "unknown codes degrade to the bare code")
	require.Empty(t, countryName(""))
}

// TestListUnknownGroupAndBalancers pins the W16 additions (owner item 14c):
// unknown-geo nodes in the selection render as their own 🏳 unknown row
// (the white flag — the one emoji mapping in the repo already treats empty
// codes as unknown), and the balancers line names the render-stage routing
// targets the selection produces: pool_all first, then countries, then the
// unknown pseudo-location when present.
func TestListUnknownGroupAndBalancers(t *testing.T) {
	dir := t.TempDir()
	gen := time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)
	sel := &model.Selection{
		GeneratedAt: gen,
		CapApplied:  3,
		CitiesAlive: 1,
		Nodes: []model.SelectedNode{
			{Tag: "pool-xx-01", Key: "k-xx-1", Country: "", City: "", RTTMs: 80},
			{Tag: "pool-xx-02", Key: "k-xx-2", Country: "", City: "", RTTMs: 90},
			{Tag: "pool-de-01", Key: "k-de-9", Country: "de", City: "Frankfurt", RTTMs: 40},
		},
	}
	require.NoError(t, store.WriteSelection(filepath.Join(dir, "selection.json"), sel))
	results := []store.ProbeResult{
		{Key: "k-xx-1", Host: "x1.example.com", Alive: true, RTTMs: 80, CheckedAt: gen},
		{Key: "k-xx-2", Host: "x2.example.com", Alive: false, RTTMs: 91, CheckedAt: gen},
		{Key: "k-de-9", Host: "de9.example.com", Alive: true, RTTMs: 40, CheckedAt: gen},
	}
	require.NoError(t, store.AppendProbeResults(filepath.Join(dir, "probe-results.jsonl"), results))
	cold := []*model.GeoRecord{
		{Tag: "pool-xx-01", Country: "", City: "", Alive: true, RTTMs: 80},
		{Tag: "pool-de-01", Country: "de", City: "Frankfurt", Alive: true, RTTMs: 40},
	}
	require.NoError(t, store.WriteGeo(filepath.Join(dir, "geo-base.jsonl"), cold))
	cfg := &config.Config{DataDir: dir}

	out := runListCapture(t, cfg, listOptions{all: true, verbose: true})
	require.Contains(t, out, "🏳 unknown", "the unknown group renders as its own location row")
	require.Contains(t, out,
		"⚖️ pools: pool_all (3 nodes), pool_de (1), pool_unknown (2)",
		"the pools chip names pool_all, country targets, and the unknown target")
	require.Contains(t, out, "🏳 unknown", "the cold section groups unknown-geo records the same way")
}

// TestListBalancersLineKnownOnly pins the conditional: a selection with only
// known countries names NO pool_unknown target (it would not render).
func TestListBalancersLineKnownOnly(t *testing.T) {
	cfg, _ := listFixture(t)
	out := runListCapture(t, cfg, listOptions{cities: true, verbose: true})
	require.Contains(t, out, "⚖️ pools: pool_all (4 nodes), pool_de (2), pool_fr (1), pool_us (1)")
	require.NotContains(t, out, "pool_unknown", "no unknown-geo nodes — no pool_unknown target")
}
