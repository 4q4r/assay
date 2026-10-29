package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func TestListGroupsActiveCoreByCountry(t *testing.T) {
	cfg, gen := listFixture(t)
	out := runListCapture(t, cfg, listOptions{})
	require.Contains(t, out, fmt.Sprintf("active core: 4 nodes (selection: %s)", gen))
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
	// Median RTT of de = the single alive probe's 40ms (median over nodes
	// CARRYING an RTT: 40, 51 → 45.5); formatted by the shared formatter.
	require.Contains(t, out, "46ms", "de median of [40,51] = 45.5 → 46ms")
	require.Contains(t, out, "60ms", "fr median is the single 60ms probe")
}

func TestListCitiesExpansion(t *testing.T) {
	cfg, _ := listFixture(t)
	out := runListCapture(t, cfg, listOptions{cities: true})
	// Germany has two cities → indented sub-rows; single-city countries get none.
	require.Contains(t, out, "· Frankfurt")
	require.Contains(t, out, "· Berlin")
	require.NotContains(t, out, "· Paris")
	require.NotContains(t, out, "· Dallas")
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
	require.Equal(t, 1, strings.Count(out, "· Frankfurt"),
		"the case-variant pair is ONE city row, not two")
	require.Contains(t, out, "· Frankfurt Am Main",
		"display = the lowest string variant of the group")
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
	require.Equal(t, 1, strings.Count(reversed, "· Frankfurt"))
	require.Contains(t, reversed, "· Frankfurt Am Main",
		"display is order-independent")
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

func TestListColorOffGolden(t *testing.T) {
	cfg, gen := listFixture(t)
	out := runListCapture(t, cfg, listOptions{})
	want := "publicvpn pool inventory — active core: 4 nodes (selection: " + gen + ")\n" +
		"LOCATION\n" +
		"loc                  nodes  alive  median\n" +
		"🇩🇪 de Germany        2      1      46ms\n" +
		"🇫🇷 fr France         1      1      60ms\n" +
		"🇺🇸 us United States  1      0      149ms\n" +
		"\nbalancers: pool_all (4 nodes), pool_de (2), pool_fr (1), pool_us (1)\n"
	require.Equal(t, want, out)
}

func TestListColorsAppliedWhenEnabled(t *testing.T) {
	cfg, _ := listFixture(t)
	colored := runListCapture(t, cfg, listOptions{color: true})
	plain := runListCapture(t, cfg, listOptions{})
	require.NotEqual(t, colored, plain, "color mode must add ANSI sequences")
	require.Contains(t, colored, "\x1b[", "expected ANSI escapes")
	require.NotContains(t, plain, "\x1b[")
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

	out := runListCapture(t, cfg, listOptions{all: true})
	require.Contains(t, out, "🏳 unknown", "the unknown group renders as its own location row")
	require.Contains(t, out,
		"balancers: pool_all (3 nodes), pool_de (1), pool_unknown (2)",
		"the balancers line names pool_all, country targets, and the unknown target")
	require.Contains(t, out, "🏳 unknown", "the cold section groups unknown-geo records the same way")
}

// TestListBalancersLineKnownOnly pins the conditional: a selection with only
// known countries names NO pool_unknown target (it would not render).
func TestListBalancersLineKnownOnly(t *testing.T) {
	cfg, _ := listFixture(t)
	out := runListCapture(t, cfg, listOptions{})
	require.Contains(t, out, "balancers: pool_all (4 nodes), pool_de (2), pool_fr (1), pool_us (1)")
	require.NotContains(t, out, "pool_unknown", "no unknown-geo nodes — no pool_unknown target")
}
