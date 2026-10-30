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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Round-7 item 12a — `publicvpn list --json`: the machine-readable twin of
// the table, same aggregation code path, color-independent by construction.
// The schema structs live in list_cmd.go; the golden pin below fixes field
// names, order, and values against the shared fixture. The schema is
// documented in the README.

// TestListJSONGolden pins the full schema: countries → cities hierarchy,
// counts, alive, median RTT, and the W12 provenance (config source). The
// expectation is built through the production wire structs — field names,
// order, and values all pinned; the output is plain JSON with no color
// codes anywhere.
func TestListJSONGolden(t *testing.T) {
	cfg, gen := listFixture(t)
	p := newPaths(cfg)

	wantDoc := listJSONDoc{
		GeneratedAt: gen,
		Config:      listJSONConfig{Source: "configless (built-in defaults)"},
		Selection:   listJSONMetadata{Path: p.selection, Nodes: 4},
		Countries: []listJSONCountry{
			{
				Code: "DE", Name: "Germany", Flag: "🇩🇪",
				Nodes: 2, Alive: 1, MedianRTTms: 45.5,
				Cities: []listJSONCity{
					{City: "Berlin", Nodes: 1, Alive: 0, MedianRTTms: 51},
					{City: "Frankfurt", Nodes: 1, Alive: 1, MedianRTTms: 40},
				},
			},
			{Code: "FR", Name: "France", Flag: "🇫🇷", Nodes: 1, Alive: 1, MedianRTTms: 60},
			{Code: "US", Name: "United States", Flag: "🇺🇸", Nodes: 1, Alive: 0, MedianRTTms: 149},
		},
		ColdBase: &listJSONColdBase{
			Path:    p.geoBase,
			Records: 4,
			Countries: []listJSONCountry{
				{Code: "DE", Name: "Germany", Flag: "🇩🇪", Nodes: 2, Alive: 1, MedianRTTms: 45.5},
				{Code: "FR", Name: "France", Flag: "🇫🇷", Nodes: 1, Alive: 1, MedianRTTms: 60},
				{Code: "NL", Name: "Netherlands", Flag: "🇳🇱", Nodes: 1, Alive: 0, MedianRTTms: 30},
			},
		},
		Balancers: []balancerTarget{
			{Name: "pool_all", Nodes: 4},
			{Name: "pool_de", Nodes: 2},
			{Name: "pool_fr", Nodes: 1},
			{Name: "pool_us", Nodes: 1},
		},
	}
	want, err := json.MarshalIndent(wantDoc, "", "  ")
	require.NoError(t, err)

	out := runListCapture(t, cfg, listOptions{json: true, cities: true, all: true})
	assert.Equal(t, string(want)+"\n", out,
		"the JSON output must match the documented schema exactly (values from the fixture)")
	assert.NotContains(t, out, "\033[", "JSON output must be color-independent")
}

// TestListJSONWithoutCitiesOmitsCityArrays pins that the cities hierarchy
// appears only under --cities (the JSON mirrors exactly what the table
// renders).
func TestListJSONWithoutCitiesOmitsCityArrays(t *testing.T) {
	cfg, _ := listFixture(t)
	out := runListCapture(t, cfg, listOptions{json: true})
	assert.NotContains(t, out, `"cities"`, "no --cities: no city arrays")
	assert.Contains(t, out, `"median_rtt_ms"`, "country-level aggregates are always present")
}

// TestListJSONCitiesMirrorTableSuppression pins the parity contract (review
// Minor-2): the JSON city arrays mirror EXACTLY the table's --cities
// expansion, including its suppression rule. Two nodes in the SAME city are
// not two cities — the table renders no sub-rows for such a country (the
// dynamically confirmed divergence: NL 2 nodes both Amsterdam → no table
// sub-row), and the JSON must suppress identically. A multi-city country
// appears in both outputs, and the city-row counts must agree one for one
// (same aggregation code path, no fork).
func TestListJSONCitiesMirrorTableSuppression(t *testing.T) {
	dir := t.TempDir()
	gen := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	sel := &model.Selection{
		GeneratedAt: gen,
		CapApplied:  4,
		CitiesAlive: 2,
		Nodes: []model.SelectedNode{
			// The NL shape: two nodes, ONE city — the table suppresses it.
			{Tag: "pool-nl-01", Key: "k-nl-1", Country: "nl", City: "Amsterdam", RTTMs: 30},
			{Tag: "pool-nl-02", Key: "k-nl-2", Country: "nl", City: "Amsterdam", RTTMs: 35},
			// The control: one country with two distinct cities.
			{Tag: "pool-de-01", Key: "k-de-1", Country: "de", City: "Frankfurt", RTTMs: 40},
			{Tag: "pool-de-02", Key: "k-de-2", Country: "de", City: "Berlin", RTTMs: 50},
		},
	}
	require.NoError(t, store.WriteSelection(filepath.Join(dir, "selection.json"), sel))
	results := []store.ProbeResult{
		{Key: "k-nl-1", Host: "nl1.example.com", Alive: true, RTTMs: 30, CheckedAt: gen},
		{Key: "k-nl-2", Host: "nl2.example.com", Alive: true, RTTMs: 35, CheckedAt: gen},
		{Key: "k-de-1", Host: "de1.example.com", Alive: true, RTTMs: 40, CheckedAt: gen},
		{Key: "k-de-2", Host: "de2.example.com", Alive: false, RTTMs: 51, CheckedAt: gen},
	}
	require.NoError(t, store.AppendProbeResults(filepath.Join(dir, "probe-results.jsonl"), results))
	cfg := &config.Config{DataDir: dir}

	table := runListCapture(t, cfg, listOptions{cities: true})
	tableCityRows := strings.Count(table, "├── ") + strings.Count(table, "└── ")

	doc := runListJSON(t, cfg, listOptions{cities: true})
	jsonCityRows := 0
	for _, c := range doc.Countries {
		jsonCityRows += len(c.Cities)
	}

	assert.Equal(t, tableCityRows, jsonCityRows,
		"JSON city count must equal the table's rendered city sub-row count:\ntable:\n%s", table)

	for _, c := range doc.Countries {
		if c.Code == "NL" {
			assert.Empty(t, c.Cities,
				"a single-city country (2 nodes, both Amsterdam) must have no city sub-rows — the table suppresses them")
		}
		if c.Code == "DE" {
			assert.Len(t, c.Cities, 2,
				"a multi-city country keeps its city sub-rows in both outputs")
		}
	}
}

// runListJSON runs list --json and decodes the document (helper for pins
// that assert on structure, not bytes).
func runListJSON(t *testing.T, cfg *config.Config, opts listOptions) listJSONDoc {
	t.Helper()
	opts.json = true
	out := runListCapture(t, cfg, opts)
	var doc listJSONDoc
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "stdout must decode:\n%s", out)
	return doc
}

// TestListJSONUnknownAndBalancers pins the W16 integration (review handoff
// note): `list --json` serializes the W16 fields as STRUCTURED data, not
// display strings —
//   - the unknown-geo pseudo-country renders as its own country entry
//     (code "" — not an ISO code; name "unknown"; flag 🏳), exactly the row
//     the table shows;
//   - the balancers line's data carries as a structured `balancers` array
//     (pool_all / pool_<cc> / pool_unknown with node counts) — the same
//     aggregation the table's display line renders from (balancerSummary),
//     never a fork and never a parsed display string.
//
// The fixture is a sandbox selection with unknown-geo nodes AND multiple
// known countries — the shape the review required the verification against.
func TestListJSONUnknownAndBalancers(t *testing.T) {
	dir := t.TempDir()
	gen := time.Date(2026, 10, 29, 13, 0, 0, 0, time.UTC)
	sel := &model.Selection{
		GeneratedAt: gen,
		CapApplied:  5,
		CitiesAlive: 2,
		Nodes: []model.SelectedNode{
			{Tag: "pool-xx-01", Key: "k-xx-1", Country: "", City: "", RTTMs: 80},
			{Tag: "pool-xx-02", Key: "k-xx-2", Country: "", City: "", RTTMs: 90},
			{Tag: "pool-de-01", Key: "k-de-9", Country: "de", City: "Frankfurt", RTTMs: 40},
			{Tag: "pool-de-02", Key: "k-de-10", Country: "de", City: "Berlin", RTTMs: 50},
			{Tag: "pool-fr-01", Key: "k-fr-9", Country: "fr", City: "Paris", RTTMs: 60},
		},
	}
	require.NoError(t, store.WriteSelection(filepath.Join(dir, "selection.json"), sel))
	results := []store.ProbeResult{
		{Key: "k-xx-1", Host: "x1.example.com", Alive: true, RTTMs: 80, CheckedAt: gen},
		{Key: "k-xx-2", Host: "x2.example.com", Alive: false, RTTMs: 91, CheckedAt: gen},
		{Key: "k-de-9", Host: "de9.example.com", Alive: true, RTTMs: 40, CheckedAt: gen},
		{Key: "k-de-10", Host: "de10.example.com", Alive: true, RTTMs: 50, CheckedAt: gen},
		{Key: "k-fr-9", Host: "fr9.example.com", Alive: true, RTTMs: 60, CheckedAt: gen},
	}
	require.NoError(t, store.AppendProbeResults(filepath.Join(dir, "probe-results.jsonl"), results))
	cold := []*model.GeoRecord{
		{Tag: "pool-xx-01", Country: "", City: "", Alive: true, RTTMs: 80},
		{Tag: "pool-de-01", Country: "de", City: "Frankfurt", Alive: true, RTTMs: 40},
	}
	require.NoError(t, store.WriteGeo(filepath.Join(dir, "geo-base.jsonl"), cold))
	cfg := &config.Config{DataDir: dir}

	doc := runListJSON(t, cfg, listOptions{all: true})

	// The unknown pseudo-country entry — structured, not a display string.
	var unknown *listJSONCountry
	for i := range doc.Countries {
		if doc.Countries[i].Code == "" {
			unknown = &doc.Countries[i]
			break
		}
	}
	require.NotNil(t, unknown, "the unknown-geo group must appear as a country entry:\n%s", doc)
	assert.Equal(t, "unknown", unknown.Name, "the empty code is named, never left blank")
	assert.Equal(t, "🏳", unknown.Flag, "the white flag marks the unknown group")
	assert.Equal(t, 2, unknown.Nodes, "both unknown-geo nodes are in the group")
	assert.Equal(t, 1, unknown.Alive, "liveness comes from the same probe wave as every row")

	// The structured balancer targets: pool_all, countries by code, then
	// pool_unknown — identical aggregation to the table's display line.
	assert.Equal(t, []balancerTarget{
		{Name: "pool_all", Nodes: 5},
		{Name: "pool_de", Nodes: 2},
		{Name: "pool_fr", Nodes: 1},
		{Name: "pool_unknown", Nodes: 2},
	}, doc.Balancers, "the balancers array must be structured data, not a parsed display string")

	// The cold base groups unknown-geo records the same structured way.
	require.NotNil(t, doc.ColdBase)
	var coldUnknown *listJSONCountry
	for i := range doc.ColdBase.Countries {
		if doc.ColdBase.Countries[i].Code == "" {
			coldUnknown = &doc.ColdBase.Countries[i]
			break
		}
	}
	require.NotNil(t, coldUnknown, "the cold base carries the unknown group too")
	assert.Equal(t, "unknown", coldUnknown.Name)
	assert.Equal(t, 1, coldUnknown.Nodes)
}

// TestListJSONOnlyJSONOnStdout pins the machine-readable contract at the
// cobra seam: with --json the human config-source line and the table
// banners are suppressed — stdout is exactly one JSON document (the
// provenance lives inside it as the config object).
func TestListJSONOnlyJSONOnStdout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	fixtureCfg, _ := listFixture(t)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf("data_dir = %q\n", fixtureCfg.DataDir)), 0o600))

	root := New()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"-c", cfgPath, "list", "--json"})
	require.NoError(t, root.Execute())

	assert.True(t, json.Valid(buf.Bytes()),
		"stdout must be exactly one JSON document:\n%s", buf.String())
	assert.NotContains(t, buf.String(), "config: ", "the human config line must not leak into JSON output")
	assert.NotContains(t, buf.String(), "LOCATION", "no table banners in JSON output")
}
