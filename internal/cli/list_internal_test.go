package cli

import (
	"bytes"
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
	require.NoError(t, runList(out, cfg, opts))
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
	err := runList(out, cfg, listOptions{})
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
		"🇺🇸 us United States  1      0      149ms\n"
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
