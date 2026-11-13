package checker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenReport is a fixed, fully determined report: every outcome class is
// present (success, partial, blocked, dead, instance-failure), so the golden
// pins the whole rendering contract.
func goldenReport() *Report {
	ok := &NodeResult{
		Tag: "pool-nl-01", Country: "NL", City: "Amsterdam", ASN: "60404", ISP: "OpenIT",
		OK: 3, Total: 3, Statuses: []int{200}, TLSVersion: "1.3", TLSOK: true,
		ConnectMS: 45, AvgTTFBMS: 210, AvgMS: 480, MedianTotalMS: 470,
		AvgSpeedBPS: 1.2 * 1024 * 1024, ResolvedIPs: []string{"104.21.8.12"},
		DNSMethod: "doh-via-exit", Verdict: VerdictSuccess,
	}
	partial := &NodeResult{
		Tag: "pool-us-05", Country: "US", City: "Dallas", ASN: "AS20473", ISP: "The Constant Company",
		OK: 2, Total: 3, Statuses: []int{200, 403}, TLSVersion: "1.3", TLSOK: true,
		ConnectMS: 120, AvgTTFBMS: 380, AvgMS: 640, MedianTotalMS: 610,
		AvgSpeedBPS: 800 * 1024, ResolvedIPs: []string{"23.20.3.4"},
		DNSMethod: "doh-via-exit", Verdict: VerdictPartial, Signature: "access denied",
	}
	blocked := &NodeResult{
		Tag: "pool-de-02", Country: "DE", City: "Frankfurt", ASN: "AS24940", ISP: "Hetzner Online",
		OK: 0, Total: 3, Statuses: []int{403}, TLSVersion: "1.3", TLSOK: true,
		Verdict: VerdictBlocked, Signature: "error code: 1020",
	}
	dead := &NodeResult{
		Tag: "pool-jp-09", Country: "JP", City: "Tokyo", ASN: "AS9371", ISP: "Sakura Internet",
		OK: 0, Total: 3, Statuses: nil, Verdict: VerdictFail,
		Attempts: []Attempt{{Verdict: VerdictDialFail}},
	}
	instFail := &NodeResult{
		Tag: "pool-ru-07", Country: "RU", City: "Moscow", ASN: "AS47241", ISP: "OOO Network",
		OK: 0, Total: 0, InstanceFailed: true, InstanceErr: "xray exited during startup",
		Verdict: VerdictError,
	}
	rep := &Report{
		Targets: []*TargetResult{{
			URL:            "https://nyaa.si",
			Rows:           []*NodeResult{ok, partial, blocked, dead, instFail},
			Countries:      RankGroups(GroupByCountry([]*NodeResult{ok, partial, blocked, dead, instFail})),
			Cities:         RankGroups(GroupByCity([]*NodeResult{ok, partial, blocked, dead, instFail})),
			Recommendation: RankGroups(GroupByCountry([]*NodeResult{ok, partial, blocked, dead, instFail})),
		}},
		Checked: 5,
		Stale:   true, StaleAge: "31h", GeoTTL: "24h",
		Attempts: 3, Timeout: "15s",
	}
	return rep
}

// M3: extreme flags/values must WIDEN their column, not collide into the
// next one: huge --attempts (ok cell "0/100000" vs width 5) and ≥1GB/s
// speeds ("1536.0MB/s" vs width 9) previously shifted every later cell of
// the row relative to the header.
func TestRenderReportExtremeValuesWidenColumns(t *testing.T) {
	rep := &Report{
		Targets: []*TargetResult{{
			URL: "https://nyaa.si",
			Rows: []*NodeResult{
				{
					Tag: "pool-nl-01", Country: "NL", City: "Amsterdam",
					OK: 0, Total: 100000, Statuses: []int{403},
					AvgSpeedBPS: 1.5 * 1024 * 1024 * 1024, Verdict: VerdictBlockedHTTP,
				},
				{
					Tag: "pool-de-02", Country: "DE", City: "Frankfurt",
					OK: 3, Total: 3, Statuses: []int{200},
					AvgSpeedBPS: 1.2 * 1024 * 1024, Verdict: VerdictSuccess,
				},
			},
		}},
		Attempts: 100000, Timeout: "15s",
	}
	out := RenderReport(rep, RenderOptions{Color: false, Top: 10})
	lines := strings.Split(out, "\n")
	require.GreaterOrEqual(t, len(lines), 8)
	header, overflow, normal := lines[4], lines[6], lines[7]

	// Row-to-row byte offsets are the honest alignment check (both rows
	// carry identical flag-emoji geometry). W18: numeric columns are
	// RIGHT-aligned, so values end at the same offset — compare value END
	// offsets (start + length), not start offsets.
	assert.Equal(t, strings.Index(normal, "3/3")+len("3/3"),
		strings.Index(overflow, "0/100000")+len("0/100000"),
		"ok column must hold the full attempt count, aligned across rows")
	assert.Equal(t, strings.Index(normal, "200")+len("200"),
		strings.Index(overflow, "403")+len("403"),
		"statuses column must stay aligned under an overflowing ok cell")
	assert.Equal(t, strings.Index(normal, "1.2MB/s")+len("1.2MB/s"),
		strings.Index(overflow, "1536.0MB/s")+len("1536.0MB/s"),
		"speed column must stay aligned under a ≥1GB/s value")
	assert.Contains(t, overflow, "0/100000", "attempt count must not be clipped")
	assert.Contains(t, overflow, "1536.0MB/s", "extreme speed must not be clipped")
	assert.Contains(t, header, "statuses")
	assert.Contains(t, header, "speed")
}

func TestRenderReportGoldenNoColor(t *testing.T) {
	out := RenderReport(goldenReport(), RenderOptions{Color: false, Top: 10})
	goldenPath := filepath.Join("testdata", "golden-check-report.txt")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Logf("golden file not found (%v) — write it on first run", err)
		require.NoError(t, os.WriteFile(goldenPath, []byte(out), 0o644), "first run materializes the golden")
		return
	}
	// .gitattributes pins LF checkouts; the strip is the belt to that
	// suspenders for working trees materialized before the attribute (a
	// windows checkout converts LF→CRLF and the CRLF bytes are checkout
	// noise, never render content — the renderer emits \n).
	assert.Equal(t, strings.ReplaceAll(string(golden), "\r\n", "\n"), out,
		"rendered report diverged from the golden file — if intentional, regenerate testdata/golden-check-report.txt deliberately")
}

// W18 palette: the shared ui traffic-light trio replaced the ANSI16 codes
// (32/33/31 → 38;5;46/38;5;214/38;5;196). Same assertion strength — the
// color classes are still pinned, the byte spelling updated.
func TestRenderReportColorAndNoColor(t *testing.T) {
	colored := RenderReport(goldenReport(), RenderOptions{Color: true, Top: 3})
	plain := RenderReport(goldenReport(), RenderOptions{Color: false, Top: 3})
	assert.Contains(t, colored, "\x1b[38;5;46m", "green success must be colored (46)")
	assert.Contains(t, colored, "\x1b[38;5;196m", "red fail must be colored (196)")
	assert.NotContains(t, colored, "\x1b[38;5;214m\x1b[38;5;214m", "no accidental double-wrap")
	assert.NotContains(t, plain, "\x1b[", "no ANSI in --no-color mode")
	assert.Contains(t, colored, "\x1b[38;5;214m",
		"amber partial must be colored (214)")
}

// W18 owner traffic light on the check table: rtt/ttfb/avg cells are
// colored by the LATENCY bands (<400 green 46, 400–799 amber 214,
// ≥800 red 196), overriding the row verdict color; dash cells keep the
// verdict color (no data is not a latency).
func TestRenderReportTrafficLightCells(t *testing.T) {
	// goldenReport: ok node rtt 45 / ttfb 210 / avg 480 → the first two are
	// green, the avg amber. partial: rtt 120 / ttfb 380 / avg 640 → same
	// classes. blocked/dead rows have no latency data — dashes carry the
	// red verdict.
	out := RenderReport(goldenReport(), RenderOptions{Color: true, Top: 3})
	require.Contains(t, out, "38;5;46m45ms", "45ms rtt is green (<400)")
	require.Contains(t, out, "38;5;46m210ms", "210ms ttfb is green (<400)")
	require.Contains(t, out, "38;5;214m480ms", "480ms avg is amber (400–799)")
	require.Contains(t, out, "38;5;214m640ms", "640ms avg is amber (400–799)")
	require.Contains(t, out, "38;5;196m—", "a failed node's dash keeps the red verdict color")
}

func TestFlagEmoji(t *testing.T) {
	t.Parallel()
	require.Equal(t, "🇳🇱", flagEmoji("NL"))
	require.Equal(t, "🇩🇪", flagEmoji("de"))
	require.Equal(t, "🏳", flagEmoji(""))
	require.Equal(t, "🏳", flagEmoji("XYZ"))
}
