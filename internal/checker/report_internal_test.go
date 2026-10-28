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
	require.GreaterOrEqual(t, len(lines), 6)
	header, overflow, normal := lines[3], lines[4], lines[5]

	// Row-to-row byte offsets are the honest alignment check (both rows
	// carry identical flag-emoji geometry; a header-vs-row byte compare
	// would be skewed by the emoji's 8 bytes, not by real alignment).
	assert.Equal(t, strings.Index(normal, "3/3"), strings.Index(overflow, "0/100000"),
		"ok column must hold the full attempt count, aligned across rows")
	assert.Equal(t, strings.Index(normal, "200"), strings.Index(overflow, "403"),
		"statuses column must stay aligned under an overflowing ok cell")
	assert.Equal(t, strings.Index(normal, "1.2MB/s"), strings.Index(overflow, "1536.0MB/s"),
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
	assert.Equal(t, string(golden), out,
		"rendered report diverged from the golden file — if intentional, regenerate testdata/golden-check-report.txt deliberately")
}

func TestRenderReportColorAndNoColor(t *testing.T) {
	colored := RenderReport(goldenReport(), RenderOptions{Color: true, Top: 3})
	plain := RenderReport(goldenReport(), RenderOptions{Color: false, Top: 3})
	assert.Contains(t, colored, "\x1b[32m", "green success must be colored by default")
	assert.Contains(t, colored, "\x1b[31m", "red fail must be colored by default")
	assert.NotContains(t, colored, "\x1b[33m\x1b[33m", "no accidental double-wrap")
	assert.NotContains(t, plain, "\x1b[", "no ANSI in --no-color mode")
	assert.Contains(t, RenderReport(goldenReport(), RenderOptions{Color: true, Top: 3}), "\x1b[33m",
		"yellow partial must be colored")
}

func TestFlagEmoji(t *testing.T) {
	t.Parallel()
	require.Equal(t, "🇳🇱", flagEmoji("NL"))
	require.Equal(t, "🇩🇪", flagEmoji("de"))
	require.Equal(t, "🏳", flagEmoji(""))
	require.Equal(t, "🏳", flagEmoji("XYZ"))
}
