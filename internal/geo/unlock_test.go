package geo_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"public_vpn/internal/geo"
	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unlockDouble serves EVERY Phase-1 probe URL from one httptest server (a
// single socks relay covers the whole set) and records the hits it saw: the
// per-exit dedup and the cache-hit contract are asserted on the wire.
type unlockDouble struct {
	srv      *httptest.Server
	bodies   map[string]string
	mu       sync.Mutex
	hits     map[string]int
	lastHdr  map[string]http.Header
	lastBody map[string][]byte
}

func newUnlockDouble(t *testing.T, bodies map[string]string) *unlockDouble {
	t.Helper()
	d := &unlockDouble{
		bodies:   bodies,
		hits:     map[string]int{},
		lastHdr:  map[string]http.Header{},
		lastBody: map[string][]byte{},
	}
	d.srv = httptest.NewServer(http.HandlerFunc(d.handle))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *unlockDouble) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	d.mu.Lock()
	d.hits[r.URL.Path]++
	d.lastHdr[r.URL.Path] = r.Header.Clone()
	d.lastBody[r.URL.Path] = body
	d.mu.Unlock()
	out, ok := d.bodies[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func (d *unlockDouble) endpoints() *geo.UnlockEndpoints {
	u := d.srv.URL
	return &geo.UnlockEndpoints{
		ChatGPCTrace:      u + "/cdn-cgi/trace",
		ChatGPTCompliance: u + "/compliance/cookie_requirements",
		NetflixTitleA:     u + "/title/81280792",
		NetflixTitleB:     u + "/title/70143836",
		YouTubePremium:    u + "/premium",
		TikTokHome:        u + "/",
		TikTokExplore:     u + "/explore",
		DisneyDevices:     u + "/devices",
		DisneyAuth:        u + "/token",
		DisneyGraphQL:     u + "/graph/v1/device/graphql",
		IPInfoWidget:      u + "/widget/demo/",
	}
}

func (d *unlockDouble) hitsOf(path string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hits[path]
}

func (d *unlockDouble) totalHits() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, c := range d.hits {
		n += c
	}
	return n
}

func (d *unlockDouble) header(path string) http.Header {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastHdr[path]
}

func (d *unlockDouble) bodyOf(path string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return string(d.lastBody[path])
}

func (d *unlockDouble) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hits = map[string]int{}
}

// unlockBodies is the all-unlocked fixture set: every probe path answers a
// clean, parseable body (the through-tunnel test pins the full happy path).
func unlockBodies() map[string]string {
	return map[string]string{
		"/cdn-cgi/trace":                  "fl=1.1\nip=203.0.113.7\nloc=DE\n",
		"/compliance/cookie_requirements": `{"cookie_consent_required":true}`,
		"/title/81280792":                 `{"x":{"id":"US","z":1},"countryName":"United States"}`,
		"/title/70143836":                 `{"x":{"id":"US","z":1},"countryName":"United States"}`,
		"/premium":                        `<html>{"contentRegion":"DE"} ad-free</html>`,
		"/":                               `<html>{"region":"US"}</html>`,
		"/explore":                        `<html>{"region":"US"}</html>`,
		"/devices":                        `{"assertion":"ASSERT-1"}`,
		"/token":                          `{"refresh_token":"RT-1"}`,
		"/graph/v1/device/graphql":        `{"extensions":{"sdk":{"session":{"location":{"countryCode":"DE"},"inSupportedLocation":true}}}}`,
		"/widget/demo/203.0.113.7":        `{"data":{"asn":{"type":"hosting"},"privacy":{"vpn":false,"proxy":false,"tor":false,"hosting":true},"is_mobile":false,"is_anonymous":false}}`,
	}
}

// unlockInput builds a geo Input with the Phase-1 stage on, both nodes
// sharing ONE exit IP (the dedup contract), and every probe riding the
// given doubles through the in-process socks relay.
func unlockInput(t *testing.T, dir string, f geo.Factory, selfURL string, ep *geo.UnlockEndpoints,
	cache *geo.ExitGeoCache,
) geo.Input {
	t.Helper()
	n1, n2 := node("1", "one.example.com"), node("2", "two.example.com")
	probes := map[string]store.ProbeResult{
		n1.Key: liveProbe(n1, "203.0.113.7"),
		n2.Key: liveProbe(n2, "203.0.113.7"),
	}
	in := baseInput(dir, []*model.Node{n1, n2}, probes, f, selfURL)
	in.Cfg.UnlockProbes = true
	in.UnlockEndpoints = ep
	in.ExitCache = cache
	return in
}

// TestUnlockProbeThroughTunnel pins the end-to-end happy path: one temp
// instance per distinct exit, every service probed through the SAME tunnel,
// the reference headers on the wire, and the verdict folded into BOTH
// records sharing the exit.
func TestUnlockProbeThroughTunnel(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), ud.endpoints(), cache)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)

	// Exactly one probe set per DISTINCT exit (two nodes share it).
	assert.Equal(t, 1, ud.hitsOf("/cdn-cgi/trace"))
	assert.Equal(t, 1, ud.hitsOf("/compliance/cookie_requirements"))
	assert.Equal(t, 1, ud.hitsOf("/title/81280792"))
	assert.Equal(t, 1, ud.hitsOf("/title/70143836"))
	assert.Equal(t, 1, ud.hitsOf("/premium"))
	assert.Equal(t, 1, ud.hitsOf("/"))
	assert.Equal(t, 1, ud.hitsOf("/devices"))
	assert.Equal(t, 1, ud.hitsOf("/token"))
	assert.Equal(t, 1, ud.hitsOf("/graph/v1/device/graphql"))
	assert.Equal(t, 1, ud.hitsOf("/widget/demo/203.0.113.7"))

	// The verdict lands on every record sharing the exit.
	st := records[0].MediaUnlocks
	assert.Equal(t, model.UnlockYes, st.ChatGPT)
	assert.Equal(t, model.UnlockNetflixFull, st.Netflix)
	assert.Equal(t, "DE", st.YouTubeRegion)
	assert.Equal(t, model.UnlockYes, st.Disney)
	assert.Equal(t, model.UnlockYes, st.TikTok)
	checkedAt, perr := time.Parse(time.RFC3339, st.CheckedAt)
	require.NoError(t, perr, "CheckedAt must be an RFC3339 stamp")
	assert.LessOrEqual(t, time.Since(checkedAt), time.Minute)
	assert.Equal(t, st, records[1].MediaUnlocks)

	// Quality from the in-tunnel evidence: the ip-api fixture is hosting
	// (Contabo) and the widget agrees (asn.type=hosting) → DataCenter/25.
	assert.Equal(t, model.IPTypeDataCenter, records[0].IPType)
	assert.Equal(t, 25, records[0].RiskScore)
	assert.True(t, records[0].IsHosting)
	assert.False(t, records[0].IsProxy)
	assert.False(t, records[0].IsResidential)
	assert.Equal(t, -1, records[0].ScamalyticsScore)
	assert.Equal(t, -1, records[0].AbuseScore)

	// Reference headers on the wire: YouTube consent cookies + en, ChatGPT
	// compliance auth, the Disney bearer (public client material) and the
	// assertion/refresh-token substitutions across the bamgrid chain.
	yh := ud.header("/premium")
	assert.Equal(t, "en", yh.Get("Accept-Language"))
	assert.Contains(t, yh.Get("Cookie"), "VISITOR_INFO1_LIVE=4VwPMkB7W5A")
	ch := ud.header("/compliance/cookie_requirements")
	assert.Equal(t, "Bearer null", ch.Get("Authorization"))
	assert.Equal(t, "https://platform.openai.com", ch.Get("Origin"))
	dh := ud.header("/devices")
	assert.Equal(t,
		"Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84",
		dh.Get("Authorization"))
	assert.Contains(t, ud.bodyOf("/devices"), `"deviceFamily":"browser"`)
	assert.Contains(t, ud.bodyOf("/token"), "subject_token=ASSERT-1")
	th := ud.header("/graph/v1/device/graphql")
	assert.Equal(t, "ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84",
		th.Get("Authorization"), "the graphql step carries the raw token, no Bearer prefix")
	assert.Contains(t, ud.bodyOf("/graph/v1/device/graphql"), `"refreshToken":"RT-1"`)
}

// TestUnlockCacheHitZeroNetworkCalls is the spec'd cache contract: the
// repeat check of the SAME exit IP inside the 7-day window costs ZERO
// network calls — hot cache first, then the geo-base.jsonl cold half — and
// an expired verdict re-probes.
func TestUnlockCacheHitZeroNetworkCalls(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), ud.endpoints(), cache)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
	freshCheckedAt := records[0].MediaUnlocks.CheckedAt
	require.NotEmpty(t, freshCheckedAt)
	firstWave := ud.totalHits()
	require.Positive(t, firstWave, "the first wave must probe")

	// Wave 2 — hot cache hit: zero unlock network calls, same verdict.
	ud.reset()
	records, _, err = geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, 0, ud.totalHits(), "fresh hot entry = zero network calls")
	assert.Equal(t, freshCheckedAt, records[0].MediaUnlocks.CheckedAt)
	assert.Equal(t, model.UnlockYes, records[0].MediaUnlocks.ChatGPT)

	// Wave 3 — expired everywhere (hot entry + geo-base): re-probe.
	aged := time.Now().Add(-8 * 24 * time.Hour).UTC().Format(time.RFC3339)
	path := filepath.Join(dir, "geo-base.jsonl")
	recs, rerr := store.ReadGeo(path)
	require.NoError(t, rerr)
	require.NotEmpty(t, recs)
	for _, r := range recs {
		r.MediaUnlocks.CheckedAt = aged
	}
	require.NoError(t, store.WriteGeo(path, recs))
	e, ok := cache.Get("203.0.113.7")
	require.True(t, ok)
	require.NotNil(t, e.MediaUnlocks)
	e.MediaUnlocks.CheckedAt = aged
	ud.reset()
	_, _, err = geo.Run(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, firstWave, ud.totalHits(), "expired verdict re-probes every service")
}

// TestUnlockStageDisabledByDefault pins the zero-behavior-change gate: with
// [geo].unlock_probes unset the stage never probes (all requests stay geo
// only) and the Phase-1 fields stay unchecked.
func TestUnlockStageDisabledByDefault(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	f, _, _ := newTestFactory(socks)
	n1 := node("1", "one.example.com")
	probes := map[string]store.ProbeResult{n1.Key: liveProbe(n1, "203.0.113.7")}
	in := baseInput(t.TempDir(), []*model.Node{n1}, probes, f, api.URL())
	in.UnlockEndpoints = ud.endpoints()
	in.ExitCache = geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Zero(t, ud.totalHits(), "stage off = zero probe requests")
	assert.Equal(t, -1, records[0].RiskScore)
	assert.Empty(t, records[0].IPType)
	assert.Empty(t, records[0].MediaUnlocks)
}

// TestUnlockParsers tables the pure probe parsers/classifiers against the
// reference semantics (fixture bodies inline).
func TestUnlockParsers(t *testing.T) {
	t.Run("ParseCDNTrace", func(t *testing.T) {
		tests := []struct {
			name, body, want string
		}{
			{"loc line", "fl=1\nip=1.2.3.4\nloc=DE\n", "DE"},
			{"no loc", "fl=1\nip=1.2.3.4\n", ""},
			{"empty", "", ""},
			{"first wins", "loc=US\nloc=DE\n", "US"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, geo.ParseCDNTrace(tc.body))
			})
		}
	})

	t.Run("ChatGPT", func(t *testing.T) {
		tests := []struct {
			name                         string
			unsupported, traceOK, compOK bool
			want                         string
		}{
			{"clean", false, true, true, model.UnlockYes},
			{"unsupported country", true, true, true, model.UnlockAppOnly},
			{"trace failed", false, false, true, model.UnlockUnknown},
			{"compliance failed", false, true, false, model.UnlockUnknown},
			{"both failed", true, false, false, model.UnlockUnknown},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, geo.ClassifyChatGPT(tc.unsupported, tc.traceOK, tc.compOK))
			})
		}
		assert.True(t, geo.ParseChatGPTCompliance(`{"error":"unsupported_country"}`))
		assert.False(t, geo.ParseChatGPTCompliance(`{"cookie_consent_required":true}`))
	})

	t.Run("NetflixRegion", func(t *testing.T) {
		body := `{"a":{"id":"DE","b":1},"c":{"id":"US","d":2},"countryName":"United States"}`
		assert.Equal(t, "US", geo.ExtractNetflixRegion(body), "greedy prefix = last id before countryName")
		assert.Empty(t, geo.ExtractNetflixRegion(`{"oh":"no"}`))
	})

	t.Run("NetflixClassify", func(t *testing.T) {
		ohNo := `Oh no! page`
		full := `{"id":"US"}`
		tests := []struct {
			name               string
			errA, errB         error
			stA, stB           int
			bodyA, bodyB, want string
		}{
			{"transport error", assert.AnError, nil, 0, 200, "", full, model.UnlockUnknown},
			{"forbidden", nil, nil, 403, 200, "", full, model.UnlockBlocked},
			{"legal block", nil, nil, 200, 451, full, "", model.UnlockBlocked},
			{"server error", nil, nil, 200, 500, full, "", model.UnlockUnknown},
			{"originals only", nil, nil, 200, 200, ohNo, ohNo, model.UnlockNetflixOriginals},
			{"one clean = full", nil, nil, 200, 200, ohNo, full, model.UnlockNetflixFull},
			{"both clean = full", nil, nil, 200, 200, full, full, model.UnlockNetflixFull},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got := geo.ClassifyNetflix(tc.errA, tc.errB, tc.stA, tc.stB, tc.bodyA, tc.bodyB)
				assert.Equal(t, tc.want, got)
			})
		}
	})

	t.Run("YouTube", func(t *testing.T) {
		tests := []struct {
			name, body, want string
			status           int
			err              error
		}{
			{"region", `<html>{"contentRegion":"de"} ad-free</html>`, "DE", 200, nil},
			{"cn redirect", `<html>www.google.cn</html>`, model.UnlockBlocked, 200, nil},
			{"no premium", `Premium is not available in your country`, model.UnlockBlocked, 200, nil},
			{"forbidden", `x`, model.UnlockBlocked, 403, nil},
			{"server error", `x`, model.UnlockUnknown, 500, nil},
			{"no region evidence", `<html>ok</html>`, model.UnlockUnknown, 200, nil},
			{"transport error", `ignored`, model.UnlockUnknown, 0, assert.AnError},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, geo.ClassifyYouTube(tc.body, tc.status, tc.err))
			})
		}
	})

	t.Run("TikTokRegion", func(t *testing.T) {
		assert.Equal(t, "US", geo.ExtractTikTokRegion(`{"a":{"region":"US"},"region":"DE"}`))
		assert.Empty(t, geo.ExtractTikTokRegion(`{"no":"region"}`))
	})

	t.Run("Disney", func(t *testing.T) {
		session := `{"extensions":{"sdk":{"session":{"location":{"countryCode":"DE"},"inSupportedLocation":true}}}}`
		country, inSupported, ok := geo.ParseDisneySession(session)
		require.True(t, ok)
		assert.Equal(t, "DE", country)
		assert.True(t, inSupported)

		_, _, ok = geo.ParseDisneySession(`not json`)
		assert.False(t, ok, "garbage body = infrastructure failure")

		country, _, ok = geo.ParseDisneySession(`{"different":"shape"}`)
		require.True(t, ok, "valid JSON without the path = jq-null case")
		assert.Empty(t, country)

		tests := []struct {
			name            string
			country         string
			inSupported, ok bool
			want            string
		}{
			{"infrastructure failure", "", false, false, model.UnlockUnknown},
			{"jp special case", "JP", false, true, model.UnlockYes},
			{"supported", "DE", true, true, model.UnlockYes},
			{"unsupported collapses to blocked", "DE", false, true, model.UnlockBlocked},
			{"no country", "", false, true, model.UnlockBlocked},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, geo.ClassifyDisney(tc.country, tc.inSupported, tc.ok))
			})
		}
	})

	t.Run("IPInfoWidget", func(t *testing.T) {
		w, err := geo.ParseIPInfoWidget(
			`{"data":{"asn":{"type":"isp"},"privacy":{"proxy":true,"hosting":false},"is_mobile":true}}`)
		require.NoError(t, err)
		assert.Equal(t, "isp", w.Data.ASN.Type)
		assert.True(t, w.Data.Privacy.Proxy)
		assert.True(t, w.Data.IsMobile)
		assert.False(t, w.Data.Privacy.Hosting)
		_, err = geo.ParseIPInfoWidget(`not json`)
		assert.Error(t, err)
	})
}

// TestComputeIPQuality tables the evidence→verdict mapping (spec formulas).
func TestComputeIPQuality(t *testing.T) {
	widget := func(json string) *geo.IPInfoWidget {
		t.Helper()
		w, err := geo.ParseIPInfoWidget(json)
		require.NoError(t, err)
		return w
	}
	ipAPIHosting := &geo.Response{Status: "success", Proxy: false, Hosting: true, Mobile: false}
	ipAPIClean := &geo.Response{Status: "success", Proxy: false, Hosting: false, Mobile: false}
	ipAPIProxy := &geo.Response{Status: "success", Proxy: true, Hosting: false, Mobile: false}

	tests := []struct {
		name                 string
		g                    *geo.Response
		widgetJSON           string
		wantType             string
		wantRisk             int
		residential, hosting bool
		proxy, mobile        bool
	}{
		{"no evidence", nil, "", "", 0, false, false, false, false},
		{"ip-api hosting only", ipAPIHosting, "", model.IPTypeDataCenter, 25, false, true, false, false},
		{"ip-api proxy", ipAPIProxy, "", model.IPTypeUnknown, 70, false, false, true, false},
		{"ip-api clean, no widget", ipAPIClean, "", model.IPTypeUnknown, 0, false, false, false, false},
		{"widget isp residential", ipAPIClean, `{"data":{"asn":{"type":"isp"}}}`,
			model.IPTypeResidential, 0, true, false, false, false},
		{"widget mobile residential", ipAPIClean, `{"data":{"is_mobile":true}}`,
			model.IPTypeMobile, 0, true, false, false, true},
		{"widget privacy vpn = proxy", ipAPIClean, `{"data":{"privacy":{"vpn":true}}}`,
			model.IPTypeUnknown, 70, false, false, true, false},
		{"widget hosting upgrades", ipAPIClean, `{"data":{"asn":{"type":"hosting"}}}`,
			model.IPTypeDataCenter, 25, false, true, false, false},
		{"widget business type", ipAPIClean, `{"data":{"asn":{"type":"business"}}}`,
			model.IPTypeBusiness, 0, false, false, false, false},
		{"proxy keeps network type", ipAPIHosting, `{"data":{"privacy":{"proxy":true}}}`,
			model.IPTypeDataCenter, 70, false, true, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var w *geo.IPInfoWidget
			if tc.widgetJSON != "" {
				w = widget(tc.widgetJSON)
			}
			q := geo.ComputeIPQuality(tc.g, w)
			if tc.g == nil && tc.widgetJSON == "" {
				assert.Nil(t, q, "no evidence = no verdict")
				return
			}
			require.NotNil(t, q)
			assert.Equal(t, tc.wantType, q.IPType)
			assert.Equal(t, tc.wantRisk, q.RiskScore)
			assert.Equal(t, tc.residential, q.IsResidential)
			assert.Equal(t, tc.hosting, q.IsHosting)
			assert.Equal(t, tc.proxy, q.IsProxy)
			assert.Equal(t, tc.mobile, q.IsMobile)
			assert.Equal(t, -1, q.ScamalyticsScore, "Phase 1 probes no Scamalytics source")
			assert.Equal(t, -1, q.AbuseScore, "Phase 1 probes no AbuseIPDB source")
		})
	}
}

// TestRiskBands pins the exact spec ranges and the reference thresholds.
func TestRiskBands(t *testing.T) {
	t.Run("ComputeRiskScore", func(t *testing.T) {
		tests := []struct {
			name           string
			proxy, hosting bool
			abuse          float64
			want           int
		}{
			{"clean", false, false, 0, 0},
			{"clean worst abuse", false, false, 1, 15},
			{"hosting", false, true, 0, 25},
			{"hosting worst abuse", false, true, 1, 40},
			{"proxy", true, false, 0, 70},
			{"proxy worst abuse", true, false, 1, 100},
			{"proxy clamps abuse", true, false, 2, 100},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, geo.ComputeRiskScore(tc.proxy, tc.hosting, tc.abuse))
			})
		}
	})

	t.Run("BandScore", func(t *testing.T) {
		tests := []struct {
			name       string
			score      int
			thresholds []int
			want       float64
		}{
			{"below first", 19, []int{20, 60, 90}, 0},
			{"middle", 59, []int{20, 60, 90}, 0.5},
			{"high", 89, []int{20, 60, 90}, 0.75},
			{"top", 90, []int{20, 60, 90}, 1},
			{"two thresholds top out at 0.75", 75, []int{25, 75}, 0.75},
			{"two thresholds mid", 24, []int{25, 75}, 0},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				assert.InDelta(t, tc.want, geo.BandScore(tc.score, tc.thresholds), 1e-9)
			})
		}
	})

	t.Run("WorstAbuse", func(t *testing.T) {
		assert.InDelta(t, 0.0, geo.WorstAbuse(-1, -1, -1), 1e-9, "nothing checked = 0")
		assert.InDelta(t, 1.0, geo.WorstAbuse(95, -1, -1), 1e-9, "scamalytics ≥90")
		assert.InDelta(t, 0.75, geo.WorstAbuse(-1, 80, -1), 1e-9, "abuseipdb ≥75")
		assert.InDelta(t, 1.0, geo.WorstAbuse(-1, -1, 92), 1e-9, "ipqs ≥90")
		assert.InDelta(t, 1.0, geo.WorstAbuse(10, -1, 92), 1e-9, "worst of present wins")
	})

	t.Run("composite", func(t *testing.T) {
		abuse := geo.WorstAbuse(95, -1, -1)
		assert.Equal(t, 100, geo.ComputeRiskScore(true, false, abuse))
		assert.Equal(t, 40, geo.ComputeRiskScore(false, true, abuse))
	})
}
