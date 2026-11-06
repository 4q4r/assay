package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"public_vpn/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mkStatus(checkedAt string) *model.MediaUnlockStatus {
	return &model.MediaUnlockStatus{CheckedAt: checkedAt}
}

// advUnlockProbe builds an unlockProbe against a test server with a real
// (non-mocked) http client and a no-op pacer — the lightest seam that
// exercises the real classification paths (adversarial-review fixes F2/F4).
func advUnlockProbe(t *testing.T, srv *httptest.Server, ep UnlockEndpoints) *unlockProbe {
	t.Helper()
	return &unlockProbe{
		cl:     srv.Client(),
		ua:     "test-probe",
		ep:     ep,
		pac:    &pacer{minDelay: 0, now: time.Now},
		now:    time.Now,
		exitIP: "203.0.113.9",
	}
}

// TestTikTokHeaderVariantDecompressesTransparently pins F2: the header-variant
// fallback must not set Accept-Encoding manually — the transport then adds
// gzip itself and decompresses the answer transparently. A real-world server
// compresses whenever the client declares gzip, and the region literal is
// byte-absent inside compressed bytes: with the old manual header the IDC
// verdict was unreachable and the exit fabricated "blocked" from 200 pages.
func TestTikTokHeaderVariantDecompressesTransparently(t *testing.T) {
	var sawHeaderVariant bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "" {
			sawHeaderVariant = true
			// Exactly what a real server does under a declared gzip:
			// compress, with enough padding that the region literal only
			// exists in the decompressed form.
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write([]byte(`<html>` + strings.Repeat("x", 8192) + `{"region":"DE"}</html>`))
			_ = zw.Close()
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(buf.Bytes())
			return
		}
		_, _ = w.Write([]byte(`<html>plain home page, no region here</html>`))
	}))
	defer srv.Close()

	p := advUnlockProbe(t, srv, UnlockEndpoints{
		TikTokHome:    srv.URL,
		TikTokExplore: srv.URL + "/explore",
	})
	got := p.tiktok(context.Background())

	require.True(t, sawHeaderVariant, "the probe must issue the header-variant request")
	assert.Equal(t, model.UnlockTikTokIDC, got,
		"the transport's transparent decompression must surface the variant region (IDC)")
}

// TestTikTok200WithoutRegionIsUnknown pins F2's fail-unknown semantics: a 200
// page without extractable region evidence carries no definite answer and is
// UNKNOWN — never a fabricated block (mirrors ClassifyYouTube).
func TestTikTok200WithoutRegionIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>region-less 200 page</html>`))
	}))
	defer srv.Close()

	p := advUnlockProbe(t, srv, UnlockEndpoints{
		TikTokHome:    srv.URL,
		TikTokExplore: srv.URL + "/explore",
	})
	assert.Equal(t, model.UnlockUnknown, p.tiktok(context.Background()))
}

// TestTikTokDefiniteBlockStaysBlocked pins the kept half of the contract:
// 403/451 remain a definite block answer.
func TestTikTokDefiniteBlockStaysBlocked(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusUnavailableForLegalReasons} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
		p := advUnlockProbe(t, srv, UnlockEndpoints{
			TikTokHome:    srv.URL,
			TikTokExplore: srv.URL + "/explore",
		})
		assert.Equal(t, model.UnlockBlocked, p.tiktok(context.Background()),
			"HTTP %d must stay blocked", code)
		srv.Close()
	}
}

// TestDisneyForbiddenLocationIsBlocked pins F4: the token step's
// forbidden-location answer is a definite BLOCK even when it arrives with a
// non-200 status — the forbidden-content check must precede the generic
// non-200 fallback (the old order made the definite-block classification
// unreachable for the reference's 403 forbidden-location answer).
func TestDisneyForbiddenLocationIsBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/devices":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"assertion":"ADVASSERT"}`))
		case "/token":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error_description":"forbidden-location"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	p := advUnlockProbe(t, srv, UnlockEndpoints{
		DisneyDevices: srv.URL + "/devices",
		DisneyAuth:    srv.URL + "/token",
		DisneyGraphQL: srv.URL + "/graphql",
	})
	assert.Equal(t, model.UnlockBlocked, p.disney(context.Background()))
}

// TestDisneyNonForbiddenFailureStaysUnknown pins the generic fallback the
// F4 reorder must preserve: a non-200 token step WITHOUT the forbidden
// answer stays unknown.
func TestDisneyNonForbiddenFailureStaysUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/devices":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"assertion":"ADVASSERT"}`))
		case "/token":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	p := advUnlockProbe(t, srv, UnlockEndpoints{
		DisneyDevices: srv.URL + "/devices",
		DisneyAuth:    srv.URL + "/token",
		DisneyGraphQL: srv.URL + "/graphql",
	})
	assert.Equal(t, model.UnlockUnknown, p.disney(context.Background()))
}

// TestClassifyNetflixEmptyBodiesFailUnknown pins F5: 200 pages with empty or
// whitespace-stripped bodies carry no catalog evidence — the verdict is
// UNKNOWN (strictly more conservative, the owner's fail-closed ruling),
// never a fabricated full unlock feeding pool_netflix.
func TestClassifyNetflixEmptyBodiesFailUnknown(t *testing.T) {
	catalog := `{"x":{"id":"US","z":1},"countryName":"United States"}`
	unavailable := `<html>Oh no!... not available in your region</html>`
	tests := []struct {
		name    string
		errA    error
		statusA int
		bodyA   string
		statusB int
		bodyB   string
		want    string
	}{
		{"both empty 200 bodies", nil, 200, "", 200, "", model.UnlockUnknown},
		{"whitespace-stripped bodies", nil, 200, "   ", 200, "\n\t", model.UnlockUnknown},
		{"one blank body", nil, 200, "", 200, catalog, model.UnlockUnknown},
		{"both catalog pages", nil, 200, catalog, 200, catalog, model.UnlockNetflixFull},
		{"both unavailable markers", nil, 200, unavailable, 200, unavailable, model.UnlockNetflixOriginals},
		{"definite block status", nil, 403, "", 200, catalog, model.UnlockBlocked},
		{"non-200 without block status", nil, 302, "", 200, catalog, model.UnlockUnknown},
		{"transport error", errors.New("reset"), 0, "", 200, catalog, model.UnlockUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyNetflix(tc.errA, nil, tc.statusA, tc.statusB, tc.bodyA, tc.bodyB)
			assert.Equal(t, tc.want, got)
		})
	}
}

// definiteStatus is a fully definite verdict (every media field carries a
// definite vocabulary answer — blocked counts as definite): the 7-day window
// shape.
func definiteStatus(checkedAt string) *model.MediaUnlockStatus {
	return &model.MediaUnlockStatus{
		ChatGPT:       model.UnlockYes,
		Netflix:       model.UnlockNetflixFull,
		YouTubeRegion: "DE",
		Disney:        model.UnlockYes,
		TikTok:        model.UnlockYes,
		CheckedAt:     checkedAt,
	}
}

// unknownStatus is an unknown-carrying verdict (one media field unknown, the
// rest definite): the dead-tunnel-at-probe-time shape the 24h window bounds.
func unknownStatus(checkedAt string) *model.MediaUnlockStatus {
	st := definiteStatus(checkedAt)
	st.ChatGPT = model.UnlockUnknown
	return st
}

// TestFreshUnlock boundaries: freshness is judged against CheckedAt alone
// (the hot LRU lease is a separate, much shorter freshness) with the
// verdict's own TTL semantics — definite verdicts live UnlockTTL (7 days),
// verdicts carrying any unknown/unchecked media field live UnlockUnknownTTL
// (24 hours, owner order 2026-11-06: a dead-tunnel-at-probe-time exit must
// not poison its verdicts for the full week).
func TestFreshUnlock(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second) // RFC3339 has second precision
	stamp := func(offset time.Duration) string {
		return now.Add(offset).Format(time.RFC3339)
	}
	tests := []struct {
		name string
		st   *model.MediaUnlockStatus
		want bool
	}{
		{"definite fresh 23h", definiteStatus(stamp(-23 * time.Hour)), true},
		{"definite fresh 6d23h", definiteStatus(stamp(-6*24*time.Hour - 23*time.Hour)), true},
		{"definite exactly at 7d TTL", definiteStatus(stamp(-UnlockTTL)), true},
		{"definite 7d1h = stale", definiteStatus(stamp(-7*24*time.Hour - time.Hour)), false},
		{"unknown fresh 23h = hit", unknownStatus(stamp(-23 * time.Hour)), true},
		{"unknown 25h = stale (re-probe)", unknownStatus(stamp(-25 * time.Hour)), false},
		{"unchecked fields 25h = stale", mkStatus(stamp(-25 * time.Hour)), false},
		{"within future skew", definiteStatus(stamp(time.Second)), true},
		{"too far in the future", definiteStatus(stamp(5 * time.Minute)), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := freshUnlock(tc.st, now)
			assert.Equal(t, tc.want, got)
		})
	}
	assert.False(t, freshUnlock(nil, now), "nil verdict = unchecked")
	assert.False(t, freshUnlock(mkStatus(""), now), "empty CheckedAt = never probed")
	assert.False(t, freshUnlock(mkStatus("not-a-time"), now), "unparsable = stale")
}

// TestUnlockVerdictUnknownTTL pins the verdict-shaped TTL: any unknown or
// unchecked ("") media field puts the verdict on the 24h window, a fully
// definite verdict (blocked answers included — they are definite answers)
// keeps the 7-day window.
func TestUnlockVerdictUnknownTTL(t *testing.T) {
	assert.Equal(t, UnlockUnknownTTL, unlockTTL(nil), "nil verdict = unchecked = 24h")
	assert.Equal(t, UnlockUnknownTTL, unlockTTL(&model.MediaUnlockStatus{}),
		"zero verdict = all fields unchecked = 24h")

	// Each single unknown field poisons the whole verdict (the probe
	// refreshes ALL fields together — they come from one probe pass).
	definite := model.MediaUnlockStatus{
		ChatGPT: model.UnlockYes, Netflix: model.UnlockNetflixFull,
		YouTubeRegion: "DE", Disney: model.UnlockYes, TikTok: model.UnlockYes,
	}
	for name, mutate := range map[string]func(*model.MediaUnlockStatus){
		"chatgpt":     func(s *model.MediaUnlockStatus) { s.ChatGPT = model.UnlockUnknown },
		"netflix":     func(s *model.MediaUnlockStatus) { s.Netflix = model.UnlockUnknown },
		"youtube":     func(s *model.MediaUnlockStatus) { s.YouTubeRegion = model.UnlockUnknown },
		"disney":      func(s *model.MediaUnlockStatus) { s.Disney = model.UnlockUnknown },
		"tiktok":      func(s *model.MediaUnlockStatus) { s.TikTok = model.UnlockUnknown },
		"empty field": func(s *model.MediaUnlockStatus) { s.TikTok = "" },
	} {
		t.Run("unknown "+name+" → 24h", func(t *testing.T) {
			st := definite
			mutate(&st)
			assert.Equal(t, UnlockUnknownTTL, unlockTTL(&st))
			assert.True(t, unlockVerdictUnknown(&st))
		})
	}

	assert.Equal(t, UnlockTTL, unlockTTL(&definite), "fully definite = 7d")
	assert.False(t, unlockVerdictUnknown(&definite))

	blocked := definite
	blocked.ChatGPT, blocked.Netflix = model.UnlockBlocked, model.UnlockBlocked
	blocked.YouTubeRegion, blocked.TikTok = model.UnlockBlocked, model.UnlockBlocked
	assert.Equal(t, UnlockTTL, unlockTTL(&blocked), "blocked is a definite answer = 7d")
	assert.False(t, unlockVerdictUnknown(&blocked))
}

// TestUnlockAliveNow pins the in-wave aliveness evidence: the node's tunnel
// demonstrably carried a successful HTTP answer during THIS wave's geo
// ladder — a self-report / DoH-fallback geo answer, the HTTPS self-geo, or a
// rate-limited answer (a 429 is an application-level answer received through
// a working tunnel). Everything else (temp-instance boot failure, dead
// tunnel, all rungs failed) is NOT alive.
func TestUnlockAliveNow(t *testing.T) {
	tests := []struct {
		name string
		rep  NodeReport
		want bool
	}{
		{"self-report geo", NodeReport{Geo: &Response{Status: "success"}}, true},
		{"https self-geo", NodeReport{HTTPS: &InfoResponse{IP: "203.0.113.7"}}, true},
		{"rate-limited (429 through the tunnel)", NodeReport{RateLimited: true}, true},
		{"doh fallback geo", NodeReport{Geo: &Response{Status: "success"}, Class: ClassDoHFallback}, true},
		{"dead tunnel (all rungs failed)", NodeReport{Class: ClassUnknown}, false},
		{"detail only", NodeReport{Detail: "self-report: timeout"}, false},
		{"bare report", NodeReport{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, unlockAliveNow(&tc.rep))
		})
	}
}

// TestDefaultUnlockEndpoints pins the production probe URL set (the Phase-1
// wire contract; the test seam overrides these, never the semantics).
func TestDefaultUnlockEndpoints(t *testing.T) {
	ep := defaultUnlockEndpoints()
	require.Equal(t, "https://chatgpt.com/cdn-cgi/trace", ep.ChatGPCTrace)
	require.Equal(t, "https://api.openai.com/compliance/cookie_requirements", ep.ChatGPTCompliance)
	assert.Equal(t, "https://www.netflix.com/title/81280792", ep.NetflixTitleA)
	assert.Equal(t, "https://www.netflix.com/title/70143836", ep.NetflixTitleB)
	assert.Equal(t, "https://www.youtube.com/premium", ep.YouTubePremium)
	assert.Equal(t, "https://www.tiktok.com/", ep.TikTokHome)
	assert.Equal(t, "https://www.tiktok.com/explore", ep.TikTokExplore)
	assert.Equal(t, "https://disney.api.edge.bamgrid.com/devices", ep.DisneyDevices)
	assert.Equal(t, "https://disney.api.edge.bamgrid.com/token", ep.DisneyAuth)
	assert.Equal(t, "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql", ep.DisneyGraphQL)
	assert.Equal(t, "https://ipinfo.io/widget/demo/", ep.IPInfoWidget)
}
