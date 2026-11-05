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

// TestFreshUnlock boundaries: the 7-day window is judged against CheckedAt
// alone (the hot LRU lease is a separate, much shorter freshness).
func TestFreshUnlock(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second) // RFC3339 has second precision
	stamp := func(offset time.Duration) string {
		return now.Add(offset).Format(time.RFC3339)
	}
	tests := []struct {
		name      string
		checkedAt string
		want      bool
	}{
		{"fresh", stamp(-24 * time.Hour), true},
		{"exactly at TTL", stamp(-UnlockTTL), true},
		{"past TTL", stamp(-UnlockTTL - time.Second), false},
		{"within future skew", stamp(time.Second), true},
		{"too far in the future", stamp(5 * time.Minute), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := freshUnlock(mkStatus(tc.checkedAt), now)
			assert.Equal(t, tc.want, got)
		})
	}
	assert.False(t, freshUnlock(nil, now), "nil verdict = unchecked")
	assert.False(t, freshUnlock(mkStatus(""), now), "empty CheckedAt = never probed")
	assert.False(t, freshUnlock(mkStatus("not-a-time"), now), "unparsable = stale")
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
