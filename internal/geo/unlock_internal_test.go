package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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
// shape. BatteryVersion is the CURRENT battery: the migration rule (older
// batteries are stale on sight) is pinned separately in
// TestFreshUnlockBatteryMigration.
func definiteStatus(checkedAt string) *model.MediaUnlockStatus {
	return &model.MediaUnlockStatus{
		ChatGPT:        model.UnlockYes,
		Netflix:        model.UnlockNetflixFull,
		YouTubeRegion:  "DE",
		Disney:         model.UnlockYes,
		TikTok:         model.UnlockYes,
		CheckedAt:      checkedAt,
		BatteryVersion: UnlockBatteryVersion,
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

// TestFreshUnlockBatteryMigration pins the battery_version migration rule:
// a verdict written by ANY battery older than the current one is stale on
// sight — fresh definite, 7-day-window shape, whatever — because the v1
// battery had no hijack detector and its definite "yes" verdicts may be
// poisoned. The current battery's verdicts serve their normal windows.
func TestFreshUnlockBatteryMigration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	stamp := now.Add(-time.Hour).Format(time.RFC3339)

	v1Definite := definiteStatus(stamp)
	v1Definite.BatteryVersion = 1
	assert.False(t, freshUnlock(v1Definite, now),
		"a battery-v1 cached definite verdict is stale under battery v2 — re-probed (the poisoned-verdict kill)")

	legacyDefinite := definiteStatus(stamp)
	legacyDefinite.BatteryVersion = 0
	assert.False(t, freshUnlock(legacyDefinite, now),
		"a legacy (versionless) verdict is stale — pre-battery-stamp entries re-probe too")

	v1Unknown := unknownStatus(stamp)
	v1Unknown.BatteryVersion = 1
	assert.False(t, freshUnlock(v1Unknown, now), "v1 unknown verdicts are stale equally")

	futureDefinite := definiteStatus(stamp)
	futureDefinite.BatteryVersion = UnlockBatteryVersion + 1
	assert.True(t, freshUnlock(futureDefinite, now),
		"a NEWER battery stamp is not downgraded by the reader (forward-compatible)")
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
// ladder — the report is a fresh ladder outcome (LadderRan) AND a self-report
// / DoH-fallback geo answer, the HTTPS self-geo, or a rate-limited answer (a
// 429 is an application-level answer received through a working tunnel).
// Everything else (temp-instance boot failure, dead tunnel, all rungs failed)
// is NOT alive — and neither is CACHED rung evidence on a cache-served clone:
// the Geo/HTTPS/RateLimited fields of a served entry describe the wave that
// produced it, never this wave (the eligibility layer, owner order
// 2026-11-06).
func TestUnlockAliveNow(t *testing.T) {
	tests := []struct {
		name string
		rep  NodeReport
		want bool
	}{
		{"self-report geo", NodeReport{LadderRan: true, Geo: &Response{Status: "success"}}, true},
		{"https self-geo", NodeReport{LadderRan: true, HTTPS: &InfoResponse{IP: "203.0.113.7"}}, true},
		{"rate-limited (429 through the tunnel)", NodeReport{LadderRan: true, RateLimited: true}, true},
		{"doh fallback geo", NodeReport{LadderRan: true, Geo: &Response{Status: "success"}, Class: ClassDoHFallback}, true},
		{"dead tunnel (all rungs failed)", NodeReport{LadderRan: true, Class: ClassUnknown}, false},
		{"detail only", NodeReport{LadderRan: true, Detail: "self-report: timeout"}, false},
		{"bare report", NodeReport{}, false},
		{"cached evidence without a ladder run", NodeReport{Geo: &Response{Status: "success"}}, false},
		{"cached 429 without a ladder run", NodeReport{RateLimited: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, unlockAliveNow(&tc.rep))
		})
	}
}

// TestUnknownCachedProbeRep pins the three-way re-classification decision
// for a fresh unknown-carrying cached verdict (the eligibility layer, owner
// order 2026-11-06): a member with in-wave tunnel evidence → the PR-#15
// alive-bypass rides THAT member; no member rode a ladder this wave (fresh
// geo, cache-served) → the unlock-only sweep rides the representative node;
// the ladder ran but no tunnel answered (dead-now) → no probe, the cached
// unknown stands until the 24h TTL ages it out.
func TestUnknownCachedProbeRep(t *testing.T) {
	geoOK := NodeReport{Key: "n1", LadderRan: true, Geo: &Response{Status: "success"}}
	clone := NodeReport{Key: "n1"} // cache-served: no ladder marker, no rung evidence
	deadNow := NodeReport{Key: "n1", LadderRan: true, Class: ClassUnknown}

	t.Run("alive bypass rides the in-wave member", func(t *testing.T) {
		g := unlockGroup{exitIP: "203.0.113.7", inds: []int{0, 1}}
		reports := []NodeReport{clone, geoOK}
		rep, doProbe := unknownCachedProbeRep(reports, g)
		assert.True(t, doProbe)
		assert.Equal(t, "n1", rep.Key)
		assert.True(t, rep.LadderRan && rep.Geo != nil, "the probe rides the member whose tunnel answered")
	})

	t.Run("no ladder this wave = unlock-only sweep via the representative", func(t *testing.T) {
		g := unlockGroup{exitIP: "203.0.113.7", inds: []int{0}}
		rep, doProbe := unknownCachedProbeRep([]NodeReport{clone}, g)
		assert.True(t, doProbe, "fresh geo must not starve the re-classification")
		assert.Equal(t, "n1", rep.Key)
		assert.False(t, rep.LadderRan, "the sweep rides the cache-served representative")
	})

	t.Run("dead-now residue keeps the cached unknown", func(t *testing.T) {
		g := unlockGroup{exitIP: "203.0.113.7", inds: []int{0}}
		_, doProbe := unknownCachedProbeRep([]NodeReport{deadNow}, g)
		assert.False(t, doProbe, "a tunnel that just failed the rungs is not re-probed")
	})

	t.Run("ladderRanThisWave needs any member flag", func(t *testing.T) {
		g := unlockGroup{exitIP: "203.0.113.7", inds: []int{0, 1}}
		assert.False(t, ladderRanThisWave([]NodeReport{clone, clone}, g))
		assert.True(t, ladderRanThisWave([]NodeReport{clone, deadNow}, g),
			"any member's fresh ladder outcome marks the exit ladder-run")
	})
}

// TestDefaultUnlockEndpoints pins the production probe URL set (the Phase-1
// wire contract; the test seam overrides these, never the semantics). The
// v2 battery adds the exit-truth channels: the cftrace primary echo, the
// ipify/ip.sb consensus echoes, the ip-api body contract, the OS
// connectivity-check alive gate, the authoritative DNS-over-TCP target and
// the STUN server.
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
	assert.Equal(t, "https://www.cloudflare.com/cdn-cgi/trace", ep.CFTrace)
	assert.Equal(t, "https://api.ipify.org", ep.EchoIPify)
	assert.Equal(t, "https://api.ip.sb/ip", ep.EchoIPSB)
	assert.Equal(t, "http://ip-api.com/json/", ep.IPAPIContract)
	assert.Equal(t, "https://connectivitycheck.gstatic.com/generate_204", ep.AlivePrimary)
	assert.Equal(t, "https://www.msftconnecttest.com/connecttest.txt", ep.AliveFallback)
	assert.Equal(t, "216.239.32.10:53", ep.DNSServer)
	assert.Equal(t, "o-o.myaddr.l.google.com", ep.DNSName)
	assert.Equal(t, "stun.l.google.com:19302", ep.STUNServer)
}

// TestParseCFTraceContract pins the cftrace parser (item 1): key=value
// lines parse into ip/colo/loc, and the BODY CONTRACT requires a parseable
// ip= line — a trace without one (or garbage) is the suspect class, never
// exit evidence.
func TestParseCFTraceContract(t *testing.T) {
	ev, ok := ParseCFTrace("fl=1.1\nip=203.0.113.7\ncolo=FRA\nloc=DE\n tsl=bogus\n")
	require.True(t, ok, "a real trace shape parses")
	assert.Equal(t, "203.0.113.7", ev.IP)
	assert.Equal(t, "FRA", ev.Colo)
	assert.Equal(t, "DE", ev.Loc)

	_, ok = ParseCFTrace("fl=1.1\ncolo=FRA\nloc=DE\n")
	assert.False(t, ok, "missing ip= line = contract-suspect (the fake-trace class)")

	_, ok = ParseCFTrace("ip=not-an-ip\nloc=DE\n")
	assert.False(t, ok, "an unparseable ip= value = contract-suspect")

	_, ok = ParseCFTrace("<html>blocked</html>")
	assert.False(t, ok, "garbage body = contract-suspect")

	_, ok = ParseCFTrace("")
	assert.False(t, ok, "empty body = contract-suspect")
}

// TestEchoConsensus pins the three-source consensus (item 2): ≥2 agreeing
// IPs pin the exit with the agree count, no agreement pins nothing, and
// echo IPs spanning >1 distinct /24 raise the ROTATING flag regardless of
// pinning.
func TestEchoConsensus(t *testing.T) {
	okEcho := func(source, ip string) EchoResult {
		return EchoResult{Source: source, IP: ip, Class: echoOK}
	}
	t.Run("three agree", func(t *testing.T) {
		res := echoConsensus([]EchoResult{
			okEcho(echoCFTrace, "203.0.113.7"), okEcho(echoIPify, "203.0.113.7"), okEcho(echoIPSB, "203.0.113.7"),
		})
		assert.Equal(t, "203.0.113.7", res.IP)
		assert.Equal(t, 3, res.Agree)
		assert.False(t, res.Rotating)
	})
	t.Run("majority pins, minority noted", func(t *testing.T) {
		res := echoConsensus([]EchoResult{
			okEcho(echoCFTrace, "203.0.113.7"), okEcho(echoIPify, "203.0.113.8"), okEcho(echoIPSB, "203.0.113.7"),
		})
		assert.Equal(t, "203.0.113.7", res.IP)
		assert.Equal(t, 2, res.Agree)
		assert.False(t, res.Rotating, "a same-/24 minority is not rotation")
	})
	t.Run("all-different cross-/24 = rotating, no pin", func(t *testing.T) {
		res := echoConsensus([]EchoResult{
			okEcho(echoCFTrace, "203.0.113.7"), okEcho(echoIPify, "198.51.100.9"), okEcho(echoIPSB, "198.52.100.10"),
		})
		assert.Empty(t, res.IP)
		assert.Zero(t, res.Agree)
		assert.True(t, res.Rotating)
	})
	t.Run("all-different same /24 = no pin, not rotating", func(t *testing.T) {
		res := echoConsensus([]EchoResult{
			okEcho(echoCFTrace, "203.0.113.7"), okEcho(echoIPify, "203.0.113.8"), okEcho(echoIPSB, "203.0.113.9"),
		})
		assert.Empty(t, res.IP)
		assert.Zero(t, res.Agree)
		assert.False(t, res.Rotating, "one /24 = one egress identity, churn within it is not cross-/24 rotation")
	})
	t.Run("majority pins even with a cross-/24 minority, but rotating", func(t *testing.T) {
		res := echoConsensus([]EchoResult{
			okEcho(echoCFTrace, "203.0.113.7"), okEcho(echoIPify, "198.51.100.9"), okEcho(echoIPSB, "203.0.113.7"),
		})
		assert.Equal(t, "203.0.113.7", res.IP)
		assert.Equal(t, 2, res.Agree)
		assert.True(t, res.Rotating, "echo IPs span two /24s — the exit rotates, the record says so")
	})
	t.Run("failed echoes carry no vote", func(t *testing.T) {
		res := echoConsensus([]EchoResult{
			{Source: echoCFTrace, Class: echoErr},
			okEcho(echoIPify, "203.0.113.7"), {Source: echoIPSB, Class: echoBad},
		})
		assert.Empty(t, res.IP)
		assert.Zero(t, res.Agree)
		assert.False(t, res.Rotating)
	})
	t.Run("zero echoes", func(t *testing.T) {
		res := echoConsensus(nil)
		assert.Empty(t, res.IP)
		assert.Zero(t, res.Agree)
		assert.False(t, res.Rotating)
	})
}

// TestHijackTLSErrorClassification pins the TLS-layer hijack signatures:
// certificate-validation failures and plaintext-where-TLS-was-mandated are
// the intercept class; timeouts, resets and EOFs are NOT (they are the
// dead-tunnel/flaky classes).
func TestHijackTLSErrorClassification(t *testing.T) {
	hijacked := []error{
		x509.CertificateInvalidError{Reason: x509.Expired},
		x509.HostnameError{Host: "chatgpt.com"},
		x509.UnknownAuthorityError{},
		tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
		errors.New(`Get "https://chatgpt.com/cdn-cgi/trace": http: server gave HTTP response to HTTPS client`),
		fmt.Errorf("wrap: %w", x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign, Detail: "wrapped"}),
	}
	for _, err := range hijacked {
		assert.True(t, hijackTLSError(err), "hijack signature: %v", err)
	}
	notHijack := []error{
		nil,
		errors.New("context deadline exceeded"),
		errors.New(`Get "https://x": read tcp 127.0.0.1:1->127.0.0.1:2: connection reset by peer`),
		errors.New("EOF"),
		errors.New(`net/http: TLS handshake timeout`),
		errors.New("socks connect tcp 1.2.3.4:443: connection refused"),
	}
	for _, err := range notHijack {
		assert.False(t, hijackTLSError(err), "NOT a hijack signature: %v", err)
	}
}

// TestValidateIPAPIBody pins the HTTP-family body contract (item 3): the
// answer MUST be JSON with a parseable query-field IP — the hijacked
// 24-byte fake answer carried no contract fields.
func TestValidateIPAPIBody(t *testing.T) {
	ip, ok := validateIPAPIBody(`{"status":"success","query":"203.0.113.7","country":"DE"}`)
	require.True(t, ok)
	assert.Equal(t, "203.0.113.7", ip)

	for name, body := range map[string]string{
		"the fake 24-byte answer": `{"err":true,"m":"x"}`,
		"plain garbage":           "\x1f\x8bgarbage-bytes",
		"query not an IP":         `{"query":"not-an-ip"}`,
		"query empty":             `{"query":""}`,
		"valid JSON no query":     `{"status":"fail","message":"boom"}`,
		"empty body":              "",
	} {
		_, ok := validateIPAPIBody(body)
		assert.False(t, ok, "contract violation must fail: %s", name)
	}
}

// TestExtractIPv4Token pins the TXT evidence extraction: the authoritative
// answer embeds the IP inside a longer character-string.
func TestExtractIPv4Token(t *testing.T) {
	ip, ok := extractIPv4Token("198.51.100.53.# 22:19:53.793 resolver evidence")
	require.True(t, ok)
	assert.Equal(t, "198.51.100.53", ip)
	_, ok = extractIPv4Token("no ip in here")
	assert.False(t, ok)
	_, ok = extractIPv4Token("")
	assert.False(t, ok)
}
