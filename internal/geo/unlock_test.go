package geo_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/geo"
	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unlockDouble serves EVERY battery probe URL from one httptest server (a
// single socks relay covers the whole set) and records the hits it saw: the
// per-wave battery contract is asserted on the wire.
type unlockDouble struct {
	srv      *httptest.Server
	bodies   map[string]string
	statuses map[string]int // per-path status override (204 alive probe etc.)
	mu       sync.Mutex
	hits     map[string]int
	lastHdr  map[string]http.Header
	lastBody map[string][]byte
}

func newUnlockDouble(t *testing.T, bodies map[string]string) *unlockDouble {
	t.Helper()
	d := &unlockDouble{
		bodies:   bodies,
		statuses: map[string]int{"/generate_204": http.StatusNoContent},
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
	out, ok := d.bodies[r.URL.Path]
	st, hasStatus := d.statuses[r.URL.Path]
	d.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if hasStatus {
		w.WriteHeader(st)
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
		CFTrace:           u + "/cftrace",
		EchoIPify:         u + "/ipify",
		EchoIPSB:          u + "/ipsb",
		IPAPIContract:     u + "/ipapi",
		AlivePrimary:      u + "/generate_204",
		AliveFallback:     u + "/connecttest.txt",
		// DNSServer/STUNServer stay "" — those channels are disabled unless
		// a test provides its local fixture addresses (hermetic default).
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

// syncLog is a mutex-guarded Progress capture: classification runs on
// concurrent per-node goroutines, so a bare strings.Builder would be a data
// race under -race.
type syncLog struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// unlockBodies is the all-unlocked fixture set: every probe path answers a
// clean, parseable body (the through-tunnel test pins the full happy path).
// The v2 battery channels answer contract-valid: cftrace with ip/loc/colo,
// agreeing plain-text echoes, an ip-api JSON with the query field, and the
// gstatic 204 the tunnel-alive gate rides.
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
		"/cftrace":                        "fl=1.1\nip=203.0.113.7\ncolo=FRA\nloc=DE\n",
		"/ipify":                          "203.0.113.7\n",
		"/ipsb":                           "203.0.113.7\n",
		"/ipapi":                          `{"status":"success","query":"203.0.113.7","hosting":true}`,
		"/generate_204":                   "",
		"/connecttest.txt":                "Microsoft Connect Test CDN service",
	}
}

// classifyUnlockInput builds a ClassifyInput whose geo ladder rides the
// given self-report endpoint double and whose battery rides the given
// endpoints, through the given test doubles — the merged flow's exact
// inputs for a hot-instance classification.
func classifyUnlockInput(t *testing.T, dir string, selfURL string, ep *geo.UnlockEndpoints) geo.ClassifyInput {
	t.Helper()
	return geo.ClassifyInput{
		DataDir: dir,
		Cfg: config.GeoConfig{
			Timeout:  config.Duration{Duration: 5 * time.Second},
			DoHURL:   "https://dns.google/resolve",
			HTTPSURL: "http://127.0.0.1:1/json", // dead loopback: rung 2 fails fast unless overridden
		},
		UserAgent:       "geo-agent/11",
		SelfURL:         selfURL,
		UnlockEndpoints: ep,
		Sleep:           func(context.Context, time.Duration) error { return nil },
	}
}

// classifyNodeFlush classifies ONE alive node through the given hot socks
// endpoint and flushes the wave (per-wave per-alive-node — every test here
// drives the merged flow's exact path). Returns the persisted records and
// the wave summary.
func classifyNodeFlush(
	t *testing.T, _ string, socksAddr string, n *model.Node, exitIP string, in geo.ClassifyInput,
) ([]*model.GeoRecord, geo.Summary) {
	t.Helper()
	clf := geo.NewClassifier(in)
	clf.ClassifyNode(context.Background(), n, socksAddr, exitIP)
	probeByKey := map[string]store.ProbeResult{n.Key: liveProbe(n, exitIP)}
	recs, sum, err := clf.Flush(nil, []*model.Node{n}, probeByKey, 1, time.Now())
	require.NoError(t, err)
	return recs, sum
}

// TestUnlockProbeThroughTunnel pins the end-to-end happy path: the FULL
// battery rides the SAME hot tunnel the probe just proved, the reference
// headers are on the wire, and the verdict folds into the geo record (which
// lands in geo-base via the flush).
func TestUnlockProbeThroughTunnel(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	dir := t.TempDir()

	in := classifyUnlockInput(t, dir, api.URL()+"/json/", ud.endpoints())
	records, _ := classifyNodeFlush(t, dir, socks.Addr(), node(), "203.0.113.7", in)
	require.Len(t, records, 1)

	// Exactly one probe request per battery endpoint (one node, one pass).
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
	assert.Equal(t, 1, ud.hitsOf("/cftrace"))
	assert.Equal(t, 1, ud.hitsOf("/ipify"))
	assert.Equal(t, 1, ud.hitsOf("/ipsb"))
	assert.Equal(t, 1, ud.hitsOf("/ipapi"))
	assert.Equal(t, 1, ud.hitsOf("/generate_204"))

	// The verdict lands on the record (and persisted through the flush).
	st := records[0].MediaUnlocks
	assert.Equal(t, model.UnlockYes, st.ChatGPT)
	assert.Equal(t, model.UnlockNetflixFull, st.Netflix)
	assert.Equal(t, "DE", st.YouTubeRegion)
	assert.Equal(t, model.UnlockYes, st.Disney)
	assert.Equal(t, model.UnlockYes, st.TikTok)
	checkedAt, perr := time.Parse(time.RFC3339, st.CheckedAt)
	require.NoError(t, perr, "CheckedAt must be an RFC3339 stamp")
	assert.LessOrEqual(t, time.Since(checkedAt), time.Minute)

	// v2 battery evidence contract: the echo consensus pinned the exit
	// (3 agree, one /24, no rotation), the cftrace evidence fields ride,
	// the battery version stamps the migration semantics.
	assert.Equal(t, geo.UnlockBatteryVersion, st.BatteryVersion)
	assert.Equal(t, "203.0.113.7", st.ExitIP)
	assert.Equal(t, 3, st.ConsensusCount)
	assert.False(t, st.Rotating)
	assert.False(t, st.Hijack)
	assert.Equal(t, "FRA", st.CFColo)
	assert.Equal(t, "DE", st.CFLoc)
	assert.Empty(t, st.DNSIP, "the DNS channel is seam-disabled in this fixture")
	assert.Empty(t, st.StunIP, "vless nodes carry no STUN channel")

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

// TestUnlockBatteryRunsEveryAliveWave pins the per-wave contract at the
// battery level: two consecutive waves each run the FULL battery for the
// alive node — no cache, no freshness gate (the self-report side of this
// contract is pinned by TestClassifyPerWaveFreshnessGateGone).
func TestUnlockBatteryRunsEveryAliveWave(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	dir := t.TempDir()
	n := node()
	in := classifyUnlockInput(t, dir, api.URL()+"/json/", ud.endpoints())

	for range 2 {
		_, _ = classifyNodeFlush(t, dir, socks.Addr(), n, "198.51.100.7", in)
	}
	assert.Equal(t, 2, ud.hitsOf("/cdn-cgi/trace"),
		"per-wave classification: both waves run the full battery")
	assert.Equal(t, 2, ud.hitsOf("/generate_204"),
		"the tunnel-alive gate fires on every wave too")
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

func deadAliveEndpoints(d *unlockDouble) *geo.UnlockEndpoints {
	ep := d.endpoints()
	ep.AlivePrimary = d.srv.URL + "/alive-dead-1"
	ep.AliveFallback = d.srv.URL + "/alive-dead-2"
	return ep
}

// TestUnlockHijackTLSCertBlockedNotYes pins the hijack detector end to end
// (the poisoned-verdict kill): a self-signed TLS fixture is what a MITM
// exit presents, and the production path validates certificates against
// the SYSTEM pool — every HTTPS probe fails validation, the exit is
// flagged hijack, and EVERY media verdict lands blocked (never yes).
func TestUnlockHijackTLSCertBlockedNotYes(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A full happy-path answer set: under a validating client NONE of
		// it may produce a yes — the cert fails validation first.
		for path, body := range unlockBodies() {
			if r.URL.Path == path {
				_, _ = w.Write([]byte(body))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	socks := newSocksServer(t)
	dir := t.TempDir()

	u := srv.URL
	in := classifyUnlockInput(t, dir, api.URL()+"/json/", &geo.UnlockEndpoints{
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
		CFTrace:           u + "/cftrace",
		EchoIPify:         u + "/ipify",
		EchoIPSB:          u + "/ipsb",
		IPAPIContract:     u + "/ipapi",
		AlivePrimary:      u + "/generate_204",
		AliveFallback:     u + "/connecttest.txt",
	})

	records, _ := classifyNodeFlush(t, dir, socks.Addr(), node(), "203.0.113.7", in)
	require.Len(t, records, 1)
	st := records[0].MediaUnlocks
	require.NotEmpty(t, st.CheckedAt, "the battery ran (the TLS answers prove a live tunnel)")
	assert.True(t, st.Hijack, "a self-signed cert through the tunnel = the hijack class")
	assert.Equal(t, model.UnlockBlocked, st.ChatGPT,
		"chatgpt must be blocked, NOT yes — cert validation is the poison kill")
	assert.Equal(t, model.UnlockBlocked, st.Netflix)
	assert.Equal(t, model.UnlockBlocked, st.YouTubeRegion)
	assert.Equal(t, model.UnlockBlocked, st.Disney)
	assert.Equal(t, model.UnlockBlocked, st.TikTok)
	assert.Equal(t, geo.UnlockBatteryVersion, st.BatteryVersion)
}

// TestUnlockIPAPIBodyContractHijack pins the HTTP-family hijack detector:
// the free-tier ip-api answer is plain HTTP (no cert to validate), so the
// BODY CONTRACT is the defense — a 200 whose JSON lacks a parseable
// query-field IP (the magiclampcloud 24-byte fake shape) flags the exit
// hijack and forces the media verdicts blocked, while the echo consensus
// still pins what it honestly saw.
func TestUnlockIPAPIBodyContractHijack(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	bodies := unlockBodies()
	bodies["/ipapi"] = `{"err":true}` // the fake 24-byte answer: no query field
	ud := newUnlockDouble(t, bodies)
	socks := newSocksServer(t)
	dir := t.TempDir()

	in := classifyUnlockInput(t, dir, api.URL()+"/json/", ud.endpoints())
	records, _ := classifyNodeFlush(t, dir, socks.Addr(), node(), "203.0.113.7", in)
	require.Len(t, records, 1)
	st := records[0].MediaUnlocks
	assert.True(t, st.Hijack, "a contract-breaking ip-api answer = the hijack/garbage class")
	assert.Equal(t, model.UnlockBlocked, st.ChatGPT, "media verdicts are forced blocked")
	assert.Equal(t, model.UnlockBlocked, st.Netflix)
	assert.Equal(t, "203.0.113.7", st.ExitIP, "the echo consensus still records what it saw")
	assert.Equal(t, 3, st.ConsensusCount)
	assert.Equal(t, geo.UnlockBatteryVersion, st.BatteryVersion)
}

// TestUnlockPlaintextOnTLSHijack pins the plaintext-where-TLS-was-mandated
// signature: an https:// endpoint answered by a PLAIN-HTTP server (the
// magiclampcloud plain-HTTP-on-:443 shape) produces the exact
// "server gave HTTP response to HTTPS client" transport signature —
// classified hijack, media verdicts blocked.
func TestUnlockPlaintextOnTLSHijack(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	bodies := unlockBodies()
	bodies["/ipapi"] = `{"status":"success","query":"203.0.113.7"}` // contract held
	ud := newUnlockDouble(t, bodies)
	// The cftrace endpoint lies about its scheme: https:// against the
	// plain-HTTP listener.
	ep := ud.endpoints()
	ep.CFTrace = "https://" + strings.TrimPrefix(ud.srv.URL, "http://") + "/cftrace"
	socks := newSocksServer(t)
	dir := t.TempDir()

	in := classifyUnlockInput(t, dir, api.URL()+"/json/", ep)
	records, _ := classifyNodeFlush(t, dir, socks.Addr(), node(), "203.0.113.7", in)
	require.Len(t, records, 1)
	st := records[0].MediaUnlocks
	assert.True(t, st.Hijack, "plaintext where TLS was mandated = the hijack class")
	assert.Equal(t, model.UnlockBlocked, st.ChatGPT)
}

// TestUnlockEchoRotatingNoPin pins the rotating class (the 5-7-distinct-
// exit research shape): echo answers spanning more than one /24 raise
// rotating=true, pin NOTHING as the classification identity, and the media
// verdicts still stand.
func TestUnlockEchoRotatingNoPin(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	bodies := unlockBodies()
	bodies["/cftrace"] = "fl=1.1\nip=203.0.113.7\ncolo=FRA\nloc=DE\n"
	bodies["/ipify"] = "198.51.100.9\n"
	bodies["/ipsb"] = "198.52.100.10\n"
	ud := newUnlockDouble(t, bodies)
	socks := newSocksServer(t)
	dir := t.TempDir()

	in := classifyUnlockInput(t, dir, api.URL()+"/json/", ud.endpoints())
	records, _ := classifyNodeFlush(t, dir, socks.Addr(), node(), "203.0.113.7", in)
	require.Len(t, records, 1)
	st := records[0].MediaUnlocks
	assert.True(t, st.Rotating, "echo IPs across three /24s = rotating")
	assert.Empty(t, st.ExitIP, "a rotating exit pins no single IP as its identity")
	assert.Zero(t, st.ConsensusCount)
	assert.False(t, st.Hijack)
	assert.Equal(t, model.UnlockYes, st.ChatGPT, "the media verdicts still stand")
}

// TestUnlockEchoMajorityPinsMinorityNoted pins the 2-agree-1-disagree case:
// the majority pins the exit IP (consensus = the agree count), the
// minority echo is recorded, and a same-/24 minority is not rotation.
func TestUnlockEchoMajorityPinsMinorityNoted(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	bodies := unlockBodies()
	bodies["/cftrace"] = "fl=1.1\nip=203.0.113.7\ncolo=FRA\nloc=DE\n"
	bodies["/ipify"] = "203.0.113.8\n" // minority, same /24
	bodies["/ipsb"] = "203.0.113.7\n"
	ud := newUnlockDouble(t, bodies)
	socks := newSocksServer(t)
	dir := t.TempDir()

	in := classifyUnlockInput(t, dir, api.URL()+"/json/", ud.endpoints())
	records, _ := classifyNodeFlush(t, dir, socks.Addr(), node(), "203.0.113.7", in)
	require.Len(t, records, 1)
	st := records[0].MediaUnlocks
	assert.Equal(t, "203.0.113.7", st.ExitIP, "the majority pins the exit IP")
	assert.Equal(t, 2, st.ConsensusCount)
	assert.False(t, st.Rotating, "a same-/24 minority is not rotation")
}

// TestUnlockRetryOKFlaky pins the retry-once wrapper (item 7): a
// transport-level failure recovered on the second shot keeps the real
// verdict (the OK_FLAKY class — the research's 25% unstable-link mass is
// not policy), a deterministic double failure stays the honest
// unknown — with exactly two attempts per endpoint — and the recovered
// pass surfaces in the production evidence tail as ok_flaky (the
// evidence counter logUnlock reads; probeUnlockSet must copy it).
func TestUnlockRetryOKFlaky(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	bodies := unlockBodies()
	ud := newUnlockDouble(t, bodies)
	var premiumKilled, titleKilled atomic.Bool
	var premiumTries, titleTries atomic.Int32
	orig := ud.srv.Config.Handler
	ud.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/premium":
			premiumTries.Add(1)
			// Fail ONCE (connection slammed shut), then answer: YouTube
			// recovers with the real region verdict (OK_FLAKY).
			if !premiumKilled.Swap(true) {
				if hj, ok := w.(http.Hijacker); ok {
					conn, _, _ := hj.Hijack()
					_ = conn.Close()
				}
				return
			}
		case "/title/81280792":
			titleTries.Add(1)
			// Fail EVERY pass (deterministic): netflix stays unknown — a
			// reset is a dead link, not a TLS hijack.
			titleKilled.Store(true)
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				_ = conn.Close()
			}
			return
		}
		orig.ServeHTTP(w, r)
	})
	socks := newSocksServer(t)
	dir := t.TempDir()

	in := classifyUnlockInput(t, dir, api.URL()+"/json/", ud.endpoints())
	var log syncLog
	in.Progress = &log // the evidence tail carries the OK_FLAKY counter pin
	records, _ := classifyNodeFlush(t, dir, socks.Addr(), node(), "203.0.113.7", in)
	require.Len(t, records, 1)
	st := records[0].MediaUnlocks
	assert.Equal(t, "DE", st.YouTubeRegion,
		"the retry recovered the premium answer — the verdict stands (OK_FLAKY)")
	assert.Equal(t, int32(2), premiumTries.Load(), "fail + exactly one retry")
	assert.Equal(t, model.UnlockUnknown, st.Netflix,
		"both title-A passes failing is the deterministic-fail class, not hijack")
	assert.Equal(t, int32(2), titleTries.Load(), "fail + exactly one retry, then stop")
	assert.False(t, st.Hijack, "a connection reset is a dead link, never a TLS intercept")
	assert.True(t, titleKilled.Load(), "fixture sanity: title A was killed on the wire")
	assert.Contains(t, log.String(), "ok_flaky=1",
		"the evidence counter carries the ONE recovered endpoint (premium) — the OK_FLAKY counter logUnlock reads")
}

// TestUnlockTunnelAliveGateSkipsDeadBattery pins the alive gate (item 5):
// the OS connectivity-check endpoints are the battery's FIRST probe — a
// tunnel failing both (after the retry-once wrapper) is dead-now, the rest
// of the battery is skipped entirely (no media/echo requests), and the
// verdict is the honest all-unknown with a fresh stamp. The merged flow
// records that honest unknown (the wave does not fail; the next wave
// re-classifies).
func TestUnlockTunnelAliveGateSkipsDeadBattery(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	dir := t.TempDir()

	in := classifyUnlockInput(t, dir, api.URL()+"/json/", deadAliveEndpoints(ud))
	records, _ := classifyNodeFlush(t, dir, socks.Addr(), node(), "203.0.113.7", in)
	require.Len(t, records, 1)
	st := records[0].MediaUnlocks
	require.NotEmpty(t, st.CheckedAt, "the alive check ran and is stamped honestly")
	assert.Equal(t, model.UnlockUnknown, st.ChatGPT)
	assert.Equal(t, model.UnlockUnknown, st.Netflix)
	assert.Zero(t, ud.hitsOf("/cdn-cgi/trace"), "a dead tunnel skips the whole battery")
	assert.Zero(t, ud.hitsOf("/premium"))
	assert.Zero(t, ud.hitsOf("/cftrace"))
	// Statuses are DATA (the getRetry contract): a wrong-status alive
	// answer is a gate miss, not a transport failure — exactly one attempt
	// per gate endpoint, then the battery is skipped.
	assert.Equal(t, 2, ud.hitsOf("/alive-dead-1")+ud.hitsOf("/alive-dead-2"),
		"primary and fallback each got one attempt, then the battery was skipped")
	assert.Equal(t, 1, ud.hitsOf("/alive-dead-2"))
}

// TestUnlockMigrationV1VerdictRefreshed pins the battery-version contract in
// the merged flow: the stored verdict ALWAYS carries the current battery
// version, and every alive wave re-classifies — so a v1-stamped (poisoned-
// era) verdict on the cold record is overwritten by the fresh v2 verdict on
// the very next alive wave (freshUnlock still rejects pre-current verdicts
// as a DATA contract — pinned by TestFreshUnlockBatteryMigration; the
// merged flow has no cache that could serve them).
func TestUnlockMigrationV1VerdictRefreshed(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	dir := t.TempDir()
	n := node()
	in := classifyUnlockInput(t, dir, api.URL()+"/json/", ud.endpoints())

	records, _ := classifyNodeFlush(t, dir, socks.Addr(), n, "203.0.113.7", in)
	require.Len(t, records, 1)
	require.Equal(t, geo.UnlockBatteryVersion, records[0].MediaUnlocks.BatteryVersion)

	// Downgrade the PERSISTED verdict to battery v1 (the poisoned-era shape
	// the migration semantics must never serve again).
	path := filepath.Join(dir, "geo-base.jsonl")
	recs, rerr := store.ReadGeo(path)
	require.NoError(t, rerr)
	for _, r := range recs {
		r.MediaUnlocks.BatteryVersion = 1
	}
	require.NoError(t, store.WriteGeo(path, recs))

	// The next alive wave re-runs the battery (per-wave classification) and
	// the record carries the current battery version again.
	ud.reset()
	records, _ = classifyNodeFlush(t, dir, socks.Addr(), n, "203.0.113.7", in)
	require.Len(t, records, 1)
	assert.Positive(t, ud.totalHits(),
		"per-wave classification: the battery re-ran regardless of the stored verdict")
	assert.Equal(t, geo.UnlockBatteryVersion, records[0].MediaUnlocks.BatteryVersion,
		"the refreshed verdict carries the current battery version")
}

// dnsTCPFixture is a minimal framed DNS-over-TCP test server: it verifies
// the 2-byte big-endian length prefix on the query, then answers with the
// frame the test scripted (rcode/TXT strings).
type dnsTCPFixture struct {
	ln       net.Listener
	queries  atomic.Int32
	lastQ    atomic.Pointer[string]
	response []byte // the FULL 2-byte-prefixed answer frame to send
}

func newDNSTCPFixture(t *testing.T, response []byte) *dnsTCPFixture {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	fx := &dnsTCPFixture{ln: ln, response: response}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				prefix := make([]byte, 2)
				if _, err := io.ReadFull(c, prefix); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(prefix))
				msg := make([]byte, n)
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				fx.queries.Add(1)
				name := dnsQuestionName(msg)
				fx.lastQ.Store(&name)
				_, _ = c.Write(fx.response)
			}(conn)
		}
	}()
	return fx
}

// dnsQuestionName extracts the question name of a query message (evidence
// the fixture asserts the framed query was well-formed).
func dnsQuestionName(msg []byte) string {
	if len(msg) < 13 {
		return ""
	}
	var b strings.Builder
	pos := 12
	for {
		l := int(msg[pos])
		if l == 0 {
			break
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(msg[pos+1 : pos+1+l])
		pos += 1 + l
	}
	return b.String()
}

// buildDNSTXTAnswer frames a DNS response carrying one TXT answer whose
// character-string embeds the given IP (the o-o.myaddr.l.google.com shape:
// "IP.# comment").
func buildDNSTXTAnswer(ip string, rcode int, withAnswer bool) []byte {
	owner := "o-o.myaddr.l.google" // 19 bytes — the label length must match
	qname := append([]byte{byte(len(owner))}, owner...)
	qname = append(qname, []byte{3}...)
	qname = append(qname, []byte("com")...)
	qname = append(qname, 0)

	msg := []byte{
		0x00, 0x00, // id
		0x80, byte(rcode & 0x0F), // QR=1, rcode
		0x00, 0x01, // qdcount
		0x00, 0x00, // ancount — patched below
		0x00, 0x00, 0x00, 0x00,
	}
	msg = append(msg, qname...)
	msg = binary.BigEndian.AppendUint16(msg, 16) // qtype TXT
	msg = binary.BigEndian.AppendUint16(msg, 1)  // IN
	if withAnswer {
		// Answer: pointer to the question name (0xC00C), TXT, IN, ttl,
		// rdlen, one character-string "IP.# evidence".
		rdata := append([]byte{byte(len(ip) + 2)}, []byte(ip+".#")...)
		msg[6], msg[7] = 0x00, 0x01
		msg = append(msg, 0xC0, 0x0C)
		msg = binary.BigEndian.AppendUint16(msg, 16)
		msg = binary.BigEndian.AppendUint16(msg, 1)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
		msg = append(msg, rdata...)
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
	return append(frame, msg...)
}

// TestUnlockDNSChannelRecorded pins the DNS-authoritative second channel
// (item 4): TXT o-o.myaddr.l.google.com queried over FRAMED TCP through the
// hot tunnel; the parsed TXT IP lands as dns_ip evidence. A failing DNS
// channel (port-53 egress filtering) is recorded non-fatally — the verdict
// stands without it.
func TestUnlockDNSChannelRecorded(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	fx := newDNSTCPFixture(t, buildDNSTXTAnswer("198.51.100.53", 0, true))
	ep := ud.endpoints()
	ep.DNSServer = fx.ln.Addr().String()
	ep.DNSName = "o-o.myaddr.l.google.com"
	socks := newSocksServer(t)
	dir := t.TempDir()

	in := classifyUnlockInput(t, dir, api.URL()+"/json/", ep)
	records, _ := classifyNodeFlush(t, dir, socks.Addr(), node(), "203.0.113.7", in)
	require.Len(t, records, 1)
	st := records[0].MediaUnlocks
	assert.Equal(t, "198.51.100.53", st.DNSIP, "the authoritative TXT echo is dns_ip evidence")
	require.NotNil(t, fx.lastQ.Load())
	assert.Equal(t, "o-o.myaddr.l.google.com", *fx.lastQ.Load(),
		"the framed query carried the TXT owner name through the tunnel")
	assert.Equal(t, model.UnlockYes, st.ChatGPT, "the DNS channel is additive evidence, never a verdict gate")

	// Non-fatal failure: a DNS server that never answers leaves the
	// verdict untouched and the evidence empty.
	fx2 := newDNSTCPFixture(t, []byte{0xFF, 0xFF, 0x00}) // garbage frame
	ep2 := ud.endpoints()
	ep2.DNSServer = fx2.ln.Addr().String()
	in2 := classifyUnlockInput(t, dir, api.URL()+"/json/", ep2)
	records, _ = classifyNodeFlush(t, dir, socks.Addr(), node(), "203.0.113.7", in2)
	require.Len(t, records, 1)
	assert.Empty(t, records[0].MediaUnlocks.DNSIP)
	assert.Equal(t, model.UnlockYes, records[0].MediaUnlocks.ChatGPT,
		"a failed DNS channel never degrades the verdict")
}

// TestUnlockStunHysteriaRecorded pins the STUN channel (item 6) end to end:
// a hysteria2 node's battery carries an RFC 5389 Binding through the socks
// UDP path (the hysteria instances are the only ones whose socks inbound
// enables UDP), and the decoded XOR-MAPPED-ADDRESS lands as stun_ip
// evidence. Failure is recorded non-fatally: a vless node's battery never
// sends a Binding at all.
func TestUnlockStunHysteriaRecorded(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	fx := newGeoStunFixture(t, [4]byte{198, 51, 100, 99}, 3478)
	ep := ud.endpoints()
	ep.STUNServer = fx.addr()
	socks := newSocksServer(t)
	dir := t.TempDir()

	// One hysteria2 node (the STUN rider) — the per-node battery shape.
	h := model.NewNode("stunsrc", "hysteria2", "stun-cred", "stun.example.com", 443, nil)
	in := classifyUnlockInput(t, dir, api.URL()+"/json/", ep)
	records, _ := classifyNodeFlush(t, dir, socks.Addr(), h, "203.0.113.7", in)
	require.Len(t, records, 1)
	st := records[0].MediaUnlocks
	assert.Equal(t, "198.51.100.99", st.StunIP,
		"the hysteria2 node's battery carries the STUN echo as stun_ip evidence")
	require.NotNil(t, fx.gotRequest(), "the Binding request rode the socks UDP path")
	require.Len(t, fx.gotRequest(), 20, "the Binding request is the 20-byte header shape")
	assert.Equal(t, geo.UnlockBatteryVersion, st.BatteryVersion)
	assert.Equal(t, model.UnlockYes, st.ChatGPT, "STUN is additive evidence, never a verdict gate")
}

// geoStunFixture is a minimal UDP "STUN" server: it captures the Binding
// request and replies with a Binding success whose XOR-MAPPED-ADDRESS
// echoes the request's own transaction id (STUNBinding generates a fresh
// one internally, so the reply must be built per-request).
type geoStunFixture struct {
	pc      *net.UDPConn
	mu      sync.Mutex
	request []byte
}

func newGeoStunFixture(t *testing.T, ip [4]byte, port uint16) *geoStunFixture {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	fx := &geoStunFixture{pc: pc}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, rerr := pc.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			fx.mu.Lock()
			fx.request = append([]byte(nil), buf[:n]...)
			var reply []byte
			if n >= 20 {
				msg := make([]byte, 0, 32)
				msg = append(msg, 0x01, 0x01) // Binding success
				msg = binary.BigEndian.AppendUint16(msg, 12)
				msg = append(msg, 0x21, 0x12, 0xA4, 0x42) // magic cookie
				msg = append(msg, buf[8:20]...)           // the request's txid
				msg = binary.BigEndian.AppendUint16(msg, 0x0020)
				msg = binary.BigEndian.AppendUint16(msg, 8)
				msg = append(msg, 0x00, 0x01) // reserved + IPv4 family
				xport := port ^ 0x2112
				msg = binary.BigEndian.AppendUint16(msg, xport)
				for i, b := range ip {
					msg = append(msg, b^[]byte{0x21, 0x12, 0xA4, 0x42}[i])
				}
				reply = msg
			}
			fx.mu.Unlock()
			if reply != nil {
				_, _ = pc.WriteToUDP(reply, raddr)
			}
		}
	}()
	return fx
}

func (fx *geoStunFixture) addr() string { return fx.pc.LocalAddr().String() }

func (fx *geoStunFixture) gotRequest() []byte {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return fx.request
}
