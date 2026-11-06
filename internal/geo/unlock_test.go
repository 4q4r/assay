package geo_test

import (
	"bytes"
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

// setBody swaps one fixture answer between waves (the alive-bypass tests
// flip the ChatGPT trace from an evidence-less body to a definite one).
func (d *unlockDouble) setBody(path, body string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.bodies[path] = body
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

// unlockInput builds a geo Input with the Phase-1 stage explicitly ON
// (baseInput's explicit-false fixture overridden — also pins that an
// explicit true is honored), both nodes sharing ONE exit IP (the dedup
// contract), and every probe riding the given doubles through the
// in-process socks relay.
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
	on := true
	in.Cfg.UnlockProbes = &on
	in.UnlockEndpoints = ep
	in.ExitCache = cache
	return in
}

// noTraceEvidenceBodies is the dead-tunnel-at-probe-time fixture set: every
// service answers, but the ChatGPT trace carries no loc evidence — the
// verdict caches chatgpt=unknown (the production 72/99 shape) with the rest
// definite.
func noTraceEvidenceBodies() map[string]string {
	b := unlockBodies()
	b["/cdn-cgi/trace"] = "fl=1.1\nip=203.0.113.7\n" // no loc= line → unknown
	return b
}

// agedStamp renders an RFC3339 stamp offset from now (test-time aging).
func agedStamp(offset time.Duration) string {
	return time.Now().Add(offset).UTC().Format(time.RFC3339)
}

// ageUnlockCache ages the cached verdict for one exit IP in BOTH halves —
// the hot entry and every geo-base record carrying the exit — the same
// dual-half aging the 7-day-expiry contract test uses.
func ageUnlockCache(t *testing.T, dir string, cache *geo.ExitGeoCache, exitIP string, offset time.Duration) {
	t.Helper()
	aged := agedStamp(offset)
	path := filepath.Join(dir, "geo-base.jsonl")
	recs, err := store.ReadGeo(path)
	require.NoError(t, err)
	require.NotEmpty(t, recs)
	for _, r := range recs {
		if r.IP == exitIP {
			r.MediaUnlocks.CheckedAt = aged
		}
	}
	require.NoError(t, store.WriteGeo(path, recs))
	if e, ok := cache.Get(exitIP); ok && e != nil && e.MediaUnlocks != nil {
		e.MediaUnlocks.CheckedAt = aged
	}
}

// TestUnlockAliveBypassReprobesCachedUnknown pins the owner's alive-bypass
// rule (2026-11-06): when the exit's tunnel demonstrably works in the
// current wave (the geo ladder's self-report answered through it), a FRESH
// cached verdict that still carries an unknown media field is bypassed and
// re-probed — the working tunnel yields a definite answer. A fully definite
// cached verdict is NEVER bypassed (wave 3: zero re-probes).
func TestUnlockAliveBypassReprobesCachedUnknown(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, noTraceEvidenceBodies())
	socks := newSocksServer(t)
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), ud.endpoints(), cache)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2) // two nodes share the exit IP
	require.Equal(t, model.UnlockUnknown, records[0].MediaUnlocks.ChatGPT,
		"fixture: wave 1 must cache the dead-tunnel unknown")

	// Age the verdict by an hour (inside the 24h unknown window): the wave-2
	// re-stamp must then differ from the cached one — RFC3339 has second
	// precision, so a same-second back-to-back stamp would hide the
	// re-probe. This also pins the bypass firing through the cold geo-base
	// half (the geo ladder re-caches the hot entry without verdicts every
	// wave — the cold half is the serving layer for fresh verdicts).
	ageUnlockCache(t, dir, cache, "203.0.113.7", -time.Hour)

	// The tunnel works NOW (the self-report just answered through it) and
	// the cached verdict carries an unknown → the next wave must bypass the
	// cache and re-probe, flipping unknown→yes.
	ud.setBody("/cdn-cgi/trace", "fl=1.1\nip=203.0.113.7\nloc=DE\n")
	ud.reset()
	records, _, err = geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, 1, ud.hitsOf("/cdn-cgi/trace"),
		"alive exit + cached unknown = bypass, the wave must re-probe")
	assert.Equal(t, 1, ud.hitsOf("/premium"),
		"the bypass re-probe refreshes ALL media fields (one probe pass)")
	assert.Equal(t, model.UnlockYes, records[0].MediaUnlocks.ChatGPT,
		"the re-probe through the working tunnel must flip unknown→yes")
	assert.Equal(t, records[0].MediaUnlocks, records[1].MediaUnlocks,
		"the flipped verdict lands on every node sharing the exit")
	assert.NotEqual(t, agedStamp(-time.Hour), records[0].MediaUnlocks.CheckedAt,
		"the bypassed verdict must be re-stamped, not served from cache")

	// Wave 3 — the verdict is now fully definite: the cache hit stands even
	// though the exit is alive again (definite verdicts are never bypassed).
	ud.reset()
	_, _, err = geo.Run(context.Background(), in)
	require.NoError(t, err)
	assert.Zero(t, ud.totalHits(),
		"definite cached verdict + alive exit = cache hit, no re-probe")
}

// TestUnlockDeadExitUnknownStalesAfter24h pins the 24h unknown TTL end to
// end (owner order 2026-11-06, FIX 2): for an exit that is NOT alive in the
// current wave (every geo-ladder rung failed hermetically), a cached
// unknown verdict still serves as a cache hit inside 24h but goes stale at
// 25h — the wave re-probes instead of serving the week-old dead-tunnel
// unknown. A definite verdict keeps the 7-day window (pinned by
// TestFreshUnlock and the existing cache-hit contract).
func TestUnlockDeadExitUnknownStalesAfter24h(t *testing.T) {
	// The self-report truth must MATCH the unlock exit key so the cold
	// geo-base record is keyed by the same IP the unlock cache uses (the
	// stock fixture answers query=203.0.113.77 — a churned mismatch).
	body := bytes.ReplaceAll(
		documentedSingleSuccess(t), []byte("203.0.113.77"), []byte("203.0.113.7"))
	api := newIPAPIDouble(t, body)
	ud := newUnlockDouble(t, noTraceEvidenceBodies())
	socks := newSocksServer(t)
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), ud.endpoints(), cache)
	// /json/ = the no-param hop the double's failMode shapes; alive waves
	// serve the healthy body there, dead waves a 503.
	in.SelfURL = api.URL() + "/json/"

	// Wave 1 — alive (the self-report answers through the tunnel): the
	// probes cache an unknown-carrying verdict AND anchor the exit IP in the
	// cold geo-base (production exits earn their cached unknowns while
	// alive; the tunnel dies afterwards).
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2) // two nodes share the exit IP
	require.Equal(t, model.UnlockUnknown, records[0].MediaUnlocks.ChatGPT)
	require.Positive(t, ud.totalHits(), "wave 1 must probe (no cache yet)")

	// 23h old — inside the unknown window: cache hit, zero network calls.
	ageUnlockCache(t, dir, cache, "203.0.113.7", -23*time.Hour)

	// Waves 2+ — the tunnel is DEAD: drop the hot entry (the geo ladder
	// reuses it unconditionally — without this it would never dial), the
	// self-report hop answers 503, and the HTTPS/DoH rungs ride dead
	// loopbacks (hermetic fail-fast, no real resolver).
	cache.Delete("203.0.113.7")
	api.failMode.Store(1)
	in.Cfg.DoHURL = "http://127.0.0.1:1/resolve"

	ud.reset()
	_, _, err = geo.Run(context.Background(), in)
	require.NoError(t, err)
	assert.Zero(t, ud.totalHits(), "unknown verdict inside 24h = cache hit")

	// 25h old — past the unknown window: re-probe (the dead exit is not
	// hammered every wave, but a day-old dead-tunnel unknown must not shield
	// it for a week either).
	ageUnlockCache(t, dir, cache, "203.0.113.7", -25*time.Hour)
	ud.reset()
	_, _, err = geo.Run(context.Background(), in)
	require.NoError(t, err)
	assert.Positive(t, ud.totalHits(), "unknown verdict past 24h = re-probe")
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
	assert.Equal(t, 1, ud.hitsOf("/cftrace"))
	assert.Equal(t, 1, ud.hitsOf("/ipify"))
	assert.Equal(t, 1, ud.hitsOf("/ipsb"))
	assert.Equal(t, 1, ud.hitsOf("/ipapi"))
	assert.Equal(t, 1, ud.hitsOf("/generate_204"))

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

// TestUnlockStageExplicitDisabled pins the opt-out contract: an EXPLICIT
// unlock_probes = false (baseInput's fixture — the production default
// flipped ON by the owner ruling 2026-11-06) keeps the stage off: zero
// probe requests, every Phase-1 field stays unchecked.
func TestUnlockStageExplicitDisabled(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	f, _, _ := newTestFactory(socks)
	n1 := node("1", "one.example.com")
	probes := map[string]store.ProbeResult{n1.Key: liveProbe(n1, "203.0.113.7")}
	in := baseInput(t.TempDir(), []*model.Node{n1}, probes, f, api.URL())
	require.NotNil(t, in.Cfg.UnlockProbes)
	require.False(t, *in.Cfg.UnlockProbes, "baseInput carries the explicit-false fixture")
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

// TestUnlockStageNilKnobEnabled pins the accessor's nil branch end to end:
// a hand-built config that never went through applyDefaults (knob nil — the
// absent case) runs the stage, exactly like a loaded config with the key
// absent (applyGeoDefaults materializes true). This is what keeps
// hand-built and loaded configs in agreement after the default flip.
func TestUnlockStageNilKnobEnabled(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	f, _, _ := newTestFactory(socks)
	n1 := node("1", "one.example.com")
	probes := map[string]store.ProbeResult{n1.Key: liveProbe(n1, "203.0.113.7")}
	in := baseInput(t.TempDir(), []*model.Node{n1}, probes, f, api.URL())
	in.Cfg.UnlockProbes = nil // absent: the pre-defaults shape a loaded config materializes to true
	in.UnlockEndpoints = ud.endpoints()
	in.ExitCache = geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Positive(t, ud.totalHits(), "absent knob = stage on")
	assert.NotEmpty(t, records[0].MediaUnlocks)
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

// deadAliveEndpoints blanks the tunnel-alive endpoints: both OS
// connectivity checks answer 404, so the gate must judge the tunnel dead
// and the battery must skip the rest of the probe set.
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
// hijack-flagged, and the media verdicts are BLOCKED (never yes/full, the
// v1 battery's false-positive class). blocked answers are definite → the
// verdict caches 7 days honestly.
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
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	u := srv.URL
	in := unlockInput(t, dir, f, api.URL(), &geo.UnlockEndpoints{
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
	}, cache)

	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
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
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), ud.endpoints(), cache)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
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
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), ep, cache)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
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
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), ud.endpoints(), cache)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
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
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), ud.endpoints(), cache)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
	st := records[0].MediaUnlocks
	assert.Equal(t, "203.0.113.7", st.ExitIP, "the majority pins the exit IP")
	assert.Equal(t, 2, st.ConsensusCount)
	assert.False(t, st.Rotating, "a same-/24 minority is not rotation")
}

// TestUnlockRetryOKFlaky pins the retry-once wrapper (item 7): a
// transport-level failure recovered on the second shot keeps the real
// verdict (the OK_FLAKY class — the research's 25% unstable-link mass is
// not policy), and a deterministic double failure stays the honest
// unknown — with exactly two attempts per endpoint.
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
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), ud.endpoints(), cache)
	in.Sleep = func(context.Context, time.Duration) error { return nil } // no real stagger waits
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
	st := records[0].MediaUnlocks
	assert.Equal(t, "DE", st.YouTubeRegion,
		"the retry recovered the premium answer — the verdict stands (OK_FLAKY)")
	assert.Equal(t, int32(2), premiumTries.Load(), "fail + exactly one retry")
	assert.Equal(t, model.UnlockUnknown, st.Netflix,
		"both title-A passes failing is the deterministic-fail class, not hijack")
	assert.Equal(t, int32(2), titleTries.Load(), "fail + exactly one retry, then stop")
	assert.False(t, st.Hijack, "a connection reset is a dead link, never a TLS intercept")
	assert.True(t, titleKilled.Load(), "fixture sanity: title A was killed on the wire")
}

// TestUnlockTunnelAliveGateSkipsDeadBattery pins the alive gate (item 5):
// the OS connectivity-check endpoints are the battery's FIRST probe — a
// tunnel failing both (after the retry-once wrapper) is dead-now, the rest
// of the battery is skipped entirely (no media/echo requests), and the
// verdict is the honest all-unknown with a fresh stamp.
func TestUnlockTunnelAliveGateSkipsDeadBattery(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), deadAliveEndpoints(ud), cache)
	in.Sleep = func(context.Context, time.Duration) error { return nil }
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
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

// TestUnlockMigrationV1DefiniteStaleReprobed pins the battery_version
// migration: a fresh cached DEFINITE verdict stamped by battery v1 (the
// pre-hijack-detector era — possibly poisoned) is STALE under battery v2
// regardless of its age, gets re-probed exactly once, and the v2 verdict
// then serves its normal window (zero hits on the follow-up wave).
func TestUnlockMigrationV1DefiniteStaleReprobed(t *testing.T) {
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
	require.Equal(t, geo.UnlockBatteryVersion, records[0].MediaUnlocks.BatteryVersion)
	firstWave := ud.totalHits()
	require.Positive(t, firstWave)

	// Downgrade the cached verdict to battery v1 (fresh definite — exactly
	// the poisoned-chatgpt=yes shape the migration must not serve), in both
	// the hot cache and the cold geo-base half.
	downgradeToV1 := func() {
		path := filepath.Join(dir, "geo-base.jsonl")
		recs, rerr := store.ReadGeo(path)
		require.NoError(t, rerr)
		for _, r := range recs {
			r.MediaUnlocks.BatteryVersion = 1
		}
		require.NoError(t, store.WriteGeo(path, recs))
		e, ok := cache.Get("203.0.113.7")
		require.True(t, ok)
		require.NotNil(t, e.MediaUnlocks)
		e.MediaUnlocks.BatteryVersion = 1
	}
	downgradeToV1()
	ud.reset()
	_, _, err = geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, firstWave, ud.totalHits(),
		"a battery-v1 definite verdict is stale under v2 — the full battery re-ran (the migration sweep)")

	// The re-probe rewrote the verdict at the current battery version: the
	// next wave is a clean cache hit.
	ud.reset()
	_, _, err = geo.Run(context.Background(), in)
	require.NoError(t, err)
	assert.Zero(t, ud.totalHits(), "battery-v2 definite verdict = normal cache hit")
	records, _, err = geo.Run(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, geo.UnlockBatteryVersion, records[0].MediaUnlocks.BatteryVersion)
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
// tunnel; the parsed TXT IP lands as dns_ip evidence. A failing DNS
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
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	in := unlockInput(t, dir, f, api.URL(), ep, cache)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
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
	cache2 := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})
	in = unlockInput(t, dir, f, api.URL(), ep2, cache2)
	records, _, err = geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Empty(t, records[0].MediaUnlocks.DNSIP)
	assert.Equal(t, model.UnlockYes, records[0].MediaUnlocks.ChatGPT,
		"a failed DNS channel never degrades the verdict")
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
	f, _, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	// One hysteria2 node (the STUN rider) — the single-node shape keeps the
	// UDP relay state machine serial.
	h := model.NewNode("stunsrc", "hysteria2", "stun-cred", "stun.example.com", 443, nil)
	probes := map[string]store.ProbeResult{h.Key: liveProbe(h, "203.0.113.7")}
	in := baseInput(dir, []*model.Node{h}, probes, f, api.URL())
	on := true
	in.Cfg.UnlockProbes = &on
	in.UnlockEndpoints = ep
	in.ExitCache = cache

	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)
	st := records[0].MediaUnlocks
	assert.Equal(t, "198.51.100.99", st.StunIP,
		"the hysteria2 node's battery carries the STUN echo as stun_ip evidence")
	require.NotNil(t, fx.gotRequest(), "the Binding request rode the socks UDP path")
	require.Len(t, fx.gotRequest(), 20, "the Binding request is the 20-byte header shape")
	assert.Equal(t, geo.UnlockBatteryVersion, st.BatteryVersion)
	assert.Equal(t, model.UnlockYes, st.ChatGPT, "STUN is additive evidence, never a verdict gate")
}
