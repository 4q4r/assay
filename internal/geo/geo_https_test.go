package geo_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
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

// infoDouble is a test double for the hop-2 HTTPS self-geo endpoint
// ([geo].https_url, default https://ipinfo.io/json). It serves the
// LIVE-VERIFIED free-tier shape (testdata/ipinfo-json-success.json: the
// ip/city/region/country/loc/org/postal/timezone/readme field set captured
// from https://ipinfo.io/json on 2026-10-29 — the free tier carries NO
// proxy/hosting flags and NO separate ISP field) and records the requests it
// saw: the wire contract (GET, configured UA) is asserted on the wire.
type infoDouble struct {
	srv     *httptest.Server
	mu      sync.Mutex
	methods []string
	paths   []string
	uagents []string
	status  atomic.Int32 // 0 = serve 200; 1 = 503
	body    []byte
}

func newInfoDouble(t *testing.T, body []byte) *infoDouble {
	t.Helper()
	d := &infoDouble{body: body}
	d.srv = httptest.NewServer(http.HandlerFunc(d.handle))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *infoDouble) handle(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.methods = append(d.methods, r.Method)
	d.paths = append(d.paths, r.URL.Path)
	d.uagents = append(d.uagents, r.Header.Get("User-Agent"))
	d.mu.Unlock()
	if d.status.Load() == 1 {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(d.body)
}

func (d *infoDouble) saw() ([]string, []string, []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.methods...), append([]string(nil), d.paths...), append([]string(nil), d.uagents...)
}

func (d *infoDouble) URL() string { return d.srv.URL }

// documentedInfoSuccess is the full documented free-tier /json shape.
func documentedInfoSuccess(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "ipinfo-json-success.json"))
	require.NoError(t, err)
	return b
}

// TestHTTPSSelfGeoSecondHopMapsFieldsHonestly pins the new rung of the W16
// failure ladder: hop 1 (plain-HTTP ip-api self-report) fails → hop 2 asks
// [geo].https_url (default ipinfo.io/json) through the SAME tunnel instance.
// The field mapping is HONEST about what the free tier provides: country,
// city, and the composite org (split into as + asname) map 1:1, while ISP and
// the proxy/hosting flags — fields ipinfo's free tier does not carry — are
// written EMPTY, with the self-report-https provenance marker naming the
// evidence class next to them.
func TestHTTPSSelfGeoSecondHopMapsFieldsHonestly(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	api.failMode.Store(1) // hop 1: 503 — the ladder advances
	info := newInfoDouble(t, documentedInfoSuccess(t))
	doh := dohDouble(t, "198.51.100.9") // served but MUST NOT be consulted
	socks := newSocksServer(t)

	n := node()
	dir := t.TempDir()
	in := classifyInput(dir, api.URL()+"/json/")
	in.Cfg.HTTPSURL = info.URL() + "/json"
	in.Cfg.DoHURL = doh.URL

	records, summary := classifyOne(t, dir, socks.Addr(), n, "203.0.113.77", in)
	require.Len(t, records, 1)
	rec := records[0]

	// Field mapping from the documented ipinfo shape — the honest subset.
	assert.Equal(t, "de", rec.Country, "country stored lowercase for tags (ipinfo country is ISO alpha-2)")
	assert.Equal(t, "Frankfurt am Main", rec.City)
	assert.Equal(t, "AS51167", rec.ASN, "asn = the org field's leading AS-number token")
	assert.Equal(t, "Contabo GmbH", rec.ASName, "asname = the org remainder (ipinfo has no separate asname)")
	assert.Empty(t, rec.ISP, "ipinfo free tier has no separate ISP field — written empty, not invented")
	assert.False(t, rec.ProxyFlag, "proxy/hosting flags are ip-api-only; empty on this hop")
	assert.False(t, rec.HostingFlag, "proxy/hosting flags are ip-api-only; empty on this hop")
	assert.Equal(t, "203.0.113.77", rec.IP, "the https self-report's ip is the freshest through-tunnel exit truth")
	assert.Equal(t, "self-report-https", rec.GeoSource, "provenance names the evidence class")
	assert.True(t, rec.Alive)

	// Wire contract: ONE GET to the configured endpoint with the pipeline UA.
	methods, paths, uagents := info.saw()
	require.Len(t, methods, 1, "exactly one https request for one node")
	assert.Equal(t, http.MethodGet, methods[0])
	assert.True(t, strings.HasSuffix(paths[0], "/json"), "the configured endpoint path is honored, got %q", paths[0])
	assert.Equal(t, "geo-agent/11", uagents[0])

	// L5 tunnel-path: the hop rode the SAME hot tunnel (2 CONNECT relays:
	// hop 1 + hop 2; keep-alives are off so each request dials), and the
	// DoH fallback was never consulted.
	assert.Equal(t, int32(2), socks.Connects.Load(), "hop 2 rides the same tunnel: two CONNECT relays total")

	// Ladder classes.
	assert.Equal(t, 1, summary.Eligible)
	assert.Equal(t, 0, summary.SelfReport)
	assert.Equal(t, 1, summary.SelfReportHTTPS)
	assert.Equal(t, 0, summary.DoHFallback)
	assert.Equal(t, 0, summary.Unknown)

	// The record persisted with its provenance marker.
	persisted, err := store.ReadGeo(filepath.Join(dir, "geo-base.jsonl"))
	require.NoError(t, err)
	require.Len(t, persisted, 1)
	assert.Equal(t, "self-report-https", persisted[0].GeoSource)
}

// TestHTTPSRescuesPlainHTTPBlockedExit pins the W16 motivation: an exit that
// blocks plain HTTP wholesale (the class W11 landed in unknown with only the
// resolver-network DoH view available) is now rescued by hop 2 — the HTTPS
// self-geo does not depend on plain HTTP at all.
func TestHTTPSRescuesPlainHTTPBlockedExit(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	api.failMode.Store(2) // connection reset...
	api.blanket.Store(true)
	info := newInfoDouble(t, documentedInfoSuccess(t))
	socks := newSocksServer(t)

	n := node()
	dir := t.TempDir()
	in := classifyInput(dir, api.URL()+"/json/")
	in.Cfg.HTTPSURL = info.URL() + "/json"
	in.Cfg.DoHURL = "http://127.0.0.1:1/resolve" // dead DoH: hop 3 must stay unreached

	records, summary := classifyOne(t, dir, socks.Addr(), n, "203.0.113.77", in)
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, "self-report-https", rec.GeoSource, "the plain-HTTP-blocked class is rescued by the https hop")
	assert.Equal(t, "de", rec.Country)
	assert.Equal(t, "203.0.113.77", rec.IP)
	assert.Equal(t, 1, summary.SelfReportHTTPS)
	assert.Equal(t, 0, summary.Unknown)
}

// TestHTTPSRunsBeforeDoHAndEveryStartIsPaced pins the ladder ORDER and the
// politeness contract with the injected clock: hop 2's request start is a
// paced slot like every other external request of the wave. A node riding
// the FULL ladder (hop 1 fails → hop 2 fails → DoH view) consumes exactly
// three waited slots — https start, DoH probe start, fallback lookup start —
// and the DoH hop only runs AFTER the https hop failed.
func TestHTTPSRunsBeforeDoHAndEveryStartIsPaced(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	api.failMode.Store(1) // hop 1: 503
	info := newInfoDouble(t, documentedInfoSuccess(t))
	info.status.Store(1) // hop 2: 503 — the ladder advances to DoH
	doh := dohDouble(t, "198.51.100.7")
	socks := newSocksServer(t)

	n := node()
	dir := t.TempDir()
	in := classifyInput(dir, api.URL()+"/json/")
	in.Cfg.HTTPSURL = info.URL() + "/json"
	in.Cfg.DoHURL = doh.URL
	now := time.Unix(1700000000, 0)
	in.Now = func() time.Time { return now }
	var waits []time.Duration
	in.Sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		now = now.Add(d) // the fake clock advances by exactly the slept amount
		return nil
	}

	clf := geo.NewClassifier(in)
	clf.ClassifyNode(context.Background(), n, socks.Addr(), "203.0.113.77")
	probeByKey := map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.77")}
	records, summary, err := clf.Flush(nil, []*model.Node{n}, probeByKey, 1, time.Now())
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, "doh-fallback", records[0].GeoSource,
		"the pin is only meaningful when the ladder actually reached the DoH hop")
	assert.Equal(t, 1, summary.DoHFallback)
	assert.Equal(t, 0, summary.SelfReportHTTPS)

	// Three paced LADDER starts: the https self-geo, the DoH probe, and the
	// fallback lookup. The priming hop-1 slot never sleeps. (Single node =
	// one pacer; the battery's own starts pace after the ladder — the first
	// three waits are exactly the ladder's.)
	require.GreaterOrEqual(t, len(waits), 3, "https start, DoH probe start, and fallback lookup start are each paced")
	assert.Equal(t, geo.DefaultSelfReportPacing, waits[0], "the https hop start waits out the default pacing")
	assert.Equal(t, geo.DefaultSelfReportPacing, waits[1], "the DoH probe start is paced")
	assert.Equal(t, geo.DefaultSelfReportPacing, waits[2], "the fallback lookup start is paced")

	// Order: the https hop ran (and failed) BEFORE the DoH probe fired.
	imethods, _, _ := info.saw()
	require.Len(t, imethods, 1, "the https hop fired exactly once before the DoH fallback")
	methods, paths, _ := api.saw()
	require.Len(t, methods, 2, "hop 1 + the resolver lookup ride the ip-api double")
	assert.True(t, strings.HasSuffix(paths[1], "/json/198.51.100.7"),
		"the second ip-api request is the DoH-fallback resolver lookup, got %q", paths[1])
}

// TestHTTPSSelfGeoChurnIsReportedLoudly pins the churn cross-check on hop 2:
// the https self-report is a SELF-report (the answer's ip IS the exit), so a
// different IP than the probe wave's anchor wins the record as the freshest
// tunnel truth and the wave log names the churn — same semantics as hop 1.
func TestHTTPSSelfGeoChurnIsReportedLoudly(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	api.failMode.Store(1)
	body := strings.ReplaceAll(string(documentedInfoSuccess(t)), "203.0.113.77", "198.51.100.9")
	info := newInfoDouble(t, []byte(body))
	socks := newSocksServer(t)

	n := node()
	dir := t.TempDir()
	in := classifyInput(dir, api.URL()+"/json/")
	in.Cfg.HTTPSURL = info.URL() + "/json"
	var log strings.Builder
	in.Progress = &log

	records, summary := classifyOne(t, dir, socks.Addr(), n, "203.0.113.77", in)
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, "198.51.100.9", rec.IP, "the https self-report's ip is the freshest exit truth")
	assert.Equal(t, 1, summary.Churn, "the churn is counted for the wave log")
	assert.Contains(t, log.String(), "exit-ip churn", "the wave log names the churn loudly")
}

// TestLadderEndsUnknownWhenEveryHopFails pins the honest terminal class of
// the four-rung ladder: hop 1 fails, the https hop is unreachable, and the
// DoH fallback is dead — the node stays usable with its geo fields
// untouched and the unknown class reported loud.
func TestLadderEndsUnknownWhenEveryHopFails(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	api.failMode.Store(1)
	socks := newSocksServer(t)

	n := node()
	dir := t.TempDir()
	in := classifyInput(dir, api.URL()+"/json/")
	// Cfg.HTTPSURL and Cfg.DoHURL keep classifyInput's dead-loopback defaults.
	in.Cfg.DoHURL = "http://127.0.0.1:1/resolve"
	var log strings.Builder
	in.Progress = &log

	records, summary := classifyOne(t, dir, socks.Addr(), n, "203.0.113.77", in)
	require.Len(t, records, 1)
	rec := records[0]
	assert.True(t, rec.Alive, "the node stays usable — missing geo never flips liveness")
	assert.Empty(t, rec.Country)
	assert.Empty(t, rec.GeoSource, "provenance empty = unknown")
	assert.Equal(t, "203.0.113.77", rec.IP, "the probe's exit IP remains the D8 anchor")
	assert.Equal(t, 1, summary.Unknown)
	assert.Contains(t, log.String(), "UNKNOWN geo", "the wave log names the class loudly")
	assert.Contains(t, log.String(), "(one.example.com)", "the wave log attributes the failure to the node")
}
