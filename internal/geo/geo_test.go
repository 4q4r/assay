package geo_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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

// ipAPIDouble is a test double for the ip-api single-IP endpoint. It serves
// the DOCUMENTED response shapes (see testdata/, pinned from
// http://ip-api.com/docs/api:json) and records the requests it saw: the
// self-report contract (GET, no ip parameter, configured UA) is asserted on
// the wire, not against a mock.
type ipAPIDouble struct {
	srv     *httptest.Server
	mu      sync.Mutex
	methods []string
	paths   []string
	uagents []string
	// failMode shapes the NO-PARAM (self-report) hop only; the
	// parameterized resolver lookup always serves the healthy body unless
	// blanket is set (the plain-HTTP-blocked exit class).
	failMode atomic.Int32 // 0 = serve, 1 = 503, 2 = reset, 3 = status-fail
	blanket  atomic.Bool
	body     []byte
}

func newIPAPIDouble(t *testing.T, body []byte) *ipAPIDouble {
	t.Helper()
	d := &ipAPIDouble{body: body}
	d.srv = httptest.NewServer(http.HandlerFunc(d.handle))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *ipAPIDouble) handle(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.methods = append(d.methods, r.Method)
	d.paths = append(d.paths, r.URL.Path)
	d.uagents = append(d.uagents, r.Header.Get("User-Agent"))
	d.mu.Unlock()

	noParam := r.URL.Path == "/json/" || r.URL.Path == "/json"
	// failMode shapes the self-report hop (no-param) — or everything when
	// blanket is set (the plain-HTTP-blocked exit class).
	if noParam || d.blanket.Load() {
		switch d.failMode.Load() {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		case 2:
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			_ = conn.Close() // reset: accept + close without any response
			return
		case 3:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"fail","message":"reserved range","query":"203.0.113.77"}`))
			return
		}
	}
	// The parameterized hop reports the queried IP in its query field.
	if !noParam {
		ip := strings.TrimPrefix(r.URL.Path, "/json/")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"success","country":"Netherlands","countryCode":"NL",`+
			`"city":"Amsterdam","isp":"LeaseWeb","as":"AS60781 LeaseWeb","asname":"LEASEWEB",`+
			`"proxy":false,"hosting":true,"query":%q}`, ip)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(d.body)
}

func (d *ipAPIDouble) saw() ([]string, []string, []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.methods...), append([]string(nil), d.paths...), append([]string(nil), d.uagents...)
}

func (d *ipAPIDouble) URL() string { return d.srv.URL }

// dohDouble answers the o-o.myaddr.l.google.com TXT probe with a fixed
// resolver IP (the dns.google/resolve JSON shape, Type 16 = TXT).
func dohDouble(t *testing.T, resolverIP string) *httptest.Server {
	t.Helper()
	ans := fmt.Sprintf(`{"Status":0,"Answer":[{"name":"o-o.myaddr.l.google.com.","type":16,"TTL":60,"data":%q}]}`,
		`"`+resolverIP+`"`)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(ans))
	}))
}

// node builds a filter-passing vless node (alive-probe eligible shape) on
// the canonical fixture host.
func node() *model.Node {
	return model.NewNode("s", "vless", "u-one", "one.example.com", 443, map[string]string{"security": "tls", "type": "tcp"})
}

// liveProbe is a probe result marking the node alive with the given exit IP.
func liveProbe(n *model.Node, exitIP string) store.ProbeResult {
	return store.ProbeResult{
		Key: n.Key, Host: n.Host, Alive: true, Status: "passed", ExitIP: exitIP,
		RTTMs: 42, CheckedAt: time.Now().UTC(),
	}
}

// deadUnlockEndpoints point every battery channel at a refused loopback
// port: the classification tests here pin the GEO LADDER (and the honest
// unknown battery verdict a dead battery stamps), never the battery
// internals — those live in unlock_test.go with their own doubles. STUN
// stays disabled (empty = channel off).
func deadUnlockEndpoints() *geo.UnlockEndpoints {
	d := "http://127.0.0.1:1"
	return &geo.UnlockEndpoints{
		ChatGPCTrace:      d,
		ChatGPTCompliance: d,
		NetflixTitleA:     d,
		NetflixTitleB:     d,
		YouTubePremium:    d,
		TikTokHome:        d,
		TikTokExplore:     d,
		DisneyDevices:     d,
		DisneyAuth:        d,
		DisneyGraphQL:     d,
		IPInfoWidget:      d,
		CFTrace:           d,
		EchoIPify:         d,
		EchoIPSB:          d,
		IPAPIContract:     d,
		AlivePrimary:      d,
		AliveFallback:     d,
		DNSServer:         "127.0.0.1:1",
		DNSName:           "o-o.myaddr.l.google.com",
	}
}

// classifyInput builds a ClassifyInput whose self-report rides the given
// endpoint double (the test seam replacing the production constant URL).
// The https hop keeps a dead-loopback [geo].https_url by default so every
// ladder test stays hermetic and rung 2 fails fast; tests exercising that
// rung override Cfg.HTTPSURL. The battery endpoints stay hermetic (dead
// loopback) unless the test overrides them.
func classifyInput(dir string, selfURL string) geo.ClassifyInput {
	return geo.ClassifyInput{
		DataDir: dir,
		Cfg: config.GeoConfig{
			Timeout:  config.Duration{Duration: 5 * time.Second},
			DoHURL:   "https://dns.google/resolve",
			HTTPSURL: "http://127.0.0.1:1/json", // dead loopback — overridden by https-hop tests
		},
		UserAgent:       "geo-agent/11",
		SelfURL:         selfURL,
		UnlockEndpoints: deadUnlockEndpoints(),
		Sleep:           func(context.Context, time.Duration) error { return nil },
	}
}

// classifyOne classifies ONE node through the given socks endpoint and
// flushes: the merged flow's exact path for a single-node wave (probe →
// hot-instance classification → flush). Returns the persisted records and
// the wave summary.
func classifyOne(
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

// TestSelfReportParsesDocumentedSingleIPShape pins the core of the redesign
// end to end: the node's HOT tunnel (the probe instance's socks endpoint —
// in tests the real in-process SOCKS5) carries a GET to the ip-api single-IP
// endpoint with NO ip parameter; the response is the documented SINGLE JSON
// OBJECT (the batch era answered with an ARRAY) and every consumed field
// maps into the geo record with self-report provenance.
func TestSelfReportParsesDocumentedSingleIPShape(t *testing.T) {
	body := documentedSingleSuccess(t)
	api := newIPAPIDouble(t, body)
	socks := newSocksServer(t)

	n := node()
	dir := t.TempDir()
	in := classifyInput(dir, api.URL()+"/json/")

	records, summary := classifyOne(t, dir, socks.Addr(), n, "203.0.113.77", in)
	require.Len(t, records, 1)
	rec := records[0]

	// Wire contract: GET, no ip parameter, the configured pipeline UA.
	methods, paths, uagents := api.saw()
	require.Len(t, methods, 1)
	assert.Equal(t, http.MethodGet, methods[0], "self-report is a GET (the batch era POSTed)")
	assert.True(t, strings.HasSuffix(paths[0], "/json/"),
		"no ip parameter: ip-api answers who is asking, got path %q", paths[0])
	assert.Equal(t, "geo-agent/11", uagents[0])
	assert.Positive(t, socks.Connects.Load(), "the classification rode the tunnel seam (the hot instance's socks endpoint)")

	// Field mapping from the documented shape.
	assert.Equal(t, "de", rec.Country, "country stored lowercase for tags")
	assert.Equal(t, "Frankfurt am Main", rec.City)
	assert.Equal(t, "AS51167", rec.ASN, "asn = the AS-number token of the composite as field")
	assert.Equal(t, "CONTABO", rec.ASName)
	assert.Equal(t, "Contabo GmbH", rec.ISP)
	assert.False(t, rec.ProxyFlag)
	assert.True(t, rec.HostingFlag)
	assert.Equal(t, "203.0.113.77", rec.IP, "the self-report's query IP is the freshest through-tunnel exit truth")
	assert.Equal(t, "self-report", rec.GeoSource, "provenance: evidence quality is visible in the cold base")

	// Summary classes.
	assert.Equal(t, 1, summary.Eligible)
	assert.Equal(t, 1, summary.SelfReport)
	assert.Equal(t, 0, summary.DoHFallback)
	assert.Equal(t, 0, summary.Unknown)

	// The record persisted with its provenance marker.
	persisted, err := store.ReadGeo(filepath.Join(dir, "geo-base.jsonl"))
	require.NoError(t, err)
	require.Len(t, persisted, 1)
	assert.Equal(t, "self-report", persisted[0].GeoSource)
}

// TestFallbackLookupStartIsPacedLikeSelfReport pins the politeness pacing
// across the FULL fallback chain with the injected clock: every external
// request start takes a pacer slot — the self-report, the https self-geo
// (W16 hop 2), the DoH TXT probe, AND the fallback resolver lookup. A node
// riding the whole fallback path must consume exactly three waited slots:
// the priming self-report slot sleeps nothing, and the three later starts
// (https, DoH, fallback lookup) each wait out the default pacing — a start
// that skipped the pacer would let the pass's bounded workers bypass the
// politeness contract exactly where the request mix is heaviest.
func TestFallbackLookupStartIsPacedLikeSelfReport(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	api.failMode.Store(1) // the self-report 503s; the fallback path runs
	doh := dohDouble(t, "198.51.100.9")
	socks := newSocksServer(t)

	n := node()
	dir := t.TempDir()
	in := classifyInput(dir, api.URL()+"/json/")
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
		"the pin is only meaningful when the fallback path actually ran")
	assert.Equal(t, 1, summary.DoHFallback)

	// The pass issued both ip-api requests (self-report + resolver lookup)
	// and paced the three later LADDER request starts: the https self-geo
	// (dead loopback — fails fast), the DoH probe, and the fallback lookup.
	// The priming self-report slot never sleeps. (Single node = one pacer;
	// the battery's own starts pace AFTER the ladder and are not this pin's
	// subject — the first three waits are exactly the ladder's.)
	require.GreaterOrEqual(t, len(waits), 3,
		"the https start, the DoH probe start, and the fallback lookup start must each be paced")
	assert.Equal(t, geo.DefaultSelfReportPacing, waits[0],
		"the https hop start waits out the default pacing")
	assert.Equal(t, geo.DefaultSelfReportPacing, waits[1],
		"the DoH probe start waits out the default pacing")
	assert.Equal(t, geo.DefaultSelfReportPacing, waits[2],
		"the fallback lookup start is paced like the self-report's slot")

	methods, paths, _ := api.saw()
	require.Len(t, methods, 2)
	assert.True(t, strings.HasSuffix(paths[1], "/json/198.51.100.9"),
		"the second ip-api request is the resolver lookup, got path %q", paths[1])
}

// TestSelfReportFailureClassesFallBackToDoH drives the fallback chain for
// every failure class the redesign names: transport reset, HTTP error, and
// ip-api status=fail. The DoH hop reveals the exit network's resolver IP
// (o-o.myaddr.l.google.com TXT through the tunnel), and the ip-api lookup of
// THAT IP rides the same tunnel — still a per-node source, so the aggregate
// limit stays gone on the fallback path too.
func TestSelfReportFailureClassesFallBackToDoH(t *testing.T) {
	for name, mode := range map[string]int32{
		"connection-reset":  2,
		"http-503":          1,
		"ipapi-status-fail": 3,
	} {
		t.Run(name, func(t *testing.T) {
			api := newIPAPIDouble(t, documentedSingleSuccess(t))
			api.failMode.Store(mode) // the no-param self-report hop fails; the resolver lookup is served
			doh := dohDouble(t, "198.51.100.9")
			socks := newSocksServer(t)

			n := node()
			dir := t.TempDir()
			in := classifyInput(dir, api.URL()+"/json/")
			in.Cfg.DoHURL = doh.URL

			records, summary := classifyOne(t, dir, socks.Addr(), n, "203.0.113.77", in)
			require.Len(t, records, 1)
			rec := records[0]
			assert.Equal(t, "doh-fallback", rec.GeoSource)
			assert.Equal(t, "nl", rec.Country)
			assert.Equal(t, "AS60781", rec.ASN)
			assert.Equal(t, "Amsterdam", rec.City)
			assert.Equal(t, "203.0.113.77", rec.IP,
				"fallback evidence describes the RESOLVER network — the record keeps the probe's exit IP")
			assert.Equal(t, 0, summary.SelfReport)
			assert.Equal(t, 1, summary.DoHFallback)
			assert.Equal(t, 0, summary.Unknown)
		})
	}
}

// TestPlainHTTPBlockedExitEndsUnknown pins the honest terminal class of the
// ladder when EVERY rung fails: an exit that blocks plain HTTP wholesale
// defeats the self-report and the fallback's ip-api lookup, and with the
// https rung unreachable too the node lands in the unknown class (the
// rescue-by-https path itself is pinned by
// TestHTTPSRescuesPlainHTTPBlockedExit).
func TestPlainHTTPBlockedExitEndsUnknown(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	api.failMode.Store(2) // reset — and blanket across ALL ip-api paths
	api.blanket.Store(true)
	doh := dohDouble(t, "198.51.100.9")
	socks := newSocksServer(t)

	n := node()
	dir := t.TempDir()
	in := classifyInput(dir, api.URL()+"/json/")
	in.Cfg.DoHURL = doh.URL
	var log strings.Builder
	in.Progress = &log

	records, summary := classifyOne(t, dir, socks.Addr(), n, "203.0.113.77", in)
	require.Len(t, records, 1)
	rec := records[0]
	assert.True(t, rec.Alive, "the node stays usable — missing geo never flips liveness")
	assert.Empty(t, rec.Country, "no geo evidence: fields stay empty for a node that never had any")
	assert.Empty(t, rec.GeoSource, "provenance empty = unknown")
	assert.Equal(t, "203.0.113.77", rec.IP, "the probe's exit IP remains the D8 anchor")
	assert.Equal(t, 1, summary.Unknown)
	assert.Contains(t, log.String(), "UNKNOWN geo", "the wave log names the class loudly")
}

// TestPreviousGeoSurvivesUnknownWave pins the evidence-preservation rule: a
// node with geo from a PREVIOUS wave whose current self-report fails keeps
// its previous geo fields and their provenance (the store blank-folds), so a
// transient failure never erases good evidence.
func TestPreviousGeoSurvivesUnknownWave(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	api.failMode.Store(2)
	api.blanket.Store(true)
	socks := newSocksServer(t)

	n := node()
	dir := t.TempDir()
	stale := "2026-10-20T00:00:00Z"
	prev := &model.GeoRecord{
		Source: n.Source, Scheme: n.Scheme, Host: n.Host, Port: n.Port,
		IP: "203.0.113.77", Country: "de", City: "Frankfurt am Main",
		ASN: "AS51167", ASName: "CONTABO", ISP: "Contabo GmbH",
		GeoSource: "self-report",
		FirstSeen: stale, LastSeen: stale, LastProbe: stale,
		RTTMs: 50, SpeedBPS: 1000, Alive: true,
	}
	require.NoError(t, store.UpsertGeo(filepath.Join(dir, "geo-base.jsonl"), []*model.GeoRecord{prev}))

	in := classifyInput(dir, api.URL()+"/json/")
	in.Cfg.DoHURL = "http://127.0.0.1:1/resolve" // dead DoH endpoint

	records, summary := classifyOne(t, dir, socks.Addr(), n, "203.0.113.77", in)
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, 1, summary.Unknown)
	assert.Equal(t, "de", rec.Country, "previous geo survives a fully-failed wave (store blank-fold)")
	assert.Equal(t, "self-report", rec.GeoSource, "provenance keeps pointing at the wave that produced the fields")
	assert.True(t, rec.Alive)
}

// TestExitIPChurnIsReportedLoudly pins the cross-check: when the self-report
// sees a DIFFERENT exit IP than the probe wave did (exit churn between the
// waves), the freshest through-tunnel truth wins the record and the wave log
// names the churn.
func TestExitIPChurnIsReportedLoudly(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t)) // fixture query = 203.0.113.77
	socks := newSocksServer(t)

	n := node()
	dir := t.TempDir()
	in := classifyInput(dir, api.URL()+"/json/")
	var log strings.Builder
	in.Progress = &log

	records, summary := classifyOne(t, dir, socks.Addr(), n, "198.51.100.1", in)
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, "203.0.113.77", rec.IP, "the self-report's query IP is the freshest exit truth")
	assert.Equal(t, 1, summary.Churn, "the churn is counted for the wave log")
	assert.Contains(t, log.String(), "exit-ip churn", "the wave log names the churn loudly")
}

// TestSameIdentityEachTunnelSelfReports — two distinct node keys sharing one
// cold-base identity (same server, different credentials) run their OWN
// classifications in the merged flow (per-wave per-alive-node; different
// credentials → different tunnels → possibly different exits); the flush
// applies them in the deterministic (identity, key) order, so the surviving
// record never depends on arrival order.
func TestSameIdentityEachTunnelSelfReports(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	socks := newSocksServer(t)

	na := model.NewNode("s", "vless", "uuid-a", "dupe.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	nb := model.NewNode("s", "vless", "uuid-b", "dupe.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	require.NotEqual(t, na.Key, nb.Key)
	dir := t.TempDir()
	in := classifyInput(dir, api.URL()+"/json/")

	clf := geo.NewClassifier(in)
	clf.ClassifyNode(context.Background(), na, socks.Addr(), "203.0.113.77")
	clf.ClassifyNode(context.Background(), nb, socks.Addr(), "203.0.113.78")
	probeByKey := map[string]store.ProbeResult{
		na.Key: liveProbe(na, "203.0.113.77"),
		nb.Key: liveProbe(nb, "203.0.113.78"),
	}
	_, _, err := clf.Flush(nil, []*model.Node{na, nb}, probeByKey, 1, time.Now())
	require.NoError(t, err)
	methods, _, _ := api.saw()
	assert.Len(t, methods, 2, "each node's tunnel self-reports its own exit (per-wave per-alive-node)")
	persisted, err := store.ReadGeo(filepath.Join(dir, "geo-base.jsonl"))
	require.NoError(t, err)
	require.Len(t, persisted, 1, "the store keeps one record per identity")
	assert.Equal(t, "self-report", persisted[0].GeoSource)
}

// TestTunnelClientProxyNilL5 pins the L5 guard on the PRODUCTION client
// builder: the transport's Proxy is hard nil — the owner's ambient
// http_proxy must never hijack a self-report through the live client — and a
// live ambient proxy demonstrably sees zero requests.
func TestTunnelClientProxyNilL5(t *testing.T) {
	proxySrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("ambient proxy saw a request — the L5 guard is broken")
	}))
	t.Cleanup(proxySrv.Close)

	cl, err := geo.NewTunnelClient("127.0.0.1:1", time.Second)
	require.NoError(t, err)
	transport, ok := cl.Transport.(*http.Transport)
	require.True(t, ok, "the production transport is the stdlib *http.Transport")
	assert.Nil(t, transport.Proxy, "Proxy must be hard nil — never ProxyFromEnvironment")
	req, rerr := http.NewRequestWithContext(context.Background(), http.MethodGet, proxySrv.URL, nil)
	require.NoError(t, rerr)
	resp, derr := cl.Do(req) // refused socks dial; the proxy must stay silent
	if derr == nil && resp != nil {
		_ = resp.Body.Close()
	}
}

// TestClassifyPerWaveFreshnessGateGone pins THE merged-flow contract the
// owner ordered («сразу на чеке»): a node classified in wave N is
// RE-classified in wave N+1 — per-wave per-alive-node, no 24h freshness
// gate, no exit-IP cache. Each wave's classification fires its own ip-api
// self-report (two waves → two self-reports) and each flush refreshes the
// geo-base record. (RED-proven against the old flow: the 24h gate served
// wave 2 from the exit cache and ip-api saw one request total.)
func TestClassifyPerWaveFreshnessGateGone(t *testing.T) {
	dir := t.TempDir()
	body := documentedSingleSuccess(t)
	d := newIPAPIDouble(t, body)
	socks := newSocksServer(t)

	n1 := node()
	in := classifyInput(dir, d.URL()+"/json/")
	for range 2 { // two consecutive waves, same node alive both times
		clf := geo.NewClassifier(in)
		clf.ClassifyNode(context.Background(), n1, socks.Addr(), "203.0.113.9")
		probeByKey := map[string]store.ProbeResult{n1.Key: liveProbe(n1, "203.0.113.9")}
		_, _, err := clf.Flush(nil, []*model.Node{n1}, probeByKey, 1, time.Now())
		require.NoError(t, err)
	}
	_, paths, _ := d.saw()
	selfReports := 0
	for _, p := range paths {
		if p == "/json/" || p == "/json" {
			selfReports++
		}
	}
	assert.Equal(t, 2, selfReports,
		"per-wave classification: both waves self-report (the 24h freshness gate is removed)")
}

// TestClassifyDeadTunnelHonestUnknown pins the merged flow's honest-failure
// contract: a node whose tunnel DIES between the probe pass and the battery
// (here: the battery's alive gate against a dead loopback) records an
// honest all-unknown verdict stamped CheckedAt, the geo record survives with
// its previous fields, the wave does NOT fail, and the next wave
// re-classifies (per-wave semantics — no cache would hide the failure).
func TestClassifyDeadTunnelHonestUnknown(t *testing.T) {
	dir := t.TempDir()
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	n := node()
	stale := "2026-10-20T00:00:00Z"
	prev := &model.GeoRecord{
		Source: n.Source, Scheme: n.Scheme, Host: n.Host, Port: n.Port,
		IP: "203.0.113.77", Country: "de",
		GeoSource: "self-report",
		FirstSeen: stale, LastSeen: stale, LastProbe: stale, Alive: true,
	}
	require.NoError(t, store.UpsertGeo(filepath.Join(dir, "geo-base.jsonl"), []*model.GeoRecord{prev}))

	in := classifyInput(dir, api.URL()+"/json/")
	clf := geo.NewClassifier(in)
	// The battery's tunnel-alive gate rides the DEAD loopback endpoints (the
	// classifyInput default) — the mid-battery tunnel-death shape.
	clf.ClassifyNode(context.Background(), n, "127.0.0.1:1", "203.0.113.77")
	probeByKey := map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.77")}
	var log strings.Builder
	records, summary, err := clf.Flush(&log, []*model.Node{n}, probeByKey, 1, time.Now())
	require.NoError(t, err, "a dead battery is an honest outcome, never a wave failure")
	require.Len(t, records, 1)
	rec := records[0]
	assert.True(t, rec.Alive, "the node stays usable")
	assert.Equal(t, "de", rec.Country, "previous geo survives")
	require.NotNil(t, rec.MediaUnlocks)
	assert.Equal(t, "unknown", rec.MediaUnlocks.ChatGPT, "the dead battery stamps honest unknowns")
	assert.NotEmpty(t, rec.MediaUnlocks.CheckedAt, "the verdict is stamped checked (this wave's truth)")
	assert.Equal(t, 1, summary.Unknown, "the ladder also ended unknown for the dead tunnel")
	assert.Contains(t, log.String(), "classify complete", "the wave-level classification summary line is present")
}

// TestFlushSummariesCarryWaveLines pins the wave-duration visibility: the
// flush prints the wave-level classification summary (count + duration) —
// the journal's consolidated replacement for the old separate geo stage
// lines.
func TestFlushSummariesCarryWaveLines(t *testing.T) {
	dir := t.TempDir()
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	socks := newSocksServer(t)
	n := node()
	in := classifyInput(dir, api.URL()+"/json/")
	var log strings.Builder
	in.Progress = &log

	clf := geo.NewClassifier(in)
	clf.ClassifyNode(context.Background(), n, socks.Addr(), "203.0.113.77")
	probeByKey := map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.77")}
	_, _, err := clf.Flush(&log, []*model.Node{n}, probeByKey, 1, time.Now())
	require.NoError(t, err)
	out := log.String()
	assert.Contains(t, out, "classify complete: 1 alive classified in", "the summary names the count and the duration")
	assert.Contains(t, out, "geo store:", "the store line keeps the wave-duration visibility contract")
}

// documentedSingleSuccess is the FULL documented default field set of the
// ip-api single-IP endpoint (testdata fixture pinned from the primary docs).
func documentedSingleSuccess(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "ip-api-single-success.json"))
	require.NoError(t, err)
	return b
}
