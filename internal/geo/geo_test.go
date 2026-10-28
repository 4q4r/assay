package geo_test

import (
	"context"
	"fmt"
	"io"
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

// documentedSingleSuccess is the FULL documented default field set of the
// ip-api single-IP endpoint (testdata fixture pinned from the primary docs).
func documentedSingleSuccess(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "ip-api-single-success.json"))
	require.NoError(t, err)
	return b
}

// fakeInstance is the Factory seam's product: a SocksInstance whose Addr is a
// real in-process SOCKS5 server relaying to the test doubles. Close counts —
// the piggyback pin asserts exactly one Close per node.
type fakeInstance struct {
	addr   string
	closed *atomic.Int32
}

func (f fakeInstance) Addr() string { return f.addr }
func (f fakeInstance) Close() error {
	f.closed.Add(1)
	return nil
}

// newTestFactory returns a Factory spawning one fake instance backed by the
// given socks server, plus the spawn counter (the piggyback pin).
func newTestFactory(socks *socksServer) (geo.Factory, *atomic.Int32, *atomic.Int32) {
	var spawns, closes atomic.Int32
	f := func(context.Context, *model.Node) (geo.SocksInstance, error) {
		spawns.Add(1)
		return fakeInstance{addr: socks.Addr(), closed: &closes}, nil
	}
	return f, &spawns, &closes
}

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

// node builds a filter-passing vless node (alive-probe eligible shape).
func node(id, host string) *model.Node {
	return model.NewNode("s", "vless", "u-"+id, host, 443, map[string]string{"security": "tls", "type": "tcp"})
}

// liveProbe is a probe result marking the node alive with the given exit IP.
func liveProbe(n *model.Node, exitIP string) store.ProbeResult {
	return store.ProbeResult{
		Key: n.Key, Host: n.Host, Alive: true, Status: "passed", ExitIP: exitIP,
		RTTMs: 42, CheckedAt: time.Now().UTC(),
	}
}

// baseInput builds a valid geo Input whose self-report rides the given
// endpoint double (the test seam replacing the production constant URL).
func baseInput(dir string, nodes []*model.Node, probes map[string]store.ProbeResult, f geo.Factory, selfURL string) geo.Input {
	return geo.Input{
		DataDir:    dir,
		Nodes:      nodes,
		ProbeByKey: probes,
		Cfg: config.GeoConfig{
			TTL:     config.Duration{Duration: 24 * time.Hour},
			Timeout: config.Duration{Duration: 5 * time.Second},
			DoHURL:  "https://dns.google/resolve",
		},
		UserAgent: "geo-agent/11",
		Factory:   f,
		SelfURL:   selfURL,
		Sleep:     func(context.Context, time.Duration) error { return nil },
	}
}

// TestSelfReportParsesDocumentedSingleIPShape pins the core of the redesign
// end to end: the node's tunnel (real in-process SOCKS5) carries a GET to the
// ip-api single-IP endpoint with NO ip parameter; the response is the
// documented SINGLE JSON OBJECT (the batch era answered with an ARRAY) and
// every consumed field maps into the geo record with self-report provenance.
func TestSelfReportParsesDocumentedSingleIPShape(t *testing.T) {
	body := documentedSingleSuccess(t)
	api := newIPAPIDouble(t, body)
	socks := newSocksServer(t)
	f, spawns, closes := newTestFactory(socks)

	n := node("1", "one.example.com")
	dir := t.TempDir()
	in := baseInput(dir, []*model.Node{n},
		map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.77")}, f, api.URL()+"/json/")

	records, summary, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)
	rec := records[0]

	// Wire contract: GET, no ip parameter, the configured pipeline UA.
	methods, paths, uagents := api.saw()
	require.Len(t, methods, 1)
	assert.Equal(t, http.MethodGet, methods[0], "self-report is a GET (the batch era POSTed)")
	assert.True(t, strings.HasSuffix(paths[0], "/json/"),
		"no ip parameter: ip-api answers who is asking, got path %q", paths[0])
	assert.Equal(t, "geo-agent/11", uagents[0])
	assert.Equal(t, int32(1), socks.Connects.Load(), "exactly one tunnel request rides the instance")
	assert.Equal(t, int32(1), spawns.Load(), "piggyback: ONE instance per node, no second spawn")
	assert.Equal(t, int32(1), closes.Load(), "the instance is closed exactly once")

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
// request start takes a pacer slot — the self-report, the DoH TXT probe, AND
// the fallback resolver lookup. A node riding the whole fallback path must
// consume exactly three slots: the priming self-report slot sleeps nothing,
// and both later starts (DoH, fallback lookup) each wait out the default
// pacing — a lookup whose start slips past the pacer would let the wave's
// bounded workers bypass the politeness contract exactly where the request
// mix is heaviest.
func TestFallbackLookupStartIsPacedLikeSelfReport(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	api.failMode.Store(1) // the self-report 503s; the fallback path runs
	doh := dohDouble(t, "198.51.100.9")
	socks := newSocksServer(t)
	f, _, _ := newTestFactory(socks)

	n := node("1", "one.example.com")
	dir := t.TempDir()
	in := baseInput(dir, []*model.Node{n},
		map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.77")}, f, api.URL()+"/json/")
	in.Cfg.DoHURL = doh.URL
	now := time.Unix(1700000000, 0)
	in.Now = func() time.Time { return now }
	var waits []time.Duration
	in.Sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		now = now.Add(d) // the fake clock advances by exactly the slept amount
		return nil
	}

	records, summary, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, "doh-fallback", records[0].GeoSource,
		"the pin is only meaningful when the fallback path actually ran")
	assert.Equal(t, 1, summary.DoHFallback)

	// The wave issued both ip-api requests (self-report + resolver lookup)
	// and paced the two later request starts: the DoH probe AND the fallback
	// lookup. The priming self-report slot never sleeps. (Single node = one
	// worker: the pacer, the sleeper, and this slice are one goroutine.)
	require.Len(t, waits, 2,
		"both the DoH probe start and the fallback lookup start must be paced")
	assert.Equal(t, geo.DefaultSelfReportPacing, waits[0],
		"the DoH probe start waits out the default pacing")
	assert.Equal(t, geo.DefaultSelfReportPacing, waits[1],
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
			f, spawns, _ := newTestFactory(socks)

			n := node("1", "one.example.com")
			dir := t.TempDir()
			in := baseInput(dir, []*model.Node{n},
				map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.77")}, f, api.URL()+"/json/")
			in.Cfg.DoHURL = doh.URL

			records, summary, err := geo.Run(context.Background(), in)
			require.NoError(t, err)
			require.Len(t, records, 1)
			rec := records[0]
			assert.Equal(t, "doh-fallback", rec.GeoSource)
			assert.Equal(t, "nl", rec.Country)
			assert.Equal(t, "AS60781", rec.ASN)
			assert.Equal(t, "Amsterdam", rec.City)
			assert.Equal(t, "203.0.113.77", rec.IP,
				"fallback evidence describes the RESOLVER network — the record keeps the probe's exit IP")
			assert.Equal(t, int32(1), spawns.Load(), "piggyback: the fallback reuses the SAME instance")
			assert.Equal(t, 0, summary.SelfReport)
			assert.Equal(t, 1, summary.DoHFallback)
			assert.Equal(t, 0, summary.Unknown)
		})
	}
}

// TestPlainHTTPBlockedExitEndsUnknown pins the honest terminal class of the
// fallback: an exit that blocks plain HTTP wholesale defeats BOTH the
// self-report and the fallback's ip-api lookup — the node lands in the
// unknown class (documented limitation; DoH-over-HTTPS itself still works,
// so a future pure-HTTPS geo fallback could rescue this class).
func TestPlainHTTPBlockedExitEndsUnknown(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	api.failMode.Store(2) // reset — and blanket across ALL ip-api paths
	api.blanket.Store(true)
	doh := dohDouble(t, "198.51.100.9")
	socks := newSocksServer(t)
	f, _, _ := newTestFactory(socks)

	n := node("1", "one.example.com")
	dir := t.TempDir()
	in := baseInput(dir, []*model.Node{n},
		map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.77")}, f, api.URL()+"/json/")
	in.Cfg.DoHURL = doh.URL
	var log strings.Builder
	in.Progress = &log

	records, summary, err := geo.Run(context.Background(), in)
	require.NoError(t, err, "unknown geo is a classified outcome, not a wave failure")
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
	f, _, _ := newTestFactory(socks)

	n := node("1", "one.example.com")
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

	in := baseInput(dir, []*model.Node{n},
		map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.77")}, f, api.URL()+"/json/")
	in.Cfg.DoHURL = "http://127.0.0.1:1/resolve" // dead DoH endpoint

	records, summary, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
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
	f, _, _ := newTestFactory(socks)

	n := node("1", "one.example.com")
	dir := t.TempDir()
	in := baseInput(dir, []*model.Node{n},
		map[string]store.ProbeResult{n.Key: liveProbe(n, "198.51.100.1")}, f, api.URL()+"/json/")
	var log strings.Builder
	in.Progress = &log

	records, summary, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, "203.0.113.77", rec.IP, "the self-report's query IP is the freshest exit truth")
	assert.Equal(t, 1, summary.Churn, "the churn is counted for the wave log")
	assert.Contains(t, log.String(), "exit-ip churn", "the wave log names the churn loudly")
}

// TestDeadNodeNeverGetsAnInstance pins the eligibility gate: nodes whose
// latest probe outcome is dead (or lacks an exit IP) spawn NO temp instance —
// the self-report rides ALIVE tunnels only.
func TestDeadNodeNeverGetsAnInstance(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	socks := newSocksServer(t)
	f, spawns, _ := newTestFactory(socks)

	alive := node("a", "alive.example.com")
	dead := node("d", "dead.example.com")
	noExit := node("e", "noexit.example.com")
	dir := t.TempDir()
	in := baseInput(dir, []*model.Node{alive, dead, noExit}, map[string]store.ProbeResult{
		alive.Key:  liveProbe(alive, "203.0.113.77"),
		dead.Key:   {Key: dead.Key, Host: dead.Host, Alive: false, CheckedAt: time.Now().UTC()},
		noExit.Key: {Key: noExit.Key, Host: noExit.Host, Alive: true, CheckedAt: time.Now().UTC()},
	}, f, api.URL()+"/json/")

	records, summary, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 3)
	assert.Equal(t, int32(1), spawns.Load(), "only the alive node with an exit IP spawns an instance")
	assert.Equal(t, 1, summary.Eligible)
	assert.Equal(t, 1, summary.SelfReport)
	for _, rec := range records {
		switch rec.Host {
		case "dead.example.com":
			assert.False(t, rec.Alive, "dead node keeps its record with alive=false")
			assert.Empty(t, rec.GeoSource)
		case "noexit.example.com":
			assert.True(t, rec.Alive, "alive without exit IP stays alive — geo just has no evidence")
			assert.Empty(t, rec.Country)
		}
	}
}

// TestSameIdentityEachTunnelSelfReports — two distinct node keys sharing one
// cold-base identity (same server, different credentials) run their OWN
// self-reports (different credentials → different tunnels → possibly
// different exits); the merge applies them in the deterministic (identity,
// key) order, so the surviving record never depends on arrival order.
func TestSameIdentityEachTunnelSelfReports(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	socks := newSocksServer(t)
	f, spawns, _ := newTestFactory(socks)

	na := model.NewNode("s", "vless", "uuid-a", "dupe.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	nb := model.NewNode("s", "vless", "uuid-b", "dupe.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})
	require.NotEqual(t, na.Key, nb.Key)
	dir := t.TempDir()
	in := baseInput(dir, []*model.Node{na, nb}, map[string]store.ProbeResult{
		na.Key: liveProbe(na, "203.0.113.77"),
		nb.Key: liveProbe(nb, "203.0.113.77"),
	}, f, api.URL()+"/json/")

	_, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, int32(2), spawns.Load(), "each node's tunnel self-reports its own exit")
	persisted, err := store.ReadGeo(filepath.Join(dir, "geo-base.jsonl"))
	require.NoError(t, err)
	require.Len(t, persisted, 1, "the store keeps one record per identity")
	assert.Equal(t, "self-report", persisted[0].GeoSource)
}

// TestRunRequiresFactory pins the loud wiring contract: the geo wave without
// the temp-instance factory is a configuration error, never a silent no-op.
func TestRunRequiresFactory(t *testing.T) {
	n := node("1", "one.example.com")
	in := baseInput(t.TempDir(), []*model.Node{n},
		map[string]store.ProbeResult{n.Key: liveProbe(n, "203.0.113.77")}, nil, "http://127.0.0.1:1/json/")
	in.Factory = nil
	_, _, err := geo.Run(context.Background(), in)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "factory")
}

// TestTunnelClientProxyNilL5 pins the L5 guard on the PRODUCTION client
// builder: the transport's Proxy is hard nil — the owner's ambient
// http_proxy must never hijack a self-report through the live client — and a
// live ambient proxy demonstrably sees zero requests.
func TestTunnelClientProxyNilL5(t *testing.T) {
	cl, err := geo.NewTunnelClient("127.0.0.1:59999", 5*time.Second)
	require.NoError(t, err)
	require.NotNil(t, cl)
	tp, ok := cl.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tp.Proxy, "L5: the tunnel client must never consult the environment proxy")

	// Behavioral proof: an ambient proxy recorder sees NOTHING while the
	// request lands on the real target through the tunnel.
	var proxyHits atomic.Int32
	proxySrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		proxyHits.Add(1)
	}))
	t.Cleanup(proxySrv.Close)
	t.Setenv("http_proxy", proxySrv.URL)
	t.Setenv("HTTP_PROXY", proxySrv.URL)

	body := documentedSingleSuccess(t)
	api := newIPAPIDouble(t, body)
	socks := newSocksServer(t)
	cl, err = geo.NewTunnelClient(socks.Addr(), 5*time.Second)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, api.URL()+"/json/", nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "ua/1")
	resp, err := cl.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.JSONEq(t, string(body), string(got))
	assert.Equal(t, int32(0), proxyHits.Load(), "L5: zero requests may touch the ambient proxy")
}
