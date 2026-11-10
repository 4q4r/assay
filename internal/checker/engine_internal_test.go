package checker

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"assay/internal/model"
	"assay/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeInstance wraps a test SOCKS5 server address as a checker instance.
type fakeInstance struct{ addr string }

func (f fakeInstance) Addr() string { return f.addr }
func (f fakeInstance) Close() error { return nil }

// engineFixture builds the full environment: an httptest site, a DoH
// endpoint, a geo base with the given nodes, and a fake instance factory
// routing through the test SOCKS5 server (which forwards every hostname to
// the site listener — exactly the exit-side behavior under test).
type engineFixture struct {
	site    *httptest.Server
	doh     *httptest.Server
	socks   *socksServer
	cfgDir  string
	factory InstanceFactory
}

func newEngineFixture(t *testing.T, site http.HandlerFunc, geoRecords []*model.GeoRecord, nodes []*model.Node) *engineFixture {
	t.Helper()
	f := &engineFixture{}
	f.site = httptest.NewServer(site)
	t.Cleanup(f.site.Close)
	f.doh = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") == "blocked.example" {
			_, _ = w.Write([]byte(`{"Answer":[{"name":"blocked.example","type":1,"TTL":300,"data":"10.9.9.9"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"Answer":[{"name":"site.example","type":1,"TTL":300,"data":"10.1.2.3"},{"name":"site.example","type":28,"TTL":300,"data":"fd00::1"}]}`))
	}))
	t.Cleanup(f.doh.Close)
	siteAddr := strings.TrimPrefix(f.site.URL, "http://")
	f.socks = newSocksServerForward(t, siteAddr)
	if u, err := url.Parse(f.doh.URL); err == nil {
		f.socks.routes[u.Host] = strings.TrimPrefix(f.doh.URL, "http://") // DoH reachable through the tunnel
	}

	f.cfgDir = t.TempDir()
	require.NoError(t, store.WriteGeo(filepath.Join(f.cfgDir, "geo-base.jsonl"), geoRecords))
	require.NoError(t, store.WriteNodes(filepath.Join(f.cfgDir, "filtered.jsonl"), nodes))

	f.factory = func(_ context.Context, _ *model.Node) (SocksInstance, error) {
		return fakeInstance{addr: f.socks.addr()}, nil
	}
	return f
}

// httpTarget renders an http:// target whose HOST is a fake name (never
// resolvable — the socks5h remote-DNS pin) and whose PORT is the site's.
func (f *engineFixture) httpTarget() string {
	u, err := url.Parse(f.site.URL)
	if err != nil {
		panic(err)
	}
	_, port, _ := net.SplitHostPort(u.Host)
	return "http://site.example:" + port
}

func (f *engineFixture) opts(targets ...string) Options {
	return Options{
		Targets:          targets,
		Attempts:         2,
		Timeout:          5 * time.Second,
		GeoBasePath:      filepath.Join(f.cfgDir, "geo-base.jsonl"),
		ProbeResultsPath: filepath.Join(f.cfgDir, "probe-results.jsonl"),
		NodesPath:        filepath.Join(f.cfgDir, "filtered.jsonl"),
		GeoTTL:           24 * time.Hour,
		WorkDir:          filepath.Join(f.cfgDir, "work"),
		Concurrency:      2,
		factoryOverride:  f.factory,
		dohOverride:      f.doh.URL + "/resolve",
	}
}

func baseGeo(tag, host, cc, city string, alive bool) *model.GeoRecord {
	return &model.GeoRecord{
		Tag: tag, Source: "test", Scheme: "vless", Host: host, Port: 443,
		Country: cc, City: city, ASN: "AS9000", ISP: "Test ISP",
		LastProbe: "2026-10-27T00:00:00Z", Alive: alive, RTTMs: 100,
	}
}

func baseNode(host string) *model.Node {
	return model.NewNode("test", "vless", "uuid-1", host, 443, map[string]string{"type": "ws", "path": "/p"})
}

func withRTT(g *model.GeoRecord, rtt float64) *model.GeoRecord {
	g.RTTMs = rtt
	return g
}

func okSite(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(strings.Repeat("<html>nyaa torrents page ", 300))) // > tinyBodyLimit
}

func TestEngineEndToEndThroughSocks(t *testing.T) {
	f := newEngineFixture(t, okSite,
		[]*model.GeoRecord{
			withRTT(baseGeo("pool-nl-01", "nl.example.com", "NL", "Amsterdam", true), 50),
			withRTT(baseGeo("pool-de-02", "de.example.com", "DE", "Frankfurt", true), 200),
			baseGeo("pool-ru-09", "ru.example.com", "RU", "Moscow", false),
		},
		[]*model.Node{baseNode("nl.example.com"), baseNode("de.example.com"), baseNode("ru.example.com")},
	)
	rep, err := Run(context.Background(), f.opts(f.httpTarget()))
	require.NoError(t, err)
	require.Len(t, rep.Targets, 1)
	tr := rep.Targets[0]
	require.Len(t, tr.Rows, 2, "dead node excluded by default")
	assert.Equal(t, "pool-nl-01", tr.Rows[0].Tag, "rows ordered alive-fastest-first")
	assert.Equal(t, VerdictSuccess, tr.Rows[0].Verdict)
	assert.Equal(t, 2, tr.Rows[0].OK)
	assert.Equal(t, 2, tr.Rows[0].Total)
	assert.Equal(t, []int{200}, tr.Rows[0].Statuses)
	assert.Equal(t, []string{"10.1.2.3"}, tr.Rows[0].ResolvedIPs, "only A records; AAAA filtered")
	assert.Equal(t, "doh-via-exit", tr.Rows[0].DNSMethod)
	assert.NotZero(t, tr.Rows[0].Attempts[0].Bytes)
	assert.NotZero(t, tr.Rows[0].Attempts[0].SpeedBPS)
	assert.NotZero(t, tr.Rows[0].AvgMS)
	assert.False(t, tr.Rows[0].TLSOK, "http target: TLS check not applicable")
	assert.Empty(t, tr.Rows[0].TLSVersion)
	require.Len(t, tr.Countries, 2)
	require.Len(t, tr.Recommendation, 2)
	assert.InDelta(t, 1.0, tr.Recommendation[0].SuccessRate, 0.0001)

	// The socks5h contract: the client must hand the HOSTNAME to the proxy,
	// never a pre-resolved IP. (The DoH call dialed a literal IP; the site
	// calls went through as domain-type CONNECTs.)
	domains := f.socks.domainRequests()
	assert.NotEmpty(t, domains, "site requests must be DOMAIN-type (remote DNS at the exit)")
	for _, host := range domains {
		assert.Equal(t, "site.example", host)
	}
	assert.Positive(t, f.socks.connections())
	assert.Equal(t, 2, rep.Checked)
	assert.Equal(t, 1, rep.Skipped)
}

func TestEngineBlockpageVerdict(t *testing.T) {
	f := newEngineFixture(t,
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("error code: 1020"))
		},
		[]*model.GeoRecord{baseGeo("pool-us-01", "us.example.com", "US", "Dallas", true)},
		[]*model.Node{baseNode("us.example.com")},
	)
	rep, err := Run(context.Background(), f.opts(f.httpTarget()))
	require.NoError(t, err)
	row := rep.Targets[0].Rows[0]
	assert.Equal(t, VerdictBlocked, row.Verdict)
	assert.Equal(t, []int{403}, row.Statuses)
	assert.Equal(t, 0, row.OK)
	assert.Empty(t, rep.Targets[0].Recommendation, "no served location → no recommendation")
}

func TestEngineInstanceFailureIsDistinctClass(t *testing.T) {
	f := newEngineFixture(t, okSite,
		[]*model.GeoRecord{baseGeo("pool-nl-01", "nl.example.com", "NL", "Amsterdam", true)},
		[]*model.Node{baseNode("nl.example.com")},
	)
	f.factory = func(_ context.Context, _ *model.Node) (SocksInstance, error) {
		return nil, context.DeadlineExceeded
	}
	o := f.opts(f.httpTarget())
	o.factoryOverride = f.factory
	rep, err := Run(context.Background(), o)
	require.NoError(t, err)
	row := rep.Targets[0].Rows[0]
	assert.True(t, row.InstanceFailed)
	assert.Equal(t, VerdictError, row.Verdict)
	assert.NotEmpty(t, row.InstanceErr)
}

func TestEngineFiltersAndLimit(t *testing.T) {
	records := []*model.GeoRecord{
		baseGeo("pool-nl-01", "nl1.example.com", "NL", "Amsterdam", true),
		baseGeo("pool-de-01", "de1.example.com", "DE", "Berlin", true),
		baseGeo("pool-fr-01", "fr1.example.com", "FR", "Paris", true),
		baseGeo("pool-us-01", "us1.example.com", "US", "Dallas", false),
	}
	nodes := []*model.Node{
		baseNode("nl1.example.com"), baseNode("de1.example.com"),
		baseNode("fr1.example.com"), baseNode("us1.example.com"),
	}
	f := newEngineFixture(t, okSite, records, nodes)
	target := f.httpTarget()

	o := f.opts(target)
	o.Countries = []string{"nl", "de"}
	rep, err := Run(context.Background(), o)
	require.NoError(t, err)
	assert.Len(t, rep.Targets[0].Rows, 2, "country filter narrows the pool")

	o = f.opts(target)
	o.Limit = 1
	rep, err = Run(context.Background(), o)
	require.NoError(t, err)
	assert.Len(t, rep.Targets[0].Rows, 1, "--limit caps the tested set")

	o = f.opts(target)
	o.WithDead = true
	rep, err = Run(context.Background(), o)
	require.NoError(t, err)
	assert.Len(t, rep.Targets[0].Rows, 4, "--with-dead includes the dead node")
	assert.Equal(t, 0, rep.Skipped)

	o = f.opts(target)
	o.Attempts = 0
	_, err = Run(context.Background(), o)
	require.Error(t, err, "attempts must be structurally positive")

	o = f.opts("not a url\x07")
	_, err = Run(context.Background(), o)
	require.Error(t, err, "invalid target rejected loud")
}

func TestEngineStalenessHint(t *testing.T) {
	f := newEngineFixture(t, okSite,
		[]*model.GeoRecord{baseGeo("pool-nl-01", "nl.example.com", "NL", "Amsterdam", true)},
		[]*model.Node{baseNode("nl.example.com")},
	)
	o := f.opts(f.httpTarget())
	o.Now = func() time.Time { return time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC) }
	rep, err := Run(context.Background(), o)
	require.NoError(t, err)
	assert.True(t, rep.Stale, "probe older than geo.ttl must flag stale")
	assert.NotEmpty(t, rep.StaleAge)
}

func TestEngineUnreachableTargetClassifies(t *testing.T) {
	// The socks server forwards everything to a closed port: the attempt
	// must classify dial-fail, never success.
	forward := newSocksServerForward(t, "127.0.0.1:1")
	f := newEngineFixture(t, okSite,
		[]*model.GeoRecord{baseGeo("pool-nl-01", "nl.example.com", "NL", "Amsterdam", true)},
		[]*model.Node{baseNode("nl.example.com")},
	)
	f.factory = func(_ context.Context, _ *model.Node) (SocksInstance, error) {
		return fakeInstance{addr: forward.addr()}, nil
	}
	o := f.opts(f.httpTarget())
	o.factoryOverride = f.factory
	rep, err := Run(context.Background(), o)
	require.NoError(t, err)
	row := rep.Targets[0].Rows[0]
	assert.Equal(t, VerdictFail, row.Verdict)
	for _, a := range row.Attempts {
		assert.Equal(t, VerdictDialFail, a.Verdict)
		assert.NotEmpty(t, a.Err)
	}
}

func TestEngineTLSCheckSeam(t *testing.T) {
	// Client-level: the explicit TLS probe against a real TLS listener.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer tlsSrv.Close()
	f := newEngineFixture(t, okSite,
		[]*model.GeoRecord{baseGeo("pool-nl-01", "nl.example.com", "NL", "Amsterdam", true)},
		[]*model.Node{baseNode("nl.example.com")},
	)
	hostPort := strings.TrimPrefix(tlsSrv.URL, "https://")
	f.socks.routes[hostPort] = hostPort // the TLS listener reachable through the tunnel
	o := f.opts("https://" + hostPort)  // https target with explicit port → TLS check dials the listener
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	o.tlsRoots = pool
	rep, err := Run(context.Background(), o)
	require.NoError(t, err)
	row := rep.Targets[0].Rows[0]
	assert.Equal(t, "1.3", row.TLSVersion, "explicit TLS check reports the negotiated version")
	assert.True(t, row.TLSOK)
}
