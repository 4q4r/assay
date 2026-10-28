package geo_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
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
	"golang.org/x/time/rate"
)

func ipAPIHandler(t *testing.T, calls *atomic.Int32, remaining *atomic.Int32) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var reqs []string
		if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
			t.Errorf("decode batch request: %v", err)
			return
		}
		if len(reqs) > 100 {
			t.Errorf("batch of %d exceeds the 100-IP free-tier cap", len(reqs))
		}
		out := make([]map[string]any, 0, len(reqs))
		for _, ip := range reqs {
			out = append(out, map[string]any{
				"status":      "success",
				"query":       ip,
				"countryCode": "NL",
				"country":     "Netherlands",
				"city":        "Amsterdam",
				"isp":         "LeaseWeb Netherlands B.V.",
				"as":          "AS60781 LeaseWeb Netherlands B.V.",
				"asname":      "LeaseWeb",
				"proxy":       true,
				"hosting":     true,
			})
		}
		w.Header().Set("X-Rl", strconv.Itoa(int(remaining.Load())))
		w.Header().Set("X-Ttl", "60")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func TestBatchEnrichmentMapsFields(t *testing.T) {
	var calls atomic.Int32
	remaining := atomic.Int32{}
	remaining.Store(14)
	srv := httptest.NewServer(ipAPIHandler(t, &calls, &remaining))
	t.Cleanup(srv.Close)

	cl := geo.NewClient(config.GeoConfig{
		Endpoint:  "http://" + strings.TrimPrefix(srv.URL, "http://"),
		BatchSize: 100,
		PerMinute: 15,
		Timeout:   config.Duration{Duration: 5 * time.Second},
	})
	resp, err := cl.Enrich(context.Background(), []string{"5.6.7.8"})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "NL", resp[0].CountryCode)
	assert.Equal(t, "Amsterdam", resp[0].City)
	assert.Equal(t, "AS60781", resp[0].ASN(), "asn = the AS number token of the as field")
	assert.Equal(t, "LeaseWeb", resp[0].ASName)
	assert.True(t, resp[0].Proxy)
	assert.True(t, resp[0].Hosting)
	assert.Equal(t, 1, int(calls.Load()))
}

func TestBatchingSplitsOver100IPs(t *testing.T) {
	var calls atomic.Int32
	remaining := atomic.Int32{}
	remaining.Store(14)
	srv := httptest.NewServer(ipAPIHandler(t, &calls, &remaining))
	t.Cleanup(srv.Close)

	// Test seam (review finding 3): the injected limiter keeps this behavior
	// test free of real 4s waits; the clamp itself is unit-tested in
	// TestBatchIntervalClampsToFreeTier.
	cl := geo.NewClientWithLimiter(config.GeoConfig{
		Endpoint:  "http://" + strings.TrimPrefix(srv.URL, "http://"),
		BatchSize: 100,
		PerMinute: 900,
		Timeout:   config.Duration{Duration: 5 * time.Second},
	}, rate.NewLimiter(rate.Inf, 1))
	ips := make([]string, 0, 250)
	for i := range 250 {
		ips = append(ips, fmt.Sprintf("10.%d.%d.1", i/256%256, i%256))
	}
	resp, err := cl.Enrich(context.Background(), ips)
	require.NoError(t, err)
	assert.Len(t, resp, 250)
	assert.Equal(t, int32(3), calls.Load(), "250 IPs at batch 100 = 3 requests")
}

// TestClientSpacesBatchesThroughLimiter pins the real spacing contract: every
// batch waits on the injected limiter before its request, so server-side
// arrivals are spaced by the limiter's interval. A fast-but-real interval
// keeps the assertion honest without paying the production 4s (finding 3).
func TestClientSpacesBatchesThroughLimiter(t *testing.T) {
	const interval = 40 * time.Millisecond
	var stamps atomicSlice
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqs []string
		_ = json.NewDecoder(r.Body).Decode(&reqs)
		if len(reqs) > 0 {
			stamps.append(time.Now())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)

	cl := geo.NewClientWithLimiter(config.GeoConfig{
		Endpoint:  srv.URL,
		BatchSize: 1,
		PerMinute: 900, // irrelevant: the limiter is injected below
		Timeout:   config.Duration{Duration: 5 * time.Second},
	}, rate.NewLimiter(rate.Every(interval), 1))
	_, err := cl.Enrich(context.Background(), []string{"a", "b", "c", "d"}) // 4 batches of 1
	require.NoError(t, err)

	got := stamps.all()
	require.Len(t, got, 4)
	for i := 1; i < len(got); i++ {
		gap := got[i].Sub(got[i-1])
		// Lower bound tolerates server-side timestamp jitter (~1ms class);
		// an unhonored limiter would show ~0 gaps, far below any jitter.
		assert.GreaterOrEqual(t, gap, interval-15*time.Millisecond,
			"batch %d arrived before the limiter interval elapsed", i)
		assert.Less(t, gap, time.Second, "no dead waiting: the injected interval is honored, not multiplied")
	}
}

// atomicSlice collects timestamps from handler goroutines.
type atomicSlice struct {
	mu sync.Mutex
	v  []time.Time
}

func (s *atomicSlice) append(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v = append(s.v, t)
}

func (s *atomicSlice) all() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.v...)
}

func Test429AbortsLoudlyNeverRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	cl := geo.NewClient(config.GeoConfig{
		Endpoint:  "http://" + strings.TrimPrefix(srv.URL, "http://"),
		BatchSize: 100,
		PerMinute: 15,
		Timeout:   config.Duration{Duration: 5 * time.Second},
	})
	ips := make([]string, 0, 150)
	for i := range 150 {
		ips = append(ips, fmt.Sprintf("10.0.0.%d", i+1))
	}
	_, err := cl.Enrich(context.Background(), ips)
	require.Error(t, err, "L6: a 429 means imminent 1h ban — abort the wave, never retry into it")
	assert.Equal(t, int32(1), calls.Load(), "no request may follow a 429")
	assert.Contains(t, err.Error(), "429")
}

func TestFailedStatusEntriesAreSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqs []string
		_ = json.NewDecoder(r.Body).Decode(&reqs)
		out := []map[string]any{
			{"status": "fail", "query": reqs[0], "message": "private range"},
			{
				"status": "success", "query": reqs[1], "countryCode": "DE", "city": "Berlin",
				"isp": "Netcup", "as": "AS197540 netcup GmbH", "asname": "netcup", "proxy": false, "hosting": true,
			},
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	cl := geo.NewClient(config.GeoConfig{
		Endpoint:  "http://" + strings.TrimPrefix(srv.URL, "http://"),
		BatchSize: 100,
		PerMinute: 15,
		Timeout:   config.Duration{Duration: 5 * time.Second},
	})
	resp, err := cl.Enrich(context.Background(), []string{"192.168.0.1", "8.8.8.8"})
	require.NoError(t, err)
	require.Len(t, resp, 1, "failed lookups are skipped")
	assert.Equal(t, "8.8.8.8", resp[0].Query)
	assert.Equal(t, "DE", resp[0].CountryCode)
}

// TestPartialProbeWaveLeavesUnprobedRecordsUntouched pins the partial-wave
// contract: a geo wave that follows a partial probe wave (--limit small) over
// a pre-populated cold base must leave unprobed records' alive/rtt/speed/
// last_probe exactly as they were — never Alive=false with zeroed metrics
// under a stale last_probe (fix-round-1 finding #1).
func TestPartialProbeWaveLeavesUnprobedRecordsUntouched(t *testing.T) {
	dir := t.TempDir()
	geoBase := filepath.Join(dir, "geo-base.jsonl")

	nodes := []*model.Node{
		model.NewNode("s", "vless", "u1", "one.example.com", 443, map[string]string{"security": "tls", "type": "tcp"}),
		model.NewNode("s", "vless", "u2", "two.example.com", 443, map[string]string{"security": "tls", "type": "tcp"}),
		model.NewNode("s", "vless", "u3", "three.example.com", 443, map[string]string{"security": "tls", "type": "tcp"}),
	}
	stale := "2026-10-20T00:00:00Z"
	base := make([]*model.GeoRecord, 0, len(nodes))
	for i, n := range nodes {
		base = append(base, &model.GeoRecord{
			Source: n.Source, Scheme: n.Scheme, Host: n.Host, Port: n.Port,
			IP: fmt.Sprintf("5.6.7.%d", i+1), Country: "nl", City: "Amsterdam",
			FirstSeen: stale, LastSeen: stale,
			LastProbe: stale, RTTMs: float64(100 + i), SpeedBPS: 1000 + int64(i), Alive: true,
		})
	}
	require.NoError(t, store.UpsertGeo(geoBase, base))
	before, err := store.ReadGeo(geoBase)
	require.NoError(t, err)
	beforeByKey := map[string]*model.GeoRecord{}
	for _, r := range before {
		beforeByKey[store.GeoIdentity(r)] = r
	}

	// Partial probe wave: only the FIRST node was probed (probe --limit 1
	// preceded this geo wave); the other two are absent from the probe map.
	var calls, remaining atomic.Int32
	remaining.Store(14)
	srv := httptest.NewServer(ipAPIHandler(t, &calls, &remaining))
	t.Cleanup(srv.Close)
	probeByKey := map[string]store.ProbeResult{
		nodes[0].Key: {Key: nodes[0].Key, Alive: true, ExitIP: "9.9.9.9", RTTMs: 55, CheckedAt: time.Now().UTC()},
	}
	_, err = geo.Run(context.Background(), geo.Input{
		DataDir:    dir,
		Nodes:      nodes,
		ProbeByKey: probeByKey,
		Cfg: config.GeoConfig{
			Endpoint:  srv.URL,
			BatchSize: 100,
			PerMinute: 15,
			Timeout:   config.Duration{Duration: 5 * time.Second},
		},
	})
	require.NoError(t, err)

	after, err := store.ReadGeo(geoBase)
	require.NoError(t, err)
	require.Len(t, after, 3)
	for _, r := range after {
		was, ok := beforeByKey[store.GeoIdentity(r)]
		require.True(t, ok, "identity %s must survive", store.GeoIdentity(r))
		if r.Host == "one.example.com" {
			continue // probed node: fresh values expected
		}
		assert.Equal(t, was.Alive, r.Alive, "unprobed %s: alive must stay byte-identical", r.Host)
		assert.Equal(t, was.RTTMs, r.RTTMs, "unprobed %s: rtt_ms must stay byte-identical", r.Host) //nolint:testifylint // byte-identical is the contract: exact bit equality is the pin
		assert.Equal(t, was.SpeedBPS, r.SpeedBPS, "unprobed %s: speed_bps must stay byte-identical", r.Host)
		assert.Equal(t, was.LastProbe, r.LastProbe, "unprobed %s: last_probe must stay byte-identical", r.Host)
		assert.True(t, r.Alive, "unprobed %s must not be flipped dead by an absent probe entry", r.Host)
	}
}

func TestGeoStageJoinsProbeExitIPsIntoGeoBase(t *testing.T) {
	dir := t.TempDir()
	// geo stage input: filtered nodes + probe results with exit IPs.
	n1 := model.NewNode("s", "vless", "u1", "one.example.com", 443, map[string]string{"security": "tls", "type": "tcp"})
	n2 := model.NewNode("s", "vless", "u2", "two.example.com", 443, map[string]string{"security": "tls", "type": "tcp"})
	require.NoError(t, store.WriteNodes(filepath.Join(dir, "filtered.jsonl"), []*model.Node{n1, n2}))

	var calls, remaining atomic.Int32
	remaining.Store(14)
	srv := httptest.NewServer(ipAPIHandler(t, &calls, &remaining))
	t.Cleanup(srv.Close)
	probeByKey := map[string]store.ProbeResult{
		n1.Key: {Key: n1.Key, Alive: true, ExitIP: "5.6.7.8", RTTMs: 120, CheckedAt: time.Now().UTC()},
		n2.Key: {Key: n2.Key, Alive: false, CheckedAt: time.Now().UTC()},
	}

	records, err := geo.Run(context.Background(), geo.Input{
		DataDir:    dir,
		Nodes:      []*model.Node{n1, n2},
		ProbeByKey: probeByKey,
		Cfg: config.GeoConfig{
			Endpoint:  "http://" + strings.TrimPrefix(srv.URL, "http://"),
			BatchSize: 100,
			PerMinute: 900,
			Timeout:   config.Duration{Duration: 5 * time.Second},
		},
	})
	require.NoError(t, err)
	require.Len(t, records, 2)
	var enriched, dead *model.GeoRecord
	for _, r := range records {
		if r.Host == "one.example.com" {
			enriched = r
		}
		if r.Host == "two.example.com" {
			dead = r
		}
	}
	require.NotNil(t, enriched)
	require.NotNil(t, dead)
	assert.Equal(t, "5.6.7.8", enriched.IP)
	assert.Equal(t, "nl", enriched.Country, "country stored lowercase for tags")
	assert.Equal(t, "Amsterdam", enriched.City)
	assert.Equal(t, "AS60781", enriched.ASN)
	assert.True(t, enriched.Alive)
	assert.False(t, dead.Alive, "dead node keeps its record with alive=false")
	assert.Empty(t, dead.IP, "no probe = no exit IP = no geo lookup for it")

	// geo-base.jsonl was persisted.
	persisted, err := store.ReadGeo(filepath.Join(dir, "geo-base.jsonl"))
	require.NoError(t, err)
	assert.Len(t, persisted, 2)
}
