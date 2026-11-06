package geo_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/geo"
	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The unlock-eligibility battery (owner order 2026-11-06, point 2 of the
// classification-acceleration plan): the UNLOCK stage's need for a ladder is
// INDEPENDENT of the geo stage's 24h freshness gate. geo-need (stale/missing
// geo record) keeps driving the full ladder with its ip-api hop; unlock-need
// (alive node + missing classification, any unknown/unchecked field, or an
// expired verdict TTL) drives an UNLOCK-ONLY sweep through the node's tunnel
// — no geo hops, no ip-api quota. The PR-#15 cache semantics (alive-bypass,
// verdict-shaped TTL) stay untouched; these tests pin the eligibility layer
// above them.

// seededGeoRecord builds a cold geo-base record for one node/exit with the
// given geo freshness and unlock state (nil = no classification yet).
func seededGeoRecord(n *model.Node, exitIP string, lastSeen time.Time, unlocks *model.MediaUnlockStatus) *model.GeoRecord {
	rec := &model.GeoRecord{
		Source: n.Source, Scheme: n.Scheme, Host: n.Host, Port: n.Port,
		IP: exitIP, Country: "de", City: "Frankfurt am Main",
		ASN: "AS51167", ASName: "CONTABO", ISP: "Contabo GmbH",
		HostingFlag: true, FlagsVerified: true, GeoSource: "self-report",
		FirstSeen: lastSeen.Format(time.RFC3339), LastSeen: lastSeen.Format(time.RFC3339),
		Alive: true,
	}
	if unlocks != nil {
		rec.MediaUnlocks = *unlocks
	}
	return rec
}

// seedFreshGeo writes the record to the cold geo-base and rehydrates the hot
// cache from it — the exact production wave-start shape (pipeline: ReadGeo →
// Rehydrate), so the test exercises the real freshness gate.
func seedFreshGeo(t *testing.T, dir string, cache *geo.ExitGeoCache, rec *model.GeoRecord) {
	t.Helper()
	require.NoError(t, store.UpsertGeo(filepath.Join(dir, "geo-base.jsonl"), []*model.GeoRecord{rec}))
	cache.Rehydrate([]*model.GeoRecord{rec})
}

// eligInput builds a single-node geo Input with the unlock stage ON — the
// eligibility battery's shape (one node, exit IP 203.0.113.7, both doubles
// wired).
func eligInput(
	t *testing.T, dir string, f geo.Factory, apiURL string, ep *geo.UnlockEndpoints,
	cache *geo.ExitGeoCache, n *model.Node,
) geo.Input {
	t.Helper()
	const exitIP = "203.0.113.7"
	in := baseInput(dir, []*model.Node{n},
		map[string]store.ProbeResult{n.Key: liveProbe(n, exitIP)}, f, apiURL+"/json/")
	on := true
	in.Cfg.UnlockProbes = &on
	in.UnlockEndpoints = ep
	in.ExitCache = cache
	return in
}

// unknownVerdict is the stuck-unknown fixture (the production 72/99 shape):
// one unknown field, the rest definite, stamped inside the 24h window.
func unknownVerdict() *model.MediaUnlockStatus {
	return &model.MediaUnlockStatus{
		ChatGPT: model.UnlockUnknown, Netflix: model.UnlockNetflixFull,
		YouTubeRegion: "DE", Disney: model.UnlockYes, TikTok: model.UnlockYes,
		CheckedAt: agedStamp(-time.Hour),
	}
}

// definiteVerdict is the fully-satisfied fixture: every field definite,
// stamped well inside the 7-day window.
func definiteVerdict() *model.MediaUnlockStatus {
	return &model.MediaUnlockStatus{
		ChatGPT: model.UnlockYes, Netflix: model.UnlockNetflixFull,
		YouTubeRegion: "DE", Disney: model.UnlockYes, TikTok: model.UnlockYes,
		CheckedAt: agedStamp(-time.Hour),
		// The fixtures represent CURRENT-battery cached verdicts: the
		// migration rule (older batteries are stale on sight) is pinned in
		// TestFreshUnlockBatteryMigration + TestUnlockMigrationV1..., not
		// here.
		BatteryVersion: geo.UnlockBatteryVersion,
	}
}

// TestUnlockEligibilityFreshGeoNoUnlockClassifiesWithoutIPAPI pins
// unlock-need rule 1: a FRESH-geo node with NO unlock classification gets an
// unlock-only sweep — the unlock probes fire, the ip-api hop is SKIPPED
// (quota + wave-time discipline), and the classification lands.
func TestUnlockEligibilityFreshGeoNoUnlockClassifiesWithoutIPAPI(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	f, spawns, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	n := node("1", "one.example.com")
	seedFreshGeo(t, dir, cache, seededGeoRecord(n, "203.0.113.7", time.Now().UTC(), nil))

	in := eligInput(t, dir, f, api.URL(), ud.endpoints(), cache, n)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)

	assert.Zero(t, lenOfRequests(api), "fresh geo = geo ladder skipped, the ip-api hop must not fire")
	assert.Equal(t, 1, ud.hitsOf("/cdn-cgi/trace"), "unlock-need drives the unlock probes")
	assert.Equal(t, int32(1), spawns.Load(), "exactly the unlock-only sweep instance — no geo-ladder instance")
	assert.Equal(t, model.UnlockYes, records[0].MediaUnlocks.ChatGPT, "the sweep classifies the exit")
	assert.Equal(t, model.UnlockNetflixFull, records[0].MediaUnlocks.Netflix)
	assert.NotEmpty(t, records[0].MediaUnlocks.CheckedAt)
}

// TestUnlockEligibilityFreshGeoUnknownReprobedWithoutLadder pins unlock-need
// rule 2 — the never-entered-a-ladder case the decoupling exists for: a
// FRESH-geo node whose cached verdict carries an unknown field (inside its
// 24h TTL) never rode a ladder this wave (geo cache-served, no in-wave
// tunnel evidence), yet MUST be re-probed. The geo stage's freshness gate
// used to starve this re-classification for up to 24h.
func TestUnlockEligibilityFreshGeoUnknownReprobedWithoutLadder(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, noTraceEvidenceBodies())
	socks := newSocksServer(t)
	f, spawns, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	n := node("1", "one.example.com")
	seedFreshGeo(t, dir, cache, seededGeoRecord(n, "203.0.113.7", time.Now().UTC(), unknownVerdict()))

	// The tunnel works NOW (the probe double answers a definite trace): the
	// sweep must flip unknown→yes even though the geo record is fresh and
	// no geo ladder ran for this exit in this wave.
	ud.setBody("/cdn-cgi/trace", "fl=1.1\nip=203.0.113.7\nloc=DE\n")

	in := eligInput(t, dir, f, api.URL(), ud.endpoints(), cache, n)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)

	assert.Equal(t, 1, ud.hitsOf("/cdn-cgi/trace"),
		"alive + unknown-carrying verdict = unlock-need, re-probe despite fresh geo")
	assert.Zero(t, lenOfRequests(api), "the re-probe is unlock-only: the ip-api hop must not fire")
	assert.Equal(t, int32(1), spawns.Load(), "exactly the unlock-only sweep instance")
	assert.Equal(t, model.UnlockYes, records[0].MediaUnlocks.ChatGPT,
		"the stuck unknown must be re-classified within ONE wave")
	assert.NotEqual(t, agedStamp(-time.Hour), records[0].MediaUnlocks.CheckedAt,
		"the re-probe re-stamps the verdict")
}

// TestUnlockEligibilityFreshGeoFreshDefiniteNoLadder pins satisfaction: a
// fresh-geo node carrying a fully definite fresh verdict (<7d, no unknown)
// needs NOTHING — no geo ladder, no unlock probes, zero temp instances.
func TestUnlockEligibilityFreshGeoFreshDefiniteNoLadder(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	f, spawns, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	n := node("1", "one.example.com")
	seedFreshGeo(t, dir, cache, seededGeoRecord(n, "203.0.113.7", time.Now().UTC(), definiteVerdict()))
	seeded := *definiteVerdict()

	in := eligInput(t, dir, f, api.URL(), ud.endpoints(), cache, n)
	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)

	assert.Zero(t, lenOfRequests(api), "fresh geo: no ip-api request")
	assert.Zero(t, ud.totalHits(), "definite fresh verdict: no unlock probes")
	assert.Equal(t, int32(0), spawns.Load(), "fully satisfied = NO ladder at all")
	assert.Equal(t, seeded, records[0].MediaUnlocks, "the cached verdict is served untouched")
}

// TestUnlockEligibilityStaleGeoRunsFullLadder pins unchanged behavior: a
// STALE-geo node gets the FULL ladder — the geo rungs (ip-api hop fires on
// geo-need) plus the unlock probes — exactly the pre-decoupling shape.
func TestUnlockEligibilityStaleGeoRunsFullLadder(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	f, spawns, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	n := node("1", "one.example.com")
	// Stale geo: the record lives ONLY in the cold base, 25h old — the hot
	// cache starts empty (production restart shape), so the exit cache-misses
	// and the geo ladder runs.
	require.NoError(t, store.UpsertGeo(filepath.Join(dir, "geo-base.jsonl"),
		[]*model.GeoRecord{seededGeoRecord(n, "203.0.113.7", time.Now().UTC().Add(-25*time.Hour), nil)}))

	in := eligInput(t, dir, f, api.URL(), ud.endpoints(), cache, n)
	records, summary, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)

	methods, _, _ := api.saw()
	require.Len(t, methods, 1, "geo-need runs the ip-api self-report hop")
	assert.Equal(t, 1, summary.SelfReport, "the geo ladder classifies the exit")
	assert.Equal(t, "self-report", records[0].GeoSource)
	assert.Positive(t, ud.totalHits(), "the same wave also probes unlocks (no cached verdict)")
	assert.Equal(t, int32(2), spawns.Load(),
		"full ladder = the geo-ladder instance + the unlock-sweep instance (per-stage, unchanged)")
	assert.NotEmpty(t, records[0].MediaUnlocks.CheckedAt, "the unlock verdict lands in the same wave")
}

// TestUnlockEligibilityDeadNodeNoLadder pins the unchanged ALIVE gate: a
// dead node has no tunnel, so no ladder of either kind can run for it.
func TestUnlockEligibilityDeadNodeNoLadder(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	ud := newUnlockDouble(t, unlockBodies())
	socks := newSocksServer(t)
	f, spawns, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	n := node("1", "one.example.com")
	in := baseInput(dir, []*model.Node{n}, map[string]store.ProbeResult{
		n.Key: {Key: n.Key, Host: n.Host, Alive: false, CheckedAt: time.Now().UTC()},
	}, f, api.URL()+"/json/")
	on := true
	in.Cfg.UnlockProbes = &on
	in.UnlockEndpoints = ud.endpoints()
	in.ExitCache = cache

	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.False(t, records[0].Alive)
	assert.Zero(t, lenOfRequests(api), "dead node: no geo hop")
	assert.Zero(t, ud.totalHits(), "dead node: no unlock probes")
	assert.Equal(t, int32(0), spawns.Load(), "dead node: no ladder, no instance")
}

// TestUnlockEligibilityWaveLevelMixedNeeds pins the wave-level contract: in
// the SAME wave a fresh-geo fresh-definite node produces NO ladder while a
// fresh-geo no-unlock node produces an unlock-only ladder — one sweep
// instance total, zero ip-api traffic, each record served its own way.
func TestUnlockEligibilityWaveLevelMixedNeeds(t *testing.T) {
	api := newIPAPIDouble(t, documentedSingleSuccess(t))
	bodies := unlockBodies()
	bodies["/widget/demo/203.0.113.9"] = bodies["/widget/demo/203.0.113.7"]
	ud := newUnlockDouble(t, bodies)
	socks := newSocksServer(t)
	f, spawns, _ := newTestFactory(socks)
	dir := t.TempDir()
	cache := geo.NewExitGeoCache(geo.ExitCacheConfig{TTL: time.Hour, MaxEntries: 16})

	na := node("a", "a.example.com") // fresh geo + fresh definite unlock: satisfied
	nb := node("b", "b.example.com") // fresh geo + no unlock classification: unlock-need
	require.NoError(t, store.UpsertGeo(filepath.Join(dir, "geo-base.jsonl"), []*model.GeoRecord{
		seededGeoRecord(na, "203.0.113.7", time.Now().UTC(), definiteVerdict()),
		seededGeoRecord(nb, "203.0.113.9", time.Now().UTC(), nil),
	}))
	cache.Rehydrate([]*model.GeoRecord{
		seededGeoRecord(na, "203.0.113.7", time.Now().UTC(), definiteVerdict()),
		seededGeoRecord(nb, "203.0.113.9", time.Now().UTC(), nil),
	})
	seededA := *definiteVerdict()

	in := baseInput(dir, []*model.Node{na, nb}, map[string]store.ProbeResult{
		na.Key: liveProbe(na, "203.0.113.7"),
		nb.Key: liveProbe(nb, "203.0.113.9"),
	}, f, api.URL()+"/json/")
	on := true
	in.Cfg.UnlockProbes = &on
	in.UnlockEndpoints = ud.endpoints()
	in.ExitCache = cache

	records, _, err := geo.Run(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, records, 2)

	assert.Zero(t, lenOfRequests(api), "both nodes are geo-fresh: zero ip-api traffic in the wave")
	assert.Equal(t, int32(1), spawns.Load(), "only the unlock-need node spawns a sweep instance")
	assert.Zero(t, ud.hitsOf("/widget/demo/203.0.113.7"),
		"the satisfied node is not probed (its exit-keyed widget path is never hit)")
	assert.Equal(t, 1, ud.hitsOf("/cdn-cgi/trace"), "the unlock-need node is swept exactly once")
	assert.Equal(t, 1, ud.hitsOf("/widget/demo/203.0.113.9"), "the unlock-need node is swept exactly once")

	byHost := map[string]*model.GeoRecord{}
	for _, rec := range records {
		byHost[rec.Host] = rec
	}
	require.Contains(t, byHost, "a.example.com")
	require.Contains(t, byHost, "b.example.com")
	assert.Equal(t, seededA, byHost["a.example.com"].MediaUnlocks,
		"the satisfied node keeps its cached verdict")
	assert.Equal(t, model.UnlockYes, byHost["b.example.com"].MediaUnlocks.ChatGPT,
		"the unlock-need node gets classified in the same wave")
	assert.NotEmpty(t, byHost["b.example.com"].MediaUnlocks.CheckedAt)
}

// lenOfRequests counts every request the ip-api double saw (any path — the
// self-report hop, the DoH resolver lookup, the batch fallback all ride it).
func lenOfRequests(api *ipAPIDouble) int {
	methods, _, _ := api.saw()
	return len(methods)
}
