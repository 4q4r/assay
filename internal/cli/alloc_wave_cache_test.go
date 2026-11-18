package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/store"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// The alloc-wave fixture corpus: a deterministic tail wave (enrich → stats →
// prune → select → render) over a seeded store. All timestamps are FIXED
// strings so the outputs are byte-stable across runs and trees; the geo TTL
// is an explicit 100-year window (an explicit value survives
// applyGeoDefaults, unlike 0 which materializes 24h) so rank's freshness
// gate stays wall-clock independent. The corpus exercises: the same-identity
// node pair (n1/n9), the unknown-geo node (n10, no geo record), the
// probe-dead pair (n7/n8), the missing-probe-entry ka rescue (n11), the
// superseded journal entry (older n1), both prune removal rules (the two
// .old.example.com baits), and the hosting/proxy flag spread for the stats
// join.

const fixedFixtureTime = "2026-06-01T00:00:00Z"

func fixtureNodes(t *testing.T) []*model.Node {
	t.Helper()
	pbk := "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"
	mk := func(source, scheme, cred, host string, port int, params map[string]string) *model.Node {
		n := model.NewNode(source, scheme, cred, host, port, params)
		fs, err := time.Parse(time.RFC3339, fixedFixtureTime)
		require.NoError(t, err)
		n.FirstSeen = fs
		n.LastSeen = fs
		return n
	}
	reality := func(s string) map[string]string {
		return map[string]string{"security": "reality", "type": "tcp", "pbk": pbk, "sid": s}
	}
	return []*model.Node{
		mk("plug-a", "vless", "uuid-0001", "de1.example.com", 443, reality("AA")),
		mk("plug-a", "vless", "uuid-0002", "de2.example.com", 443, reality("AB")),
		mk("plug-a", "vless", "uuid-0003", "nl1.example.com", 443, reality("AC")),
		mk("plug-a", "vless", "uuid-0004", "fr1.example.com", 443, reality("AD")),
		mk("plug-a", "vless", "uuid-0005", "us1.example.com", 443, reality("AE")),
		mk("plug-b", "trojan", "uuid-0006", "de3.example.com", 8443, nil),
		mk("plug-b", "vless", "uuid-0007", "pl1.example.com", 443, reality("AF")),
		mk("plug-b", "vmess", "uuid-0008", "us2.example.com", 443,
			map[string]string{"type": "ws", "security": "tls", "path": "/ws"}),
		mk("plug-a", "vless", "uuid-0009", "de1.example.com", 443, reality("AA")),
		mk("plug-a", "vless", "uuid-0010", "xx1.example.com", 443, reality("AG")),
		mk("plug-b", "vless", "uuid-0011", "it1.example.com", 443, reality("AH")),
	}
}

func fixtureConfig(t *testing.T, dir string) *config.Config {
	t.Helper()
	tomlPath := filepath.Join(dir, "config.toml")
	content := `
data_dir = '` + dir + `'

[geo]
ttl = "876000h"

[maintain]
prune_dead_after = "720h"
`
	require.NoError(t, os.WriteFile(tomlPath, []byte(content), 0o644))
	cfg, err := config.Load(tomlPath)
	require.NoError(t, err)
	return cfg
}

func seedAllocFixture(t *testing.T, cfg *config.Config) []*model.Node {
	t.Helper()
	p := newPaths(cfg)
	require.NoError(t, os.MkdirAll(p.cacheDir, 0o750))
	require.NoError(t, os.MkdirAll(p.renderedDir, 0o750))
	nodes := fixtureNodes(t)

	// filtered.jsonl
	var b strings.Builder
	for _, n := range nodes {
		raw, err := json.Marshal(n)
		require.NoError(t, err)
		b.Write(raw)
		b.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(p.filtered, []byte(b.String()), 0o600))

	// geo-base.jsonl (sorted by identity, as the store contract requires).
	fixed := func(tag, scheme, host string, port int, cc, city, isp string,
		alive bool, rtt float64, speed int64, lastProbe string, hosting, proxy bool,
	) *model.GeoRecord {
		return &model.GeoRecord{
			Tag: tag, Source: "plug-x", Scheme: scheme, Host: host, Port: port,
			IP: "203.0.113.10", Country: cc, City: city, ASN: "AS51167",
			ASName: "CONTABO", ISP: isp, ProxyFlag: proxy, HostingFlag: hosting,
			FlagsVerified: true, GeoSource: "self-report",
			FirstSeen: fixedFixtureTime, LastSeen: fixedFixtureTime, LastProbe: lastProbe,
			RTTMs: rtt, SpeedBPS: speed, Alive: alive,
		}
	}
	geo := []*model.GeoRecord{
		fixed("pool-de-01", "vless", "de1.example.com", 443, "de", "Frankfurt am Main", "Contabo GmbH", true, 120, 1_000_000, fixedFixtureTime, true, false),
		fixed("pool-de-02", "vless", "de2.example.com", 443, "de", "Berlin", "Contabo GmbH", true, 140, 2_000_000, fixedFixtureTime, true, false),
		fixed("pool-nl-01", "vless", "nl1.example.com", 443, "nl", "Amsterdam", "NForce BV", true, 100, 3_000_000, fixedFixtureTime, false, false),
		fixed("pool-fr-01", "vless", "fr1.example.com", 443, "fr", "Paris", "OVH SAS", true, 200, 4_000_000, fixedFixtureTime, true, false),
		fixed("pool-us-01", "vless", "us1.example.com", 443, "us", "Ashburn", "DataShack", true, 180, 5_000_000, fixedFixtureTime, false, true),
		fixed("pool-de-03", "trojan", "de3.example.com", 8443, "de", "Frankfurt am Main", "Contabo GmbH", true, 90, 6_000_000, fixedFixtureTime, true, false),
		fixed("pool-pl-01", "vless", "pl1.example.com", 443, "pl", "Warsaw", "Netia SA", false, 0, 0, "", false, false),
		fixed("pool-us-02", "vmess", "us2.example.com", 443, "us", "Kansas", "Cogent", false, 0, 0, "", false, false),
		fixed("pool-it-01", "vless", "it1.example.com", 443, "it", "Rome", "Fastweb", true, 160, 7_000_000, fixedFixtureTime, true, false),
		fixed("pool-old-01", "vless", "dead1.old.example.com", 443, "ro", "Bucharest", "RCS", false, 0, 0, "2026-01-01T00:00:00Z", false, false),
		fixed("pool-old-02", "vless", "gone.old.example.com", 443, "ro", "Bucharest", "RCS", false, 0, 0, "", false, false),
	}
	var gb strings.Builder
	for _, g := range geo {
		raw, err := json.Marshal(g)
		require.NoError(t, err)
		gb.Write(raw)
		gb.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(p.geoBase, []byte(gb.String()), 0o600))

	// probe-results.jsonl: fixed CheckedAt; n1 carries an older superseded
	// entry (LatestProbeByKey reduction); n11 has NO entry (ka rescue path).
	probeAt, err := time.Parse(time.RFC3339, fixedFixtureTime)
	require.NoError(t, err)
	older := probeAt.Add(-time.Hour)
	pr := func(n *model.Node, alive bool, rtt float64, at time.Time) []byte {
		raw, err := json.Marshal(store.ProbeResult{
			Key: n.Key, Host: n.Host, Alive: alive,
			Status: map[bool]string{true: "passed", false: "timeout"}[alive],
			RTTMs:  rtt, Checks: 3, TotalChecks: 3, CheckedAt: at,
		})
		require.NoError(t, err)
		return raw
	}
	var pb strings.Builder
	for _, raw := range [][]byte{
		pr(nodes[0], true, 999, older),
		pr(nodes[0], true, 120, probeAt),
		pr(nodes[1], true, 140, probeAt),
		pr(nodes[2], true, 100, probeAt),
		pr(nodes[3], true, 200, probeAt),
		pr(nodes[4], true, 180, probeAt),
		pr(nodes[5], true, 90, probeAt),
		pr(nodes[6], false, 0, probeAt),
		pr(nodes[7], false, 0, probeAt),
	} {
		pb.Write(raw)
		pb.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(p.probeResults, []byte(pb.String()), 0o600))

	// known-alive.jsonl: the ka rescue record for n11 (no probe entry).
	ka, err := json.Marshal(store.KnownAliveRecord{
		Key: nodes[10].Key, Host: "it1.example.com",
		LastSeen: probeAt, LastStatus: "passed", AliveStreak: 2,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p.knownAlive, append(ka, '\n'), 0o600))

	// fetch manifest with plugin stats to enrich — the shape production
	// writes (json.Marshal of fetchManifest: Go field names, time.Time
	// RFC3339).
	manifest := `{
  "fetched_at": "` + fixedFixtureTime + `",
  "sources": {"plug-a": [], "plug-b": []},
  "plugin_stats": [
    {"PluginID": "plug-a", "TotalNodes": 6},
    {"PluginID": "plug-b", "TotalNodes": 5}
  ]
}`
	require.NoError(t, os.WriteFile(p.manifest, []byte(manifest), 0o600))
	return nodes
}

// runAllocFixtureWave runs the deterministic tail wave over the fixture.
// reader selects the store-read seam under test: nil = the legacy
// direct-store path (single-stage verb semantics), non-nil = the
// wave-scoped cache. Both paths must produce identical observable outputs.
func runAllocFixtureWave(t *testing.T, cfg *config.Config, reader *waveRecordCache) {
	t.Helper()
	prevStats := recordStageStatFunc
	recordStageStatFunc = func(string, StageStat) error { return nil }
	t.Cleanup(func() { recordStageStatFunc = prevStats })

	out := &bytes.Buffer{}
	stages := &maintainStages{
		fetch:  func(*cobra.Command, *config.Config) error { return nil },
		parse:  func(*cobra.Command, *config.Config) error { return nil },
		filter: func(*cobra.Command, *config.Config) error { return nil },
		probe:  func(*cobra.Command, *config.Config) error { return nil },
		pluginStatsEnrich: func(c *cobra.Command, cc *config.Config) error {
			return runPluginStatsEnrichment(c, cc, nil, reader)
		},
		stats:   func(c *cobra.Command, cc *config.Config) error { return runStatsStage(c, cc, reader) },
		prune:   func(c *cobra.Command, cc *config.Config) error { return runPruneStage(c, cc, reader) },
		selectS: func(c *cobra.Command, cc *config.Config) error { return runSelect(c, cc, reader) },
		render:  func(c *cobra.Command, cc *config.Config) error { return runRender(c, cc, reader) },
	}
	opts := maintainOptions{skipProbe: true, noActivate: true}
	require.NoError(t, runMaintain(out, cfg, opts, stages))
}

func normalizeSelectionForParity(t *testing.T, raw []byte) []byte {
	t.Helper()
	var sel model.Selection
	require.NoError(t, json.Unmarshal(raw, &sel))
	sel.GeneratedAt = time.Time{}
	norm, err := json.MarshalIndent(&sel, "", "  ")
	require.NoError(t, err)
	return append(norm, '\n')
}

func fixtureGoldenPath(name string) string {
	return filepath.Join("testdata", "allocparity", name)
}

// countingCache wraps the cache loaders with per-file disk-read counters.
func countingCache(t *testing.T) (*waveRecordCache, *map[string]int) {
	t.Helper()
	counts := map[string]int{}
	c := newWaveRecordCache()
	c.loadNodes = func(path string) ([]*model.Node, error) {
		counts[filepath.Base(path)]++
		return store.ReadNodes(path)
	}
	c.loadGeo = func(path string) ([]*model.GeoRecord, error) {
		counts[filepath.Base(path)]++
		return store.ReadGeo(path)
	}
	c.loadProbe = func(path string) (map[string]store.ProbeResult, error) {
		counts[filepath.Base(path)]++
		return store.LatestProbeByKey(path)
	}
	return c, &counts
}

// TestAllocWaveStoreFilesReadOncePerWave is the F1 gate: within ONE wave
// process, each store file is read from disk exactly once, no matter how
// many stages consume it (the tail consumes filtered 4x, geo-base 5x, and
// the probe journal 2x — every re-read re-unmarshals every line into fresh
// structs, the churn class behind the swap incident).
func TestAllocWaveStoreFilesReadOncePerWave(t *testing.T) {
	dir := t.TempDir()
	cfg := fixtureConfig(t, dir)
	seedAllocFixture(t, cfg)

	cache, counts := countingCache(t)
	runAllocFixtureWave(t, cfg, cache)

	for _, file := range []string{"filtered.jsonl", "geo-base.jsonl", "probe-results.jsonl"} {
		require.LessOrEqual(t, (*counts)[file], 1,
			"%s must be read from disk at most once per wave (got %d reads — the wave is re-reading the store)", file, (*counts)[file])
	}
}

// TestWaveRecordCacheWriteInvalidation pins the audit-F1 write contract:
// a stage write that replaces a cached file must be visible to the next
// consumer. The probe-journal entry populated BEFORE probe.Run's rewrite is
// dropped by InvalidateProbe (the loader runs again); SetGeo publishes the
// exact records a stage wrote (no reload); a nil cache reads the store
// directly (single-stage verb semantics).
func TestWaveRecordCacheWriteInvalidation(t *testing.T) {
	dir := t.TempDir()
	cfg := fixtureConfig(t, dir)
	nodes := seedAllocFixture(t, cfg)
	p := newPaths(cfg)

	cache, counts := countingCache(t)

	// First read populates (loader runs once).
	first, err := cache.ReadLatestProbe(p.probeResults)
	require.NoError(t, err)
	require.Len(t, first, 8)
	// Cached second read: no loader call, identical content (map identity
	// proven by the untouched load counter — Equal is the map contract).
	second, err := cache.ReadLatestProbe(p.probeResults)
	require.NoError(t, err)
	require.Equal(t, first, second, "the cached map is reused within the wave")
	require.Equal(t, 1, (*counts)["probe-results.jsonl"])

	// The stage write invalidates: the next read is a fresh load carrying
	// the post-write truth.
	cache.InvalidateProbe()
	third, err := cache.ReadLatestProbe(p.probeResults)
	require.NoError(t, err)
	require.Equal(t, 2, (*counts)["probe-results.jsonl"], "the invalidated entry reloads from disk")
	require.Equal(t, third, cache.probe, "the reload repopulates the cache")

	// SetGeo publishes the written records without a reload. Slice identity
	// is proven by mutating through the returned slice and observing the
	// written set change (same backing array).
	written := []*model.GeoRecord{{Scheme: "vless", Host: "written.example.com", Port: 443}}
	cache.SetGeo(written)
	got, err := cache.ReadGeo(p.geoBase)
	require.NoError(t, err)
	require.Equal(t, 0, (*counts)["geo-base.jsonl"], "a published set never triggers a disk read")
	got[0].Country = "identity-probe"
	require.Equal(t, "identity-probe", written[0].Country,
		"SetGeo publishes the written set verbatim (same backing array, no copy)")

	// Nil cache: direct store reads (single-stage verbs).
	var nilCache *waveRecordCache
	direct, err := nilCache.ReadNodes(p.filtered)
	require.NoError(t, err)
	require.Len(t, direct, len(nodes))
}

// TestAllocWaveParityAgainstPreChangeGoldens pins the refactor's observable
// contract: the wave's store outputs are BYTE-IDENTICAL to the pre-change
// tree's outputs on this fixture corpus, and the cache path matches the
// legacy direct-read path byte for byte.
//
// Golden provenance: originally generated on the base commit a70c40d
// (pre-alloc12, pre-balancer-never-empty) to prove the alloc12 read-once
// refactor changed no observable output; DELIBERATELY REGENERATED on
// integration/mem-alloc-bal after the balancer-never-empty contract wave
// (fix/render d3fabeb) changed the RENDERED candidate's balancer section by
// design — runtime fallback chain (variant → country → pool_all → block at
// the root) and widened empty clean/service tiers. Every candidate delta was
// classified against that contract before regeneration: 12 fallbackTag
// re-parentings + 4 widened country-clean tiers, all intended; the six
// actual store files (filtered/geo-base/selection/manifest/probe-results/
// known-alive) remain byte-identical to the a70c40d goldens. The test's
// purpose is unchanged: any future change to the read/cache paths or to a
// store artifact's content that is not accompanied by a deliberate golden
// regeneration fails here.
//
// selection.json is compared with generated_at normalized (the one
// wall-clock field rank stamps); provider-history.json and the prune backup
// name carry wall-clock stamps and are excluded (asserted for existence
// instead).
func TestAllocWaveParityAgainstPreChangeGoldens(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reader *waveRecordCache
	}{
		{name: "legacy direct-store path", reader: nil},
		{name: "wave-scoped cache path", reader: newWaveRecordCache()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := fixtureConfig(t, dir)
			seedAllocFixture(t, cfg)
			runAllocFixtureWave(t, cfg, tc.reader)
			p := newPaths(cfg)

			for _, pair := range [][2]string{
				{p.filtered, "filtered.jsonl"},
				{p.geoBase, "geo-base.jsonl"},
				{p.selection, "selection.json"},
				{ownCandidatePath(p), "candidate.json"},
				{p.manifest, "manifest.json"},
				{p.probeResults, "probe-results.jsonl"},
				{p.knownAlive, "known-alive.jsonl"},
			} {
				got, err := os.ReadFile(pair[0])
				require.NoError(t, err, "source %s", pair[0])
				want, err := os.ReadFile(fixtureGoldenPath(pair[1]))
				require.NoError(t, err, "golden %s", pair[1])
				if pair[1] == "selection.json" {
					got = normalizeSelectionForParity(t, got)
				}
				require.Equal(t, string(want), string(got),
					"%s must be byte-identical to the pre-change tree's output (golden-equal parity)", pair[1])
			}
			// The prune pass exercised the backup path (removals happened).
			entries, err := os.ReadDir(p.dataDir)
			require.NoError(t, err)
			sawBackup := false
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "geo-base.jsonl.bak-") {
					sawBackup = true
				}
			}
			require.True(t, sawBackup, "the fixture prune must exercise the backup path")
		})
	}
}

// TestMaintainStagesCarryTheWaveCache pins the daemon-override contract
// (allocation audit F1): the wave's stage set exposes THE cache its runners
// use, so a caller that replaces a runner (the daemon re-binds probe and
// pluginStatsEnrich for its beat feed) threads the same cache — running a
// stage through the set must populate stages.cache, proving the runners
// share it instead of holding a private copy.
func TestMaintainStagesCarryTheWaveCache(t *testing.T) {
	dir := t.TempDir()
	cfg := fixtureConfig(t, dir)
	seedAllocFixture(t, cfg)
	prevStats := recordStageStatFunc
	recordStageStatFunc = func(string, StageStat) error { return nil }
	t.Cleanup(func() { recordStageStatFunc = prevStats })

	stages := defaultMaintainStages(maintainOptions{}, nil)
	require.NotNil(t, stages.cache, "the wired stage set must expose the wave cache for runner overrides")

	cmd := &cobra.Command{}
	require.NoError(t, stages.selectS(cmd, cfg))
	require.True(t, stages.cache.haveFiltered, "the stage runner must read through stages.cache (the set's own cache)")
	require.True(t, stages.cache.haveGeo, "the stage runner must read through stages.cache (the set's own cache)")
	require.True(t, stages.cache.haveProbe, "the stage runner must read through stages.cache (the set's own cache)")
}
