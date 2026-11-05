package plugins

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPluginStatsCollection tests the plugin stats aggregation from plugin nodes.
func TestPluginStatsCollection(t *testing.T) {
	// Create mock geo records
	geoRecords := []*GeoRecord{
		{Scheme: "vless", Host: "example.com", Port: 443, HostingFlag: true, ProxyFlag: false},
		{Scheme: "vmess", Host: "test.org", Port: 8443, HostingFlag: false, ProxyFlag: true},
		{Scheme: "trojan", Host: "clean.net", Port: 443, HostingFlag: false, ProxyFlag: false},
		{Scheme: "ss", Host: "unknown.io", Port: 8388, HostingFlag: false, ProxyFlag: false},
		{Scheme: "vless", Host: "other.com", Port: 443, HostingFlag: false, ProxyFlag: false},
		{Scheme: "vmess", Host: "another.org", Port: 8443, HostingFlag: false, ProxyFlag: false},
	}

	collector := NewPluginStatsCollector(geoRecords)

	// Plugin A nodes - 5 unique nodes (different Raw URIs = different keys)
	nodesA := []Node{
		{Raw: "vless://uuid1@example.com:443?security=tls#node1", Source: "pluginA", Scheme: "vless", Host: "example.com", Port: 443},
		{Raw: "vmess://uuid2@test.org:8443?security=tls#node2", Source: "pluginA", Scheme: "vmess", Host: "test.org", Port: 8443},
		{Raw: "trojan://uuid3@clean.net:443?security=tls#node3", Source: "pluginA", Scheme: "trojan", Host: "clean.net", Port: 443},
		{Raw: "ss://uuid4@unknown.io:8388?method=aes-256-gcm#node4", Source: "pluginA", Scheme: "ss", Host: "unknown.io", Port: 8388},
		// Different Raw URI but same server (different credentials) - different key
		{Raw: "vless://uuid5@example.com:443?security=tls&type=ws#node5", Source: "pluginA", Scheme: "vless", Host: "example.com", Port: 443},
	}

	// Plugin B nodes - 3 nodes, one cross-plugin duplicate with pluginA
	nodesB := []Node{
		{Raw: "vless://uuid6@other.com:443?security=tls#node6", Source: "pluginB", Scheme: "vless", Host: "other.com", Port: 443},
		// Cross-plugin duplicate: SAME Raw URI as pluginA's first node
		{Raw: "vless://uuid1@example.com:443?security=tls#node1", Source: "pluginB", Scheme: "vless", Host: "example.com", Port: 443},
		{Raw: "vmess://uuid8@another.org:8443?security=tls#node8", Source: "pluginB", Scheme: "vmess", Host: "another.org", Port: 8443},
	}

	collector.AddPluginNodes("pluginA", nodesA)
	collector.AddPluginNodes("pluginB", nodesB)

	// Compute basic stats (total nodes, duplicates)
	collector.ComputeBasicStats()

	// Verify TotalNodes
	statsA := collector.GetPluginStats("pluginA")
	statsB := collector.GetPluginStats("pluginB")

	if statsA.TotalNodes != 5 {
		t.Errorf("pluginA TotalNodes = %d, want 5", statsA.TotalNodes)
	}
	if statsB.TotalNodes != 3 {
		t.Errorf("pluginB TotalNodes = %d, want 3", statsB.TotalNodes)
	}

	// Verify DuplicateCount
	// Key K1 (from nodesA[0] and nodesB[1] - same Raw URI): appears in pluginA (1 node) and pluginB (1 node)
	// Key K2 (from nodesA[4] - different Raw but same server): appears only in pluginA (1 node) - not a cross-plugin duplicate
	// So pluginA DuplicateCount = 1 (only node0 shares key with pluginB)
	// pluginB DuplicateCount = 1 (its node1 shares key with pluginA)
	if statsA.DuplicateCount != 1 {
		t.Errorf("pluginA DuplicateCount = %d, want 1", statsA.DuplicateCount)
	}
	if statsB.DuplicateCount != 1 {
		t.Errorf("pluginB DuplicateCount = %d, want 1", statsB.DuplicateCount)
	}

	// Live nodes - each unique key gets its own liveness
	liveByKey := map[string]bool{
		computeNodeKey(nodesA[0]): true,  // live (shared with pluginB)
		computeNodeKey(nodesA[1]): true,  // live
		computeNodeKey(nodesA[2]): false, // dead
		computeNodeKey(nodesA[3]): true,  // live
		computeNodeKey(nodesA[4]): true,  // live (unique key, different from nodesA[0])
		computeNodeKey(nodesB[0]): true,  // live
		computeNodeKey(nodesB[1]): true,  // live (same key as pluginA[0])
		computeNodeKey(nodesB[2]): false, // dead
	}

	collector.ComputeEnrichedStats(liveByKey)

	// Refresh stats
	statsA = collector.GetPluginStats("pluginA")
	statsB = collector.GetPluginStats("pluginB")

	// pluginA live nodes: all 5 nodes have unique keys, 4 are live (index 2 is dead)
	if statsA.LiveNodes != 4 {
		t.Errorf("pluginA LiveNodes = %d, want 4", statsA.LiveNodes)
	}
	// pluginB live nodes: 2 live (index 0 and 1), 1 dead (index 2)
	if statsB.LiveNodes != 2 {
		t.Errorf("pluginB LiveNodes = %d, want 2", statsB.LiveNodes)
	}

	// Verify hosting/proxy/clean counts
	// pluginA: 5 nodes total
	// - node0: vless://example.com:443 -> geo has HostingFlag=true -> hosting
	// - node1: vmess://test.org:8443 -> geo has ProxyFlag=true -> proxy
	// - node2: trojan://clean.net:443 -> geo has neither -> clean
	// - node3: ss://unknown.io:8388 -> geo has neither -> clean
	// - node4: vless://example.com:443 (different Raw, same server) -> same geo as node0 -> hosting
	// So: hosting=2, proxy=1, clean=2
	if statsA.HostingCount != 2 {
		t.Errorf("pluginA HostingCount = %d, want 2", statsA.HostingCount)
	}
	if statsA.ProxyCount != 1 {
		t.Errorf("pluginA ProxyCount = %d, want 1", statsA.ProxyCount)
	}
	if statsA.CleanCount != 2 {
		t.Errorf("pluginA CleanCount = %d, want 2", statsA.CleanCount)
	}

	// pluginB: 3 nodes
	// - node0: vless://other.com:443 -> geo has neither -> clean
	// - node1: vless://example.com:443 (same as pluginA node0) -> geo has HostingFlag=true -> hosting
	// - node2: vmess://another.org:8443 -> geo has neither -> clean
	// So: hosting=1, proxy=0, clean=2
	if statsB.HostingCount != 1 {
		t.Errorf("pluginB HostingCount = %d, want 1", statsB.HostingCount)
	}
	if statsB.ProxyCount != 0 {
		t.Errorf("pluginB ProxyCount = %d, want 0", statsB.ProxyCount)
	}
	if statsB.CleanCount != 2 {
		t.Errorf("pluginB CleanCount = %d, want 2", statsB.CleanCount)
	}

	// Test GetStats returns all plugins
	allStats := collector.GetStats()
	if len(allStats) != 2 {
		t.Errorf("GetStats returned %d plugins, want 2", len(allStats))
	}

	// Test nil geo records (during fetch before geo stage)
	collectorNoGeo := NewPluginStatsCollector(nil)
	collectorNoGeo.AddPluginNodes("pluginC", []Node{
		{Raw: "vless://uuid@test.com:443?security=tls#node", Source: "pluginC", Scheme: "vless", Host: "test.com", Port: 443},
	})
	collectorNoGeo.ComputeBasicStats()
	collectorNoGeo.ComputeEnrichedStats(map[string]bool{computeNodeKey(collectorNoGeo.AllNodes[0].node): true})

	statsC := collectorNoGeo.GetPluginStats("pluginC")
	if statsC.TotalNodes != 1 {
		t.Errorf("pluginC TotalNodes = %d, want 1", statsC.TotalNodes)
	}
	if statsC.LiveNodes != 1 {
		t.Errorf("pluginC LiveNodes = %d, want 1", statsC.LiveNodes)
	}
	// Classified-only counting (owner ruling 2026-11-04): with no geo
	// records nothing is classified — CleanCount stays 0 (the old
	// "all clean" fold fabricated clean evidence), ClassifiedCount 0.
	if statsC.CleanCount != 0 {
		t.Errorf("pluginC CleanCount = %d, want 0 (nothing geo-classified)", statsC.CleanCount)
	}
	if statsC.ClassifiedCount != 0 {
		t.Errorf("pluginC ClassifiedCount = %d, want 0 (no geo records)", statsC.ClassifiedCount)
	}
}

// TestGetStatsDeterministicOrder pins F3: GetStats returns plugins ordered
// by PluginID. Go map iteration order must never reach the disk (store.go's
// determinism invariant) — plugin_stats in fetch-manifest.json used to
// shuffle per run (proven 199/200 by the adversarial review).
func TestGetStatsDeterministicOrder(t *testing.T) {
	collector := NewPluginStatsCollector(nil)
	for _, id := range []string{"zeta", "alpha", "mid", "beta", "gamma"} {
		collector.AddPluginNodes(id, []Node{{Raw: id + "://x@a.example:443"}})
	}
	ids := make([]string, 0, len(collector.Stats))
	for _, st := range collector.GetStats() {
		ids = append(ids, st.PluginID)
	}
	assert.Equal(t, []string{"alpha", "beta", "gamma", "mid", "zeta"}, ids,
		"GetStats must be deterministically ordered by PluginID")
}

// TestComputeEnrichedStatsClassifiedOnly pins F6's collector half: nodes
// without a geo record are UNCLASSIFIED — never folded into CleanCount. The
// honest clean share is CleanCount/ClassifiedCount (classified-only
// numerator AND denominator, owner ruling 2026-11-04).
func TestComputeEnrichedStatsClassifiedOnly(t *testing.T) {
	geoRecords := []*GeoRecord{
		{Scheme: "vless", Host: "clean.example", Port: 443},
		{Scheme: "vless", Host: "hosting.example", Port: 443, HostingFlag: true},
	}
	collector := NewPluginStatsCollector(geoRecords)
	collector.AddPluginNodes("pluginP", []Node{
		{Raw: "vless://u1@clean.example:443#n1", Source: "pluginP", Scheme: "vless", Host: "clean.example", Port: 443},
		{Raw: "vless://u2@hosting.example:443#n2", Source: "pluginP", Scheme: "vless", Host: "hosting.example", Port: 443},
		{Raw: "vless://u3@ungeo1.example:443#n3", Source: "pluginP", Scheme: "vless", Host: "ungeo1.example", Port: 443},
		{Raw: "vless://u4@ungeo2.example:443#n4", Source: "pluginP", Scheme: "vless", Host: "ungeo2.example", Port: 443},
	})
	collector.ComputeBasicStats()
	collector.ComputeEnrichedStats(nil)

	st := collector.GetPluginStats("pluginP")
	assert.Equal(t, 2, st.ClassifiedCount, "only geo'd nodes are classified")
	assert.Equal(t, 1, st.CleanCount, "ungeo'd nodes are never counted as clean")
	assert.Equal(t, 1, st.HostingCount)
}

// TestCleanPercentClassifiedOnly pins the F6 reporting formula:
// CleanPercent = Clean/Classified when Classified>0, else 0 (unknown).
func TestCleanPercentClassifiedOnly(t *testing.T) {
	tests := []struct {
		name        string
		clean       int
		classified  int
		wantPercent float64
	}{
		{"honest share", 3, 4, 75.0},
		{"all classified clean", 5, 5, 100.0},
		{"no classified nodes", 0, 0, 0},
		{"clean without classified is impossible but reports 0", 2, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := PluginStats{CleanCount: tc.clean, ClassifiedCount: tc.classified}
			assert.InDelta(t, tc.wantPercent, st.CleanPercent(), 1e-9)
		})
	}
}

// TestGeoIdentityKey tests the GeoIdentityKey function.
func TestGeoIdentityKey(t *testing.T) {
	key := GeoIdentityKey("vless", "Example.COM", 443)
	expected := "vless|example.com|443"
	if key != expected {
		t.Errorf("GeoIdentityKey = %q, want %q", key, expected)
	}

	key = GeoIdentityKey("vmess", "TEST.ORG", 8443)
	expected = "vmess|test.org|8443"
	if key != expected {
		t.Errorf("GeoIdentityKey = %q, want %q", key, expected)
	}
}

// TestComputeNodeKey tests the node key computation.
func TestComputeNodeKey(t *testing.T) {
	n1 := Node{
		Scheme: "vless",
		Host:   "example.com",
		Port:   443,
		Raw:    "vless://uuid123@example.com:443?security=tls#node",
	}
	key1 := computeNodeKey(n1)

	// Same node should produce same key
	n2 := Node{
		Scheme: "vless",
		Host:   "example.com",
		Port:   443,
		Raw:    "vless://uuid123@example.com:443?security=tls#node",
	}
	key2 := computeNodeKey(n2)

	if key1 != key2 {
		t.Errorf("computeNodeKey not stable: %q != %q", key1, key2)
	}

	// Different Raw should produce different key
	n3 := Node{
		Scheme: "vless",
		Host:   "example.com",
		Port:   443,
		Raw:    "vless://uuid456@example.com:443?security=tls#node",
	}
	key3 := computeNodeKey(n3)
	if key1 == key3 {
		t.Errorf("computeNodeKey same for different Raw URIs")
	}
}
