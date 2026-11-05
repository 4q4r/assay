package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// PluginStats holds per-plugin statistics collected during a fetch wave.
// These stats feed the status command and the threshold enforcement
// (MaxDuplicatePercent, MinLivePercent from PluginsConfig).
//
// Field lifecycle across the wave: TotalNodes and DuplicateCount are
// fetch-stage facts; LiveNodes, HostingCount, ProxyCount, CleanCount,
// ClassifiedCount and UnlockCount are enriched after probe+geo
// (runPluginStatsEnrichment) and reflect the FULL wave cycle; UniqueYield
// and TopOverlaps come from the pairwise identity-overlap matrix computed
// at enrichment time.
type PluginStats struct {
	PluginID       string
	TotalNodes     int
	LiveNodes      int
	DuplicateCount int // bidirectional: nodes with same key from other plugins
	HostingCount   int
	ProxyCount     int
	// CleanCount counts the plugin's geo-CLASSIFIED nodes that are neither
	// hosting nor proxy. Nodes without a geo record are unclassified —
	// never folded into clean (owner ruling 2026-11-04, adversarial
	// review F6).
	CleanCount int
	// ClassifiedCount is the number of the plugin's nodes WITH a geo
	// record (geo-classified). The honest clean share is
	// CleanCount/ClassifiedCount — classified-only numerator AND
	// denominator (CleanPercent).
	ClassifiedCount int
	// UnlockCount counts the plugin's parse records whose geo record carries
	// a CHECKED Phase-1 media-unlock status with at least one positive
	// unlock signal (the [geo].unlock_probes stage must be on for any of
	// these to exist).
	UnlockCount int
	// UniqueYield is the % of the plugin's DISTINCT geo identities that no
	// other plugin also carries (the provider-pruning signal: a plugin whose
	// yield is ~0 adds nothing to the pool).
	UniqueYield float64
	// TopOverlaps lists the strongest overlap partners (descending percent,
	// plugin-id tie-break, max 2) — e.g. "matin (61%), mhd (18%)".
	TopOverlaps []OverlapPair
}

// OverlapPair is one directional overlap share: Percent is the share of the
// OWNING plugin's distinct identities that PluginID also carries.
type OverlapPair struct {
	PluginID string  `json:"plugin_id"`
	Percent  float64 `json:"percent"`
}

// OverlapMatrix is the full pairwise identity-overlap structure. Sets maps
// each plugin to its distinct GeoIdentity count; Cells[A][B] is
// |A∩B| / |A| × 100. Phase 4's --overlap view consumes the whole matrix —
// the per-plugin TopOverlaps are just its top-2 projection.
type OverlapMatrix struct {
	Sets  map[string]int                `json:"sets"`
	Cells map[string]map[string]float64 `json:"cells"`
}

// topOverlapPartners is how many partners each PluginStats carries.
const topOverlapPartners = 2

// pluginsNode is an internal node wrapper carrying the plugin id.
type pluginsNode struct {
	pluginID string
	node     Node
	key      string // computed key for duplicate detection
}

// GeoRecord is the cold-base geo record (re-exported from internal/model for
// cross-package use without importing the model package into plugins).
type GeoRecord struct {
	Scheme      string
	Host        string
	Port        int
	IP          string
	Country     string
	City        string
	ASN         string
	ASName      string
	ISP         string
	ProxyFlag   bool
	HostingFlag bool
	GeoSource   string
	FirstSeen   string
	LastSeen    string
	LastProbe   string
	RTTMs       float64
	SpeedBPS    int64
	Alive       bool
	BytesUp     int64
	BytesDown   int64
	Tag         string
	Source      string
}

// PluginStatsCollector aggregates per-plugin stats during a fetch wave.
// Collection happens in two phases:
//  1. During fetch: AddPluginNodes collects nodes, ComputeBasicStats computes
//     TotalNodes and DuplicateCount.
//  2. After probe/geo: ComputeEnrichedStats computes LiveNodes, HostingCount,
//     ProxyCount, CleanCount using probe liveness and geo records.
type PluginStatsCollector struct {
	Stats    map[string]*PluginStats // by plugin id
	AllNodes []*pluginsNode          // all nodes from all plugins for duplicate detection
	GeoByKey map[string]*GeoRecord   // geo records keyed by GeoIdentity for hosting/proxy flags
}

// geoIdentityKey computes the GeoIdentity key: scheme|lowercase(host)|port.
func geoIdentityKey(scheme, host string, port int) string {
	return scheme + "|" + strings.ToLower(host) + "|" + strconv.Itoa(port)
}

// GeoIdentityKey is the public version of geoIdentityKey for cross-package use.
func GeoIdentityKey(scheme, host string, port int) string {
	return geoIdentityKey(scheme, host, port)
}

// NewPluginStatsCollector creates a new collector. Geo records can be nil
// during fetch; they can be set later via SetGeoRecords for enrichment.
func NewPluginStatsCollector(geoRecords []*GeoRecord) *PluginStatsCollector {
	var geoByKey map[string]*GeoRecord
	if geoRecords != nil {
		geoByKey = make(map[string]*GeoRecord, len(geoRecords))
		for _, g := range geoRecords {
			key := geoIdentityKey(g.Scheme, g.Host, g.Port)
			geoByKey[key] = g
		}
	}
	return &PluginStatsCollector{
		Stats:    make(map[string]*PluginStats),
		AllNodes: nil,
		GeoByKey: geoByKey,
	}
}

// SetGeoRecords updates the geo records for enrichment (called after geo stage).
func (c *PluginStatsCollector) SetGeoRecords(geoRecords []*GeoRecord) {
	c.GeoByKey = make(map[string]*GeoRecord, len(geoRecords))
	for _, g := range geoRecords {
		key := geoIdentityKey(g.Scheme, g.Host, g.Port)
		c.GeoByKey[key] = g
	}
}

// AddPluginNodes adds nodes from one plugin to the collector.
func (c *PluginStatsCollector) AddPluginNodes(pluginID string, nodes []Node) {
	if c.Stats[pluginID] == nil {
		c.Stats[pluginID] = &PluginStats{PluginID: pluginID}
	}
	st := c.Stats[pluginID]
	st.TotalNodes += len(nodes)

	// Ensure AllNodes is initialized
	if c.AllNodes == nil {
		c.AllNodes = make([]*pluginsNode, 0)
	}

	for _, n := range nodes {
		// Compute the identity key for this node (same as model.identityKey logic)
		key := computeNodeKey(n)
		c.AllNodes = append(c.AllNodes, &pluginsNode{pluginID: pluginID, node: n, key: key})
	}
}

// ComputeBasicStats computes TotalNodes (already counted) and DuplicateCount.
// Called after all plugins have been added during the fetch wave.
func (c *PluginStatsCollector) ComputeBasicStats() {
	// Count duplicates by key across all plugins
	keyToPlugins := make(map[string]map[string]bool) // key -> set of plugin IDs
	for _, pn := range c.AllNodes {
		if keyToPlugins[pn.key] == nil {
			keyToPlugins[pn.key] = make(map[string]bool)
		}
		keyToPlugins[pn.key][pn.pluginID] = true
	}

	// For each plugin, count how many of its nodes have duplicates in OTHER plugins
	for _, pn := range c.AllNodes {
		pluginsWithKey := keyToPlugins[pn.key]
		if len(pluginsWithKey) > 1 {
			// This key appears in multiple plugins
			// Count it for each plugin that has it
			c.Stats[pn.pluginID].DuplicateCount++
		}
	}
}

// ComputeEnrichedStats computes LiveNodes, HostingCount, ProxyCount, CleanCount.
// Called after probe (for liveByKey) and geo (for geo records) stages.
func (c *PluginStatsCollector) ComputeEnrichedStats(liveByKey map[string]bool) {
	// Compute LiveNodes
	for _, pn := range c.AllNodes {
		if liveByKey[pn.key] {
			c.Stats[pn.pluginID].LiveNodes++
		}
	}

	// Compute hosting/proxy/clean/classified counts per plugin using geo
	// records. Classified-only counting (owner ruling 2026-11-04): a node
	// without a geo record is UNCLASSIFIED — it never enters CleanCount
	// (the old "no geo record - treat as clean" fold fabricated clean
	// evidence, adversarial review F6).
	for pluginID, st := range c.Stats {
		hosting, proxy, clean, classified := 0, 0, 0, 0
		for _, pn := range c.AllNodes {
			if pn.pluginID != pluginID {
				continue
			}
			// Look up geo record by GeoIdentity key
			geoKey := geoIdentityKey(pn.node.Scheme, pn.node.Host, pn.node.Port)
			if gr, ok := c.GeoByKey[geoKey]; ok {
				classified++
				if gr.HostingFlag {
					hosting++
				}
				if gr.ProxyFlag {
					proxy++
				}
				if !gr.HostingFlag && !gr.ProxyFlag {
					clean++
				}
			}
		}
		st.HostingCount = hosting
		st.ProxyCount = proxy
		st.CleanCount = clean
		st.ClassifiedCount = classified
	}
}

// CleanPercent is the honest clean share: clean among geo-CLASSIFIED nodes
// only (CleanCount/ClassifiedCount). ClassifiedCount == 0 means no geo
// evidence — 0, i.e. unknown (owner ruling 2026-11-04: never fold
// never-geo'd nodes into the numerator or the denominator).
func (st PluginStats) CleanPercent() float64 {
	if st.ClassifiedCount <= 0 {
		return 0
	}
	return float64(st.CleanCount) * 100 / float64(st.ClassifiedCount)
}

// GetStats returns the computed stats for all plugins, deterministically
// ordered by PluginID: Go map iteration order must never reach the disk
// (store.go determinism invariant) — plugin_stats in fetch-manifest.json is
// byte-comparable across runs (adversarial review F3).
func (c *PluginStatsCollector) GetStats() []PluginStats {
	out := make([]PluginStats, 0, len(c.Stats))
	for _, st := range c.Stats {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PluginID < out[j].PluginID })
	return out
}

// computeNodeKey computes a key for duplicate detection using the Raw URI hash.
// At fetch time, plugins.Node doesn't have UUID and Params (those are parsed
// from Raw in the parse stage). We use a hash of the Raw URI which uniquely
// identifies the share link. The parse stage will do full dedupe with the
// proper identity key.
func computeNodeKey(n Node) string {
	// Use scheme|host|port|raw hash as a composite key that captures
	// the plugin's hints plus the full raw URI for uniqueness.
	h := sha256.Sum256([]byte(n.Raw))
	rawHash := hex.EncodeToString(h[:])[:16]
	return n.Scheme + "|" + n.Host + "|" + strconv.Itoa(n.Port) + "|" + rawHash
}

// GetPluginStats returns the stats for a specific plugin.
func (c *PluginStatsCollector) GetPluginStats(pluginID string) *PluginStats {
	return c.Stats[pluginID]
}

// ComputeOverlapMatrix builds the full pairwise overlap model from
// per-plugin DISTINCT GeoIdentity sets (identity = scheme|lower(host)|port,
// the model.GeoIdentity string format). Cells[A][B] = |A∩B|/|A|×100 with the
// diagonal pinned at 100 and empty sets producing 0 (never a division by
// zero). Values depend only on the sets — deterministic.
func ComputeOverlapMatrix(identitiesByPlugin map[string]map[string]bool) OverlapMatrix {
	m := OverlapMatrix{
		Sets:  make(map[string]int, len(identitiesByPlugin)),
		Cells: make(map[string]map[string]float64, len(identitiesByPlugin)),
	}
	for id, set := range identitiesByPlugin {
		m.Sets[id] = len(set)
		m.Cells[id] = make(map[string]float64, len(identitiesByPlugin))
	}
	for a, setA := range identitiesByPlugin {
		for b, setB := range identitiesByPlugin {
			switch {
			case a == b:
				m.Cells[a][b] = 100
			case len(setA) == 0:
				m.Cells[a][b] = 0
			default:
				shared := 0
				for identity := range setA {
					if setB[identity] {
						shared++
					}
				}
				m.Cells[a][b] = float64(shared) * 100 / float64(len(setA))
			}
		}
	}
	return m
}

// ApplyOverlap projects the overlap model onto the collector's stats.
// identitiesByPlugin must be the SAME sets the matrix was computed from:
// UniqueYield counts identities carried by no other plugin, and TopOverlaps
// keeps the strongest topOverlapPartners partners from the matrix row
// (descending percent, plugin-id ascending tie-break — deterministic).
func (c *PluginStatsCollector) ApplyOverlap(m OverlapMatrix, identitiesByPlugin map[string]map[string]bool) {
	for id, st := range c.Stats {
		st.TopOverlaps = nil
		distinct := m.Sets[id]
		if distinct == 0 {
			st.UniqueYield = 0
			continue
		}
		unique := 0
		for identity := range identitiesByPlugin[id] {
			if !identityShared(identity, id, identitiesByPlugin) {
				unique++
			}
		}
		st.UniqueYield = float64(unique) * 100 / float64(distinct)

		type pair struct {
			id  string
			pct float64
		}
		partners := make([]pair, 0, len(m.Cells))
		for other := range m.Cells {
			if other == id {
				continue
			}
			// Direction: the share of THIS plugin's identities the partner
			// also carries — Cells[id][other] = |id∩other| / |id| × 100.
			if pct := m.Cells[id][other]; pct > 0 {
				partners = append(partners, pair{id: other, pct: pct})
			}
		}
		sort.Slice(partners, func(i, j int) bool {
			if partners[i].pct != partners[j].pct {
				return partners[i].pct > partners[j].pct
			}
			return partners[i].id < partners[j].id
		})
		for _, p := range partners[:min(len(partners), topOverlapPartners)] {
			st.TopOverlaps = append(st.TopOverlaps, OverlapPair{PluginID: p.id, Percent: p.pct})
		}
	}
}

// identityShared reports whether any OTHER plugin also carries the identity.
func identityShared(identity, owner string, identitiesByPlugin map[string]map[string]bool) bool {
	for other, set := range identitiesByPlugin {
		if other == owner {
			continue
		}
		if set[identity] {
			return true
		}
	}
	return false
}
