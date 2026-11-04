package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// PluginStats holds per-plugin statistics collected during a fetch wave.
// These stats feed the status command and the threshold enforcement
// (MaxDuplicatePercent, MinLivePercent from PluginsConfig).
//
// Field lifecycle across the wave: TotalNodes and DuplicateCount are
// fetch-stage facts; LiveNodes, HostingCount, ProxyCount and CleanCount
// are enriched after probe+geo (runPluginStatsEnrichment) and reflect the
// FULL wave cycle.
type PluginStats struct {
	PluginID       string
	TotalNodes     int
	LiveNodes      int
	DuplicateCount int // bidirectional: nodes with same key from other plugins
	HostingCount   int
	ProxyCount     int
	CleanCount     int // !hosting && !proxy
}

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

	// Compute hosting/proxy/clean counts per plugin using geo records
	for pluginID, st := range c.Stats {
		hosting, proxy, clean := 0, 0, 0
		for _, pn := range c.AllNodes {
			if pn.pluginID != pluginID {
				continue
			}
			// Look up geo record by GeoIdentity key
			geoKey := geoIdentityKey(pn.node.Scheme, pn.node.Host, pn.node.Port)
			if gr, ok := c.GeoByKey[geoKey]; ok {
				if gr.HostingFlag {
					hosting++
				}
				if gr.ProxyFlag {
					proxy++
				}
				if !gr.HostingFlag && !gr.ProxyFlag {
					clean++
				}
			} else {
				// No geo record - treat as clean (unknown)
				clean++
			}
		}
		st.HostingCount = hosting
		st.ProxyCount = proxy
		st.CleanCount = clean
	}
}

// GetStats returns the computed stats for all plugins.
func (c *PluginStatsCollector) GetStats() []PluginStats {
	out := make([]PluginStats, 0, len(c.Stats))
	for _, st := range c.Stats {
		out = append(out, *st)
	}
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
