package cli

import (
	"assay/internal/model"
	"assay/internal/store"
)

// waveRecordCache is the wave-scoped store-read seam (allocation audit F1):
// within ONE wave process the store files are read from disk once and every
// later consumer reuses the parsed records — filtered.jsonl was re-read by
// five stages, geo-base by seven, the probe journal by up to five, and every
// pass re-unmarshaled every line into fresh structs (the allocation-churn
// class behind the 148k-node swap incident).
//
// The disk files REMAIN the truth (W17): they are still written at stage end
// exactly as before, and every stage write that replaces a cached file
// updates or invalidates the corresponding entry (SetGeo / InvalidateProbe /
// InvalidateGeo), so a consumer never sees content differing from the store
// file at its stage boundary:
//
//   - probe.Run's AppendProbeResults rewrites the journal inside the store
//     layer → runProbe calls InvalidateProbe after the stage's write;
//   - the classification flush rewrites geo-base (geo.Classifier.Flush) →
//     flushClassifier calls InvalidateGeo after the flush;
//   - runStatsStage's fold write and runPruneStage's prune rewrite both
//     write records this package holds → SetGeo publishes exactly the
//     written records;
//   - runFilter's filtered.jsonl write happens BEFORE the first wave
//     consumer reads it (stage order), so no hook is needed there.
//
// A nil *waveRecordCache is valid everywhere: single-stage CLI verbs
// (assay select / render / prune / ...) read from disk directly —
// byte-identical to the pre-cache tree.
type waveRecordCache struct {
	filtered []*model.Node
	geo      []*model.GeoRecord
	probe    map[string]store.ProbeResult

	haveFiltered bool
	haveGeo      bool
	haveProbe    bool

	// Loader seams: production wiring leaves them at the store defaults;
	// tests count disk reads through them.
	loadNodes func(string) ([]*model.Node, error)
	loadGeo   func(string) ([]*model.GeoRecord, error)
	loadProbe func(string) (map[string]store.ProbeResult, error)
}

// newWaveRecordCache builds the wave's empty cache.
func newWaveRecordCache() *waveRecordCache {
	return &waveRecordCache{
		loadNodes: store.ReadNodes,
		loadGeo:   store.ReadGeo,
		loadProbe: store.LatestProbeByKey,
	}
}

// ReadNodes returns the wave's filtered records, loading them from disk at
// first need.
func (c *waveRecordCache) ReadNodes(path string) ([]*model.Node, error) {
	if c == nil {
		return store.ReadNodes(path)
	}
	if !c.haveFiltered {
		nodes, err := c.loadNodes(path)
		if err != nil {
			return nil, err
		}
		c.filtered, c.haveFiltered = nodes, true
	}
	return c.filtered, nil
}

// ReadGeo returns the wave's cold-base records, loading them from disk at
// first need.
func (c *waveRecordCache) ReadGeo(path string) ([]*model.GeoRecord, error) {
	if c == nil {
		return store.ReadGeo(path)
	}
	if !c.haveGeo {
		recs, err := c.loadGeo(path)
		if err != nil {
			return nil, err
		}
		c.geo, c.haveGeo = recs, true
	}
	return c.geo, nil
}

// ReadLatestProbe returns the wave's latest-per-key probe evidence, loading
// the journal from disk at first need.
func (c *waveRecordCache) ReadLatestProbe(path string) (map[string]store.ProbeResult, error) {
	if c == nil {
		return store.LatestProbeByKey(path)
	}
	if !c.haveProbe {
		probe, err := c.loadProbe(path)
		if err != nil {
			return nil, err
		}
		c.probe, c.haveProbe = probe, true
	}
	return c.probe, nil
}

// SetGeo publishes the records a stage just WROTE to geo-base: the write is
// authoritative, so the cache must carry exactly the file's new content.
func (c *waveRecordCache) SetGeo(records []*model.GeoRecord) {
	if c == nil {
		return
	}
	c.geo, c.haveGeo = records, true
}

// InvalidateProbe drops the probe-journal entry (probe.Run rewrote the file
// inside the store layer; a pre-write entry is stale).
func (c *waveRecordCache) InvalidateProbe() {
	if c == nil {
		return
	}
	c.probe, c.haveProbe = nil, false
}

// InvalidateGeo drops the geo entry (a stage rewrote the file outside this
// cache's Set discipline).
func (c *waveRecordCache) InvalidateGeo() {
	if c == nil {
		return
	}
	c.geo, c.haveGeo = nil, false
}
