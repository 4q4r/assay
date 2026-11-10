// Package prune implements the W4 dead-node pruning (DESIGN.md §4.9). Two
// rules, both sharing rank's own freshness semantics (AliveDataFresh — never
// a divergent copy):
//
//   - dead_after: a record that is not alive and whose last_probe is strictly
//     older than maintain.prune_dead_after is removed (default 48h).
//   - ttl-stale orphan: a record that rank's geo.ttl freshness check already
//     refuses for selection AND whose node no longer appears in the current
//     filtered set (the source dropped the link) is removed physically.
//     A stale record still referenced by the sources stays: a future probe
//     can refresh it, so no recoverable state is destroyed.
package prune

import (
	"time"

	"assay/internal/model"
	"assay/internal/rank"
)

// Options bundles one pruning pass's inputs.
type Options struct {
	DeadAfter time.Duration // maintain.prune_dead_after (default 48h)
	TTL       time.Duration // geo.ttl — rank's alive-freshness window
	Now       time.Time     // injected clock (no sleeps, deterministic tests)
}

// Report summarizes one pass.
type Report struct {
	RemovedDead     int // rule A hits
	RemovedStale    int // rule B hits
	Kept            int `json:"-"`
	RemovedTags     []string
	RemovedIdentity []string
}

// Select partitions records into (kept, removed) under the pruning rules.
// filteredIdentities carries model.GeoIdentity keys of the just-filtered node
// set — the same identity key rank's candidate lookup builds.
func Select(
	records []*model.GeoRecord,
	filteredIdentities map[string]bool,
	opts Options,
) ([]*model.GeoRecord, []*model.GeoRecord, Report) {
	var kept, removed []*model.GeoRecord
	var report Report
	for _, r := range records {
		id := model.GeoIdentity(r)
		switch {
		case ruleDead(r, opts):
			removed = append(removed, r)
			report.RemovedDead++
			report.RemovedTags = append(report.RemovedTags, r.Tag)
			report.RemovedIdentity = append(report.RemovedIdentity, id)
		case ruleStaleOrphan(r, filteredIdentities, opts):
			removed = append(removed, r)
			report.RemovedStale++
			report.RemovedTags = append(report.RemovedTags, r.Tag)
			report.RemovedIdentity = append(report.RemovedIdentity, id)
		default:
			kept = append(kept, r)
			report.Kept++
		}
	}
	return kept, removed, report
}

// ruleDead: not alive AND last_probe strictly older than dead_after. A record
// with no parseable last_probe has no death evidence — it falls through to
// the orphan rule instead.
func ruleDead(r *model.GeoRecord, opts Options) bool {
	if r.Alive {
		return false
	}
	t, ok := parseLastProbe(r.LastProbe)
	if !ok {
		return false
	}
	return opts.Now.Sub(t) > opts.DeadAfter
}

// ruleStaleOrphan: rank's ttl freshness refuses the record AND the node is no
// longer in the filtered set — rank can never select it again on this data.
func ruleStaleOrphan(r *model.GeoRecord, filteredIdentities map[string]bool, opts Options) bool {
	if filteredIdentities[model.GeoIdentity(r)] {
		return false
	}
	return !rank.AliveDataFresh(r.LastProbe, opts.TTL, opts.Now)
}

func parseLastProbe(lastProbe string) (time.Time, bool) {
	if lastProbe == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, lastProbe)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
