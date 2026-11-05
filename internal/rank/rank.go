// Package rank implements the select stage (W2, D5/D7; W19 unbounded flip):
// rank alive nodes by checks then speed (rtt as tiebreaker). Every [select]
// cap defaults to UNBOUNDED (owner order «259 живых, значит 259 раскидываются
// по балансирам стран и городов»): absent/0 = ALL alive nodes go active —
// per-country K unlimited, no soft cap, no ceiling, unknown-geo group
// included — so the render carries every alive node into the country/city
// balancers. An explicit positive knob keeps its D7 cap semantics. Tags are
// flat pool-<cc>-NN (cc=xx for unknown geo).
package rank

import (
	"sort"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/store"
)

// Select builds the active selection. probeByKey (optional) supplies the
// check counts from the latest probe wave; nil means every alive node counts
// as fully checked. maxAliveAge is the geo.ttl wiring: alive data whose
// last_probe is older (or absent) is stale liveness evidence and the node is
// not selectable until re-probed; 0 disables expiry (review finding 7).
//
// W19 cap doctrine (owner no-floor/no-ceiling ruling class — knobs stay, the
// DEFAULT is unbounded): a zero-value SelectConfig selects every alive
// candidate, so the wave emits ALL alive nodes across the country/city
// balancers and the city-expansion threshold is moot (nothing left to
// expand). The unbounded path is O(N log N): one sort + one pass — no
// greedy rescanning.
func Select(
	nodes []*model.Node,
	geo []*model.GeoRecord,
	probeByKey map[string]store.ProbeResult,
	cfg config.SelectConfig,
	maxAliveAge time.Duration,
	knownAlive ...map[string]store.KnownAliveRecord,
) *model.Selection {
	ka := map[string]store.KnownAliveRecord{}
	if len(knownAlive) > 0 && knownAlive[0] != nil {
		ka = knownAlive[0]
	}
	cands := collectCandidates(nodes, geo, probeByKey, cfg, maxAliveAge, ka)
	sortByPrimaryMetrics(cands)
	capApplied := effectiveCap(cands, cfg)
	selected := greedySelect(cands, cfg, capApplied)
	return assignTags(selected, capApplied, cands)
}

// candidate couples a node with its geo+probe facts.
type candidate struct {
	node   *model.Node
	rec    *model.GeoRecord
	checks int
	total  int
}

// collectCandidates gathers alive, geo-tagged nodes whose alive data is
// fresh under maxAliveAge (0 = no expiry). W16: nodes with NO geo evidence
// (empty country) are ADMITTED — the unknown-geo pseudo-location is a cap
// group like a country (owner item 14a: "unknown" never drops a usable
// node); their tags carry the xx pseudo-code and the pool_unknown balancer
// groups them at render time.
func collectCandidates(
	nodes []*model.Node,
	geo []*model.GeoRecord,
	probeByKey map[string]store.ProbeResult,
	cfg config.SelectConfig,
	maxAliveAge time.Duration,
	knownAlive ...map[string]store.KnownAliveRecord,
) []candidate {
	ka := map[string]store.KnownAliveRecord{}
	if len(knownAlive) > 0 && knownAlive[0] != nil {
		ka = knownAlive[0]
	}
	geoByKey := map[string]*model.GeoRecord{}
	for _, g := range geo {
		geoByKey[model.GeoIdentity(g)] = g
	}
	var cands []candidate
	now := time.Now()
	for _, n := range nodes {
		c, ok := admitCandidate(n, geoByKey, probeByKey, cfg, maxAliveAge, ka, now)
		if ok {
			cands = append(cands, c)
		}
	}
	return cands
}

// admitCandidate evaluates one node for inclusion. Returns (candidate, true)
// when the node should be admitted.
func admitCandidate(
	n *model.Node,
	geoByKey map[string]*model.GeoRecord,
	probeByKey map[string]store.ProbeResult,
	cfg config.SelectConfig,
	maxAliveAge time.Duration,
	ka map[string]store.KnownAliveRecord,
	now time.Time,
) (candidate, bool) {
	orig, ok := geoByKey[model.GeoIdentity(&model.GeoRecord{Scheme: n.Scheme, Host: n.Host, Port: n.Port})]
	if !ok {
		return candidate{}, false
	}
	// Clone GeoRecord so mutations (e.g. from knownAlive or node-specific probe status)
	// do not leak across distinct candidates sharing the same pointer or identity.
	gCopy := *orig
	g := &gCopy

	if !ensureAlive(g, n, ka) {
		return candidate{}, false
	}
	if !ensureFresh(g, n, ka, maxAliveAge, now) {
		return candidate{}, false
	}
	if cfg.OnlyClean != nil && *cfg.OnlyClean && !cleanIP(g) {
		return candidate{}, false
	}
	if !probeAllows(n, probeByKey, ka) {
		return candidate{}, false
	}
	c := candidate{node: n, rec: g}
	applyProbeOutcome(&c, n, probeByKey, ka)
	return c, true
}

// probeAllows gates candidates by their OWN latest probe result. The
// knownAlive escape is DELIBERATE (owner ruling 2026-11-04, F7): a node
// whose own latest probe is dead still admits when a ≤2h known-alive record
// exists — anti-flake protection for temp-xray boots, where a single probe
// wave racing a boot must not evict a node the in-client observatory
// (burstObservatory) will drop independently if it is truly dead. The
// in-client observatory is the second dead-node layer.
func probeAllows(n *model.Node, probeByKey map[string]store.ProbeResult, ka map[string]store.KnownAliveRecord) bool {
	if len(probeByKey) == 0 {
		return true
	}
	pr, ok := probeByKey[n.Key]
	if !ok {
		_, ok2 := ka[n.Key]
		return ok2
	}
	if pr.Alive {
		return true
	}
	_, ok2 := ka[n.Key]
	return ok2
}

func ensureAlive(g *model.GeoRecord, n *model.Node, ka map[string]store.KnownAliveRecord) bool {
	if g.Alive {
		return true
	}
	rec, ok2 := ka[n.Key]
	if !ok2 {
		return false
	}
	g.Alive = true
	if g.LastProbe == "" {
		g.LastProbe = rec.LastSeen.UTC().Format(time.RFC3339)
	}
	return true
}

func ensureFresh(
	g *model.GeoRecord, n *model.Node, ka map[string]store.KnownAliveRecord,
	maxAliveAge time.Duration, now time.Time,
) bool {
	if maxAliveAge <= 0 || AliveDataFresh(g.LastProbe, maxAliveAge, now) {
		return true
	}
	rec, ok2 := ka[n.Key]
	if !ok2 || rec.LastSeen.IsZero() || time.Since(rec.LastSeen) > maxAliveAge {
		return false
	}
	g.LastProbe = rec.LastSeen.UTC().Format(time.RFC3339)
	return true
}

func cleanIP(g *model.GeoRecord) bool {
	return g.FlagsVerified && !g.HostingFlag && !g.ProxyFlag
}

func applyProbeOutcome(
	c *candidate, n *model.Node, probeByKey map[string]store.ProbeResult,
	_ map[string]store.KnownAliveRecord,
) {
	pr, ok := probeByKey[n.Key]
	if !ok {
		c.checks, c.total = 1, 1
		return
	}
	if !pr.Alive {
		c.checks, c.total = 1, 1
		return
	}
	c.checks, c.total = pr.Checks, pr.TotalChecks
}

// AliveDataFresh reports whether the record's last_probe timestamp is present
// and within maxAge of now. Unparseable or missing timestamps carry no fresh
// liveness evidence. Exported for the W4 prune stage, which must reuse rank's
// exact freshness semantics (never a divergent copy).
func AliveDataFresh(lastProbe string, maxAge time.Duration, now time.Time) bool {
	if lastProbe == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, lastProbe)
	if err != nil {
		return false
	}
	return now.Sub(t) <= maxAge
}

// sortByPrimaryMetrics orders candidates: checks desc, speed desc, rtt asc,
// key asc (deterministic total order).
func sortByPrimaryMetrics(cands []candidate) {
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.checks != b.checks {
			return a.checks > b.checks
		}
		if a.rec.SpeedBPS != b.rec.SpeedBPS {
			return a.rec.SpeedBPS > b.rec.SpeedBPS
		}
		if a.rec.RTTMs != b.rec.RTTMs {
			return a.rec.RTTMs < b.rec.RTTMs
		}
		return a.node.Key < b.node.Key
	})
}

// distinctCities counts the distinct cities among alive candidates. The
// distinctness unit is the folded key (model.CityKey, M-b): case variants
// of one city count once toward the D7 caps and city diversity.
func distinctCities(cands []candidate) int {
	seen := map[string]bool{}
	for _, c := range cands {
		if c.rec.City != "" {
			seen[model.CityKey(c.rec.City)] = true
		}
	}
	return len(seen)
}

// effectiveCap applies the W19 cap doctrine: absent/0 imposes NO constraint.
// soft_cap absent → ALL alive nodes (the D7 city expansion is moot — there
// is nothing left to expand). An explicit soft_cap keeps D7: it expands to
// cover city diversity only when an explicit city_expand_threshold fires,
// bounded by the ceiling only when the ceiling is itself present.
func effectiveCap(cands []candidate, cfg config.SelectConfig) int {
	n := len(cands)
	if cfg.SoftCap <= 0 {
		return n // unbounded: every alive node goes active
	}
	capApplied := cfg.SoftCap
	if cfg.CityExpandThreshold > 0 {
		cities := distinctCities(cands)
		if cities >= cfg.CityExpandThreshold {
			limit := n
			if cfg.Ceiling > 0 {
				limit = min(cfg.Ceiling, n)
			}
			capApplied = min(max(cities, cfg.SoftCap), limit)
		}
	}
	// Defensive no-op: validation guarantees ceiling ≥ soft_cap when both
	// are positive, and the expansion branch already clamped to
	// min(Ceiling, n).
	if cfg.Ceiling > 0 {
		capApplied = min(capApplied, cfg.Ceiling)
	}
	return capApplied
}

// greedySelect runs the cap-aware greedy pass with the city-diversity
// tie-break inside metric tie-bands. The band width comes from the
// [select].tie_band_rtt_tolerance knob (0 → the DefaultTieBandRTTTolerance).
//
// W19: the unbounded default (no cap left to reach, no K to enforce) takes a
// fast path — every candidate, in the primary sort order, one pass. The
// greedy loop below is O(capApplied × N); it only runs under EXPLICIT caps,
// where capApplied is bounded by the operator's own configuration.
func greedySelect(cands []candidate, cfg config.SelectConfig, capApplied int) []candidate {
	if cfg.PerCountryCap <= 0 && capApplied >= len(cands) {
		return append([]candidate(nil), cands...) // O(N) fast path (sort lives in Select)
	}
	tolerance := cfg.TieBandRTTTolerance
	if tolerance <= 0 {
		tolerance = config.DefaultTieBandRTTTolerance
	}
	selected := make([]candidate, 0, capApplied)
	picked := make([]bool, len(cands))
	countryCount := map[string]int{}
	cityCount := map[string]int{}
	for len(selected) < capApplied {
		base := nextSelectable(cands, picked, countryCount, cfg)
		if base < 0 {
			break
		}
		pick := pickWithCityTieBreak(cands, picked, countryCount, cityCount, cfg, base, tolerance)
		chosen := cands[pick]
		picked[pick] = true
		countryCount[chosen.rec.Country]++
		cityCount[model.CityKey(chosen.rec.City)]++ // folded: variants are one city (M-b)
		selected = append(selected, chosen)
	}
	return selected
}

// nextSelectable returns the first unpicked candidate whose country still has
// headroom under K (0/absent K = unlimited), or -1.
func nextSelectable(cands []candidate, picked []bool, countryCount map[string]int, cfg config.SelectConfig) int {
	for i, c := range cands {
		if picked[i] || (cfg.PerCountryCap > 0 && countryCount[c.rec.Country] >= cfg.PerCountryCap) {
			continue
		}
		return i
	}
	return -1
}

// pickWithCityTieBreak scans the head's tie-band for an unrepresented city.
// Representation is counted through the folded city key (model.CityKey,
// M-b): a case-variant pair is one represented city, so a variant spelling
// never counts as city diversity.
func pickWithCityTieBreak(
	cands []candidate, picked []bool, countryCount, cityCount map[string]int, cfg config.SelectConfig, base int,
	tolerance float64,
) int {
	head := cands[base]
	pick := base
	for i := base + 1; i < len(cands); i++ {
		c := cands[i]
		if picked[i] || (cfg.PerCountryCap > 0 && countryCount[c.rec.Country] >= cfg.PerCountryCap) {
			continue
		}
		if !sameBand(head, c, tolerance) {
			break
		}
		if cityCount[model.CityKey(c.rec.City)] == 0 && cityCount[model.CityKey(head.rec.City)] > 0 {
			pick = i
		}
	}
	return pick
}

// assignTags renders the selection with per-country stable NN sequences in
// pick order. W16: unknown-geo nodes (raw empty country) tag with the xx
// pseudo-code — pool-xx-NN — keeping the D5 grammar intact; SelectedNode
// carries the RAW country (""), so the renderer's grouping mirrors resolved
// geo presence (pool_unknown), not a synthesized code.
func assignTags(selected []candidate, capApplied int, all []candidate) *model.Selection {
	seqByCountry := map[string]int{}
	sel := &model.Selection{
		GeneratedAt: time.Now().UTC(),
		CapApplied:  capApplied,
		CitiesAlive: distinctCities(all),
	}
	for _, c := range selected {
		seqByCountry[c.rec.Country]++
		tagCC := c.rec.Country
		if tagCC == "" {
			tagCC = model.UnknownCountryCode
		}
		isClean := c.rec.FlagsVerified && !c.rec.HostingFlag && !c.rec.ProxyFlag
		sel.Nodes = append(sel.Nodes, model.SelectedNode{
			Tag:     model.PoolTag(tagCC, seqByCountry[c.rec.Country]),
			Key:     c.node.Key,
			Country: c.rec.Country,
			City:    c.rec.City,
			RTTMs:   c.rec.RTTMs,
			Speed:   c.rec.SpeedBPS,
			Checks:  c.checks,
			Total:   c.total,
			IsClean: isClean,
		})
	}
	return sel
}

// sameBand reports whether two candidates tie on the primary metrics closely
// enough that city diversity may decide (same checks, same speed, rtt within
// tolerance·head RTT). tolerance is the [select].tie_band_rtt_tolerance knob
// (normalized: > 0).
func sameBand(head, c candidate, tolerance float64) bool {
	return head.checks == c.checks &&
		head.rec.SpeedBPS == c.rec.SpeedBPS &&
		(head.rec.RTTMs <= 0 || c.rec.RTTMs <= head.rec.RTTMs*tolerance)
}
