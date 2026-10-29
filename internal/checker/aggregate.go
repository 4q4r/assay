package checker

import (
	"sort"
	"strings"

	"public_vpn/internal/model"
)

// Aggregate computes the node-level aggregates from the raw attempts:
// success counts, the unique HTTP statuses seen, mean/median timings over
// SUCCESSFUL attempts, and the overall node verdict used for coloring.
func (r *NodeResult) Aggregate() {
	if r.InstanceFailed {
		r.Verdict = VerdictError
		return
	}
	statusSeen := map[int]bool{}
	var goodTotalMS, goodSpeedBPS, goodTTFB []float64
	var goodConnect []float64
	blocked, anySuccess := 0, false
	r.Total = len(r.Attempts)
	for i := range r.Attempts {
		a := &r.Attempts[i]
		if a.Status > 0 {
			statusSeen[a.Status] = true
		}
		if a.Verdict == VerdictSuccess {
			anySuccess = true
			r.OK++
			goodTotalMS = append(goodTotalMS, a.TotalMS)
			goodSpeedBPS = append(goodSpeedBPS, a.SpeedBPS)
			goodTTFB = append(goodTTFB, a.TTFBMS)
			goodConnect = append(goodConnect, a.ConnectMS+a.TLSMS)
		}
		if a.Verdict == VerdictBlockedHTTP || a.Verdict == VerdictBlockedPage {
			blocked++
			if a.Signature != "" && r.Signature == "" {
				r.Signature = a.Signature
			}
		}
	}
	r.Statuses = make([]int, 0, len(statusSeen))
	for s := range statusSeen {
		r.Statuses = append(r.Statuses, s)
	}
	sort.Ints(r.Statuses)
	r.AvgMS = mean(goodTotalMS)
	r.MedianTotalMS = Median(goodTotalMS)
	r.AvgTTFBMS = mean(goodTTFB)
	r.AvgSpeedBPS = mean(goodSpeedBPS)
	r.ConnectMS = mean(goodConnect)
	switch {
	case r.Total == 0:
		r.Verdict = VerdictError
	case r.OK == r.Total:
		r.Verdict = VerdictSuccess
	case anySuccess:
		r.Verdict = VerdictPartial
	case blocked > 0:
		r.Verdict = VerdictBlocked
	default:
		r.Verdict = VerdictFail
	}
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

// Median returns the median of a float slice (0 for empty). The input is
// copied before sorting — callers keep their ordering.
func Median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	cp := append([]float64(nil), v...)
	sort.Float64s(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[mid]
	}
	return (cp[mid-1] + cp[mid]) / 2
}

// GroupByCountry buckets node rows per country with summary math.
func GroupByCountry(rows []*NodeResult) []GroupStat {
	return groupBy(rows, func(r *NodeResult) (string, string) { return r.Country, "" })
}

// GroupByCity buckets node rows per (country, city) pair.
func GroupByCity(rows []*NodeResult) []GroupStat {
	return groupBy(rows, func(r *NodeResult) (string, string) { return r.Country, r.City })
}

func groupBy(rows []*NodeResult, keyOf func(*NodeResult) (string, string)) []GroupStat {
	order := []string{}
	byKey := map[string]GroupStat{}
	for _, r := range rows {
		cc, city := keyOf(r)
		if strings.TrimSpace(cc) == "" {
			cc = "??"
		}
		// The city part of the key is case-folded (model.CityKey): geo
		// case variants of one city are one bucket. The bucket's displayed
		// City stays an original spelling — the lowest variant seen.
		k := cc + "|" + model.CityKey(city)
		g, ok := byKey[k]
		if !ok {
			g = GroupStat{Country: strings.ToUpper(cc), City: strings.TrimSpace(city)}
			order = append(order, k)
		} else {
			g.City = model.CityDisplay(g.City, city)
		}
		g.Nodes++
		g.Total += r.Total
		g.OK += r.OK
		byKey[k] = g
	}
	out := make([]GroupStat, 0, len(order))
	for _, k := range order {
		g := byKey[k]
		if g.Total > 0 {
			g.SuccessRate = float64(g.OK) / float64(g.Total)
		}
		out = append(out, g)
	}
	// Per-group timing aggregates read the rows once more, bucketed.
	fillTimings(out, rows, keyOf)
	return out
}

func fillTimings(groups []GroupStat, rows []*NodeResult, keyOf func(*NodeResult) (string, string)) {
	byKey := map[string]*GroupStat{}
	for i := range groups {
		byKey[groups[i].Country+"|"+model.CityKey(groups[i].City)] = &groups[i]
	}
	perGroupMedians := map[string][]float64{}
	speeds := map[string][]float64{}
	for _, r := range rows {
		cc, city := keyOf(r)
		if strings.TrimSpace(cc) == "" {
			cc = "??"
		}
		k := strings.ToUpper(cc) + "|" + model.CityKey(city)
		if r.MedianTotalMS > 0 {
			perGroupMedians[k] = append(perGroupMedians[k], r.MedianTotalMS)
		}
		if r.AvgSpeedBPS > 0 {
			speeds[k] = append(speeds[k], r.AvgSpeedBPS)
		}
	}
	for k, g := range byKey {
		g.MedianMS = Median(perGroupMedians[k])
		g.AvgMS = mean(perGroupMedians[k])
		g.AvgSpeedBPS = mean(speeds[k])
	}
}

// RankGroups orders geo-summary buckets for the recommendation block:
// success rate desc, then median ms asc, then avg speed desc. Deterministic
// ties keep the caller's order (stable sort).
func RankGroups(groups []GroupStat) []GroupStat {
	out := append([]GroupStat(nil), groups...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.SuccessRate != b.SuccessRate {
			return a.SuccessRate > b.SuccessRate
		}
		if a.MedianMS != b.MedianMS {
			return a.MedianMS < b.MedianMS
		}
		if a.AvgSpeedBPS != b.AvgSpeedBPS {
			return a.AvgSpeedBPS > b.AvgSpeedBPS
		}
		return false
	})
	return out
}
