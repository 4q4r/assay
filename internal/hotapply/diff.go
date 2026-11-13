package hotapply

import "reflect"

// Diff is the apply-vs-restart verdict for a live/candidate pair (plan T3).
//
// HotCapable means EVERY changed top-level section is "routing" — the only
// section the running core can rebuild in-memory through RoutingService.
// Reasons names the changed restart-only sections (sorted, deterministic)
// for the CLI's actionable message; RoutingChanged reports whether the
// routing section itself differs (a hot delta buried in a restart-only pair
// is still reported — the operator sees the whole picture, and the verdict
// stays fail-closed: apply never partially applies, plan §3.3).
type Diff struct {
	HotCapable     bool
	Reasons        []string
	RoutingChanged bool
}

// routingSection is the ONLY hot-applicable top-level section: balancers and
// rules both live inside it and are rebuilt together by the AddRule full
// replace (ReloadRules, shouldAppend=false). Everything else — outbounds
// (R8: node swaps), inbounds (D2 topology), log (no SetLogLevel RPC),
// observatory/policy/stats/api — is restart-only (plan §2).
const routingSection = "routing"

// Classify deep-compares two rendered configs (live.json vs candidate.json —
// the artifacts the wave already produces; §1.6: there is no full-config
// dump RPC, so the on-disk pair IS the diff source). Every top-level section
// except routing must be semantically equal for the pair to be hot-capable;
// routing may differ.
func Classify(live, candidate map[string]any) Diff {
	var reasons []string
	routingChanged := false
	for _, section := range mergeKeys(live, candidate) {
		lv, lok := live[section]
		cv, cok := candidate[section]
		equal := lok && cok && reflect.DeepEqual(lv, cv)
		if equal {
			continue
		}
		if section == routingSection {
			routingChanged = true
			continue
		}
		reasons = append(reasons, section)
	}
	return Diff{
		HotCapable:     len(reasons) == 0,
		Reasons:        reasons,
		RoutingChanged: routingChanged,
	}
}

// mergeKeys returns the union of both maps' keys in sorted order — a section
// added or removed between renders counts as changed, and the deterministic
// order keeps the CLI's message stable.
func mergeKeys(a, b map[string]any) []string {
	seen := map[string]bool{}
	var keys []string
	for k := range a {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range b {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
