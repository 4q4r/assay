package hotapply

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The base live/candidate pair both sides of every case build from: the
// real own-config section set (log, inbounds, outbounds, routing,
// observatory, policy, stats, api). The fixture canonicalizes through a JSON
// round trip — production always compares two JSON-DECODED configs
// (live.json vs candidate.json), where every number is a float64; the
// canonicalization mirrors that shape exactly.
func baseConfig() map[string]any {
	raw, err := json.Marshal(rawBaseConfig())
	if err != nil {
		panic(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

func rawBaseConfig() map[string]any {
	return map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"inbounds": []any{
			map[string]any{"tag": "in", "listen": "127.0.0.1", "port": 10810, "protocol": "socks"},
			map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": 15491, "protocol": "dokodemo-door"},
		},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "pool-us-01", "protocol": "vless"},
		},
		"routing": map[string]any{
			"rules": []any{
				map[string]any{"type": "field", "inboundTag": []any{"api-in"}, "outboundTag": "api"},
				map[string]any{
					"type": "field", "ruleTag": "pool-route-0",
					"domain": []any{"domain:nyaa.si"}, "balancerTag": "pool_nl",
				},
				map[string]any{"type": "field", "network": "tcp,udp", "balancerTag": "pool_all"},
			},
			"balancers": []any{
				map[string]any{"tag": "pool_nl", "selector": []any{"pool-nl-"}, "strategy": map[string]any{"type": "leastLoad"}},
				map[string]any{"tag": "pool_all", "selector": []any{"pool-"}, "strategy": map[string]any{"type": "leastLoad"}},
			},
		},
		"observatory": map[string]any{"subjectSelector": []any{"pool-"}, "probeInterval": "1m0s"},
		"policy":      map[string]any{"system": map[string]any{"statsOutboundUplink": true}},
		"stats":       map[string]any{},
		"api":         map[string]any{"tag": "api", "services": []any{"StatsService"}},
	}
}

func cloneCfg(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestClassifyIdenticalConfigsAreHotNoOp(t *testing.T) {
	live := baseConfig()
	candidate := cloneCfg(t, live)

	d := Classify(live, candidate)
	assert.True(t, d.HotCapable, "an identical pair changes nothing — trivially hot")
	assert.False(t, d.RoutingChanged)
	assert.Empty(t, d.Reasons)
}

func TestClassifyRoutingOnlyDeltaIsHotCapable(t *testing.T) {
	live := baseConfig()
	candidate := cloneCfg(t, live)
	// The owner's nvidia.com case: one pool route added.
	candidate["routing"].(map[string]any)["rules"] = append(
		candidate["routing"].(map[string]any)["rules"].([]any),
		map[string]any{
			"type": "field", "ruleTag": "pool-route-1",
			"domain": []any{"domain:nvidia.com"}, "balancerTag": "pool_us",
		},
	)

	d := Classify(live, candidate)
	assert.True(t, d.HotCapable, "a routing-only delta is the hot-apply surface")
	assert.True(t, d.RoutingChanged)
	assert.Empty(t, d.Reasons)
}

func TestClassifyEachSectionDeltaBlocksHot(t *testing.T) {
	// One mutated section per case — the reason must NAME it.
	cases := []struct {
		name    string
		section string
		mutate  func(map[string]any)
	}{
		{"outbounds", "outbounds", func(c map[string]any) {
			obs := c["outbounds"].([]any)
			c["outbounds"] = append(obs[:1], obs[2:]...) // R8: one pool node removed
		}},
		{"inbounds", "inbounds", func(c map[string]any) {
			c["inbounds"].([]any)[0].(map[string]any)["port"] = 10812
		}},
		{"log", "log", func(c map[string]any) {
			c["log"].(map[string]any)["loglevel"] = "info"
		}},
		{"observatory", "observatory", func(c map[string]any) {
			c["observatory"].(map[string]any)["probeInterval"] = "2m0s"
		}},
		{"policy", "policy", func(c map[string]any) {
			c["policy"].(map[string]any)["system"].(map[string]any)["statsOutboundUplink"] = false
		}},
		{"stats", "stats", func(c map[string]any) {
			c["stats"] = map[string]any{"someCounter": true}
		}},
		{"api", "api", func(c map[string]any) {
			c["api"].(map[string]any)["services"] = []any{"StatsService", "RoutingService"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			live := baseConfig()
			candidate := cloneCfg(t, live)
			tc.mutate(candidate)

			d := Classify(live, candidate)
			assert.False(t, d.HotCapable, "%s changed → NOT hot-capable (fail-closed)", tc.name)
			assert.False(t, d.RoutingChanged, "%s is outside routing", tc.name)
			require.Len(t, d.Reasons, 1, "exactly the changed section is named")
			assert.Contains(t, d.Reasons[0], tc.section)
		})
	}
}

func TestClassifyRoutingPlusOtherDeltaBlocksHotWithBothNames(t *testing.T) {
	live := baseConfig()
	candidate := cloneCfg(t, live)
	candidate["routing"].(map[string]any)["rules"] = append(
		candidate["routing"].(map[string]any)["rules"].([]any),
		map[string]any{"type": "field", "ruleTag": "pool-route-1", "domain": []any{"domain:x.com"}, "balancerTag": "pool_nl"},
	)
	candidate["outbounds"] = append(candidate["outbounds"].([]any), map[string]any{"tag": "pool-de-01", "protocol": "vless"})

	d := Classify(live, candidate)
	assert.False(t, d.HotCapable, "a hot delta plus a restart-only delta is restart-only — never partial")
	assert.True(t, d.RoutingChanged, "routing DID change (reported even though the verdict is restart)")
	require.Len(t, d.Reasons, 1)
	assert.Contains(t, d.Reasons[0], "outbounds")
}

func TestClassifyDeepValueChangeInsideSectionBlocksHot(t *testing.T) {
	// A change NESTED deep inside a non-routing section (a balancer tolerance
	// knob changing an outbound's sockopt, say) must not slip through a
	// shallow top-key comparison.
	live := baseConfig()
	candidate := cloneCfg(t, live)
	ob := candidate["outbounds"].([]any)[1].(map[string]any)
	ob["streamSettings"] = map[string]any{"sockopt": map[string]any{"tcpMaxSeg": 1400}}

	d := Classify(live, candidate)
	assert.False(t, d.HotCapable, "deep changes inside a section count as section changes")
	assert.Contains(t, d.Reasons[0], "outbounds")
}

// The plan §2 apply-vs-restart classification table, pinned mechanically:
// each config.toml lever is mapped to the RENDERED-SECTION delta class it
// produces, and the classifier's verdict for that class is asserted. This is
// the test the plan's DoD calls "pin the plan's table as a test".

func TestApplyVsRestartClassificationTable(t *testing.T) {
	// hotDelta builds a candidate whose routing section differs (the class a
	// routing-only lever produces); buildRow overrides the exact mutation.
	type row struct {
		name       string // the plan §2 row
		lever      string // the config.toml lever
		hotCapable bool   // the §2 verdict
		build      func(t *testing.T, live map[string]any) map[string]any
	}

	addRoute := func(t *testing.T, live map[string]any) map[string]any {
		t.Helper()
		c := cloneCfg(t, live)
		c["routing"].(map[string]any)["rules"] = append(
			c["routing"].(map[string]any)["rules"].([]any),
			map[string]any{
				"type": "field", "ruleTag": "pool-route-1",
				"domain": []any{"domain:nvidia.com"}, "balancerTag": "pool_nl",
			},
		)
		return c
	}
	rebalance := func(t *testing.T, live map[string]any) map[string]any {
		t.Helper()
		// balancer_tolerance / strategy settings: the balancer objects live
		// INSIDE routing — a settings-only change is still a routing delta.
		c := cloneCfg(t, live)
		bal := c["routing"].(map[string]any)["balancers"].([]any)
		bal[0].(map[string]any)["strategy"] = map[string]any{"type": "leastLoad", "settings": map[string]any{"tolerance": 0.5}}
		return c
	}
	nodeSwap := func(t *testing.T, live map[string]any) map[string]any {
		t.Helper()
		// selection.json-driven pool node swap: the outbound SET changes (R8).
		c := cloneCfg(t, live)
		obs := c["outbounds"].([]any)
		obs[1] = map[string]any{"tag": "pool-us-02", "protocol": "vless"}
		return c
	}
	inboundTopology := func(t *testing.T, live map[string]any) map[string]any {
		t.Helper()
		// socks_port / http_port / api_port / per_country_inbounds.
		c := cloneCfg(t, live)
		c["inbounds"].([]any)[0].(map[string]any)["port"] = 10812
		return c
	}
	loglevel := func(t *testing.T, live map[string]any) map[string]any {
		t.Helper()
		c := cloneCfg(t, live)
		c["log"].(map[string]any)["loglevel"] = "debug"
		return c
	}
	observatoryKnob := func(t *testing.T, live map[string]any) map[string]any {
		t.Helper()
		// observatory_interval / tcp_max_seg / tls_fingerprint land outside
		// routing (observatory block / outbound sockopt+TLS).
		c := cloneCfg(t, live)
		c["observatory"].(map[string]any)["probeInterval"] = "2m0s"
		return c
	}

	rows := []row{
		{"[render].pool_routes (domain→balancer rules)", "[render].pool_routes", true, addRoute},
		{"balancer set: selectors/tolerance/strategy (outbound set unchanged)", "[render].balancer_tolerance", true, rebalance},
		{"selection.json-driven pool node swap → outbound set add/remove", "selection", false, nodeSwap},
		{"[core].socks_port/http_port/api_port/per_country_inbounds", "[core].socks_port", false, inboundTopology},
		{"[core].loglevel / access", "[core].loglevel", false, loglevel},
		{"[render].observatory_interval/tcp_max_seg/tls_fingerprint", "[render].observatory_interval", false, observatoryKnob},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			live := baseConfig()
			candidate := r.build(t, live)
			d := Classify(live, candidate)
			assert.Equal(t, r.hotCapable, d.HotCapable, "plan §2 verdict for lever %s", r.lever)
			if !r.hotCapable {
				assert.NotEmpty(t, d.Reasons, "a restart-only verdict names the blocking sections")
			}
		})
	}
	// The binary-swap row ([core].xray_bin, auto_update) is restart-only BY
	// DEFINITION — no render section changes at all (the same render comes
	// out of a different binary), so the classifier never sees it; the CLI
	// does not parse a binary delta. Documented here as the table's only row
	// outside Classify's reach.
	t.Run("binary swap is restart-only by definition (outside the render)", func(t *testing.T) {
		live := baseConfig()
		d := Classify(live, cloneCfg(t, live))
		assert.True(t, d.HotCapable, "an identical render is hot/no-op — the BINARY is what changed, which apply does not touch")
	})
}

// ExpectedFromRouting extracts the verification contract from a rendered
// routing section: every ruleTag (in rule order) and the total rule count —
// what VerifyApplied checks the running core against after the replace.

func TestExpectedFromRouting(t *testing.T) {
	routing := baseConfig()["routing"].(map[string]any)
	tags, count, err := ExpectedFromRouting(routing)
	require.NoError(t, err)
	assert.Equal(t, 3, count, "api rule + pool route + catch-all")
	assert.Equal(t, []string{"pool-route-0"}, tags, "only explicitly tagged rules are verifiable")

	_, _, err = ExpectedFromRouting(map[string]any{})
	require.Error(t, err, "a routing section without rules is a programming error — fail loud")
}
