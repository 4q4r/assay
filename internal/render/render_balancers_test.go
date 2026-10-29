package render_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"public_vpn/internal/model"
	"public_vpn/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// balancersOf extracts routing.balancers as typed objects.
func balancersOf(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	routing, ok := m["routing"].(map[string]any)
	require.True(t, ok, "routing object present")
	raw, ok := routing["balancers"].([]any)
	require.True(t, ok, "routing.balancers array present")
	out := make([]map[string]any, 0, len(raw))
	for _, b := range raw {
		bm, ok := b.(map[string]any)
		require.True(t, ok, "balancer must be an object")
		out = append(out, bm)
	}
	return out
}

// balancerByTag finds one balancer object by tag.
func balancerByTag(t *testing.T, m map[string]any, tag string) map[string]any {
	t.Helper()
	for _, b := range balancersOf(t, m) {
		if bt, _ := b["tag"].(string); bt == tag {
			return b
		}
	}
	return nil
}

// unknownSelection builds a selection mixing one unknown-geo node (raw
// empty country/city, pool-xx tag — the rank stage's W16 output shape) with
// one known-country node.
func unknownSelection(t *testing.T) ([]*model.Node, *model.Selection) {
	t.Helper()
	nu, snu := mkSelected(t, "pool-xx-01", "", "", "unknown1.example.com", 443, nodeOpts{network: "tcp", extra: map[string]string{"flow": "xtls-rprx-vision"}})
	de, sde := mkSelected(t, "pool-de-01", "de", "Frankfurt", "de1.example.com", 2053, nodeOpts{network: "tcp", extra: map[string]string{"flow": "xtls-rprx-vision"}})
	nodes := []*model.Node{nu, de}
	sel := &model.Selection{Nodes: []model.SelectedNode{snu, sde}}
	return nodes, sel
}

// TestPoolUnknownBalancerRendersForUnknownGeoNodes pins owner item 14a: the
// unknown-geo pseudo-location gets its OWN balancer (pool_unknown) whenever
// ≥1 unknown-geo node is in the active selection; the selector is the xx
// pseudo-code prefix (the D5 tag grammar stays pool-xx-NN), and the balancer
// is a first-class pool_routes target exactly like a country balancer.
func TestPoolUnknownBalancerRendersForUnknownGeoNodes(t *testing.T) {
	nodes, sel := unknownSelection(t)
	m := doRender(t, nodes, sel, render.PoolRoute{Balancer: "pool_unknown", Domains: []string{"domain:x.com"}})

	bal := balancerByTag(t, m, "pool_unknown")
	require.NotNil(t, bal, "pool_unknown renders when unknown-geo nodes exist")
	assert.Equal(t, []any{"pool-xx-"}, bal["selector"], "the selector is the xx pseudo-code prefix")
	assert.Equal(t, "block", bal["fallbackTag"], "security invariant: pool_unknown is a pool balancer")
	strategy, ok := bal["strategy"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "leastLoad", strategy["type"])

	// The route targeting pool_unknown is valid and renders as balancerTag.
	var route map[string]any
	for _, r := range m["routing"].(map[string]any)["rules"].([]any) {
		rm := r.(map[string]any)
		if bt, _ := rm["balancerTag"].(string); bt == "pool_unknown" {
			route = rm
		}
	}
	require.NotNil(t, route, "a pool route may target pool_unknown like a country balancer")
	assert.Equal(t, []any{"socks-in", "http-in"}, route["inboundTag"])
}

// TestPoolUnknownAbsentWithoutUnknownNodes pins the conditional rendering:
// a selection with only known countries renders NO pool_unknown balancer.
func TestPoolUnknownAbsentWithoutUnknownNodes(t *testing.T) {
	nodes, sel := twoCountrySelection(t)
	m := doRender(t, nodes, sel)
	assert.Nil(t, balancerByTag(t, m, "pool_unknown"),
		"pool_unknown must not render when every node has geo")
}

// TestPoolAllBalancerAlwaysRendersWithPool pins owner item 14b: the
// pool-wide balancer (the «общий балансир») renders whenever ≥1 pool node
// exists, selects over the WHOLE pool- namespace (every country balancer's
// candidates plus the unknown pseudo-location), carries the block fallback,
// and is a valid pool_routes target.
func TestPoolAllBalancerAlwaysRendersWithPool(t *testing.T) {
	nodes, sel := unknownSelection(t)
	m := doRender(t, nodes, sel, render.PoolRoute{Balancer: "pool_all", Domains: []string{"domain:x.com"}})

	bal := balancerByTag(t, m, "pool_all")
	require.NotNil(t, bal, "pool_all renders whenever the pool is non-empty")
	assert.Equal(t, []any{"pool-"}, bal["selector"],
		"the selector is the whole pool- prefix: country nodes AND pool-xx-NN unknown nodes")
	assert.Equal(t, "block", bal["fallbackTag"], "security invariant: pool_all is a pool balancer")
	strategy, ok := bal["strategy"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "leastLoad", strategy["type"])

	var route map[string]any
	for _, r := range m["routing"].(map[string]any)["rules"].([]any) {
		rm := r.(map[string]any)
		if bt, _ := rm["balancerTag"].(string); bt == "pool_all" {
			route = rm
		}
	}
	require.NotNil(t, route, "a pool route may target pool_all (the whole-pool use case)")
}

// TestPoolAllAbsentOnEmptyPool pins the L1 boundary: an empty selection
// renders NO pool artifacts at all — pool_all included.
func TestPoolAllAbsentOnEmptyPool(t *testing.T) {
	m := doRender(t, nil, &model.Selection{})
	assert.Nil(t, balancerByTag(t, m, "pool_all"), "L1: nothing pool-related renders on an empty pool")
	for _, b := range balancersOf(t, m) {
		tag, _ := b["tag"].(string)
		assert.False(t, strings.HasPrefix(tag, "pool_"), "no pool balancer on an empty pool, got %s", tag)
	}
}

// TestPoolBalancersCarryBlockFallbackOnNewBalancers pins the W9 invariant
// extended to the W16 balancers: pool_unknown and pool_all carry
// fallbackTag block, and re-rendering from a previous output does not
// duplicate either (strip idempotency covers the new tags).
func TestPoolBalancersCarryBlockFallbackOnNewBalancers(t *testing.T) {
	nodes, sel := unknownSelection(t)
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	cfg := renderCfg([]render.PoolRoute{
		{Balancer: "pool_unknown", Domains: []string{"domain:x.com"}},
		{Balancer: "pool_all", Domains: []string{"domain:y.com"}},
	})
	first, err := render.Render(render.Input{Template: testTemplate(t), Selection: sel, NodesByKey: byKey, Cfg: cfg})
	require.NoError(t, err)
	second, err := render.Render(render.Input{Template: first.Config, Selection: sel, NodesByKey: byKey, Cfg: cfg})
	require.NoError(t, err)
	var m2 map[string]any
	require.NoError(t, json.Unmarshal(second.Config, &m2))

	counts := map[string]int{}
	for _, b := range balancersOf(t, m2) {
		tag, _ := b["tag"].(string)
		if strings.HasPrefix(tag, "pool_") {
			counts[tag]++
			assert.Equal(t, "block", b["fallbackTag"], "pool balancer %s must carry the block fallback", tag)
		}
	}
	assert.Equal(t, map[string]int{"pool_unknown": 1, "pool_all": 1, "pool_de": 1},
		counts, "re-render must not duplicate the new balancers")
}

// TestUnknownAndAllGoldenPassesXrayTest materializes (first run) and
// byte-pins a golden render containing BOTH new balancers (pool_unknown +
// pool_all) and validates it against the REAL 26.3.27 binary — the task's
// xray -test gate for the new surface.
func TestUnknownAndAllGoldenPassesXrayTest(t *testing.T) {
	bin := "/usr/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("xray binary not present at %s", bin)
	}
	nodes, sel := unknownSelection(t)
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	res, err := render.Render(render.Input{
		Template:   testTemplate(t),
		Selection:  sel,
		NodesByKey: byKey,
		Cfg:        renderCfg(nil),
	})
	require.NoError(t, err)
	assert.Empty(t, res.DroppedParams)

	goldenPath := filepath.Join("testdata", "golden-unknown-and-all.json")
	golden, err := os.ReadFile(goldenPath)
	if err == nil {
		assert.Equal(t, string(golden), string(res.Config),
			"render diverged from %s — if intentional, regenerate deliberately", goldenPath)
	} else {
		require.NoError(t, os.WriteFile(goldenPath, res.Config, 0o644), "first run materializes the golden")
		golden = res.Config
		t.Logf("materialized %s", goldenPath)
	}

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "rendered.json")
	require.NoError(t, os.WriteFile(cfgPath, golden, 0o644))
	cmd := exec.CommandContext(context.Background(), bin, "run", "-test", "-c", cfgPath)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+tmp)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "xray run -test rejected the unknown+all render:\n%s", out)
	assert.Contains(t, string(out), "Configuration OK")
}
