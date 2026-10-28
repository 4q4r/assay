package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maintainStateFixture builds a data dir whose cold base + filter set model
// one node, so the real prune → select → render stages can run against it.
func maintainStateFixture(t *testing.T, alive bool, lastProbeAge time.Duration) *config.Config {
	t.Helper()
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "template.json")
	require.NoError(t, os.WriteFile(tmpl, []byte(`{
		"outbounds": [{"protocol":"freedom","settings":{"domainStrategy":"AsIs"},"tag":"direct"}],
		"inbounds": [],
		"routing": {"rules": []}
	}`), 0o600))
	cfg := &config.Config{
		DataDir: dir,
		Geo:     config.GeoConfig{TTL: config.Duration{Duration: 24 * time.Hour}},
		Maintain: config.MaintainConfig{
			PruneDeadAfter: config.Duration{Duration: 48 * time.Hour},
		},
		Render: config.RenderConfig{Template: tmpl, OutputDir: "rendered", StatsPort: 15490},
		Activate: config.ActivateConfig{
			Target:  filepath.Join(dir, "live.json"),
			XrayBin: "/usr/bin/xray",
		},
	}
	p := newPaths(cfg)
	require.NoError(t, os.MkdirAll(p.dataDir, 0o750))

	// One filtered node + its matching cold-base record.
	n := model.NewNode("src", "vless", "uuid-1", "De.Example.com", 443,
		map[string]string{"security": "reality", "type": "tcp"})
	b, err := json.Marshal(n)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p.filtered, []byte(string(b)+"\n"), 0o600))

	rec := &model.GeoRecord{
		Tag:       "pool-de-01",
		Scheme:    n.Scheme,
		Host:      n.Host, // identity is case-insensitive on host; keep the node's spelling
		Port:      n.Port,
		Alive:     alive,
		LastProbe: time.Now().UTC().Add(-lastProbeAge).Format(time.RFC3339),
	}
	rb, err := json.Marshal(rec)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p.geoBase, []byte(string(rb)+"\n"), 0o600))
	return cfg
}

func runMaintainStagesDirectly(t *testing.T, cfg *config.Config, stages ...func(*cobra.Command, *config.Config) error) string {
	t.Helper()
	buf := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	for _, s := range stages {
		require.NoError(t, s(cmd, cfg))
	}
	return buf.String()
}

func storeReadSelectionForTest(t *testing.T, cfg *config.Config) (*model.Selection, error) {
	t.Helper()
	return store.ReadSelection(newPaths(cfg).selection)
}

// TestPruneToEmptyPoolRenderRefusesObservatory verifies the L1 contract
// end-to-end through the W4 stages: when the active pool shrinks to zero
// (here: the single candidate goes ttl-stale, so rank drops it), the next
// render carries no pool observatory and no pool balancers — the busy-loop
// shape can never reach the core through a maintain wave.
func TestPruneToEmptyPoolRenderRefusesObservatory(t *testing.T) {
	// alive=true but last_probe 72h old: stale per geo.ttl (24h). Prune KEEPS
	// it (still referenced by the filter set — a future probe can refresh
	// it); rank refuses it; the selection is empty; the render is L1-safe.
	cfg := maintainStateFixture(t, true, 72*time.Hour)
	out := runMaintainStagesDirectly(t, cfg, runPruneStage, runSelect, runRender)
	assert.Contains(t, out, "WARNING: empty pool — no pool observatory/balancers rendered (L1 hard gate)")

	sel, err := storeReadSelectionForTest(t, cfg)
	require.NoError(t, err)
	require.NotNil(t, sel)
	assert.Empty(t, sel.Nodes, "the stale candidate must not re-enter the selection")

	p := newPaths(cfg)
	raw, err := os.ReadFile(p.rendered)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	_, hasObs := m["observatory"]
	assert.False(t, hasObs, "L1: empty selection must not render a pool observatory")
	routing, _ := m["routing"].(map[string]any)
	balancers, _ := routing["balancers"].([]any)
	assert.Empty(t, balancers, "L2: empty selection must not render balancers")
	for _, o := range m["outbounds"].([]any) {
		om := o.(map[string]any)
		tag, _ := om["tag"].(string)
		assert.NotContains(t, tag, "pool-", "no pool outbounds may render from an empty selection")
	}
}

// TestPruneDeadNodeThenSelectFailsLoudOnEmptyBase pins the total-die-out
// contract: when pruning removes the last record, the geo base is empty and
// the select stage fails loud (owner convention) — maintain never renders a
// silently emptied config from dead data.
func TestPruneDeadNodeThenSelectFailsLoudOnEmptyBase(t *testing.T) {
	// dead (alive=false) with last_probe 72h old: beyond dead_after (48h) →
	// physically removed even though the source still references it.
	cfg := maintainStateFixture(t, false, 72*time.Hour)
	runMaintainStagesDirectly(t, cfg, runPruneStage)

	p := newPaths(cfg)
	recs, err := os.ReadFile(p.geoBase)
	require.NoError(t, err)
	assert.Empty(t, recs, "the dead record is physically removed")

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	err = runSelect(cmd, cfg)
	require.Error(t, err, "an empty cold base must fail the wave loud, not render an empty pool")
	assert.Contains(t, err.Error(), "geo base empty")
}
