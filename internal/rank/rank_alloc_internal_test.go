package rank

import (
	"strconv"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/model"
	"assay/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allocFixture builds N distinct nodes that share ONE geo identity (one geo
// record): the worst case for the audit M1 clone-before-checks pattern —
// every node looks up the same record and, pre-fix, pays the full GeoRecord
// clone before the cheap gates reject it.
func allocFixture(t *testing.T, n int, alive bool) ([]*model.Node, *model.GeoRecord) {
	t.Helper()
	nodes := make([]*model.Node, 0, n)
	for i := range n {
		nodes = append(nodes, model.NewNode("plug-a", "vless", "uuid-"+strconv.Itoa(i), "de1.example.com", 443,
			map[string]string{"security": "reality", "type": "tcp", "pbk": "PBK", "sid": "S"}))
	}
	rec := &model.GeoRecord{
		Tag: "pool-de-01", Scheme: "vless", Host: "de1.example.com", Port: 443,
		Country: "de", City: "Frankfurt", FlagsVerified: true,
		Alive: alive, LastProbe: "2026-06-01T00:00:00Z", RTTMs: 100,
	}
	return nodes, rec
}

// TestSelectRejectPathAvoidsPerNodeRecordClone is the audit M1 RED
// instrument: hundreds of rejected candidates sharing one geo record must
// not pay a per-node GeoRecord clone + throwaway key struct on the reject
// path. The bound holds only once the clone moves to the admission path
// (audit M1/F4) and the identity key is the field-form concat (M2/F5);
// pre-fix the per-node Sprintf + struct + ~300B clone overshoot it.
func TestSelectRejectPathAvoidsPerNodeRecordClone(t *testing.T) {
	const n = 400
	probeDead := make(map[string]store.ProbeResult, n)
	build := func(alive bool) int {
		nodes, rec := allocFixture(t, n, alive)
		for _, node := range nodes {
			probeDead[node.Key] = store.ProbeResult{Key: node.Key, Alive: false, CheckedAt: time.Now().UTC()}
		}
		allocs := testing.AllocsPerRun(20, func() {
			sel := Select(nodes, []*model.GeoRecord{rec}, probeDead, config.SelectConfig{}, 0)
			require.NotNil(t, sel)
			assert.Empty(t, sel.Nodes, "every candidate is probe-dead — nothing is admitted")
		})
		return int(allocs)
	}

	t.Run("dead record rejected at the alive gate", func(t *testing.T) {
		allocs := build(false)
		t.Logf("allocs/op for %d rejected candidates: %d (%.2f/node)", n, allocs, float64(allocs)/n)
		assert.Less(t, allocs, 3*n,
			"rejected candidates must not pay a clone/struct/Sprintf set per node (audit M1)")
	})
	t.Run("alive record rejected at the probe gate", func(t *testing.T) {
		allocs := build(true)
		t.Logf("allocs/op for %d rejected candidates: %d (%.2f/node)", n, allocs, float64(allocs)/n)
		assert.Less(t, allocs, 3*n,
			"rejected candidates must not pay a clone/struct/Sprintf set per node (audit M1)")
	})
}

// TestSelectSharedRecordRejectDoesNotMutate pins the property the M1 reorder
// must preserve: candidate evidence (the known-alive rescue stamps) never
// lands on the SHARED geo record — a later candidate and the cold base never
// see one candidate's evidence. Pre-fix the clone already protected this;
// post-fix the read-only evaluation preserves it by construction (the audit's
// mandated mutation test, M1).
func TestSelectSharedRecordRejectDoesNotMutate(t *testing.T) {
	nodes, rec := allocFixture(t, 2, false)
	ka := map[string]store.KnownAliveRecord{
		nodes[0].Key: {Key: nodes[0].Key, LastSeen: time.Now().UTC().Add(-time.Minute), LastStatus: "passed"},
	}
	// No probe entries: probeAllows admits on missing entries, so the FIRST
	// node is admitted and the ka-rescue stamps evidence on ITS candidate
	// record only. The shared record must stay dead with its probe stamp —
	// a SECOND admission would be the leak detector firing (node 1 has no
	// ka entry; it is only admittable if node 0's evidence leaked into the
	// shared record).
	sel := Select(nodes, []*model.GeoRecord{rec}, nil, config.SelectConfig{}, 0, ka)
	require.Len(t, sel.Nodes, 1,
		"only the ka-carrying node is admitted — two admissions would mean the evidence leaked into the shared record")
	assert.False(t, rec.Alive, "shared record must stay untouched by admitted-candidate evidence")
	assert.Equal(t, "2026-06-01T00:00:00Z", rec.LastProbe, "shared record's probe stamp must stay untouched")
}

// TestSelectAdmittedKaRescueAdmitsThroughBothGates pins the admitted-path
// semantics: a dead, stamp-less shared record plus a known-alive entry admits
// the candidate (alive rescue + probe escape) exactly as the pre-fix clone
// path did — the reorder must not change WHO is admitted, only WHO pays the
// clone.
func TestSelectAdmittedKaRescueAdmitsThroughBothGates(t *testing.T) {
	nodes, rec := allocFixture(t, 1, false)
	rec.LastProbe = "" // nothing alive, nothing fresh: only the ka rescue admits
	ka := map[string]store.KnownAliveRecord{
		nodes[0].Key: {Key: nodes[0].Key, LastSeen: time.Now().UTC().Add(-time.Minute), LastStatus: "passed"},
	}
	sel := Select(nodes, []*model.GeoRecord{rec}, nil, config.SelectConfig{}, time.Hour, ka)
	require.Len(t, sel.Nodes, 1, "the ka rescue must admit the candidate through alive+fresh gates")
	assert.False(t, rec.Alive, "rescued evidence stays off the shared record")
	assert.Empty(t, rec.LastProbe, "rescued evidence stays off the shared record")
}
