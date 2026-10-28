package store_test

import (
	"path/filepath"
	"strings"
	"testing"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/prune"
	"public_vpn/internal/rank"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGeoIdentityEquivalenceAcrossStoreRankPrune is the W7 M2 equivalence pin:
// the geo-record identity (scheme|lower(host)|port) is ONE canonical function
// (model.GeoIdentity), and every consumer site — the store upsert join, the
// rank select join, and the prune referenced/orphan rules — agrees with it for
// a table of edge inputs. Before the hoist the same expression lived in
// triplicate (store.GeoIdentity, an inline rank key, prune.Identity); a
// divergence in any copy would silently split or mis-join cold-base records.
func TestGeoIdentityEquivalenceAcrossStoreRankPrune(t *testing.T) {
	edgeInputs := []model.GeoRecord{
		{Scheme: "vless", Host: "de.example.com", Port: 443},
		{Scheme: "trojan", Host: "De.Example.COM", Port: 8443},
		{Scheme: "vless", Host: "2001:db8::1", Port: 2053},
		{Scheme: "ss", Host: "[2001:db8::2]", Port: 65535},
	}

	for _, in := range edgeInputs {
		rec := in // one copy per subtest (the subtests mutate it)
		t.Run(rec.Scheme+"|"+rec.Host, func(t *testing.T) {
			canonical := model.GeoIdentity(&rec)

			// STORE site: the upsert join key. A case-variant spelling of the
			// same identity must merge into ONE record.
			base := filepath.Join(t.TempDir(), "geo-base.jsonl")
			variant := rec
			variant.Host = strings.ToUpper(rec.Host)
			require.NoError(t, store.UpsertGeo(base, []*model.GeoRecord{&rec, &variant}))
			roundTrip, err := store.ReadGeo(base)
			require.NoError(t, err)
			require.Len(t, roundTrip, 1, "case-variant host spellings share one identity in the store upsert")
			assert.Equal(t, canonical, model.GeoIdentity(roundTrip[0]))

			// RANK site: collectCandidates joins nodes to geo records by the
			// same identity. A node whose host spelling differs only in case
			// from the geo record must still join (one selected candidate).
			geoRec := rec
			geoRec.Country = "de"
			geoRec.Alive = true
			geoRec.LastProbe = "2099-01-01T00:00:00Z" // far-fresh under any clock
			node := model.NewNode("s", rec.Scheme, "uuid", strings.ToUpper(rec.Host), rec.Port, nil)
			sel := rank.Select([]*model.Node{node}, []*model.GeoRecord{&geoRec}, nil, config.SelectConfig{
				PerCountryCap: 5, SoftCap: 10, CityExpandThreshold: 25, Ceiling: 40,
			}, 0)
			require.Len(t, sel.Nodes, 1,
				"rank must join the node to the geo record through the same case-insensitive identity")

			// PRUNE site: a record referenced under the canonical identity is
			// never an orphan — the referenced set and the record identity are
			// the same string.
			kept, removed, report := prune.Select(
				[]*model.GeoRecord{{Scheme: rec.Scheme, Host: rec.Host, Port: rec.Port}},
				map[string]bool{canonical: true},
				prune.Options{DeadAfter: 1, TTL: 1},
			)
			assert.Empty(t, removed, "a record referenced by its canonical identity is never orphaned")
			assert.Len(t, kept, 1)
			assert.Zero(t, report.RemovedStale)
		})
	}
}
