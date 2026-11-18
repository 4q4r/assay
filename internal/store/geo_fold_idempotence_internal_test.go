package store

// Allocation-audit F2 pin: the blank-fold matrix (mergeGeoRecord) is
// idempotent under a second application. The PRE-change flush path ran the
// fold twice (geo.Flush's own merge, then UpsertGeo's internal re-merge)
// and its byte-stable output depended on the second application being a
// no-op; the fused flush path runs the fold exactly once. This pin
// guarantees both paths land on the same record bytes.

import (
	"testing"

	"assay/internal/model"

	"github.com/stretchr/testify/require"
)

func TestMergeGeoRecordSecondFoldIsNoOp(t *testing.T) {
	prev := &model.GeoRecord{
		Scheme: "vless", Host: "prev.example.com", Port: 443,
		IP: "198.51.100.9", Country: "de", City: "Berlin",
		ASN: "AS51167", ASName: "CONTABO", ISP: "Contabo GmbH",
		GeoSource: "self-report", FirstSeen: "2026-01-01T00:00:00Z",
		LastSeen: "2026-01-01T00:00:00Z", LastProbe: "2026-01-01T01:00:00Z",
		Alive: true, RTTMs: 42, SpeedBPS: 1234,
		BytesUp: 10, BytesDown: 20, Tag: "pool-de-01",
		RiskScore: 7, ScamalyticsScore: 11, AbuseScore: 3, IPType: "hosting",
		MediaUnlocks: model.MediaUnlockStatus{
			CheckedAt: "2026-01-01T02:00:00Z", BatteryVersion: 2,
			ChatGPT: "yes", Netflix: "full", YouTubeRegion: "DE",
		},
	}
	byIdentity := map[string]*model.GeoRecord{
		model.GeoIdentity(prev): prev,
	}

	// First application: fresh value wins (country), every blank field
	// folds to prev's surviving value.
	first := &model.GeoRecord{
		Scheme: "vless", Host: "prev.example.com", Port: 443,
		Country: "de",
	}
	once := mergeGeoRecord(byIdentity, first)
	require.Same(t, first, once, "the fold mutates the incoming record in place")
	snapshot := *once

	// Second application (the old double-merge shape): must change nothing.
	second := &model.GeoRecord{
		Scheme: "vless", Host: "prev.example.com", Port: 443,
		Country: "de",
	}
	twice := mergeGeoRecord(byIdentity, second)
	require.Equal(t, snapshot, *twice,
		"a second fold over an already-folded record must change nothing (the idempotence the fusion relies on)")
}

// TestMergeGeoRecordUnmatchedRecordPinned pins the no-prev branch the fused
// merge keeps: an incoming record with no existing identity is returned
// untouched (the merge loop inserts it; the fold itself never invents a
// prev).
func TestMergeGeoRecordUnmatchedRecordPinned(t *testing.T) {
	byIdentity := map[string]*model.GeoRecord{}
	r := &model.GeoRecord{Scheme: "vless", Host: "new.example.com", Port: 443, Country: "fr"}
	got := mergeGeoRecord(byIdentity, r)
	require.Same(t, r, got, "an unmatched record is returned as-is (the merge loop performs the insert)")
	require.Empty(t, byIdentity, "the fold helper alone never inserts")
}
