package model_test

import (
	"encoding/json"
	"testing"

	"public_vpn/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMediaUnlockStatusJSONContract pins the stored vocabulary and the JSON
// tags (the geo-base.jsonl field names are a regression contract).
func TestMediaUnlockStatusJSONContract(t *testing.T) {
	st := model.MediaUnlockStatus{
		ChatGPT:       model.UnlockYes,
		Netflix:       model.UnlockNetflixFull,
		YouTubeRegion: "DE",
		Disney:        model.UnlockBlocked,
		TikTok:        model.UnlockTikTokIDC,
		CheckedAt:     "2026-11-04T00:00:00Z",
	}
	b, err := json.Marshal(st)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"chatgpt": "yes", "netflix": "full", "youtube_region": "DE",
		"disney": "blocked", "tiktok": "idc", "checked_at": "2026-11-04T00:00:00Z"
	}`, string(b))

	var back model.MediaUnlockStatus
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, st, back)

	// The full vocabulary survives a round trip verbatim.
	all := model.MediaUnlockStatus{
		ChatGPT: model.UnlockWebOnly, Netflix: model.UnlockNetflixOriginals,
		YouTubeRegion: model.UnlockBlocked, Disney: model.UnlockUnknown, TikTok: model.UnlockUnknown,
	}
	b2, err2 := json.Marshal(all)
	require.NoError(t, err2)
	assert.Contains(t, string(b2), `"chatgpt":"webonly"`)
	assert.Contains(t, string(b2), `"netflix":"originals"`)
}

// TestMediaUnlockStatusBatteryEvidenceContract pins the v2 battery evidence
// fields: omitempty keeps a v1 verdict's JSON byte-shape (legacy records
// round-trip unchanged), the evidence fields marshal under their contract
// names, and a LEGACY record (no battery_version key) decodes to zero —
// which is exactly the migration semantics (0 < current → stale → re-probe).
func TestMediaUnlockStatusBatteryEvidenceContract(t *testing.T) {
	v2 := model.MediaUnlockStatus{
		ChatGPT:        model.UnlockYes,
		Netflix:        model.UnlockNetflixFull,
		YouTubeRegion:  "DE",
		Disney:         model.UnlockYes,
		TikTok:         model.UnlockYes,
		CheckedAt:      "2026-11-07T00:00:00Z",
		BatteryVersion: 2,
		ExitIP:         "203.0.113.7",
		ConsensusCount: 3,
		Rotating:       false,
		Hijack:         false,
		CFColo:         "FRA",
		CFLoc:          "DE",
		DNSIP:          "198.51.100.53",
		StunIP:         "198.51.100.99",
	}
	b, err := json.Marshal(v2)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"battery_version":2`)
	assert.Contains(t, string(b), `"exit_ip":"203.0.113.7"`)
	assert.Contains(t, string(b), `"consensus":3`)
	assert.Contains(t, string(b), `"cf_colo":"FRA"`)
	assert.Contains(t, string(b), `"cf_loc":"DE"`)
	assert.Contains(t, string(b), `"dns_ip":"198.51.100.53"`)
	assert.Contains(t, string(b), `"stun_ip":"198.51.100.99"`)
	assert.NotContains(t, string(b), `"rotating"`, "false omits (omitempty)")
	assert.NotContains(t, string(b), `"hijack"`, "false omits (omitempty)")

	var back model.MediaUnlockStatus
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, v2, back)

	// A v1 verdict carries NO evidence keys — byte-shape preserved.
	v1 := model.MediaUnlockStatus{ChatGPT: model.UnlockYes, CheckedAt: "2026-11-01T00:00:00Z"}
	b1, err1 := json.Marshal(v1)
	require.NoError(t, err1)
	assert.NotContains(t, string(b1), "battery_version")
	assert.NotContains(t, string(b1), "exit_ip")

	// Legacy JSON (pre-v2 records) decodes to BatteryVersion 0 — the
	// migration's stale-on-sight input.
	var legacy model.MediaUnlockStatus
	require.NoError(t, json.Unmarshal(
		[]byte(`{"chatgpt":"yes","checked_at":"2026-11-01T00:00:00Z"}`), &legacy))
	assert.Zero(t, legacy.BatteryVersion)
	assert.Equal(t, model.UnlockYes, legacy.ChatGPT)

	// The hijack/rotating flags survive a round trip.
	flagged := model.MediaUnlockStatus{ChatGPT: model.UnlockBlocked, Hijack: true, Rotating: true, BatteryVersion: 2}
	bf, errf := json.Marshal(flagged)
	require.NoError(t, errf)
	assert.Contains(t, string(bf), `"hijack":true`)
	assert.Contains(t, string(bf), `"rotating":true`)
	var flaggedBack model.MediaUnlockStatus
	require.NoError(t, json.Unmarshal(bf, &flaggedBack))
	assert.Equal(t, flagged, flaggedBack)
}

// TestGeoRecordPhase1JSONContract pins the Phase-1 field names on
// GeoRecord and the unchecked zero values a brand-new record carries.
func TestGeoRecordPhase1JSONContract(t *testing.T) {
	rec := model.GeoRecord{
		Tag: "t", Source: "s", Scheme: "vless", Host: "h", Port: 443,
		// The new-record literal semantics (mergeGeoRecords): scores start
		// unchecked, everything else at its zero value.
		RiskScore: -1, ScamalyticsScore: -1, AbuseScore: -1,
	}
	b, err := json.Marshal(rec)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	for _, k := range []string{
		"risk_score", "is_residential", "is_hosting", "is_proxy", "is_mobile",
		"scamalytics_score", "abuse_score", "ip_type", "media_unlocks",
	} {
		assert.Contains(t, m, k, "phase-1 field %s is part of the cold-base contract", k)
	}
	assert.InDelta(t, -1, m["risk_score"], 1e-9)
	assert.Empty(t, m["ip_type"])
	assert.False(t, m["is_residential"].(bool))
	mu, ok := m["media_unlocks"].(map[string]any)
	require.True(t, ok)
	assert.Empty(t, mu["chatgpt"])
	assert.Empty(t, mu["checked_at"])

	// The pre-Phase-1 field set must remain untouched (the on-disk
	// regression contract).
	for _, k := range []string{
		"tag", "source", "scheme", "host", "port", "ip", "proxy_flag",
		"hosting_flag", "flags_verified", "geo_source",
	} {
		assert.Contains(t, m, k)
	}
}

// TestGeoRecordLegacyDecode pins what a pre-Phase-1 record decodes to: the
// missing fields land on their Go zero values (scores 0, booleans false,
// empty strings) and the store's blank-fold + prev-carry semantics keep a
// later evidence-less wave from clobbering checked values.
func TestGeoRecordLegacyDecode(t *testing.T) {
	legacy := `{"tag":"t","source":"s","scheme":"vless","host":"h","port":443,` +
		`"ip":"203.0.113.7","proxy_flag":true,"hosting_flag":false,"flags_verified":true}`
	var rec model.GeoRecord
	require.NoError(t, json.Unmarshal([]byte(legacy), &rec))
	assert.Equal(t, 0, rec.RiskScore, "legacy records decode 0 (documented; prev-carry protects them)")
	assert.Equal(t, 0, rec.ScamalyticsScore, "absent fields decode to the Go zero value")
	assert.Empty(t, rec.IPType)
	assert.Equal(t, model.MediaUnlockStatus{}, rec.MediaUnlocks)
	assert.True(t, rec.ProxyFlag)
}
