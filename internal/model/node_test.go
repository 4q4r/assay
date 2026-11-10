package model_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"assay/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityKeyIsDeterministicAndOrderIndependent(t *testing.T) {
	a := model.NewNode("src", "vless", "uuid-1", "h1.example.com", 443, map[string]string{
		"sni": "a.com", "type": "tcp", "security": "reality",
	})
	b := model.NewNode("other-src", "vless", "uuid-1", "h1.example.com", 443, map[string]string{
		"security": "reality", "type": "tcp", "sni": "a.com",
	})
	assert.Equal(t, a.Key, b.Key, "param order must not affect the identity key")
	assert.NotEmpty(t, a.Key)
	assert.Len(t, a.Key, 16, "key is a 16-hex-char prefix of sha256")
}

func TestIdentityKeySeparatesCredentialsAndParams(t *testing.T) {
	base := map[string]string{"type": "tcp", "security": "tls"}
	same := model.NewNode("s", "vless", "u1", "h", 443, base)
	diffUUID := model.NewNode("s", "vless", "u2", "h", 443, base)
	diffHost := model.NewNode("s", "vless", "u1", "h2", 443, base)
	diffPort := model.NewNode("s", "vless", "u1", "h", 8443, base)
	diffParam := model.NewNode("s", "vless", "u1", "h", 443, map[string]string{"type": "tcp", "security": "tls", "path": "/x"})
	diffScheme := model.NewNode("s", "trojan", "u1", "h", 443, base)

	all := []string{same.Key, diffUUID.Key, diffHost.Key, diffPort.Key, diffParam.Key, diffScheme.Key}
	seen := map[string]bool{}
	for _, k := range all {
		assert.False(t, seen[k], "distinct identities must produce distinct keys")
		seen[k] = true
	}
}

func TestGeoRecordSchemaMatchesDesign(t *testing.T) {
	// The cold-base record schema is fixed by DESIGN.md §5; the JSON keys are a
	// regression contract with the on-disk geo-base.jsonl store.
	rec := model.GeoRecord{
		Tag: "pool-nl-01", Source: "matin", Scheme: "vless", Host: "h", Port: 443,
		IP: "5.6.7.8", Country: "nl", City: "Amsterdam", ASN: "AS60781", ASName: "LeaseWeb",
		ISP: "LeaseWeb", ProxyFlag: true, HostingFlag: true,
		FirstSeen: "2026-10-28T00:00:00Z", LastSeen: "2026-10-28T00:00:00Z", LastProbe: "2026-10-28T00:00:00Z",
		RTTMs: 120.5, SpeedBPS: 1024, Alive: true,
	}
	b, err := json.Marshal(rec)
	require.NoError(t, err)
	for _, key := range []string{
		"tag", "source", "scheme", "host", "port", "ip", "country", "city", "asn", "asname",
		"isp", "proxy_flag", "hosting_flag", "first_seen", "last_seen", "last_probe",
		"rtt_ms", "speed_bps", "alive", "bytes_up", "bytes_down",
	} {
		assert.Contains(t, string(b), `"`+key+`":`, "schema key %q missing", key)
	}
}

func TestPoolTagContract(t *testing.T) {
	// D5: flat tags pool-<cc>-NN, cc lowercase ISO alpha-2, NN zero-padded stable sequence.
	assert.Equal(t, "pool-nl-01", model.PoolTag("nl", 1))
	assert.Equal(t, "pool-fr-03", model.PoolTag("fr", 3))
	assert.Equal(t, "pool-de-25", model.PoolTag("de", 25))
	assert.Equal(t, "pool-us-07", model.PoolTag("US", 7), "country code is normalized to lowercase")
}

func TestBalancerTagContract(t *testing.T) {
	assert.Equal(t, "pool_nl", model.CountryBalancerTag("NL"))
	assert.Equal(t, "pool_de_berlin", model.CityBalancerTag("de", "Berlin"))
	assert.Equal(t, "pool_us_new_york", model.CityBalancerTag("us", "New York"))
}

// TestVMESSLinkPayloadIsStdBase64RoundTrip pins the vmess link encoding: the
// payload decodes with base64.StdEncoding and re-encodes byte-identically —
// guarding the hand-rolled-encoder → stdlib swap as behavior-preserving
// (review finding 13).
func TestVMESSLinkPayloadIsStdBase64RoundTrip(t *testing.T) {
	n := model.NewNode("s", "vmess", "11111111-2222-3333-4444-555555555555", "VM.example.COM", 8443,
		map[string]string{"net": "ws", "tls": "tls", "sni": "cdn.example", "path": "/ws", "host": "cdn.example"})
	link := n.Link()
	require.True(t, strings.HasPrefix(link, "vmess://"), link)

	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	require.NoError(t, err, "payload must be standard base64 with padding")

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(payload, &parsed))
	assert.Equal(t, n.Host, parsed["add"], "host is lowercased at NewNode")
	assert.Equal(t, "8443", parsed["port"])
	assert.Equal(t, n.UUID, parsed["id"])

	reencoded := base64.StdEncoding.EncodeToString(payload)
	assert.Equal(t, strings.TrimPrefix(link, "vmess://"), reencoded, "std decode→encode round-trips byte-identically")
}
