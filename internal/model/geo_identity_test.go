package model_test

import (
	"testing"

	"assay/internal/model"

	"github.com/stretchr/testify/assert"
)

// TestGeoIdentityFormat pins the cold-base record identity:
// scheme (verbatim) | lowercased host | port. The scheme is deliberately NOT
// case-normalized — that is the historical store.GeoIdentity behavior this
// function hoisted (W7 M2), and changing it would silently re-key the cold
// base on disk.
func TestGeoIdentityFormat(t *testing.T) {
	cases := []struct {
		name string
		rec  model.GeoRecord
		want string
	}{
		{"plain", model.GeoRecord{Scheme: "vless", Host: "de.example.com", Port: 443}, "vless|de.example.com|443"},
		{"host case is normalized", model.GeoRecord{Scheme: "trojan", Host: "De.Example.COM", Port: 8443}, "trojan|de.example.com|8443"},
		{"scheme is verbatim (not lowercased)", model.GeoRecord{Scheme: "VLESS", Host: "de.example.com", Port: 443}, "VLESS|de.example.com|443"},
		{"ipv6-ish host", model.GeoRecord{Scheme: "vless", Host: "2001:db8::1", Port: 2053}, "vless|2001:db8::1|2053"},
		{"bracketed ipv6 host", model.GeoRecord{Scheme: "vless", Host: "[2001:db8::2]", Port: 443}, "vless|[2001:db8::2]|443"},
		{"zero port", model.GeoRecord{Scheme: "ss", Host: "nl1.example.com", Port: 0}, "ss|nl1.example.com|0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, model.GeoIdentity(&tc.rec))
		})
	}
}

// TestGeoIdentityOfMatchesGeoIdentity is the allocation-audit M2 pin: the
// field-form identity key is THE implementation (GeoIdentity delegates), so
// per-node lookup sites key maps without constructing throwaway GeoRecord
// structs. Every edge input must produce the exact same bytes through both
// forms — a divergence would split or mis-join cold-base records.
func TestGeoIdentityOfMatchesGeoIdentity(t *testing.T) {
	cases := []struct {
		name   string
		scheme string
		host   string
		port   int
	}{
		{"plain", "vless", "de.example.com", 443},
		{"host case is normalized", "trojan", "De.Example.COM", 8443},
		{"scheme is verbatim", "VLESS", "de.example.com", 443},
		{"ipv6-ish host", "vless", "2001:db8::1", 2053},
		{"bracketed ipv6 host", "vless", "[2001:db8::2]", 65535},
		{"zero port", "ss", "nl1.example.com", 0},
		{"empty host", "vless", "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			viaStruct := model.GeoIdentity(&model.GeoRecord{Scheme: tc.scheme, Host: tc.host, Port: tc.port})
			assert.Equal(t, viaStruct, model.GeoIdentityOf(tc.scheme, tc.host, tc.port),
				"field-form key must be byte-identical to the record-form key")
		})
	}
}

// TestGeoIdentitySeparatesCaseVariants pins that case-variant spellings of the
// SAME host collapse onto one identity (the upsert join key), while a
// different scheme or port never does.
func TestGeoIdentitySeparatesCaseVariants(t *testing.T) {
	a := model.GeoIdentity(&model.GeoRecord{Scheme: "vless", Host: "De1.Example.com", Port: 443})
	b := model.GeoIdentity(&model.GeoRecord{Scheme: "vless", Host: "de1.example.com", Port: 443})
	assert.Equal(t, a, b, "host case must not change the identity")

	assert.NotEqual(t, a, model.GeoIdentity(&model.GeoRecord{Scheme: "trojan", Host: "de1.example.com", Port: 443}),
		"a different scheme is a different record")
	assert.NotEqual(t, a, model.GeoIdentity(&model.GeoRecord{Scheme: "vless", Host: "de1.example.com", Port: 8443}),
		"a different port is a different record")
}
