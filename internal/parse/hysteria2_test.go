package parse_test

import (
	"testing"

	"assay/internal/parse"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W7 item 10: hysteria2 (hysteria2:// and hy2://) share links.
//
// VERIFY-FIRST verdict (2026-10-28, xray 26.3.27 binary + tagged source):
// the core HAS a real hysteria2 client (proxy/hysteria speaks the
// hysteria2 wire protocol over apernet/quic-go; version must == 2), so
// hysteria2 links are PARSED (acceptance stays a [filter].protocols
// policy, opt-in like ss). hysteria v1 links stay rejected — the core
// refuses version != 2, and the v1 wire protocol is a different protocol.

func TestParseHysteria2Link(t *testing.T) {
	link := "hysteria2://secretpw@hy1.example.com:8443/?insecure=0&sni=real.example.com&pinSHA256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef&ech=AEz%2BDQBIAAAg#hy-node"
	n, err := parse.Link("parse-test", link)
	require.NoError(t, err)

	assert.Equal(t, "hysteria2", n.Scheme, "the canonical scheme is hysteria2")
	assert.Equal(t, "secretpw", n.UUID, "the auth credential rides the userinfo")
	assert.Equal(t, "hy1.example.com", n.Host)
	assert.Equal(t, 8443, n.Port)
	// L9: params pass through verbatim (keys lowercased by the shared
	// query normalization, values untouched).
	assert.Equal(t, "0", n.Params["insecure"])
	assert.Equal(t, "real.example.com", n.Params["sni"])
	assert.Equal(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", n.Params["pinsha256"])
	assert.Equal(t, "AEz+DQBIAAAg", n.Params["ech"], "the query value is percent-decoded once")
	assert.Equal(t, "hy-node", n.Fragment)
}

func TestHy2AliasNormalizesToHysteria2(t *testing.T) {
	a, err := parse.Link("s", "hysteria2://pw@n1.example.com:443#one")
	require.NoError(t, err)
	b, err := parse.Link("s", "hy2://pw@n1.example.com:443#two")
	require.NoError(t, err)

	assert.Equal(t, "hysteria2", b.Scheme, "hy2:// is the documented alias of hysteria2://")
	assert.Equal(t, a.Key, b.Key, "the same server via both spellings must share one identity (dedupe join)")
}

func TestHysteria2AuthIsOptional(t *testing.T) {
	// The official URI spec marks auth optional: hysteria2://host:port.
	n, err := parse.Link("s", "hysteria2://open.example.com:443#open")
	require.NoError(t, err)
	assert.Equal(t, "hysteria2", n.Scheme)
	assert.Empty(t, n.UUID, "auth-less links parse; the renderer passes the empty auth 1:1")
	assert.Equal(t, "open.example.com", n.Host)
	assert.Equal(t, 443, n.Port)
}

func TestHysteriaV1LinksStayRejected(t *testing.T) {
	// The core enforces version == 2; a v1 link is a DIFFERENT protocol the
	// renderer could never express faithfully — it stays a parse-time
	// rejection with the kind counted.
	res := parse.Lines("s", "hysteria://auth@old.example.com:443/?auth=x&upmbps=50\n")
	assert.Empty(t, res.Nodes)
	assert.Equal(t, 1, res.Rejected)
	assert.Equal(t, 1, res.RejectedKinds["hysteria"])
}

func TestHysteria2AndHy2NoLongerInRejectedKinds(t *testing.T) {
	res := parse.Lines("s", "hysteria2://pw@a.example.com:443\nhy2://pw@b.example.com:443\n")
	assert.Len(t, res.Nodes, 2, "hysteria2/hy2 are parsed now")
	assert.Equal(t, 0, res.Rejected)
	for _, kind := range []string{"hysteria2", "hy2"} {
		assert.Zero(t, res.RejectedKinds[kind], "kind %q must not be a rejection kind anymore", kind)
	}
}

func TestHysteria2MalformedInputsAreCounted(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"missing port", "hysteria2://pw@hostless-port.example.com#x"},
		{"port range (port hopping) is not a port", "hysteria2://pw@hop.example.com:123,5000-6000#x"},
		{"zero port", "hysteria2://pw@zero.example.com:0#x"},
		{"empty host", "hysteria2://pw@:443#x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := parse.Lines("s", tc.line+"\n")
			assert.Equal(t, 1, res.Malformed, "the line must be counted malformed, never fatal")
			assert.Empty(t, res.Nodes)
		})
	}
}

func TestHysteria2IsSupported(t *testing.T) {
	assert.True(t, parse.IsSupported("hysteria2://pw@h.example.com:443"))
	assert.True(t, parse.IsSupported("hy2://pw@h.example.com:443"))
	assert.False(t, parse.IsSupported("hysteria://pw@h.example.com:443"), "v1 stays unsupported")
}
