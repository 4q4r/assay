package probe

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"assay/internal/model"
	"assay/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The probe-stage dedup key (allocation audit M5/F8): jobs dedup on the
// node's STORED identity key (model.identityKey — scheme|host|port|cred|
// params) instead of rebuilding a full share-link URL per node per wave.
// The Link() URL construction (~30-45k per wave at incident scale) existed
// only to compute that dedup key; it is gone.

// TestProbeDedupMergesSameIdentityNodes is the M5 RED instrument: two nodes
// with ONE identity (same scheme/host/port/credential/params) that differ
// only in the remark fragment must probe ONCE — the fragment is a remark,
// it never reaches the wire config, so the two nodes are one probe job.
// Pre-change the pair built two distinct Link() URLs (the fragment rides
// the link text) and probed twice.
func TestProbeDedupMergesSameIdentityNodes(t *testing.T) {
	params := map[string]string{"security": "tls", "type": "tcp", "sni": "svc.example.com"}
	a := model.NewNode("plug-a", "vless", "uuid-1", "de1.example.com", 443, params)
	a.Fragment = "remark one"
	b := model.NewNode("plug-a", "vless", "uuid-1", "de1.example.com", 443, params)
	b.Fragment = "remark two"
	require.Equal(t, a.Key, b.Key, "the pair shares one identity key")
	require.NotEqual(t, a.Link(), b.Link(), "the pair's link TEXTS differ by fragment only")

	site := healthySite(t)
	socks := newSocksServer(t, site.Listener.Addr().String())
	var boots atomic.Int32
	factory := Factory(func(_ context.Context, _ *model.Node) (SocksInstance, error) {
		boots.Add(1)
		return &staticInstance{addr: socks.Addr()}, nil
	})
	out, err := Run(context.Background(), []*model.Node{a, b}, factory,
		Options{TCPPrefilter: prefilterOff(), Now: func() time.Time { return time.Now().UTC() }}, "")
	require.NoError(t, err)
	assert.Equal(t, int32(1), boots.Load(),
		"one identity = one probe job — the fragment-variant twin must not boot a second instance")
	require.Len(t, out, 2, "both identity keys still take the outcome (write-back unchanged)")
	byKey := map[string]bool{out[0].Key: true, out[1].Key: true}
	assert.True(t, byKey[a.Key] && byKey[b.Key])
}

// TestLinkImpliesIdentityKey pins the dedup-key SAFETY direction over the
// scheme families: two nodes whose rendered links are byte-equal always
// share the stored identity key — so Key-dedup keeps every merge the old
// Link-dedup performed (strictly-more dedup, never less).
func TestLinkImpliesIdentityKey(t *testing.T) {
	cases := []struct {
		name   string
		scheme string
		cred   string
		host   string
		port   int
		params map[string]string
	}{
		{
			"vless reality", "vless", "uuid-1", "de1.example.com", 443,
			map[string]string{"security": "reality", "type": "tcp", "pbk": "PBK", "sid": "AA"},
		},
		{"trojan", "trojan", "uuid-2", "de3.example.com", 8443, nil},
		{
			"ss", "ss", "method:password", "us1.example.com", 8388,
			map[string]string{"method": "aes-256-gcm", "password": "pw"},
		},
		{
			"hysteria2", "hysteria2", "uuid-3", "jp1.example.jp", 443,
			map[string]string{"sni": "svc.jp"},
		},
		{
			"vmess", "vmess", "uuid-4", "us2.example.com", 443,
			map[string]string{"type": "ws", "security": "tls", "path": "/ws"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := model.NewNode("s", tc.scheme, tc.cred, tc.host, tc.port, tc.params)
			a.Fragment = "frag-a"
			b := model.NewNode("s", tc.scheme, tc.cred, tc.host, tc.port, tc.params)
			b.Fragment = "frag-a" // same remark: links byte-equal
			require.Equal(t, a.Link(), b.Link(), "fixture must render equal links")
			assert.Equal(t, a.Key, b.Key,
				"equal links must collapse onto one identity key (the Key-dedup safety direction)")
		})
	}
}

// TestFragmentNeverReachesTheWireConfig documents WHY the fragment-variant
// merge is verdict-neutral: the rendered xray outbound is byte-equal for two
// same-identity nodes regardless of their remark fragments — one probe job
// covers both nodes' wire semantics exactly.
func TestFragmentNeverReachesTheWireConfig(t *testing.T) {
	params := map[string]string{"security": "tls", "type": "tcp", "sni": "svc.example.com"}
	a := model.NewNode("s", "vless", "uuid-1", "de1.example.com", 443, params)
	a.Fragment = "remark one"
	b := model.NewNode("s", "vless", "uuid-1", "de1.example.com", 443, params)
	b.Fragment = "remark two"

	obA, dropsA, err := render.BuildOutbound(a, "probe-out-0", render.Config{TCPMaxSeg: 1440})
	require.NoError(t, err)
	obB, dropsB, err := render.BuildOutbound(b, "probe-out-0", render.Config{TCPMaxSeg: 1440})
	require.NoError(t, err)
	assert.Equal(t, dropsA, dropsB)
	assert.Equal(t, obA, obB,
		"the fragment is a remark only — the wire config cannot tell the twins apart")
}
