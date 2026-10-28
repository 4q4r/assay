package filter_test

import (
	"strings"
	"testing"

	"public_vpn/internal/filter"
	"public_vpn/internal/model"
	"public_vpn/internal/parse"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mk(t *testing.T, source, link string) *model.Node {
	t.Helper()
	n, err := parse.Link(source, link)
	require.NoError(t, err)
	return n
}

func TestKeepsRealityAndTLSOnly(t *testing.T) {
	nodes := []*model.Node{
		mk(t, "s", "vless://u@real.example.com:443?security=reality&type=tcp#r"),
		mk(t, "s", "vless://u@tls.example.com:443?security=tls&type=tcp#t"),
		mk(t, "s", "trojan://p@tj.example.com:443?type=tcp#tj"),  // trojan defaults to tls
		mk(t, "s", "vless://u@plain.example.com:443?type=tcp#p"), // security none
		mk(t, "s", "vless://u@none.example.com:443?security=none&type=tcp#n"),
	}
	kept, dropped := filter.Run(nodes)
	require.Len(t, kept, 3)
	require.Len(t, dropped, 2)
	for _, d := range dropped {
		assert.Contains(t, d.Reason, "no reality/tls security")
	}
}

func TestDropsAllowInsecure(t *testing.T) {
	nodes := []*model.Node{
		mk(t, "s", "vless://u@a.example.com:443?security=tls&allowInsecure=1&type=tcp#a"),
		mk(t, "s", "vless://u@b.example.com:443?security=tls&allowinsecure=true&type=tcp#b"),
		mk(t, "s", "vless://u@c.example.com:443?security=tls&insecure=1&type=tcp#c"),
		mk(t, "s", "vless://u@ok.example.com:443?security=tls&type=tcp#ok"),
	}
	kept, dropped := filter.Run(nodes)
	require.Len(t, kept, 1)
	assert.Len(t, dropped, 3)
	assert.Contains(t, dropped[0].Reason, "insecure")
}

func TestDropsPrivateAndLoopbackHosts(t *testing.T) {
	nodes := []*model.Node{
		mk(t, "s", "vless://u@127.0.0.1:443?security=tls&type=tcp#loop"),
		mk(t, "s", "vless://u@10.0.0.5:443?security=tls&type=tcp#priv"),
		mk(t, "s", "vless://u@192.168.1.10:443?security=tls&type=tcp#lan"),
		mk(t, "s", "vless://u@172.16.0.9:443?security=tls&type=tcp#docker"),
		mk(t, "s", "vless://u@[::1]:443?security=tls&type=tcp#v6loop"),
		mk(t, "s", "vless://u@localhost:443?security=tls&type=tcp#lh"),
		mk(t, "s", "vless://u@[fe80::1]:443?security=tls&type=tcp#linklocal"),
		mk(t, "s", "vless://u@8.8.8.8:443?security=tls&type=tcp#public"),
	}
	kept, dropped := filter.Run(nodes)
	require.Len(t, kept, 1)
	assert.Equal(t, "8.8.8.8", kept[0].Host)
	assert.Len(t, dropped, 7)
	for _, d := range dropped {
		assert.Contains(t, d.Reason, "private/loopback host")
	}
}

func TestDropsEmptyAndBogusHosts(t *testing.T) {
	n := &model.Node{Key: "x", Scheme: "vless", Host: "", Port: 443, Params: map[string]string{"security": "tls"}}
	n2 := &model.Node{Key: "y", Scheme: "vless", Host: "ok.example.com", Port: 0, Params: map[string]string{"security": "tls"}}
	kept, dropped := filter.Run([]*model.Node{n, n2})
	assert.Empty(t, kept)
	assert.Len(t, dropped, 2)
}

func TestDropsDuplicateKeysKeepingFirst(t *testing.T) {
	a := mk(t, "first", "vless://u@dup.example.com:443?security=tls&sni=a.com&type=tcp#one")
	b := mk(t, "second", "vless://u@dup.example.com:443?security=tls&sni=a.com&type=tcp#two")
	c := mk(t, "third", "vless://u@dup.example.com:443?security=tls&sni=b.com&type=tcp#three")
	kept, dropped := filter.Run([]*model.Node{a, b, c})
	require.Len(t, kept, 2)
	assert.Equal(t, "first", kept[0].Source, "first occurrence wins")
	assert.Len(t, dropped, 1)
	assert.Contains(t, dropped[0].Reason, "duplicate")
}

func TestPerSourceCap(t *testing.T) {
	nodes := make([]*model.Node, 0, 10)
	for i := range 10 {
		nodes = append(nodes, mk(t, "big", "vless://u@cap"+strings.Repeat("x", i+1)+".example.com:443?security=tls&type=tcp#c"))
	}
	kept, _ := filter.Run(nodes, filter.WithSourceCap(3))
	assert.Len(t, kept, 3)
}

func TestFilterIsDeterministicAndStable(t *testing.T) {
	nodes := []*model.Node{
		mk(t, "s", "vless://u@z.example.com:443?security=tls&type=tcp#z"),
		mk(t, "s", "vless://u@a.example.com:443?security=tls&type=tcp#a"),
		mk(t, "s", "vless://u@m.example.com:443?security=tls&type=tcp#m"),
	}
	kept1, _ := filter.Run(nodes)
	kept2, _ := filter.Run(nodes)
	assert.Equal(t, kept1, kept2, "filter output order must be deterministic")
}

// TestProtocolsAllowlist pins the W5 acceptance policy: ss is parsed but
// DROPPED unless allowlisted ([filter].protocols, default vless,vmess,trojan).
func TestProtocolsAllowlist(t *testing.T) {
	ssNode := model.NewNode("s", "ss", "aes-128-gcm:pw", "ss.example.com", 8388,
		map[string]string{"method": "aes-128-gcm", "password": "pw", "security": "tls", "type": "tcp"})
	vlessNode := model.NewNode("s", "vless", "u", "v.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp"})

	t.Run("default drops ss", func(t *testing.T) {
		kept, dropped := filter.Run([]*model.Node{ssNode, vlessNode})
		assert.Equal(t, []*model.Node{vlessNode}, kept)
		require.Len(t, dropped, 1)
		assert.Contains(t, dropped[0].Reason, "allowlist")
		assert.Contains(t, dropped[0].Reason, `"ss"`)
	})
	t.Run("ss opt-in passes security-checked", func(t *testing.T) {
		kept, dropped := filter.Run([]*model.Node{ssNode, vlessNode}, filter.WithProtocols([]string{"vless", "vmess", "trojan", "ss"}))
		assert.Len(t, kept, 2)
		assert.Empty(t, dropped)
	})
	t.Run("PSK-only ss still fails the security stance", func(t *testing.T) {
		plain := model.NewNode("s", "ss", "aes-128-gcm:pw", "ss.example.com", 8388,
			map[string]string{"method": "aes-128-gcm", "password": "pw", "type": "tcp"})
		kept, dropped := filter.Run([]*model.Node{plain}, filter.WithProtocols([]string{"ss"}))
		assert.Empty(t, kept, "no security=reality|tls → dropped even when allowlisted (documented stance)")
		assert.Contains(t, dropped[0].Reason, "no reality/tls security")
	})
	t.Run("empty allowlist option falls back to default", func(t *testing.T) {
		kept, _ := filter.Run([]*model.Node{vlessNode}, filter.WithProtocols(nil))
		assert.Len(t, kept, 1)
	})
}

// TestAllowInsecurePolicy pins the W5 [filter].allow_insecure knob: denial in
// filter (default), admitted links reach the renderer (which surfaces the
// removed feature as a drop-report entry — never a rendered key).
func TestAllowInsecurePolicy(t *testing.T) {
	// Keys arrive lowercased from parse (pipeline-realistic input).
	n := model.NewNode("s", "vless", "u", "v.example.com", 443,
		map[string]string{"security": "tls", "type": "tcp", "allowinsecure": "1"})
	kept, dropped := filter.Run([]*model.Node{n})
	assert.Empty(t, kept)
	require.Len(t, dropped, 1)
	assert.Contains(t, dropped[0].Reason, "allow_insecure=false")

	kept, _ = filter.Run([]*model.Node{n}, filter.WithAllowInsecure(true))
	assert.Len(t, kept, 1, "explicit policy admits the link (renderer reports the limitation)")
}
