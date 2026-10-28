package parse_test

import (
	"strings"
	"testing"

	"public_vpn/internal/parse"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVLESSRealityXHTTP(t *testing.T) {
	link := "vless://1918fb45-3312-4893-b3f9-77b7c3e647b6@109.122.197.79:443?type=xhttp&security=reality&sni=www.kit.edu&host=www.kit.edu&path=%2F&pbk=I-reZxJUuER7atFvxyYlI_OxoDdV0rQev16Hewhjcz4&sid=616f0ee48093b218&fp=chrome&mode=packet-up#Germans%20Primary"
	n, err := parse.Link("matin", link)
	require.NoError(t, err)
	assert.Equal(t, "vless", n.Scheme)
	assert.Equal(t, "1918fb45-3312-4893-b3f9-77b7c3e647b6", n.UUID)
	assert.Equal(t, "109.122.197.79", n.Host)
	assert.Equal(t, 443, n.Port)
	assert.Equal(t, "xhttp", n.Network)
	assert.Equal(t, "reality", n.Security)
	// L9: params verbatim.
	assert.Equal(t, "www.kit.edu", n.Params["sni"])
	assert.Equal(t, "www.kit.edu", n.Params["host"])
	assert.Equal(t, "I-reZxJUuER7atFvxyYlI_OxoDdV0rQev16Hewhjcz4", n.Params["pbk"])
	assert.Equal(t, "616f0ee48093b218", n.Params["sid"])
	assert.Equal(t, "packet-up", n.Params["mode"])
	assert.Equal(t, "Germans Primary", n.Fragment)
}

func TestParseVLESSFlowAndEmptyPath(t *testing.T) {
	link := "vless://uuid-abc@node.example.org:2053?type=tcp&security=reality&sni=www.microsoft.com&flow=xtls-rprx-vision&fp=firefox#"
	n, err := parse.Link("s", link)
	require.NoError(t, err)
	assert.Equal(t, "xtls-rprx-vision", n.Params["flow"])
	assert.Equal(t, "firefox", n.Params["fp"])
	assert.Empty(t, n.Params["path"], "explicitly empty param stays present verbatim")
}

func TestParseTrojanDefaultsTLS(t *testing.T) {
	link := "trojan://pa55word@t.example.net:443?security=tls&type=tcp&sni=t.example.net#tj"
	n, err := parse.Link("s", link)
	require.NoError(t, err)
	assert.Equal(t, "trojan", n.Scheme)
	assert.Equal(t, "pa55word", n.UUID)
	assert.Equal(t, "tls", n.Security)
}

func TestParseTrojanWSParams(t *testing.T) {
	link := "trojan://pw@t.example.net:443?type=ws&security=tls&host=cdn.example.net&path=%2Ftrojan%2Fws"
	n, err := parse.Link("s", link)
	require.NoError(t, err)
	assert.Equal(t, "ws", n.Network)
	assert.Equal(t, "/trojan/ws", n.Params["path"])
	assert.Equal(t, "cdn.example.net", n.Params["host"])
}

func TestParseVMESSBase64JSON(t *testing.T) {
	// vmess://base64(JSON)
	raw := `{"v":"2","ps":"JP node","add":"vm.example.com","port":"8443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/vmws","tls":"tls","sni":"vm.example.com","fp":"chrome"}`
	link := "vmess://" + b64(raw)
	n, err := parse.Link("s", link)
	require.NoError(t, err)
	assert.Equal(t, "vmess", n.Scheme)
	assert.Equal(t, "b831381d-6324-4d53-ad4f-8cda48b30811", n.UUID)
	assert.Equal(t, "vm.example.com", n.Host)
	assert.Equal(t, 8443, n.Port)
	assert.Equal(t, "ws", n.Network)
	assert.Equal(t, "tls", n.Security)
	assert.Equal(t, "/vmws", n.Params["path"])
	assert.Equal(t, "auto", n.Params["scy"])
	assert.Equal(t, "JP node", n.Fragment)
}

func TestParseVMESSAltIDDefaultZero(t *testing.T) {
	raw := `{"v":"2","add":"h","port":"1","id":"x","net":"tcp","tls":""}`
	n, err := parse.Link("s", "vmess://"+b64(raw))
	require.NoError(t, err)
	assert.Empty(t, n.Security)
	assert.Equal(t, "0", n.Params["aid"], "missing alterId defaults to 0")
}

func TestParseVMESSURLForm(t *testing.T) {
	// Some aggregators emit vmess://<base64 of uuid@host:port?query> instead of JSON.
	inner := "b831381d-6324-4d53-ad4f-8cda48b30811@vm.example.com:8443?encryption=none&security=tls&sni=s.example.com&type=ws&host=h.example.com&path=%2Fp"
	link := "vmess://" + b64(inner)
	n, err := parse.Link("s", link)
	require.NoError(t, err)
	assert.Equal(t, "b831381d-6324-4d53-ad4f-8cda48b30811", n.UUID)
	assert.Equal(t, "tls", n.Security)
	assert.Equal(t, "/p", n.Params["path"])
}

func TestRejectedSchemesAreCounted(t *testing.T) {
	lines := []string{
		"tuic://uuid@h:443?congestion_control=bbr",
		"hy2://pw@h:443",
		"hysteria://pw@h:443",
		"hysteria2://pw@h:443",
		"ssr://base64stuff",
		"ss://YWVzLTI1Ni1nY206cHc@h:443",
		"vless://u@ok.example.com:443?security=tls&type=tcp#ok",
	}
	res := parse.Lines("s", strings.Join(lines, "\n"))
	require.Len(t, res.Nodes, 1)
	assert.Equal(t, 6, res.Rejected, "tuic/hy2/hysteria/hysteria2/ssr/ss are rejected")
	assert.Equal(t, "ok.example.com", res.Nodes[0].Host)
	assert.Len(t, res.RejectedKinds, 6)
}

func TestBase64BodyIsDetectedAndDecoded(t *testing.T) {
	body := b64("vless://u@b64.example.com:443?security=tls&type=tcp#a\nvless://u2@b64b.example.com:443?security=tls&type=tcp#b")
	res := parse.Lines("s", body)
	require.Len(t, res.Nodes, 2)
	assert.Equal(t, 0, res.Rejected)
}

func TestBase64WithURLEncodingAndNoPadding(t *testing.T) {
	body := b64URL("vless://u@nopad.example.com:443?security=tls&type=tcp#x")
	body = strings.TrimRight(body, "=")
	res := parse.Lines("s", body)
	require.Len(t, res.Nodes, 1)
	assert.Equal(t, "nopad.example.com", res.Nodes[0].Host)
}

func TestPlainBodyPassesThrough(t *testing.T) {
	body := "vless://u@p1.example.com:443?security=tls&type=tcp#a\n\n# just a comment\nvless://u2@p2.example.com:443?security=tls&type=tcp#b"
	res := parse.Lines("s", body)
	require.Len(t, res.Nodes, 2)
}

func TestMalformedInputsAreCountedNotFatal(t *testing.T) {
	lines := []string{
		"vless://@:443",                     // empty uuid and host
		"vless://u@not-a-host",              // missing port
		"vless://u@h:0?security=tls",        // port zero
		"vless://u@h:99999?security=tls",    // port out of range
		"vless://u@h:443?security=tls#frag", // ok
		"::::not a link at all::::",         // garbage line
		"vmess://bm90IGpzb24gYXQgYWxsIQ==",  // base64 of "not json at all!"
	}
	res := parse.Lines("s", strings.Join(lines, "\n"))
	assert.Len(t, res.Nodes, 1)
	assert.Equal(t, 6, res.Malformed, "malformed lines are counted, never fatal")
}

func TestBracketedIPv6Host(t *testing.T) {
	link := "vless://u@[2001:db8::1]:443?security=tls&type=tcp#v6"
	n, err := parse.Link("s", link)
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::1", n.Host)
	assert.Equal(t, 443, n.Port)
}

func TestLinkRoundTripPreservesParamsVerbatim(t *testing.T) {
	orig := "vless://1918fb45-3312-4893-b3f9-77b7c3e647b6@1.2.3.4:443?type=xhttp&security=reality&sni=www.kit.edu&host=www.kit.edu&pbk=PK&sid=a1b2&fp=chrome&mode=packet-up#n"
	n, err := parse.Link("s", orig)
	require.NoError(t, err)
	again, err := parse.Link("s", n.Link())
	require.NoError(t, err)
	assert.Equal(t, n.Key, again.Key, "link round-trip must preserve the identity key")
	for k, v := range n.Params {
		assert.Equal(t, v, again.Params[k], "param %s must round-trip 1:1", k)
	}
}

func b64(s string) string { return b64With(s, "+/") }

func b64URL(s string) string { return b64With(s, "-_") }

func b64With(s, alphabet string) string {
	std := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var c [3]byte
		n := copy(c[:], data[i:])
		v := uint32(c[0])<<16 | uint32(c[1])<<8 | uint32(c[2])
		out.WriteByte(std[v>>18&0x3F])
		out.WriteByte(std[v>>12&0x3F])
		if n > 1 {
			out.WriteByte(std[v>>6&0x3F])
		}
		if n > 2 {
			out.WriteByte(std[v&0x3F])
		}
	}
	if alphabet != "+/" {
		return strings.NewReplacer("+", string(alphabet[0]), "/", string(alphabet[1])).Replace(out.String())
	}
	return out.String()
}

// TestDuplicateQueryKeysAreDeterministic pins the param-pick contract: when a
// query carries the same key several times (or in case variants), the winner
// is the lexicographically smallest value — deterministic, never dependent on
// Go's randomized map iteration (review finding 13).
func TestDuplicateQueryKeysAreDeterministic(t *testing.T) {
	line := "vless://u@h.example.com:443?security=tls&Type=tcp&type=ws"
	for range 20 {
		n, err := parse.Link("s", line)
		require.NoError(t, err)
		assert.Equal(t, "tcp", n.Network,
			"sorted-first value wins every time (tcp < ws); map order must not decide")
	}
}

// TestFragmentIsDecodedExactlyOnce pins the fragment contract: url.Parse
// already decodes the fragment; a second unescape corrupts literal % sequences
// (review finding 13).
func TestFragmentIsDecodedExactlyOnce(t *testing.T) {
	n, err := parse.Link("s", "vless://u@h.example.com:443?security=tls#tag%2520one")
	require.NoError(t, err)
	assert.Equal(t, "tag%20one", n.Fragment,
		"%25 must decode to % exactly once — not to a space")
}

// TestFragmentPlainSurvives: fragments without escapes pass through verbatim.
func TestFragmentPlainSurvives(t *testing.T) {
	n, err := parse.Link("s", "vless://u@h.example.com:443?security=tls#Berlin%20node")
	require.NoError(t, err)
	assert.Equal(t, "Berlin node", n.Fragment)
}

// TestExactDuplicateKeyKeepsFirstOccurrence pins the within-key convention:
// exact duplicates keep the first occurrence (url.Values order), which is
// already deterministic — only case-variant collisions need the min rule.
func TestExactDuplicateKeyKeepsFirstOccurrence(t *testing.T) {
	n, err := parse.Link("s", "vless://u@h.example.com:443?security=tls&type=ws&type=grpc")
	require.NoError(t, err)
	assert.Equal(t, "ws", n.Network, "first occurrence wins within one exact key")
}
