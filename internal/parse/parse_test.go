package parse_test

import (
	"strings"
	"testing"

	"assay/internal/parse"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVLESSRealityXHTTP(t *testing.T) {
	link := "vless://1918fb45-3312-4893-b3f9-77b7c3e647b6@109.122.197.79:443?type=xhttp&security=reality&sni=www.kit.edu&host=www.kit.edu&path=%2F&pbk=I-reZxJUuER7atFvxyYlI_OxoDdV0rQev16Hewhjcz4&sid=616f0ee48093b218&fp=chrome&mode=packet-up#Germans%20Primary"
	n, err := parse.Link("prov-a", link)
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
		"hysteria://pw@h:443",
		"ssr://base64stuff",
		"vless://u@ok.example.com:443?security=tls&type=tcp#ok",
	}
	res := parse.Lines("s", []byte(strings.Join(lines, "\n")), nil)
	require.Len(t, res.Nodes, 1)
	assert.Equal(t, 3, res.Rejected, "tuic/hysteria-v1/ssr are rejected (W7 item 10: hysteria2/hy2 moved to parsed — the core has a real hysteria2 client)")
	assert.Equal(t, "ok.example.com", res.Nodes[0].Host)
	assert.Len(t, res.RejectedKinds, 3)
}

// TestSSIsParsedNotRejected pins the W5 policy shift: ss links are PARSED
// (acceptance is a filter policy — [filter].protocols), never scheme-rejected.
func TestSSIsParsedNotRejected(t *testing.T) {
	res := parse.Lines("s", []byte("ss://YWVzLTI1Ni1nY206cHc@h:443"), nil)
	require.Len(t, res.Nodes, 1)
	assert.Equal(t, 0, res.Rejected, "ss is parsed; acceptance is the filter's allowlist decision")
	assert.Equal(t, "ss", res.Nodes[0].Scheme)
}

func TestBase64BodyIsDetectedAndDecoded(t *testing.T) {
	body := b64("vless://u@b64.example.com:443?security=tls&type=tcp#a\nvless://u2@b64b.example.com:443?security=tls&type=tcp#b")
	res := parse.Lines("s", []byte(body), nil)
	require.Len(t, res.Nodes, 2)
	assert.Equal(t, 0, res.Rejected)
}

func TestBase64WithURLEncodingAndNoPadding(t *testing.T) {
	body := b64URL("vless://u@nopad.example.com:443?security=tls&type=tcp#x")
	body = strings.TrimRight(body, "=")
	res := parse.Lines("s", []byte(body), nil)
	require.Len(t, res.Nodes, 1)
	assert.Equal(t, "nopad.example.com", res.Nodes[0].Host)
}

func TestPlainBodyPassesThrough(t *testing.T) {
	body := "vless://u@p1.example.com:443?security=tls&type=tcp#a\n\n# just a comment\nvless://u2@p2.example.com:443?security=tls&type=tcp#b"
	res := parse.Lines("s", []byte(body), nil)
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
	res := parse.Lines("s", []byte(strings.Join(lines, "\n")), nil)
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

// TestSSSIP002Links pins the shadowsocks link variants the parser accepts.
func TestSSSIP002Links(t *testing.T) {
	t.Run("base64url userinfo", func(t *testing.T) {
		n, err := parse.Link("s", "ss://"+b64URL("aes-128-gcm:secret-pw")+"@ss.example.com:8388?sni=s.example.com&type=tcp#ss-node")
		require.NoError(t, err)
		assert.Equal(t, "ss", n.Scheme)
		assert.Equal(t, "ss.example.com", n.Host)
		assert.Equal(t, 8388, n.Port)
		assert.Equal(t, "aes-128-gcm", n.Params["method"])
		assert.Equal(t, "secret-pw", n.Params["password"])
		assert.Equal(t, "s.example.com", n.Params["sni"], "query params pass through verbatim")
		assert.Equal(t, "ss-node", n.Fragment)
	})
	t.Run("plaintext userinfo", func(t *testing.T) {
		n, err := parse.Link("s", "ss://chacha20-ietf-poly1305:pw123@ss2.example.com:443?security=tls")
		require.NoError(t, err)
		assert.Equal(t, "chacha20-ietf-poly1305", n.Params["method"])
		assert.Equal(t, "pw123", n.Params["password"])
		assert.Equal(t, "tls", n.Security, "ss+security=tls is admitted by NewNode like any scheme")
	})
	t.Run("legacy whole-link base64", func(t *testing.T) {
		n, err := parse.Link("s", "ss://"+b64("aes-256-gcm:legacypw@ss3.example.com:8388"))
		require.NoError(t, err)
		assert.Equal(t, "ss3.example.com", n.Host)
		assert.Equal(t, "aes-256-gcm", n.Params["method"])
		assert.Equal(t, "legacypw", n.Params["password"])
	})
	t.Run("plugin param passes through verbatim", func(t *testing.T) {
		n, err := parse.Link("s", "ss://"+b64URL("aes-128-gcm:pw")+"@ss4.example.com:443?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example")
		require.NoError(t, err)
		assert.Equal(t, "obfs-local;obfs=http;obfs-host=cdn.example", n.Params["plugin"], "plugin params parsed and stored 1:1 (render fails loud)")
	})
	t.Run("round-trips through Node.Link", func(t *testing.T) {
		n, err := parse.Link("s", "ss://"+b64URL("aes-128-gcm:pw")+"@ss5.example.com:443?type=tcp&sni=s.example.com#frag")
		require.NoError(t, err)
		again, err := parse.Link("s", n.Link())
		require.NoError(t, err)
		assert.Equal(t, n.Key, again.Key, "rebuilt ss link parses to the same identity")
		assert.Equal(t, n.Params["method"], again.Params["method"])
	})
	t.Run("malformed", func(t *testing.T) {
		for _, bad := range []string{
			"ss://",                                // empty
			"ss://nosuffix",                        // no @ and not base64 of a target
			"ss://withoutcolons@h.example.com:443", // userinfo without method:password
			"ss://" + b64URL("m:pw") + "@h.example.com:0",     // port 0
			"ss://" + b64URL("m:pw") + "@h.example.com:99999", // port out of range
		} {
			_, err := parse.Link("s", bad)
			require.Error(t, err, "expected %q to be rejected", bad)
		}
	})
}

// TestVMESSHeaderTypePreserved pins the vmess tcp http-obfs datum: the JSON
// "type" field is the header-obfuscation value (never the network), and it
// survives parse as headerType so tcp+type=http renders its header block.
func TestVMESSHeaderTypePreserved(t *testing.T) {
	payload := `{"v":"2","ps":"vm","add":"vm.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","net":"tcp","type":"http","host":"","path":"","tls":"tls","sni":"s.example.com"}`
	n, err := parse.Link("s", "vmess://"+b64(payload))
	require.NoError(t, err)
	assert.Equal(t, "tcp", n.Network, "net wins as the network")
	assert.Equal(t, "http", n.Params["headerType"], "the header datum is preserved as headerType")
	assert.Equal(t, "tcp", n.Params["type"])
}

// recordingPrefilter is a LinePrefilter test double that rejects lines by
// exact match and records every MarkSeen — enough to pin Lines' seam
// behavior (when the hook fires, what gets counted, what gets marked).
type recordingPrefilter struct {
	rejects map[string]string
	marked  []string
	asked   []string
}

func (r *recordingPrefilter) PreReject(_ []byte, line []byte) string {
	r.asked = append(r.asked, string(line))
	if class, ok := r.rejects[string(line)]; ok {
		return class
	}
	return ""
}

func (r *recordingPrefilter) MarkSeen(line string) {
	r.marked = append(r.marked, line)
}

// TestLinesPreRejectSeam pins the F3 scan loop's contract: the prefilter is
// consulted with the TRIMMED raw line before any full parse, pre-rejects are
// counted by class and never produce nodes, survivors are MarkSeen'd with
// the line string they parsed from (so a prefilter dedup can key on it), and
// a nil prefilter changes nothing.
func TestLinesPreRejectSeam(t *testing.T) {
	keep := "vless://k@keep.example.com:443?security=reality&type=tcp#k"
	body := strings.Join([]string{
		keep,
		"vless://n@nosec.example.com:443?security=none#n",
		keep + "-again-x",
	}, "\n") + "\n"

	pre := &recordingPrefilter{rejects: map[string]string{
		"vless://n@nosec.example.com:443?security=none#n": "no-tls-security",
	}}
	res := parse.Lines("s", []byte(body), pre)
	require.Len(t, res.Nodes, 2)
	assert.Equal(t, 1, res.PreRejected)
	assert.Equal(t, map[string]int{"no-tls-security": 1}, res.PreRejectedKinds)
	require.Len(t, pre.marked, 2, "exactly the two full-parse survivors are marked")
	assert.Equal(t, keep, pre.marked[0], "MarkSeen receives the trimmed line string")
	require.Len(t, pre.asked, 3, "every accepted-scheme line is consulted")

	// The marked line string is the exact string the full parse consumed:
	// feeding it to Link yields the same node identity the scan produced.
	n, err := parse.Link("s", pre.marked[0])
	require.NoError(t, err)
	assert.Equal(t, res.Nodes[0].Key, n.Key)

	// Nil prefilter: identical node set, zero pre-rejects.
	resNil := parse.Lines("s", []byte(body), nil)
	require.Len(t, resNil.Nodes, 3)
	assert.Equal(t, 0, resNil.PreRejected)
}

// TestLinesBlankCountsMatchPreF3Semantics pins the byte scanner's line
// segmentation against the pre-F3 reference (ReplaceAll CRLF + strings.Split
// + TrimSpace): the blank-line counts and parseable-line sets the old
// scanner produced must be reproduced verbatim — a trailing newline is a
// final empty segment, an empty body is one empty segment, CRLF lines trim
// identically without the full-body ReplaceAll pass.
func TestLinesBlankCountsMatchPreF3Semantics(t *testing.T) {
	cases := []string{
		"",
		"\n",
		"a\n",
		"a",
		"a\nb",
		"a\nb\n",
		"a\r\nb\r\n",
		"\r\n\r\n",
		"a\n\nb\n",
		"\n\n",
		"vless://u@x.example.com:443?security=tls#x\r\n\r\n# c\r\n",
	}
	for _, tc := range cases {
		wantBlank := 0
		for raw := range strings.SplitSeq(strings.ReplaceAll(tc, "\r\n", "\n"), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				wantBlank++
			}
		}
		res := parse.Lines("s", []byte(tc), nil)
		assert.Equal(t, wantBlank, res.Blank, "blank count of %q must match the pre-F3 scanner", tc)
	}
}

// TestLinesSeamCountersPostFusion pins the fused scan's allocation contract
// at the parse-package level: one full-body materialization ONLY for a
// base64 body (the decode), none for a plain body, one full parse per
// pre-reject survivor.
func TestLinesSeamCountersPostFusion(t *testing.T) {
	plain := "vless://p@plain.example.com:443?security=tls#p\nvless://p2@plain2.example.com:443?security=tls#p2"
	encoded := b64("vless://b@b64.example.com:443?security=tls#b")

	parse.WithSeam(func(seam *parse.Seam) {
		res := parse.Lines("s", []byte(plain), nil)
		require.Len(t, res.Nodes, 2)
		assert.Equal(t, int64(0), seam.BodyCopies.Load(),
			"a plain body scans in place: zero full-body copies")
		assert.Equal(t, int64(2), seam.FullParses.Load())

		res = parse.Lines("s", []byte(encoded), nil)
		require.Len(t, res.Nodes, 1)
		assert.Equal(t, int64(1), seam.BodyCopies.Load(),
			"a base64 body pays exactly the decode")
		assert.Equal(t, int64(3), seam.FullParses.Load())
	})
}
