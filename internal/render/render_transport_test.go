package render_test

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"public_vpn/internal/model"
	"public_vpn/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W5 transport-surface tests. Every field name and every "removed" verdict
// below was verified twice: against the REAL binary (`xray run -test`,
// 26.3.27) and against the tagged source (XTLS/Xray-core v26.3.27,
// infra/conf/transport_internet.go + infra/conf/shadowsocks.go).

// mkTransportNode builds one node with explicit params (unlike mkSelected,
// which defaults to reality+sni+pbk). All transport-variant fixtures live in
// one country/city — the balancer layer has its own dedicated fixtures.
func mkTransportNode(tag, scheme, host string, port int, params map[string]string) (*model.Node, model.SelectedNode) {
	n := model.NewNode("s", scheme, "pool-uuid-1", host, port, params)
	return n, model.SelectedNode{Tag: tag, Key: n.Key, Country: "nl", City: "Amsterdam", RTTMs: 100, Speed: 1_000_000, Checks: 3, Total: 3}
}

func renderOne(t *testing.T, n *model.Node, sn model.SelectedNode) (map[string]any, render.Result) {
	t.Helper()
	res, err := render.Render(render.Input{
		Template:   testTemplate(t),
		Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
		NodesByKey: map[string]*model.Node{n.Key: n},
		Cfg:        renderCfg(nil),
	})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(res.Config, &m))
	return m, res
}

// variant is one per-transport golden case.
type variant struct {
	name   string
	scheme string
	params map[string]string
}

// transportVariants covers one golden per supported transport + ss. kcp is
// golden'd PLAIN: seed/header are REMOVED from the 26.3.27 core and their
// presence is a loud render failure (tested below), not a golden.
func transportVariants() []variant {
	return []variant{
		{"tcp-raw", "vless", map[string]string{"type": "tcp", "security": "tls", "sni": "donor.example", "flow": "xtls-rprx-vision"}},
		{"tcp-httpobfs", "vless", map[string]string{"type": "tcp", "headerType": "http", "host": "obfs.example", "path": "/hub", "security": "tls", "sni": "donor.example"}},
		{"ws-tls", "trojan", map[string]string{"type": "ws", "path": "/tj", "host": "ws.example", "ed": "2048", "security": "tls", "sni": "donor.example"}},
		{"grpc-tls", "vless", map[string]string{"type": "grpc", "serviceName": "grpc-svc", "mode": "multi", "security": "tls", "sni": "donor.example"}},
		{"httpupgrade", "vless", map[string]string{"type": "httpupgrade", "path": "/up", "host": "up.example", "security": "tls", "sni": "donor.example"}},
		{"kcp-plain", "vless", map[string]string{"type": "kcp", "security": "none"}},
		{"xhttp-reality", "vless", map[string]string{"type": "xhttp", "mode": "packet-up", "path": "/pool", "host": "cdn.example", "security": "reality", "sni": "donor.example", "pbk": "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M", "sid": "b1"}},
		{"ss-tls", "ss", map[string]string{"type": "tcp", "method": "aes-128-gcm", "password": "ss-pw", "security": "tls", "sni": "donor.example"}},
	}
}

// TestTransportGoldenVariants materializes (first run) and byte-pins one
// golden render per transport; unexpected diffs are failures (regression
// contract, same as golden-render.json).
func TestTransportGoldenVariants(t *testing.T) {
	for _, v := range transportVariants() {
		t.Run(v.name, func(t *testing.T) {
			tag := "pool-nl-01"
			n, sn := mkTransportNode(tag, v.scheme, "node1.example.com", 443, v.params)
			m, res := renderOne(t, n, sn)
			assert.Empty(t, res.DroppedParams, "variant %s must consume every param", v.name)

			// sockopt.tcpMaxSeg 1440 on EVERY tunneled outbound (W5 mandate).
			ss := poolOutbound(t, m, tag)["streamSettings"].(map[string]any)
			assert.InDelta(t, 1440, ss["sockopt"].(map[string]any)["tcpMaxSeg"], 0.001)

			goldenPath := filepath.Join("testdata", "golden-transport-"+v.name+".json")
			golden, err := os.ReadFile(goldenPath)
			if err == nil {
				assert.Equal(t, string(golden), string(res.Config),
					"render diverged from %s — if intentional, regenerate deliberately", goldenPath)
				return
			}
			require.NoError(t, os.WriteFile(goldenPath, res.Config, 0o644), "first run materializes the golden")
			t.Logf("materialized %s", goldenPath)
		})
	}
}

// TestTransportGoldenVariantsPassXrayTest validates every per-transport
// golden against the REAL 26.3.27 binary in the default suite (skips when the
// binary is absent).
func TestTransportGoldenVariantsPassXrayTest(t *testing.T) {
	bin := "/usr/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("xray binary not present at %s", bin)
	}
	for _, v := range transportVariants() {
		t.Run(v.name, func(t *testing.T) {
			golden, err := os.ReadFile(filepath.Join("testdata", "golden-transport-"+v.name+".json"))
			require.NoError(t, err, "run the suite once to materialize the goldens")
			xrayTestConfig(t, bin, golden)
		})
	}
}

// TestMultiTransportCombinedRenderPassesXrayTest is the W5 golden capstone:
// ONE render carrying every supported transport at once must pass
// `xray run -test` on the real binary — the Plan A template accepts the full
// transport mix in a single config.
func TestMultiTransportCombinedRenderPassesXrayTest(t *testing.T) {
	bin := "/usr/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("xray binary not present at %s", bin)
	}
	variants := transportVariants()
	nodes := make([]*model.Node, 0, len(variants))
	selected := make([]model.SelectedNode, 0, len(variants))
	for i, v := range variants {
		tag := model.PoolTag("nl", i+1)
		n, sn := mkTransportNode(tag, v.scheme, "node"+strconv.Itoa(i+1)+".example.com", 443, v.params)
		nodes = append(nodes, n)
		selected = append(selected, sn)
	}
	byKey := map[string]*model.Node{}
	for _, n := range nodes {
		byKey[n.Key] = n
	}
	res, err := render.Render(render.Input{
		Template:   testTemplate(t),
		Selection:  &model.Selection{Nodes: selected},
		NodesByKey: byKey,
		Cfg:        renderCfg(nil),
	})
	require.NoError(t, err)
	assert.Empty(t, res.DroppedParams, "the combined render must consume every param of every transport")

	goldenPath := filepath.Join("testdata", "golden-transport-combined.json")
	golden, err := os.ReadFile(goldenPath)
	if err == nil {
		assert.Equal(t, string(golden), string(res.Config),
			"combined render diverged from the golden — if intentional, regenerate deliberately")
	} else {
		require.NoError(t, os.WriteFile(goldenPath, res.Config, 0o644))
		golden = res.Config
	}
	xrayTestConfig(t, bin, golden)
}

func xrayTestConfig(t *testing.T, bin string, cfg []byte) {
	t.Helper()
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "c.json")
	require.NoError(t, os.WriteFile(cfgPath, cfg, 0o644))
	cmd := exec.CommandContext(context.Background(), bin, "run", "-test", "-c", cfgPath)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+tmp)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "xray run -test rejected the config:\n%s", out)
	assert.Contains(t, string(out), "Configuration OK")
}

// TestWSHostRendersIndependentField pins the migration: the link's host
// renders as the INDEPENDENT wsSettings.host (headers.Host is deprecated
// upstream and warns on config build).
func TestWSHostRendersIndependentField(t *testing.T) {
	n, sn := mkTransportNode("pool-nl-01", "trojan", "n1.example.com", 443,
		map[string]string{"type": "ws", "path": "/tj", "host": "ws.example", "ed": "2048", "security": "tls"})
	m, res := renderOne(t, n, sn)
	ws := poolOutbound(t, m, "pool-nl-01")["streamSettings"].(map[string]any)["wsSettings"].(map[string]any)
	assert.Equal(t, "ws.example", ws["host"], "independent host field (headers.Host deprecated upstream)")
	assert.Nil(t, ws["headers"], "no headers.Host — the deprecated spelling must not render")
	assert.Equal(t, "/tj?ed=2048", ws["path"], "ed is appended to the path query — the core parses it out of the path")
	assert.Empty(t, res.DroppedParams)
}

// TestGRPMMultiModeRenders pins serviceName + mode=multi → multiMode.
func TestGRPMMultiModeRenders(t *testing.T) {
	n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443,
		map[string]string{"type": "grpc", "serviceName": "grpc-svc", "mode": "multi", "security": "tls"})
	m, res := renderOne(t, n, sn)
	gs := poolOutbound(t, m, "pool-nl-01")["streamSettings"].(map[string]any)["grpcSettings"].(map[string]any)
	assert.Equal(t, "grpc-svc", gs["serviceName"])
	assert.Equal(t, true, gs["multiMode"])
	assert.Empty(t, res.DroppedParams)
}

// TestTCPHTTPObfuscationRenders pins the tcp type=http header block.
func TestTCPHTTPObfuscationRenders(t *testing.T) {
	n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443,
		map[string]string{"type": "tcp", "headerType": "http", "host": "obfs.example", "path": "/hub", "security": "none"})
	m, res := renderOne(t, n, sn)
	tcp := poolOutbound(t, m, "pool-nl-01")["streamSettings"].(map[string]any)["tcpSettings"].(map[string]any)
	header := tcp["header"].(map[string]any)
	assert.Equal(t, "http", header["type"])
	req := header["request"].(map[string]any)
	assert.Equal(t, []any{"/hub"}, req["path"])
	hostHdr := req["headers"].(map[string]any)["Host"].([]any)
	assert.Equal(t, []any{"obfs.example"}, hostHdr)
	assert.Empty(t, res.DroppedParams)
}

// TestHTTPUpgradeRenders pins path/host.
func TestHTTPUpgradeRenders(t *testing.T) {
	n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443,
		map[string]string{"type": "httpupgrade", "path": "/up", "host": "up.example", "security": "tls"})
	m, res := renderOne(t, n, sn)
	hu := poolOutbound(t, m, "pool-nl-01")["streamSettings"].(map[string]any)["httpupgradeSettings"].(map[string]any)
	assert.Equal(t, "/up", hu["path"])
	assert.Equal(t, "up.example", hu["host"])
	assert.Empty(t, res.DroppedParams)
}

// TestXHTTPExtraPassthrough pins the extra JSON-object passthrough.
func TestXHTTPExtraPassthrough(t *testing.T) {
	n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443,
		map[string]string{
			"type": "xhttp", "mode": "packet-up", "path": "/p", "host": "cdn.example",
			"extra": `{"scMaxEachPostBytes":1000000,"noGRPCHeader":false}`, "security": "reality",
			"pbk": "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M", "sid": "b1",
		})
	m, res := renderOne(t, n, sn)
	xs := poolOutbound(t, m, "pool-nl-01")["streamSettings"].(map[string]any)["xhttpSettings"].(map[string]any)
	extra, ok := xs["extra"].(map[string]any)
	require.True(t, ok, "extra renders as a JSON object")
	assert.InDelta(t, 1000000, extra["scMaxEachPostBytes"], 0.001)
	assert.Equal(t, false, extra["noGRPCHeader"])
	assert.Empty(t, res.DroppedParams)
}

// TestXHTTPExtraNonObjectFailsLoud pins the W5 M-2 verdict: a malformed or
// non-object `extra` is behavior-changing link material, consistent with
// ed/early-data (materialParams) — it must FAIL the render naming the param,
// not surface as a drop-report entry.
func TestXHTTPExtraNonObjectFailsLoud(t *testing.T) {
	for _, bad := range []string{"not-json", "null", "[1,2]"} {
		n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443,
			map[string]string{"type": "xhttp", "mode": "auto", "extra": bad, "security": "tls"})
		_, err := render.Render(render.Input{
			Template:   testTemplate(t),
			Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
			NodesByKey: map[string]*model.Node{n.Key: n},
			Cfg:        renderCfg(nil),
		})
		require.Error(t, err, "non-object extra %q must fail the render, not land in the drop report", bad)
		assert.Contains(t, err.Error(), `"extra"`, "the offending param must be named")
		assert.Contains(t, err.Error(), bad)
	}
}

// TestSSOutboundRenders pins the shadowsocks outbound shape.
func TestSSOutboundRenders(t *testing.T) {
	n, sn := mkTransportNode("pool-nl-01", "ss", "n1.example.com", 8388,
		map[string]string{"type": "tcp", "method": "aes-128-gcm", "password": "ss-pw", "security": "tls", "sni": "donor.example"})
	m, res := renderOne(t, n, sn)
	ob := poolOutbound(t, m, "pool-nl-01")
	assert.Equal(t, "shadowsocks", ob["protocol"])
	srv := ob["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	assert.Equal(t, "aes-128-gcm", srv["method"])
	assert.Equal(t, "ss-pw", srv["password"])
	assert.InDelta(t, 8388, srv["port"], 0.001)
	assert.Equal(t, "tls", ob["streamSettings"].(map[string]any)["security"], "ss+security=tls renders TLS stream settings")
	assert.Empty(t, res.DroppedParams)
}

// TestSSPluginParamFailsLoud pins the verified verdict: the 26.3.27 core has
// NO SIP003 plugin support in its shadowsocks outbound (source: no
// plugin/pluginOpts fields; binary: silent-ignore without the guard) —
// dropping the plugin would silently change the transport, so the render
// fails loud naming the param (M-f precedent generalized).
func TestSSPluginParamFailsLoud(t *testing.T) {
	n, sn := mkTransportNode("pool-nl-01", "ss", "n1.example.com", 8388,
		map[string]string{
			"type": "tcp", "method": "aes-128-gcm", "password": "ss-pw",
			"plugin": "obfs-local;obfs=http;obfs-host=cdn.example", "security": "none",
		})
	_, err := render.Render(render.Input{
		Template:   testTemplate(t),
		Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
		NodesByKey: map[string]*model.Node{n.Key: n},
		Cfg:        renderCfg(nil),
	})
	require.Error(t, err, "a SIP003 plugin cannot be expressed by this core — fail loud")
	assert.Contains(t, err.Error(), `"plugin"`)
	assert.Contains(t, err.Error(), "obfs-local")
}

// TestKCPSseedAndHeaderFailLoud pins the removed-feature verdict: mKCP
// header/seed were removed from the 26.3.27 core (config build error naming
// finalmask/mkcp-original/mkcp-aes128gcm) — rendering them would fail the
// -test gate; dropping them would silently change the transport. Either way
// is unacceptable: loud failure (L9).
func TestKCPSeedAndHeaderFailLoud(t *testing.T) {
	for _, extra := range []map[string]string{
		{"seed": "s3cret"},
		{"headerType": "srtp"},
	} {
		params := map[string]string{"type": "kcp", "security": "none"}
		maps.Copy(params, extra)
		n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443, params)
		_, err := render.Render(render.Input{
			Template:   testTemplate(t),
			Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
			NodesByKey: map[string]*model.Node{n.Key: n},
			Cfg:        renderCfg(nil),
		})
		require.Error(t, err, "kcp %v must fail loud on 26.3.27 (feature removed)", extra)
		assert.Contains(t, err.Error(), "removed")
	}
}

// TestRemovedTransportsFailLoud pins the loud unsupported errors for
// transports the 26.3.27 core removed or does not know.
func TestRemovedTransportsFailLoud(t *testing.T) {
	for _, net := range []string{"http", "h2", "h3", "quic", "fakenet"} {
		n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443,
			map[string]string{"type": net, "path": "/p", "security": "tls"})
		_, err := render.Render(render.Input{
			Template:   testTemplate(t),
			Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
			NodesByKey: map[string]*model.Node{n.Key: n},
			Cfg:        renderCfg(nil),
		})
		require.Error(t, err, "transport %q must fail loud", net)
		assert.Contains(t, err.Error(), `type="`+net+`"`, "the offending param must be named")
	}
}

// TestNetworkAliasesNormalize pins the alias normalization: raw→tcp,
// websocket→ws, splithttp→xhttp, mkcp→kcp (TransportProtocol.Build accepts
// the same set; the renderer emits the canonical name).
func TestNetworkAliasesNormalize(t *testing.T) {
	cases := map[string]string{"raw": "tcp", "websocket": "ws", "splithttp": "xhttp", "mkcp": "kcp", "TCP": "tcp"}
	for link, want := range cases {
		n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443,
			map[string]string{"type": link, "security": "none"})
		m, _ := renderOne(t, n, sn)
		ss := poolOutbound(t, m, "pool-nl-01")["streamSettings"].(map[string]any)
		assert.Equal(t, want, ss["network"], "alias %q must render canonical %q", link, want)
	}
}

// TestRealityNetworkCompatibilityIsLoud pins the core restriction: REALITY
// only supports RAW/XHTTP/gRPC (StreamConfig.Build) — reality+ws would fail
// the -test gate, so the renderer refuses loud.
func TestRealityNetworkCompatibilityIsLoud(t *testing.T) {
	for _, net := range []string{"ws", "kcp", "httpupgrade"} {
		n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443,
			map[string]string{
				"type": net, "security": "reality", "sni": "donor.example",
				"pbk": "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M", "sid": "b1",
			})
		_, err := render.Render(render.Input{
			Template:   testTemplate(t),
			Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
			NodesByKey: map[string]*model.Node{n.Key: n},
			Cfg:        renderCfg(nil),
		})
		require.Error(t, err, "reality+%s must fail loud (core restriction)", net)
		assert.Contains(t, err.Error(), "tcp/xhttp/grpc")
	}
}

// TestEHSWrongHeaderFailsLoud pins the ehs verdict: the xray websocket
// transport uses the FIXED Sec-WebSocket-Protocol early-data header (no
// config field); an ehs param with any other value would change semantics —
// loud failure. The correct value is consumed silently.
func TestEHSWrongHeaderFailsLoud(t *testing.T) {
	n, sn := mkTransportNode("pool-nl-01", "trojan", "n1.example.com", 443,
		map[string]string{"type": "ws", "path": "/tj", "ehs": "X-Custom-Ed", "security": "tls"})
	_, err := render.Render(render.Input{
		Template:   testTemplate(t),
		Selection:  &model.Selection{Nodes: []model.SelectedNode{sn}},
		NodesByKey: map[string]*model.Node{n.Key: n},
		Cfg:        renderCfg(nil),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Sec-WebSocket-Protocol")

	ok, snOk := mkTransportNode("pool-nl-01", "trojan", "n1.example.com", 443,
		map[string]string{"type": "ws", "path": "/tj", "ehs": "Sec-WebSocket-Protocol", "ed": "1024", "security": "tls"})
	m, res := renderOne(t, ok, snOk)
	ws := poolOutbound(t, m, "pool-nl-01")["streamSettings"].(map[string]any)["wsSettings"].(map[string]any)
	assert.Equal(t, "/tj?ed=1024", ws["path"])
	assert.Empty(t, res.DroppedParams, "the fixed header value is the same datum the core uses — consumed")
}

// TestAllowInsecureSurfacesInDropReport pins the W5 policy split: denial in
// filter ([filter].allow_insecure=false default), capability-limitation in
// renderer — the 26.3.27 core REMOVED allowInsecure (migrated to
// pinnedPeerCertSha256), so an admitted link loses the param with a loud
// drop-report entry, never a rendered allowInsecure key.
func TestAllowInsecureSurfacesInDropReport(t *testing.T) {
	n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443,
		map[string]string{"type": "tcp", "security": "tls", "allowInsecure": "1"})
	m, res := renderOne(t, n, sn)
	tls := poolOutbound(t, m, "pool-nl-01")["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
	assert.Nil(t, tls["allowInsecure"], "the removed feature must never render (core rejects it)")
	require.Len(t, res.DroppedParams, 1)
	assert.Contains(t, res.DroppedParams[0].Params, "allowInsecure")
}

// TestFingerprintOnlyOnTLSReality pins the fp policy: the firefox override
// renders ONLY where a uTLS fingerprint exists (tls/reality); on
// security=none the fp param is reported, not consumed.
func TestFingerprintOnlyOnTLSReality(t *testing.T) {
	n, sn := mkTransportNode("pool-nl-01", "vless", "n1.example.com", 443,
		map[string]string{"type": "tcp", "security": "none", "fp": "chrome"})
	_, res := renderOne(t, n, sn)
	require.Len(t, res.DroppedParams, 1)
	assert.Contains(t, res.DroppedParams[0].Params, "fp", "security=none has no uTLS fingerprint — fp is reported")
}
