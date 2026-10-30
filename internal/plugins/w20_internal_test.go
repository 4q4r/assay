package plugins

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"public_vpn/internal/fetch"
	"public_vpn/internal/parse"
)

// W20 fixture tests: each of the seven new embedded plugins runs against an
// httptest fixture of its REAL upstream file shapes (verified 2026-10-30 via
// the GitHub API; see the wave report for per-repo evidence). The
// github_files plugins keep their real repo strings — the fixture mux routes
// those exact paths. The format contract under test: URI lists
// (vless/vmess/trojan/ss/hysteria2/hy2/tuic) and whole-body base64 are
// ingestible; everything else (YAML/JSON profiles, credits, bookkeeping)
// loud-skips per file — logged through publicvpn.log, never fatal.

const (
	hidashimoraRepo = "Hidashimora/free-vpn-anti-rkn"
	kort0881Repo    = "kort0881/vpn-vless-configs-russia"
	au1rxxRepo      = "Au1rxx/free-vpn-subscriptions"
	barryfarRepo    = "barry-far/V2ray-Config"
	nirevilRepo     = "NiREvil/vless"
	mhditaheriRepo  = "MhdiTaheri/V2rayCollector"
)

func b64Of(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// fixtureTree renders a trees/HEAD payload for the given path list.
func fixtureTree(paths []string) string {
	var b strings.Builder
	b.WriteString(`{"tree":[`)
	for i, p := range paths {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"path":%q,"type":"blob"}`, p)
	}
	b.WriteString(`],"truncated":false}`)
	return b.String()
}

// newRepoFixture hosts trees/HEAD + raw routes for ONE repo. Raw paths use
// the /<repo>/HEAD/<path> layout the real raw host serves.
func newRepoFixture(t *testing.T, repo string, raws map[string]string) *httptest.Server {
	t.Helper()
	paths := make([]string, 0, len(raws))
	for p := range raws {
		paths = append(paths, strings.TrimPrefix(p, "/"+repo+"/HEAD/"))
	}
	sort.Strings(paths)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/repos/"+repo+"/git/trees/HEAD", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fixtureTree(paths)))
	})
	for path, body := range raws {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newW20Engine builds a fixture engine: github_files routed to srv, publicvpn.log to log.
func newW20Engine(srv *httptest.Server, log *strings.Builder) *Engine {
	return newEngine(engineOptions{
		Log: log,
		GitHub: fetch.NewClient(fetch.ClientConfig{
			APIBase:   srv.URL + "/api",
			RawBase:   srv.URL,
			UserAgent: "w20-fixture",
			Timeout:   5 * time.Second,
			Retries:   0,
		}),
	})
}

// runW20 runs one embedded default against a fixture-routed engine.
func runW20(t *testing.T, srv *httptest.Server, id string, log *strings.Builder) ([]Node, error) {
	t.Helper()
	code, ok := defaultSources()[id+".lua"]
	require.True(t, ok, "embedded default %s.lua missing", id)
	return newW20Engine(srv, log).Run(context.Background(), &Plugin{ID: id, Path: id + ".lua", Code: code})
}

func sortedRaws(nodes []Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Raw)
	}
	sort.Strings(out)
	return out
}

func TestW20HidashimoraFixture(t *testing.T) {
	srv := newRepoFixture(t, hidashimoraRepo, map[string]string{
		"/" + hidashimoraRepo + "/HEAD/configs/1.1.txt":     "# slim list 1.1 (300-cap)\nvless://a@h1:443?s=1#n1\nvless://b@h2:443?s=1#n2\n",
		"/" + hidashimoraRepo + "/HEAD/configs/1.2.txt":     "# full list 1.2 (broken upstream: header only)\n",
		"/" + hidashimoraRepo + "/HEAD/configs/27.txt":      "vmess://" + b64Of(`{"add":"example"}`) + "\n",
		"/" + hidashimoraRepo + "/HEAD/configs/vpn.txt":     "trojan://c@h3:443?s=1#n3\nss://YWJjZEBmNDoyNDQ0#n4\n",
		"/" + hidashimoraRepo + "/HEAD/configs/counts.json": `{"1.1": 2, "totalUnique": 3}` + "\n",
	})
	var log strings.Builder
	nodes, err := runW20(t, srv, "hidashimora", &log)
	require.NoError(t, err)

	// The empty .2 (full-tier, broken upstream) and the counts.json
	// bookkeeping loud-skip; the slim .1, the short-only N.txt and the vpn.txt merge land;
	// header comments drop.
	assert.Equal(t, []string{
		"ss://YWJjZEBmNDoyNDQ0#n4",
		"trojan://c@h3:443?s=1#n3",
		"vless://a@h1:443?s=1#n1",
		"vless://b@h2:443?s=1#n2",
		"vmess://" + b64Of(`{"add":"example"}`),
	}, sortedRaws(nodes))
	assert.Contains(t, log.String(), "configs/counts.json")
	assert.Contains(t, log.String(), "configs/1.2.txt")
}

func TestW20Kort0881Fixture(t *testing.T) {
	srv := newRepoFixture(t, kort0881Repo, map[string]string{
		"/" + kort0881Repo + "/HEAD/data/subscriptions/all.txt":            "",
		"/" + kort0881Repo + "/HEAD/data/subscriptions/all_base64.txt":     "",
		"/" + kort0881Repo + "/HEAD/data/githubmirror/clean/vless.txt":     "vless://a@h1:443?path=%2Fws&type=ws&amp;security=tls&amp;sni=cdn.example.net#n1\nvless://b@h2:2053?type=ws#n2\n",
		"/" + kort0881Repo + "/HEAD/data/githubmirror/clean/trojan.txt":    "trojan://c@h3:443?s=1#n3\n",
		"/" + kort0881Repo + "/HEAD/data/githubmirror/clean/vmess.txt":     "vmess://" + b64Of(`{"add":"example"}`) + "\n",
		"/" + kort0881Repo + "/HEAD/data/githubmirror/clean/hysteria2.txt": "hysteria2://e@h9:443/?insecure=1#h4\n",
		"/" + kort0881Repo + "/HEAD/output/vless.txt":                      "vless://a@h1:443?path=%2Fws&type=ws&amp;security=tls&amp;sni=cdn.example.net#n1\n",
	})
	var log strings.Builder
	nodes, err := runW20(t, srv, "kort0881", &log)
	require.NoError(t, err)

	// 6 candidates: the clean per-protocol full sets (vless/vmess/trojan/
	// hysteria2 — real files upstream, drift-class coverage for the dir
	// walk) + the merged output (overlap is the pipeline's dedupe domain);
	// the empty merge tier loud-skips.
	// Upstream HTML entities (&amp;) decode BEFORE the scheme gate: the
	// emitted raw carries real query separators, so parse sees security/
	// sni instead of the dead amp;security class (~5.2% of clean/vless.txt
	// was lost to the no-tls bucket before the de-entity fix).
	assert.Equal(t, []string{
		"hysteria2://e@h9:443/?insecure=1#h4",
		"trojan://c@h3:443?s=1#n3",
		"vless://a@h1:443?path=%2Fws&type=ws&security=tls&sni=cdn.example.net#n1",
		"vless://a@h1:443?path=%2Fws&type=ws&security=tls&sni=cdn.example.net#n1",
		"vless://b@h2:2053?type=ws#n2",
		"vmess://" + b64Of(`{"add":"example"}`),
	}, sortedRaws(nodes))
	// Pin: an entity-carrying line parses structurally intact — security,
	// network and params all present (RED with the neutered entity form:
	// params split at the first & into amp;security/amp;sni, so security
	// and sni went missing and the node died in the filter's no-tls class).
	for _, n := range nodes {
		if !strings.HasPrefix(n.Raw, "vless://a@h1") {
			continue
		}
		parsed, err := parse.Link(kort0881Repo, n.Raw)
		require.NoError(t, err)
		assert.Equal(t, "tls", parsed.Security)
		assert.Equal(t, "ws", parsed.Network)
		assert.Equal(t, "/ws", parsed.Params["path"])
		assert.Equal(t, "cdn.example.net", parsed.Params["sni"])
	}
	assert.Contains(t, log.String(), "data/subscriptions/all.txt")
	assert.Contains(t, log.String(), "all_base64.txt")
}

func TestW20Au1rxxFixture(t *testing.T) {
	shard := b64Of("vless://a@h1:443?s=1#n1\nss://YWJjZEBmNDoyNDQ0#n2\n")
	srv := newRepoFixture(t, au1rxxRepo, map[string]string{
		"/" + au1rxxRepo + "/HEAD/output/all-verified/v2ray-base64-0001.txt": shard,
		"/" + au1rxxRepo + "/HEAD/output/all-verified/clash-0001.yaml":       "proxies:\n  - name: x\n    type: ss\n",
		"/" + au1rxxRepo + "/HEAD/output/all-verified/singbox-0001.json":     `{"outbounds": [{"type": "shadowsocks"}]}` + "\n",
	})
	var log strings.Builder
	nodes, err := runW20(t, srv, "au1rxx", &log)
	require.NoError(t, err)

	// The base64 TXT shard decodes; the in-dir YAML/JSON classes loud-skip
	// (the owner-mandated skip class) and contribute nothing.
	assert.Equal(t, []string{
		"ss://YWJjZEBmNDoyNDQ0#n2",
		"vless://a@h1:443?s=1#n1",
	}, sortedRaws(nodes))
	assert.Contains(t, log.String(), "clash-0001.yaml")
	assert.Contains(t, log.String(), "singbox-0001.json")
}

func TestW20BarryfarFixture(t *testing.T) {
	srv := newRepoFixture(t, barryfarRepo, map[string]string{
		"/" + barryfarRepo + "/HEAD/All_Configs_Sub.txt": "#profile-title: base64:8J+GkyBHaXRodWI=\n" +
			"#profile-update-interval: 1\n" +
			"vless://a@h1:443?s=1#n1\nssr://" + b64Of(`junk`) + "#n4\n",
		"/" + barryfarRepo + "/HEAD/All_Configs_base64_Sub.txt": b64Of("vmess://" + b64Of(`{"add":"example"}`) + "\ntrojan://d@x0:443#n3\n"),
	})
	var log strings.Builder
	nodes, err := runW20(t, srv, "barryfar", &log)
	require.NoError(t, err)

	// Plain list + base64 twin both ingest; the #profile metadata headers
	// drop and ssr:// (outside the pipeline's protocol set) drops at the
	// scheme gate.
	assert.Equal(t, []string{
		"trojan://d@x0:443#n3",
		"vless://a@h1:443?s=1#n1",
		"vmess://" + b64Of(`{"add":"example"}`),
	}, sortedRaws(nodes))
	assert.NotContains(t, log.String(), "ssr://")
}

func TestW20NirevilFixture(t *testing.T) {
	srv := newRepoFixture(t, nirevilRepo, map[string]string{
		"/" + nirevilRepo + "/HEAD/sub/SSTime": "# profile-title: base64:U0hBRE9XU09DS1MgVElNRQ==\n" +
			"# profile-update-interval: 23\n" +
			"ss://YWJjZEBmNDoyNDQ0#s1\nss://ZGVmQG1uOjQ0NDIjczI=\n" +
			"hysteria2://e@h9:443/?insecure=1#h1\n",
	})
	var log strings.Builder
	nodes, err := runW20(t, srv, "nirevil", &log)
	require.NoError(t, err)

	// The one ingestible file in the toolkit repo: both ss:// links and the
	// hysteria2:// link land; the metadata header comments drop.
	assert.Equal(t, []string{
		"hysteria2://e@h9:443/?insecure=1#h1",
		"ss://YWJjZEBmNDoyNDQ0#s1",
		"ss://ZGVmQG1uOjQ0NDIjczI=",
	}, sortedRaws(nodes))
}

func TestW20MhditaheriFixture(t *testing.T) {
	srv := newRepoFixture(t, mhditaheriRepo, map[string]string{
		"/" + mhditaheriRepo + "/HEAD/sub/mix": "trojan://bcacaab-baca-baca-dbac-accaabbcbacb@127.0.0.1:1080?security=tls#LATEST\n" +
			"vless://f@h11:443?s=1#n5\nss://YWJjZEBmNDoyNDQ0#n2\n",
		"/" + mhditaheriRepo + "/HEAD/sub/mixbase64": b64Of("vmess://" + b64Of(`{"add":"example"}`) + "\n"),
	})
	var log strings.Builder
	nodes, err := runW20(t, srv, "mhditaheri", &log)
	require.NoError(t, err)

	// The union + its base64 twin; the upstream trojan://127.0.0.1 update
	// marker is KEPT as a candidate on purpose — the parse stage (loopback
	// rejection) owns it, the plugin does not second-guess.
	assert.Equal(t, []string{
		"ss://YWJjZEBmNDoyNDQ0#n2",
		"trojan://bcacaab-baca-baca-dbac-accaabbcbacb@127.0.0.1:1080?security=tls#LATEST",
		"vless://f@h11:443?s=1#n5",
		"vmess://" + b64Of(`{"add":"example"}`),
	}, sortedRaws(nodes))
}

// newMehdirzfxFixture hosts a catalog README plus its nested subscription
// routes. The README body is filled in after the server exists (it embeds
// the server URL). fetches records per-path request counts.
func newMehdirzfxFixture(t *testing.T) (*httptest.Server, map[string]int, *strings.Builder) {
	t.Helper()
	fetches := map[string]int{}
	mux := http.NewServeMux()
	var catalogBody string
	mux.HandleFunc("/raw/mehdirzfx/v2ray-sub/main/README.md", func(w http.ResponseWriter, _ *http.Request) {
		fetches["README"]++
		_, _ = w.Write([]byte(catalogBody))
	})
	serve := func(path, body string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			fetches[path]++
			_, _ = w.Write([]byte(body))
		})
	}
	serve("/raw/sub1.txt", "vless://a@h1:443?s=1#n1\nvless://b@h2:443?s=1#n2\n")
	serve("/raw/sub2.txt", "vmess://"+b64Of(`{"add":"example"}`)+"\n")
	serve("/raw/sub3.txt", b64Of("trojan://d@x0:443#n3\n")+"\n")
	// The never-fetch classes: any request fails the test via the counts.
	serve("/raw/sub1.yaml", "MUST NEVER BE FETCHED")
	serve("/raw/other.yaml", "MUST NEVER BE FETCHED")
	serve("/raw/x.json", "MUST NEVER BE FETCHED")
	serve("/raw/somerepo", "MUST NEVER BE FETCHED")
	serve("/raw/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt",
		"vmess://"+b64Of(`{"add":"mirror"}`)+"\n")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	catalogBody = fmt.Sprintf(`# Free V2Ray Subscription Links

Intro paragraph.

## Mixed Subscription Links

- [sub1](%[1]s/raw/sub1.txt)
- [clashy](%[1]s/raw/sub1.yaml)
- [dup](%[1]s/raw/sub1.txt)
- [blob](https://github.com/0xRadikal/Free-v2ray-Configs/blob/main/secure/configs.txt)

## VLESS Subscription Links

- [sub3](%[1]s/raw/sub3.txt)

## Clash and Mihomo YAML Links

- [y](%[1]s/raw/other.yaml)

## Sing-box and JSON Links

- [j](%[1]s/raw/x.json)

## Sources and Credits

- [c](%[1]s/raw/somerepo)
`, srv.URL)
	return srv, fetches, new(strings.Builder)
}

// fixtureCode rewrites the plugin's raw.githubusercontent.com strings (the
// catalog URL and the blob-normalization target) onto the fixture server, so
// even the github.com/blob normalization path stays hermetic.
func fixtureCode(t *testing.T, id string, srv *httptest.Server) string {
	t.Helper()
	code, ok := defaultSources()[id+".lua"]
	require.True(t, ok, "embedded default %s.lua missing", id)
	return strings.ReplaceAll(string(code),
		"https://raw.githubusercontent.com/", srv.URL+"/raw/")
}

func TestW20MehdirzfxFixture(t *testing.T) {
	srv, fetches, log := newMehdirzfxFixture(t)
	code := fixtureCode(t, "mehdirzfx", srv)
	eng := newEngine(engineOptions{Log: log})
	nodes, err := eng.Run(context.Background(), &Plugin{
		ID: "mehdirzfx", Path: "mehdirzfx.lua", Code: []byte(code),
	})
	require.NoError(t, err)

	// sub1 (2 URIs; the duplicate URL dedupes to one fetch), the
	// blob-normalized sub2 (1 vmess) and the base64 sub3 (1 trojan). The
	// .yaml URL inside a kept section pre-filters at the URL gate; the
	// three out-of-scope sections never reach the wire.
	assert.Equal(t, []string{
		"trojan://d@x0:443#n3",
		"vless://a@h1:443?s=1#n1",
		"vless://b@h2:443?s=1#n2",
		"vmess://" + b64Of(`{"add":"mirror"}`),
	}, sortedRaws(nodes))
	assert.Equal(t, 1, fetches["README"], "the catalog is fetched exactly once")
	assert.Equal(t, 1, fetches["/raw/sub1.txt"], "duplicate catalog URL fetched once")
	assert.Equal(t, 1, fetches["/raw/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt"])
	assert.Equal(t, 1, fetches["/raw/sub3.txt"])
	for _, never := range []string{
		"/raw/sub1.yaml", "/raw/other.yaml", "/raw/x.json", "/raw/somerepo",
	} {
		assert.Equal(t, 0, fetches[never], "%s must never be fetched", never)
	}
	assert.Contains(t, log.String(), "skip out-of-scope url ")
	assert.Contains(t, log.String(), "sub1.yaml")
	assert.Contains(t, log.String(), "Clash and Mihomo YAML Links")
	assert.Contains(t, log.String(), "Sing-box and JSON Links")
	assert.Contains(t, log.String(), "Sources and Credits")
}

// TestW20MehdirzfxFetchCap pins the bounded-crawl contract: with a lowered
// budget the crawler stops after MAX_FETCHES attempts, logs the cap loud,
// and walks the sections round-robin (the second section reaches the wire
// before the cap binds).
func TestW20MehdirzfxFetchCap(t *testing.T) {
	fetches := map[string]int{}
	mux := http.NewServeMux()
	var catalogBody string
	mux.HandleFunc("/raw/mehdirzfx/v2ray-sub/main/README.md", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(catalogBody))
	})
	serve := func(path string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			fetches[path]++
			_, _ = w.Write([]byte("vless://n" + path + "\n"))
		})
	}
	serve("/raw/sub1.txt")
	serve("/raw/sub2.txt")
	serve("/raw/sub3.txt")
	serve("/raw/sub4.txt")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	catalogBody = fmt.Sprintf(`## Mixed Subscription Links

- [sub1](%[1]s/raw/sub1.txt)
- [sub2](%[1]s/raw/sub2.txt)

## VLESS Subscription Links

- [sub3](%[1]s/raw/sub3.txt)
- [sub4](%[1]s/raw/sub4.txt)
`, srv.URL)

	code := fixtureCode(t, "mehdirzfx", srv)
	code = strings.Replace(code, "local MAX_FETCHES = 25", "local MAX_FETCHES = 2", 1)

	var log strings.Builder
	eng := newEngine(engineOptions{Log: &log})
	nodes, err := eng.Run(context.Background(), &Plugin{
		ID: "mehdirzfx", Path: "mehdirzfx.lua", Code: []byte(code),
	})
	require.NoError(t, err)

	// Round-robin queue [sub1, sub3, sub2, sub4]: budget 2 → sub1 + sub3
	// fetched, the cap logs loud before sub2/sub4 ever reach the wire.
	assert.Equal(t, []string{
		"vless://n/raw/sub1.txt",
		"vless://n/raw/sub3.txt",
	}, sortedRaws(nodes))
	assert.Equal(t, 1, fetches["/raw/sub1.txt"])
	assert.Equal(t, 1, fetches["/raw/sub3.txt"])
	assert.Equal(t, 0, fetches["/raw/sub2.txt"])
	assert.Equal(t, 0, fetches["/raw/sub4.txt"])
	assert.Contains(t, log.String(), "catalog crawl capped")
}

// TestW20DefaultsCompileLoad pins the load-check contract for all seven new
// embedded defaults: the chunk is side-effect-free (no network at load) and
// compiles into the canonical discover-function shape.
func TestW20DefaultsCompileLoad(t *testing.T) {
	for _, id := range []string{
		"hidashimora", "kort0881", "au1rxx", "barryfar", "nirevil", "mehdirzfx", "mhditaheri",
	} {
		code, ok := defaultSources()[id+".lua"]
		require.True(t, ok, "embedded default %s.lua missing", id)
		p, err := Compile(id, id+".lua", code, io.Discard)
		require.NoError(t, err, "%s must pass the load check", id)
		assert.Equal(t, id, p.ID)
	}
}
