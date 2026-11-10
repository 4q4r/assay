package plugins

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"assay/internal/fetch"
	"assay/internal/parse"
)

// Hermetic fixture tests for the github_files and catalog-crawl host-API
// contracts. Every fixture feeds INLINE fixture Lua into the engine — no
// fixture reads the embedded defaults (a fresh clone embeds only the
// tracked sample template; the suite must be green there). Shared helpers
// (fixtureTree, newRepoFixture, newW20Engine, sortedRaws) serve this file
// and defaults_wave_internal_test.go.

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

// newW20Engine builds a fixture engine: github_files routed to srv, assay.log to log.
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

func sortedRaws(nodes []Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Raw)
	}
	sort.Strings(out)
	return out
}

// TestGitHubFilesNestedWalkFixture pins the nested-path walk contract
// through a fixture plugin: deep repo paths are walked, an empty
// header-only upstream file (broken list tier) loud-skips, JSON bookkeeping
// files loud-skip at the format gate, and the healthy lists merge — header
// comments drop.
func TestGitHubFilesNestedWalkFixture(t *testing.T) {
	const repo = "example-owner/example-walk"
	srv := newRepoFixture(t, repo, map[string]string{
		"/" + repo + "/HEAD/configs/1.1.txt":     "# slim list 1.1\nvless://a@h1:443?s=1#n1\nvless://b@h2:443?s=1#n2\n",
		"/" + repo + "/HEAD/configs/1.2.txt":     "# full list 1.2 (broken upstream: header only)\n",
		"/" + repo + "/HEAD/configs/27.txt":      "vmess://" + b64Of(`{"add":"example"}`) + "\n",
		"/" + repo + "/HEAD/configs/vpn.txt":     "trojan://c@h3:443?s=1#n3\nss://YWJjZEBmNDoyNDQ0#n4\n",
		"/" + repo + "/HEAD/configs/counts.json": `{"1.1": 2, "totalUnique": 3}` + "\n",
	})
	code := fixtureHarvestLua + `
local function collect()
  local nodes = {}
  local files = assay.github_files{
    repo = "` + repo + `",
    include = { "configs/1.1.txt", "configs/1.2.txt", "configs/27.txt", "configs/vpn.txt", "configs/counts.json" },
  }
  for _, file in ipairs(files) do
    harvest(nodes, file)
  end
  return nodes
end
return collect
`
	var log strings.Builder
	nodes, err := runFixtureLua(t, "walk-fixture", code, srv, &log)
	require.NoError(t, err)

	// The header-only 1.2 (broken upstream) and the counts.json bookkeeping
	// loud-skip; the slim 1.1, the short-only 27.txt and the vpn.txt merge
	// land; header comments drop.
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

// TestGitHubFilesEntityDecodeFixture pins the HTML-entity decode contract:
// upstream lists may carry &amp; entities in share-link query strings — the
// de-entity step runs BEFORE the scheme gate, so the emitted raw carries
// real query separators and parse sees security/sni instead of the dead
// amp;security class. The duplicate across two walked files also lands
// (cross-file overlap is the pipeline's dedupe domain, not the plugin's).
func TestGitHubFilesEntityDecodeFixture(t *testing.T) {
	const repo = "example-owner/example-entities"
	entityLine := "vless://a@h1:443?path=%2Fws&type=ws&amp;security=tls&amp;sni=cdn.example.net#n1"
	srv := newRepoFixture(t, repo, map[string]string{
		"/" + repo + "/HEAD/data/subs/all.txt":        "",
		"/" + repo + "/HEAD/data/subs/all_base64.txt": "",
		"/" + repo + "/HEAD/data/clean/vless.txt":     entityLine + "\nvless://b@h2:2053?type=ws#n2\n",
		"/" + repo + "/HEAD/data/clean/trojan.txt":    "trojan://c@h3:443?s=1#n3\n",
		"/" + repo + "/HEAD/data/clean/vmess.txt":     "vmess://" + b64Of(`{"add":"example"}`) + "\n",
		"/" + repo + "/HEAD/data/clean/hysteria2.txt": "hysteria2://e@h9:443/?insecure=1#h4\n",
		"/" + repo + "/HEAD/output/vless.txt":         entityLine + "\n",
	})
	code := fixtureHarvestLua + `
-- HTML entities decode BEFORE the scheme gate: share-link query strings
-- written for HTML pages carry &amp; — harvesting them raw would strand
-- params in the dead amp;security class.
local function deentity(s)
  return (s:gsub("&amp;", "&"))
end
local function collect()
  local nodes = {}
  local files = assay.github_files{
    repo = "` + repo + `",
    include = {
      "data/subs/all.txt",
      "data/subs/all_base64.txt",
      "data/clean/vless.txt",
      "data/clean/trojan.txt",
      "data/clean/vmess.txt",
      "data/clean/hysteria2.txt",
      "output/vless.txt",
    },
  }
  for _, file in ipairs(files) do
    local src = file.content:gsub("[^\r\n]+", deentity)
    harvest(nodes, { path = file.path, content = src })
  end
  return nodes
end
return collect
`
	var log strings.Builder
	nodes, err := runFixtureLua(t, "entity-fixture", code, srv, &log)
	require.NoError(t, err)

	// Candidates: the clean per-format sets (vless/vmess/trojan/hysteria2)
	// + the merged output duplicate (dedupe is the pipeline's domain); the
	// empty subscription tier loud-skips. The entity-carrying line arrives
	// decoded: real query separators, no amp; residue.
	assert.Equal(t, []string{
		"hysteria2://e@h9:443/?insecure=1#h4",
		"trojan://c@h3:443?s=1#n3",
		"vless://a@h1:443?path=%2Fws&type=ws&security=tls&sni=cdn.example.net#n1",
		"vless://a@h1:443?path=%2Fws&type=ws&security=tls&sni=cdn.example.net#n1",
		"vless://b@h2:2053?type=ws#n2",
		"vmess://" + b64Of(`{"add":"example"}`),
	}, sortedRaws(nodes))
	for _, n := range nodes {
		assert.NotContains(t, n.Raw, "&amp;", "entities must decode before the scheme gate")
	}
	// Pin: an entity-carrying line parses structurally intact — security,
	// network and params all present (RED with the neutered entity form:
	// params split at the first & into amp;security/amp;sni, so security
	// and sni went missing and the node died in the filter's no-tls class).
	for _, n := range nodes {
		if !strings.HasPrefix(n.Raw, "vless://a@h1") {
			continue
		}
		parsed, err := parse.Link(repo, n.Raw)
		require.NoError(t, err)
		assert.Equal(t, "tls", parsed.Security)
		assert.Equal(t, "ws", parsed.Network)
		assert.Equal(t, "/ws", parsed.Params["path"])
		assert.Equal(t, "cdn.example.net", parsed.Params["sni"])
	}
	assert.Contains(t, log.String(), "data/subs/all.txt")
	assert.Contains(t, log.String(), "all_base64.txt")
}

// TestGitHubFilesFormatGateFixture pins the plugin-boundary format gate:
// URI lists and whole-body base64 are ingestible; #profile metadata
// headers drop; ssr:// (outside the pipeline's protocol set) drops at the
// scheme gate; YAML/JSON profile classes loud-skip per file and contribute
// nothing.
func TestGitHubFilesFormatGateFixture(t *testing.T) {
	const repo = "example-owner/example-formats"
	srv := newRepoFixture(t, repo, map[string]string{
		"/" + repo + "/HEAD/lists/subs.txt": "#profile-title: base64:8J+GkyBHaXRodWI=\n" +
			"#profile-update-interval: 1\n" +
			"vless://a@h1:443?s=1#n1\nssr://" + b64Of(`junk`) + "#n4\n",
		"/" + repo + "/HEAD/lists/subs_base64.txt": b64Of("vmess://" + b64Of(`{"add":"example"}`) + "\ntrojan://d@x0:443#n3\n"),
		"/" + repo + "/HEAD/lists/shard.txt":       b64Of("vless://g@h7:443?s=1#s1\nss://YWJjZEBmNDoyNDQ0#n2\n"),
		"/" + repo + "/HEAD/lists/clash.yaml":      "proxies:\n  - name: x\n    type: ss\n",
		"/" + repo + "/HEAD/lists/singbox.json":    `{"outbounds": [{"type": "shadowsocks"}]}` + "\n",
	})
	code := fixtureHarvestLua + `
local function collect()
  local nodes = {}
  local files = assay.github_files{
    repo = "` + repo + `",
    include = { "lists/subs.txt", "lists/subs_base64.txt", "lists/shard.txt", "lists/clash.yaml", "lists/singbox.json" },
  }
  for _, file in ipairs(files) do
    harvest(nodes, file)
  end
  return nodes
end
return collect
`
	var log strings.Builder
	nodes, err := runFixtureLua(t, "format-gate-fixture", code, srv, &log)
	require.NoError(t, err)

	// Plain list + base64 twins ingest (the shard's vless/ss and the base64
	// twin's vmess/trojan land); profile metadata headers drop and
	// ssr:// drops at the scheme gate; the YAML/JSON classes loud-skip.
	assert.Equal(t, []string{
		"ss://YWJjZEBmNDoyNDQ0#n2",
		"trojan://d@x0:443#n3",
		"vless://a@h1:443?s=1#n1",
		"vless://g@h7:443?s=1#s1",
		"vmess://" + b64Of(`{"add":"example"}`),
	}, sortedRaws(nodes))
	assert.Contains(t, log.String(), "clash.yaml")
	assert.Contains(t, log.String(), "singbox.json")
	assert.NotContains(t, log.String(), "ssr://")
}

// catalogFixtureLua is the catalog-crawler fixture: a README catalog under
// "## " headings, section allow-list (clash/mihomo/singbox/credits skip),
// URL-level gate for YAML/JSON profiles, github.com blob → raw-host
// normalization, per-URL dedupe, bounded round-robin crawl. Modeled on the
// documented catalog contract in sample.lua's template family. The
// raw.githubusercontent.com literal is REWRITTEN onto the fixture server
// (both the catalog URL and the normalize() replacement target) so even
// the blob-normalization path stays hermetic.
//
//nolint:dupword // Lua `end` keywords close nested blocks — consecutive identical words inside the raw string are Lua syntax
const catalogFixtureLua = `
local CATALOG_URL =
  "https://raw.githubusercontent.com/example-owner/example-catalog/main/README.md"

local MAX_FETCHES = 25

-- Out-of-scope catalog sections (substring-matched lowercase).
local SKIP_SECTION = {
  clash = true,
  mihomo = true,
  sing = true,
  credit = true,
}

local function section_skipped(name)
  local low = name:lower()
  for word in pairs(SKIP_SECTION) do
    if low:find(word, 1, true) then
      return true
    end
  end
  return false
end

-- URL-level skip: YAML/JSON profile files and sing-box endpoints. Plain
-- find (no patterns) — the dots are literal. The body gate below stays
-- the final arbiter: an extension-less URL serving YAML skips at harvest.
local function url_skipped(url)
  local low = url:lower()
  if low:find(".yaml", 1, true) or low:find(".yml", 1, true)
    or low:find(".json", 1, true) or low:find("sing-box", 1, true)
    or low:find("singbox", 1, true) then
    return true
  end
  return false
end

-- github.com blob pages carry HTML, not the file: rewrite to the raw host
-- (and strip any "#" suffix) so both catalog spellings dedupe to one fetch.
local function normalize(url)
  local out = url:gsub("#.*$", "")
  out = out:gsub("^https?://github%.com/([^/]+)/([^/]+)/blob/(.+)$",
    "https://raw.githubusercontent.com/%1/%2/%3")
  return out
end

-- Extract per-section ingestible URL lists in catalog order, logging the
-- out-of-scope classes loud (one line per skipped section, one per
-- skipped URL inside kept sections).
local function catalog_lists(md)
  local lists = {}
  local current = nil
  local name = ""
  local skipped = 0
  for line in md:gmatch("([^\r\n]+)") do
    local heading = line:match("^##%s+(.-)%s*$")
    if heading then
      if current == nil and skipped > 0 then
        assay.log("skip section '", name, "': ", skipped,
          " out-of-scope links (clash/singbox/credits or yaml/json)")
      end
      current = nil
      name = heading
      skipped = 0
      if not section_skipped(heading) then
        current = {}
        lists[#lists + 1] = current
      end
    else
      -- Bare URL match: the catalog mixes bare links (fenced blocks) and
      -- markdown [name](url) links — matching any http(s) substring covers
      -- both (a trailing markdown ")" is trimmed below).
      local url = line:match("(https?://%S+)")
      if url then
        url = url:gsub("[%)%]%,>%.]+$", "")
        if url_skipped(url) then
          assay.log("skip out-of-scope url ", url)
          skipped = skipped + 1
        elseif current == nil then
          skipped = skipped + 1
        else
          current[#current + 1] = url
        end
      end
    end
  end
  if current == nil and skipped > 0 then
    assay.log("skip section '", name, "': ", skipped,
      " out-of-scope links (clash/singbox/credits or yaml/json)")
  end
  return lists
end

-- Round-robin across sections: item 1 of every list first, then item 2,
-- ... — the fetch cap cannot starve the tail categories.
local function round_robin(lists)
  local queue = {}
  local cursors = {}
  local more = true
  while more do
    more = false
    for _, urls in ipairs(lists) do
      local next_url = urls[(cursors[urls] or 0) + 1]
      if next_url then
        cursors[urls] = (cursors[urls] or 0) + 1
        queue[#queue + 1] = next_url
        more = true
      end
    end
  end
  return queue
end

local function collect()
  local resp = assay.http{ url = CATALOG_URL, timeout = 30 }
  if resp.status ~= 200 then
    error("catalog fetch returned HTTP " .. tostring(resp.status))
  end
  local queue = round_robin(catalog_lists(resp.body))
  local seen = {}
  local nodes = {}
  local used = 0
  for _, raw_url in ipairs(queue) do
    if used >= MAX_FETCHES then
      assay.log("catalog crawl capped at ", MAX_FETCHES,
        " fetches per run — raising MAX_FETCHES in this file goes deeper")
      break
    end
    local url = normalize(raw_url)
    if not seen[url] then
      seen[url] = true
      used = used + 1
      local ok, sub = pcall(assay.http,
    { url = url, timeout = 3, max_body_bytes = 2 * 1024 * 1024 })
      if not ok then
        assay.log("fetch failed ", url, ": ", tostring(sub))
      elseif sub.status ~= 200 then
        assay.log("skip ", url, ": HTTP ", tostring(sub.status))
      else
        harvest(nodes, { path = url, content = sub.body })
      end
    end
  end
  return nodes
end

return collect
`

// catalogCode rewrites the fixture crawler's raw.githubusercontent.com
// literals (the catalog URL and the blob-normalization target) onto the
// fixture server, so even the github.com/blob normalization path stays
// hermetic. The shared harvester (fixtureHarvestLua) supplies body_lines
// and harvest.
func catalogCode(srv *httptest.Server) string {
	return strings.ReplaceAll(fixtureHarvestLua+catalogFixtureLua,
		"https://raw.githubusercontent.com/", srv.URL+"/raw/")
}

// TestCatalogCrawlFixture pins the catalog-crawl contract: the catalog is
// fetched exactly once, a duplicate catalog URL fetches once, a
// github.com/blob spelling normalizes onto the raw host and fetches, the
// out-of-scope sections (clash/singbox/credits) never reach the wire, and
// base64 subscription bodies decode.
func TestCatalogCrawlFixture(t *testing.T) {
	fetches := map[string]int{}
	mux := http.NewServeMux()
	var catalogBody string
	mux.HandleFunc("/raw/example-owner/example-catalog/main/README.md", func(w http.ResponseWriter, _ *http.Request) {
		fetches["catalog"]++
		_, _ = w.Write([]byte(catalogBody))
	})
	serve := func(path, body string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			fetches[path]++
			_, _ = w.Write([]byte(body))
		})
	}
	serve("/raw/sub1.txt", "vless://a@h1:443?s=1#n1\nvless://b@h2:443?s=1#n2\n")
	serve("/raw/example-owner/example-blobrepo/main/subs/sub2.txt",
		"vmess://"+b64Of(`{"add":"mirror"}`)+"\n")
	serve("/raw/sub3.txt", b64Of("trojan://d@x0:443#n3\n")+"\n")
	// The never-fetch classes: any request fails the test via the counts.
	serve("/raw/sub1.yaml", "MUST NEVER BE FETCHED")
	serve("/raw/other.yaml", "MUST NEVER BE FETCHED")
	serve("/raw/x.json", "MUST NEVER BE FETCHED")
	serve("/raw/somerepo", "MUST NEVER BE FETCHED")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	catalogBody = fmt.Sprintf(`# Example Subscription Catalog

Intro paragraph.

## Mixed Subscription Links

- [sub1](%[1]s/raw/sub1.txt)
- [clashy](%[1]s/raw/sub1.yaml)
- [dup](%[1]s/raw/sub1.txt)
- [blob](https://github.com/example-owner/example-blobrepo/blob/main/subs/sub2.txt)

## VLESS Subscription Links

- [sub3](%[1]s/raw/sub3.txt)

## Clash and Mihomo YAML Links

- [y](%[1]s/raw/other.yaml)

## Sing-box and JSON Links

- [j](%[1]s/raw/x.json)

## Sources and Credits

- [c](%[1]s/raw/somerepo)
`, srv.URL)

	code := catalogCode(srv)
	var log strings.Builder
	eng := newEngine(engineOptions{Log: &log})
	nodes, err := eng.Run(context.Background(), &Plugin{
		ID: "catalog-fixture", Path: "catalog-fixture.lua", Code: []byte(code),
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
	assert.Equal(t, 1, fetches["catalog"], "the catalog is fetched exactly once")
	assert.Equal(t, 1, fetches["/raw/sub1.txt"], "duplicate catalog URL fetched once")
	assert.Equal(t, 1, fetches["/raw/example-owner/example-blobrepo/main/subs/sub2.txt"])
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

// TestCatalogCrawlFetchCap pins the bounded-crawl contract: with a lowered
// budget the crawler stops after MAX_FETCHES attempts, logs the cap loud,
// and walks the sections round-robin (the second section reaches the wire
// before the cap binds).
func TestCatalogCrawlFetchCap(t *testing.T) {
	fetches := map[string]int{}
	mux := http.NewServeMux()
	var catalogBody string
	mux.HandleFunc("/raw/example-owner/example-catalog/main/README.md", func(w http.ResponseWriter, _ *http.Request) {
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

	code := catalogCode(srv)
	code = strings.Replace(code, "local MAX_FETCHES = 25", "local MAX_FETCHES = 2", 1)

	var log strings.Builder
	eng := newEngine(engineOptions{Log: &log})
	nodes, err := eng.Run(context.Background(), &Plugin{
		ID: "catalog-fixture", Path: "catalog-fixture.lua", Code: []byte(code),
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
