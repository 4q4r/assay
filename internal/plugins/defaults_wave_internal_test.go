package plugins

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Hermetic fixture tests for the source-ingest host API. Every fixture
// feeds INLINE fixture Lua into the engine — no fixture reads the embedded
// defaults (a fresh clone embeds only the tracked sample template, and the
// suite must be green there). The contracts pinned here are the ENGINE
// contracts a plugin author relies on: github_files include-listing and
// wire-path semantics, plain-HTTP subscription handling (base64 + URI
// bodies, empty-wipe semantics, defensive body cap), remark pass-through,
// and the load-check contract for whatever is embedded.

const (
	includeRepo = "example-owner/example-lists"
	remarksRepo = "example-owner/example-remarks"
	plusRepo    = "example-owner/example-plus-lists"
)

func b64WaveOf(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// runFixtureLua compiles and runs one INLINE fixture plugin against a
// fixture-routed engine (github_files routed to srv, log to log).
func runFixtureLua(t *testing.T, id string, code string, srv *httptest.Server, log *strings.Builder) ([]Node, error) {
	t.Helper()
	return newW20Engine(srv, log).Run(context.Background(), &Plugin{
		ID: id, Path: id + ".lua", Code: []byte(code),
	})
}

// fixtureHarvestLua is the common harvester body of the github_files
// fixtures: exact include list, metadata-header drop, scheme gate, and the
// whole-body-base64 fallback. Modeled on the documented plugin template
// contract (sample.lua).
//
//nolint:dupword // Lua `end` keywords close nested blocks — consecutive identical words inside the raw string are Lua syntax
const fixtureHarvestLua = `
local SCHEMES = { vless = true, vmess = true, trojan = true, ss = true, hysteria2 = true, hy2 = true, tuic = true }
local function ingestible(line)
  local scheme = line:match("^(%w+)://")
  return scheme ~= nil and SCHEMES[scheme] == true
end
local function body_lines(body)
  local trimmed = body:gsub("^%s+", ""):gsub("%s+$", "")
  if trimmed:find("://", 1, true) then
    return trimmed
  end
  local flat = trimmed:gsub("%s+", "")
  local ok, decoded = pcall(assay.base64.decode, flat)
  if ok and decoded:find("://", 1, true) then
    return decoded
  end
  return nil
end
local function harvest(nodes, file)
  local src = body_lines(file.content)
  if src == nil then
    assay.log("skip ", file.path, ": not URI/base64 content")
    return
  end
  local kept = 0
  for line in src:gmatch("([^\r\n]+)") do
    line = line:gsub("^%s+", ""):gsub("%s+$", "")
    if line:find("^#") then
      -- metadata headers (#announce, #profile-*) skip explicitly
    elseif ingestible(line) then
      nodes[#nodes + 1] = assay.node{ raw = line }
      kept = kept + 1
    end
  end
  if kept == 0 then
    assay.log("skip ", file.path, ": no ingestible links")
  end
end
`

// TestGitHubFilesIncludeListFixture pins the include-list contract through
// a fixture plugin: only the exact-filename INCLUDE entries are fetched
// (a file outside the list never contributes a node), metadata headers
// (#announce / #profile-*) drop, ingestible URI lines land (hysteria2 with
// insecure params KEPT — the filter policy owns insecure transport and
// drops those loudly by design), and whole-body base64 decodes.
func TestGitHubFilesIncludeListFixture(t *testing.T) {
	srv := newRepoFixture(t, includeRepo, map[string]string{
		"/" + includeRepo + "/HEAD/list_full.txt": "#announce: t.me/example\n" +
			"#profile-title: FULL LIST\n" +
			"vless://a@h1:443?s=1#n1\n" +
			"hysteria2://e@h9:443/?insecure=1#h4\n",
		"/" + includeRepo + "/HEAD/list_base64.txt": b64WaveOf("trojan://c@h3:443?s=1#n3\n"),
		// Outside the INCLUDE list: a fetched-and-harvested marker would
		// fail the exact-node assertion below.
		"/" + includeRepo + "/HEAD/list_split.txt": "vless://must-never-appear@x:1#extra\n",
	})
	code := fixtureHarvestLua + `
local function collect()
  local nodes = {}
  local files = assay.github_files{
    repo = "` + includeRepo + `",
    include = { "list_full.txt", "list_base64.txt" },
  }
  for _, file in ipairs(files) do
    harvest(nodes, file)
  end
  return nodes
end
return collect
`
	var log strings.Builder
	nodes, err := runFixtureLua(t, "include-fixture", code, srv, &log)
	require.NoError(t, err)

	assert.Equal(t, []string{
		"hysteria2://e@h9:443/?insecure=1#h4",
		"trojan://c@h3:443?s=1#n3",
		"vless://a@h1:443?s=1#n1",
	}, sortedRaws(nodes))
	for _, n := range nodes {
		assert.NotContains(t, n.Raw, "must-never-appear",
			"a file outside the INCLUDE list reached the wire")
	}
	// The excluded file is include-filtered INSIDE the fetch helper
	// (Discover matches the git-tree paths before any download), so no
	// skip log line exists for it — the exact node set above is the
	// observable include contract.
}

// TestGitHubFilesRemarksFixture pins the remark contract: remarks travel
// with the raw link verbatim (parse owns remark extraction) across two
// quality-annotated lists.
func TestGitHubFilesRemarksFixture(t *testing.T) {
	srv := newRepoFixture(t, remarksRepo, map[string]string{
		"/" + remarksRepo + "/HEAD/ping_tested.txt":  "vless://a@h1:443?s=1#DE-Hetzner-42ms\n",
		"/" + remarksRepo + "/HEAD/speed_tested.txt": "vless://b@h2:8443?type=ws#FI-Speed-120Mbps\n",
	})
	code := fixtureHarvestLua + `
local function collect()
  local nodes = {}
  local files = assay.github_files{
    repo = "` + remarksRepo + `",
    include = { "ping_tested.txt", "speed_tested.txt" },
  }
  for _, file in ipairs(files) do
    harvest(nodes, file)
  end
  return nodes
end
return collect
`
	var log strings.Builder
	nodes, err := runFixtureLua(t, "remarks-fixture", code, srv, &log)
	require.NoError(t, err)

	assert.Equal(t, []string{
		"vless://a@h1:443?s=1#DE-Hetzner-42ms",
		"vless://b@h2:8443?type=ws#FI-Speed-120Mbps",
	}, sortedRaws(nodes))
}

// TestGitHubFilesPlusPathFixture pins the literal-'+' wire-path decision
// for the github_files helper:
//   - the helper builds raw URLs by plain string concatenation
//     (internal/fetch rawURL — no path escaping), so the include entry is
//     used verbatim as the URL path;
//   - include matching compares the literal git-trees path, so a "%2B"
//     spelling would never match and the discovery would fail loud;
//   - Go's net/url keeps '+' literal in request paths (RFC 3986 path
//     segment), and the raw host serves the file.
//
// The fixture records the WIRE request URI and asserts the '+' arrived
// unescaped (no %2B on the wire).
func TestGitHubFilesPlusPathFixture(t *testing.T) {
	plusPath := "/" + plusRepo + "/HEAD/list+extra.txt"
	var wireMu sync.Mutex // handlers run concurrently (fetch concurrency 4)
	wire := map[string]string{}
	record := func(r *http.Request) {
		wireMu.Lock()
		defer wireMu.Unlock()
		wire[r.URL.Path] = r.RequestURI
	}
	mux := http.NewServeMux()
	raws := map[string]string{
		"/" + plusRepo + "/HEAD/list+extra.txt": "ss://YWJjZEBmNDoyNDQ0#ssall\n",
		"/" + plusRepo + "/HEAD/list_plain.txt": "vless://a@h1:443?s=1#rus1\n",
		// In the tree but outside INCLUDE: must never contribute a node.
		"/" + plusRepo + "/HEAD/README.md": "vless://must-never-appear@x:1#readme\n",
	}
	paths := make([]string, 0, len(raws))
	for p := range raws {
		paths = append(paths, strings.TrimPrefix(p, "/"+plusRepo+"/HEAD/"))
	}
	mux.HandleFunc("/api/repos/"+plusRepo+"/git/trees/HEAD", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fixtureTree(paths)))
	})
	for path, body := range raws {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			record(r)
			_, _ = w.Write([]byte(body))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	code := fixtureHarvestLua + `
local function collect()
  local nodes = {}
  local files = assay.github_files{
    repo = "` + plusRepo + `",
    include = { "list+extra.txt", "list_plain.txt" },
  }
  for _, file in ipairs(files) do
    harvest(nodes, file)
  end
  return nodes
end
return collect
`
	var log strings.Builder
	nodes, err := runFixtureLua(t, "plus-fixture", code, srv, &log)
	require.NoError(t, err)

	// Both included files harvested; the README marker absent.
	assert.Equal(t, []string{
		"ss://YWJjZEBmNDoyNDQ0#ssall",
		"vless://a@h1:443?s=1#rus1",
	}, sortedRaws(nodes))
	for _, n := range nodes {
		assert.NotContains(t, n.Raw, "must-never-appear")
	}
	// The '+' decision, asserted at the helper level: the request arrived
	// with the literal filename, never a %2B escape.
	uri, fetched := wire[plusPath]
	require.True(t, fetched, "list+extra.txt was never fetched — include match failed")
	assert.Contains(t, uri, "list+extra.txt", "wire path must carry the literal '+'")
	assert.NotContains(t, uri, "%2B", "the helper must not percent-encode the '+' — include matching compares the literal tree path")
}

// TestPlainHTTPSubscriptionFixture pins the single-fetch plain-HTTP
// contract through a fixture plugin (the sample.lua fetch shape): the
// whole-body base64 list decodes, plain URI bodies are ingestible,
// non-200 and transport failures are loud plugin errors (breaker path), an
// empty body logs loud and returns zero nodes, and an oversized body fails
// loud on the defensive body cap (the accidental bulk-mirror landmine —
// a multi-MB swap must never balloon a run).
func TestPlainHTTPSubscriptionFixture(t *testing.T) {
	newSrv := func(t *testing.T, status int, body string) *httptest.Server {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	fixtureCode := func(srv *httptest.Server) string {
		return fmt.Sprintf(`
local SOURCE_URL = %q
%s
local function collect()
  local ok, resp = pcall(assay.http, {
    url = SOURCE_URL,
    timeout = 30,
    max_body_bytes = 1 * 1024 * 1024,
  })
  if not ok then
    error("plain-http fetch failed: " .. tostring(resp))
  end
  if resp.status ~= 200 then
    error("plain-http fetch returned HTTP " .. tostring(resp.status))
  end
  if resp.body == "" then
    assay.log("plain-http body is empty — zero nodes this run")
    return {}
  end
  local nodes = {}
  harvest(nodes, { path = SOURCE_URL, content = resp.body })
  return nodes
end
return collect
`, srv.URL, fixtureHarvestLua)
	}
	run := func(t *testing.T, srv *httptest.Server, log *strings.Builder) ([]Node, error) {
		t.Helper()
		eng := newEngine(engineOptions{Log: log})
		return eng.Run(context.Background(), &Plugin{
			ID: "plain-http-fixture", Path: "plain-http-fixture.lua", Code: []byte(fixtureCode(srv)),
		})
	}

	t.Run("whole-body base64 decodes to nodes", func(t *testing.T) {
		srv := newSrv(t, http.StatusOK,
			b64WaveOf("vless://a@h1:443?s=1#n1\ntrojan://c@h3:443?s=1#n3\n"))
		var log strings.Builder
		nodes, err := run(t, srv, &log)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"trojan://c@h3:443?s=1#n3",
			"vless://a@h1:443?s=1#n1",
		}, sortedRaws(nodes))
	})
	t.Run("plain URI body is also ingestible", func(t *testing.T) {
		srv := newSrv(t, http.StatusOK, "vless://a@h1:443?s=1#n1\n")
		var log strings.Builder
		nodes, err := run(t, srv, &log)
		require.NoError(t, err)
		assert.Equal(t, []string{"vless://a@h1:443?s=1#n1"}, sortedRaws(nodes))
	})
	t.Run("non-200 fails loud", func(t *testing.T) {
		srv := newSrv(t, http.StatusNotFound, "gone")
		var log strings.Builder
		_, err := run(t, srv, &log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 404")
	})
	t.Run("empty body logs loud and yields zero nodes", func(t *testing.T) {
		srv := newSrv(t, http.StatusOK, "")
		var log strings.Builder
		nodes, err := run(t, srv, &log)
		require.NoError(t, err, "an upstream wipe is a valid state, not a fetch failure")
		assert.Empty(t, nodes)
		assert.Contains(t, log.String(), "empty")
	})
	t.Run("oversized body fails loud on the defensive cap", func(t *testing.T) {
		srv := newSrv(t, http.StatusOK, strings.Repeat("A", 2<<20)) // 2 MiB > 1 MiB cap
		var log strings.Builder
		_, err := run(t, srv, &log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds max_body_bytes")
	})
}

// TestWaveDefaultsCompileLoad pins the load-check contract for whatever is
// embedded (a fresh clone embeds exactly the tracked sample template; a
// tree carrying additional untracked plugins embeds those too): every
// embedded chunk is side-effect-free (no network at load) and compiles
// into the canonical discover-function shape.
func TestWaveDefaultsCompileLoad(t *testing.T) {
	require.NotEmpty(t, defaultSources(), "the go:embed glob is compile-load-bearing — it must match at least the sample template")
	for name, code := range defaultSources() {
		id := IDFromPath(name)
		p, err := Compile(id, name, code, io.Discard)
		require.NoError(t, err, "%s must pass the load check", name)
		assert.Equal(t, id, p.ID)
	}
}

// TestSampleDefaultEmptyBodies runs the TRACKED sample template (the one
// default guaranteed to be embedded on every tree) against a stub fetch
// surface whose URL answers an EMPTY body: the cold upstream state must
// return zero nodes without error.
func TestSampleDefaultEmptyBodies(t *testing.T) {
	code, ok := defaultSources()["sample.lua"]
	require.True(t, ok, "tracked sample.lua missing from the embedded defaults")
	// Point the template's placeholder SOURCE_URL at the empty-body stub:
	// the single hardcoded placeholder string is rewritten onto the server
	// (same hermetic rewrite the plain-HTTP fixtures use).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(""))
	}))
	t.Cleanup(srv.Close)
	code = []byte(strings.ReplaceAll(string(code), "https://example.invalid/assay-sample-subscription.txt", srv.URL))

	var log strings.Builder
	eng := newEngine(engineOptions{Log: &log})
	nodes, err := eng.Run(context.Background(), &Plugin{
		ID: "sample", Path: "sample.lua", Code: code,
	})
	require.NoError(t, err)
	assert.Empty(t, nodes)
	assert.Contains(t, log.String(), "empty")
}
