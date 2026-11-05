package plugins

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fixture tests for the 2026-11-05 source wave: four new embedded plugins
// (flat447, luxxuria, igareck — github_files; nodesradar — plain HTTP).
// The github_files fixtures keep the real repo strings and route those
// exact paths (the W20 harness pattern); nodesradar rewrites its hardcoded
// URL onto the fixture server (the mehdirzfx fixtureCode pattern).

const (
	flat447Repo  = "FLAT447/v2ray-lists"
	luxxuriaRepo = "luxxuria/harvester"
	igareckRepo  = "igareck/vpn-configs-for-russia"
	// nodesradarURL is the exact URL string hardcoded in nodesradar.lua —
	// the fixture rewrites it onto the test server (fixtureURL below).
	nodesradarURL = "https://radarhub.top/v2ray.txt"
)

func b64WaveOf(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// fixtureURL rewrites the plugin's hardcoded radarhub URL onto srv so the
// single-fetch plugin stays hermetic.
func fixtureURL(t *testing.T, id string, srv *httptest.Server, url string) string {
	t.Helper()
	code, ok := defaultSources()[id+".lua"]
	require.True(t, ok, "embedded default %s.lua missing", id)
	return strings.ReplaceAll(string(code), url, srv.URL+"/v2ray.txt")
}

func runFixturePlugin(t *testing.T, id string, srv *httptest.Server, log *strings.Builder) ([]Node, error) {
	t.Helper()
	code, ok := defaultSources()[id+".lua"]
	require.True(t, ok, "embedded default %s.lua missing", id)
	return newW20Engine(srv, log).Run(context.Background(), &Plugin{ID: id, Path: id + ".lua", Code: code})
}

// TestFlat447Fixture pins the two-file include contract and the format
// gate: metadata headers (#announce / #profile-*) drop, ingestible URI
// lines land (hysteria2 with insecure params KEPT — the filter policy owns
// insecure transport and drops those loudly by design), and a file outside
// the exact INCLUDE list never contributes a node.
func TestFlat447Fixture(t *testing.T) {
	srv := newRepoFixture(t, flat447Repo, map[string]string{
		"/" + flat447Repo + "/HEAD/BLACK_FULL.txt": "#announce: t.me/example\n" +
			"#profile-title: BLACK FULL\n" +
			"vless://a@h1:443?s=1#n1\n" +
			"hysteria2://e@h9:443/?insecure=1#h4\n",
		"/" + flat447Repo + "/HEAD/WHITE_FULL.txt": "trojan://c@h3:443?s=1#n3\n",
		// Outside the INCLUDE list: a fetched-and-harvested marker would
		// fail the exact-node assertion below.
		"/" + flat447Repo + "/HEAD/BLACK_VLESS.txt": "vless://must-never-appear@x:1#extra\n",
	})
	var log strings.Builder
	nodes, err := runFixturePlugin(t, "flat447", srv, &log)
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

// TestLuxxuriaFixture pins the two quality-tested vless lists: remarks
// travel with the raw link verbatim (parse owns remark extraction).
func TestLuxxuriaFixture(t *testing.T) {
	srv := newRepoFixture(t, luxxuriaRepo, map[string]string{
		"/" + luxxuriaRepo + "/HEAD/ping_tested.txt":  "vless://a@h1:443?s=1#DE-Hetzner-42ms\n",
		"/" + luxxuriaRepo + "/HEAD/speed_tested.txt": "vless://b@h2:8443?type=ws#FI-Speed-120Mbps\n",
	})
	var log strings.Builder
	nodes, err := runFixturePlugin(t, "luxxuria", srv, &log)
	require.NoError(t, err)

	assert.Equal(t, []string{
		"vless://a@h1:443?s=1#DE-Hetzner-42ms",
		"vless://b@h2:8443?type=ws#FI-Speed-120Mbps",
	}, sortedRaws(nodes))
}

// TestIgareckFixture pins the five-file include list AND the literal-'+'
// URL decision for BLACK_SS+All_RUS.txt:
//   - the github_files helper builds raw URLs by plain string concatenation
//     (internal/fetch rawURL — no path escaping), so the include entry is
//     used verbatim as the URL path;
//   - include matching compares the literal git-trees path, so a "%2B"
//     spelling would never match and the discovery would fail loud;
//   - Go's net/url keeps '+' literal in request paths (RFC 3986 path
//     segment), and the raw host serves the file.
//
// The fixture records the WIRE request URI and asserts the '+' arrived
// unescaped (no %2B on the wire).
func TestIgareckFixture(t *testing.T) {
	plusPath := "/" + igareckRepo + "/HEAD/BLACK_SS+All_RUS.txt"
	var wireMu sync.Mutex // handlers run concurrently (fetch concurrency 4)
	wire := map[string]string{}
	record := func(r *http.Request) {
		wireMu.Lock()
		defer wireMu.Unlock()
		wire[r.URL.Path] = r.RequestURI
	}
	mux := http.NewServeMux()
	raws := map[string]string{
		"/" + igareckRepo + "/HEAD/BLACK_VLESS_RUS.txt":        "vless://a@h1:443?s=1#rus1\n",
		"/" + igareckRepo + "/HEAD/BLACK_VLESS_RUS_mobile.txt": "vless://b@h2:443?s=1#rusmob\n",
		plusPath: "ss://YWJjZEBmNDoyNDQ0#ssall\n",
		"/" + igareckRepo + "/HEAD/BLACK_SS_WEAK_DPI_RUS.txt":                "ss://ZGVmQG1uOjQ0NDIjssweak\n",
		"/" + igareckRepo + "/HEAD/Vless-Reality-White-Lists-Rus-Mobile.txt": "vless://c@h3:443?security=reality#whitemob\n",
		// In the tree but outside INCLUDE: must never contribute a node.
		"/" + igareckRepo + "/HEAD/README.md": "vless://must-never-appear@x:1#readme\n",
	}
	paths := make([]string, 0, len(raws))
	for p := range raws {
		paths = append(paths, strings.TrimPrefix(p, "/"+igareckRepo+"/HEAD/"))
	}
	mux.HandleFunc("/api/repos/"+igareckRepo+"/git/trees/HEAD", func(w http.ResponseWriter, _ *http.Request) {
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

	var log strings.Builder
	nodes, err := runFixturePlugin(t, "igareck", srv, &log)
	require.NoError(t, err)

	// All five included files harvested; the README marker absent.
	assert.Equal(t, []string{
		"ss://YWJjZEBmNDoyNDQ0#ssall",
		"ss://ZGVmQG1uOjQ0NDIjssweak",
		"vless://a@h1:443?s=1#rus1",
		"vless://b@h2:443?s=1#rusmob",
		"vless://c@h3:443?security=reality#whitemob",
	}, sortedRaws(nodes))
	for _, n := range nodes {
		assert.NotContains(t, n.Raw, "must-never-appear")
	}
	// The '+' decision, asserted at the helper level: the request arrived
	// with the literal filename, never a %2B escape.
	uri, fetched := wire[plusPath]
	require.True(t, fetched, "BLACK_SS+All_RUS.txt was never fetched — include match failed")
	assert.Contains(t, uri, "BLACK_SS+All_RUS.txt", "wire path must carry the literal '+'")
	assert.NotContains(t, uri, "%2B", "the helper must not percent-encode the '+' — include matching compares the literal tree path")
}

// TestNodesradarFixture pins the single-fetch plain-HTTP contract: the
// whole-body base64 list decodes, non-200 and transport failures are loud
// plugin errors (breaker path), an empty body logs loud and returns zero
// nodes, and an oversized body fails loud on the defensive body cap (the
// accidental bulk-mirror landmine — a ~10.5 MB swap must never balloon a run).
func TestNodesradarFixture(t *testing.T) {
	newSrv := func(t *testing.T, status int, body string) *httptest.Server {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	run := func(t *testing.T, srv *httptest.Server, log *strings.Builder) ([]Node, error) {
		t.Helper()
		code := fixtureURL(t, "nodesradar", srv, nodesradarURL)
		eng := newEngine(engineOptions{Log: log})
		return eng.Run(context.Background(), &Plugin{
			ID: "nodesradar", Path: "nodesradar.lua", Code: []byte(code),
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

// TestWaveDefaultsCompileLoad pins the load-check contract for the four new
// embedded defaults: the chunk is side-effect-free (no network at load) and
// compiles into the canonical discover-function shape.
func TestWaveDefaultsCompileLoad(t *testing.T) {
	for _, id := range []string{"flat447", "luxxuria", "igareck", "nodesradar"} {
		code, ok := defaultSources()[id+".lua"]
		require.True(t, ok, "embedded default %s.lua missing", id)
		p, err := Compile(id, id+".lua", code, io.Discard)
		require.NoError(t, err, "%s must pass the load check", id)
		assert.Equal(t, id, p.ID)
	}
}

// TestWaveDefaultsEmptyBodies runs every new plugin against a stub fetch
// surface whose every URL answers an EMPTY body: all four must return zero
// nodes without error (fresh-source cold state).
func TestWaveDefaultsEmptyBodies(t *testing.T) {
	for _, tc := range []struct {
		id   string
		repo string
	}{
		{id: "flat447", repo: flat447Repo},
		{id: "luxxuria", repo: luxxuriaRepo},
		{id: "igareck", repo: igareckRepo},
	} {
		t.Run(tc.id, func(t *testing.T) {
			srv := newRepoFixture(t, tc.repo, map[string]string{
				"/" + tc.repo + "/HEAD/BLACK_FULL.txt":                           "",
				"/" + tc.repo + "/HEAD/WHITE_FULL.txt":                           "",
				"/" + tc.repo + "/HEAD/ping_tested.txt":                          "",
				"/" + tc.repo + "/HEAD/speed_tested.txt":                         "",
				"/" + tc.repo + "/HEAD/BLACK_VLESS_RUS.txt":                      "",
				"/" + tc.repo + "/HEAD/BLACK_VLESS_RUS_mobile.txt":               "",
				"/" + tc.repo + "/HEAD/BLACK_SS+All_RUS.txt":                     "",
				"/" + tc.repo + "/HEAD/BLACK_SS_WEAK_DPI_RUS.txt":                "",
				"/" + tc.repo + "/HEAD/Vless-Reality-White-Lists-Rus-Mobile.txt": "",
			})
			var log strings.Builder
			nodes, err := runFixturePlugin(t, tc.id, srv, &log)
			require.NoError(t, err)
			assert.Empty(t, nodes)
		})
	}
	t.Run("nodesradar", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(""))
		}))
		t.Cleanup(srv.Close)
		var log strings.Builder
		code := fixtureURL(t, "nodesradar", srv, nodesradarURL)
		eng := newEngine(engineOptions{Log: &log})
		nodes, err := eng.Run(context.Background(), &Plugin{
			ID: "nodesradar", Path: "nodesradar.lua", Code: []byte(code),
		})
		require.NoError(t, err)
		assert.Empty(t, nodes)
	})
}
