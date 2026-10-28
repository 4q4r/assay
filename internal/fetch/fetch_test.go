package fetch_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/fetch"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServer emulates the GitHub contents API + raw hosts. The returned
// client is pointed at the fake hosts; no real network is used.
func newTestServer(t *testing.T, files map[string]string) *fetch.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/git/trees/{ref}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(treeForTest))
	})
	mux.HandleFunc("/raw/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/raw/")
		parts := strings.SplitN(rest, "/", 3) // owner / repo / HEAD/<path>
		if len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		path := "/" + strings.TrimPrefix(parts[2], "HEAD/")
		body, ok := files[path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("If-None-Match") == `"etag-`+path+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"etag-`+path+`"`)
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cfg := fetch.ClientConfig{
		APIBase: srv.URL,
		RawBase: srv.URL + "/raw",
		Timeout: 5 * time.Second,
		Retries: 1,
	}
	return fetch.NewClient(cfg)
}

const treeForTest = `{"tree":[
 {"path":"README.md","type":"blob"},
 {"path":"Splitted-By-Protocol/vless.txt","type":"blob"},
 {"path":"Splitted-By-Protocol/trojan.txt","type":"blob"},
 {"path":"Splitted-By-Protocol/ss.txt","type":"blob"},
 {"path":"subscriptions/v2ray/super-sub.txt","type":"blob"},
 {"path":"secure/configs.txt","type":"blob"}
]}`

func TestDiscoveryIncludePatterns(t *testing.T) {
	files := map[string]string{
		"/Splitted-By-Protocol/vless.txt":  "vless://u@a.example.com:443?security=tls&type=tcp",
		"/Splitted-By-Protocol/trojan.txt": "trojan://p@b.example.com:443?type=tcp",
		"/secure/configs.txt":              "vless://u@c.example.com:443?security=tls&type=tcp",
	}
	cl := newTestServer(t, files)

	src := config.Source{
		Repo:      "owner/repo",
		Discovery: "github-contents",
		Include:   []string{"Splitted-By-Protocol/vless.txt", "Splitted-By-Protocol/trojan.txt"},
	}
	got, err := cl.Discover(context.Background(), src)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"Splitted-By-Protocol/vless.txt", "Splitted-By-Protocol/trojan.txt"}, got)
}

func TestDiscoveryBasenamePattern(t *testing.T) {
	files := map[string]string{"/secure/configs.txt": "x"}
	cl := newTestServer(t, files)
	src := config.Source{Repo: "owner/repo", Discovery: "github-contents", Include: []string{"configs.txt"}}
	got, err := cl.Discover(context.Background(), src)
	require.NoError(t, err)
	assert.Equal(t, []string{"secure/configs.txt"}, got, "bare basename matches at any depth")
}

func TestDiscoveryNoMatchIsLoudError(t *testing.T) {
	cl := newTestServer(t, map[string]string{})
	src := config.Source{Repo: "owner/repo", Discovery: "github-contents", Include: []string{"nonexistent.txt"}}
	_, err := cl.Discover(context.Background(), src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no files matched")
}

func TestFetchSourceDownloadsAllDiscoveredFiles(t *testing.T) {
	files := map[string]string{
		"/Splitted-By-Protocol/vless.txt":  "vless://u@a.example.com:443?security=tls&type=tcp",
		"/Splitted-By-Protocol/trojan.txt": "trojan://p@b.example.com:443?type=tcp",
	}
	cl := newTestServer(t, files)
	src := config.Source{
		Repo:      "owner/repo",
		Discovery: "github-contents",
		Include:   []string{"Splitted-By-Protocol/vless.txt", "Splitted-By-Protocol/trojan.txt"},
	}
	got, err := cl.Source(context.Background(), "epodonios", src)
	require.NoError(t, err)
	require.Len(t, got, 2)
	bodies := make([]string, 0, len(got))
	for _, f := range got {
		bodies = append(bodies, string(f.Body))
	}
	assert.Contains(t, bodies, files["/Splitted-By-Protocol/vless.txt"])
	assert.Contains(t, bodies, files["/Splitted-By-Protocol/trojan.txt"])
}

func TestFetch404IsLoud(t *testing.T) {
	cl := newTestServer(t, map[string]string{})
	_, err := cl.Fetch(context.Background(), "owner/repo", "Splitted-By-Protocol/vless.txt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestFetchRetriesOnServerError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("vless://u@a.example.com:443?security=tls&type=tcp"))
	}))
	t.Cleanup(srv.Close)
	cl := fetch.NewClient(fetch.ClientConfig{
		APIBase: srv.URL, RawBase: srv.URL, Timeout: 2 * time.Second, Retries: 3,
	})
	body, err := cl.Fetch(context.Background(), "o/r", "f.txt")
	require.NoError(t, err)
	assert.Contains(t, string(body), "vless://")
	assert.Equal(t, int32(2), calls.Load(), "second attempt must succeed after 502")
}

func TestManifestDiscoveryRadikalShape(t *testing.T) {
	// Manifest mirrors the real 0xRadikal index.json: protocol_files map,
	// categories/cascade maps with files dicts, raw + mirror twins of the same
	// path (mirror must not duplicate the fetch).
	manifest := `{
	  "raw_base": "https://raw.example/own/repo/main",
	  "protocol_files": {"vless": "https://raw.example/own/repo/main/protocols/vless.txt"},
	  "categories": {
	    "all": {"files": {"configs_txt": "https://raw.example/own/repo/main/all/configs.txt",
	                      "configs_txt_mirror": "https://cdn.example/own/repo@main/all/configs.txt"}}
	  },
	  "cascade_categories": {
	    "verified": {"files": {"configs_txt": "https://raw.example/own/repo/main/secure/configs.txt"}}
	  }
	}`
	files := map[string]string{
		"/own/repo/HEAD/protocols/vless.txt": "vless://u@a.example.com:443?security=tls&type=tcp",
		"/own/repo/HEAD/secure/configs.txt":  "vless://u@b.example.com:443?security=tls&type=tcp",
		"/own/repo/HEAD/all/configs.txt":     "vless://u@c.example.com:443?security=tls&type=tcp",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/own/repo/HEAD/manifest", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(manifest))
	})
	for p := range files {
		mux.HandleFunc("GET "+p, func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte(files[req.URL.Path]))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cl := fetch.NewClient(fetch.ClientConfig{
		APIBase: srv.URL, RawBase: srv.URL, Timeout: 5 * time.Second, Retries: 1,
	})
	src := config.Source{
		Repo:      "own/repo",
		Discovery: "manifest",
		Manifest:  "manifest",
		Include:   []string{"protocols/vless.txt", "secure/configs.txt"},
	}
	got, err := cl.Source(context.Background(), "radikal", src)
	require.NoError(t, err)
	require.Len(t, got, 2, "include filter applies to manifest entries; mirror twins dedupe")
	paths := []string{got[0].Path, got[1].Path}
	assert.ElementsMatch(t, []string{"protocols/vless.txt", "secure/configs.txt"}, paths)
}

func TestCacheReuses304Bodies(t *testing.T) {
	files := map[string]string{"/Splitted-By-Protocol/vless.txt": "vless://u@a.example.com:443?security=tls&type=tcp"}
	cl := newTestServer(t, files)
	cacheDir := t.TempDir()

	src := config.Source{Repo: "owner/repo", Discovery: "github-contents", Include: []string{"Splitted-By-Protocol/vless.txt"}}
	first, err := cl.SourceCached(context.Background(), "epo", src, cacheDir)
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.False(t, first[0].Cached)

	second, err := cl.SourceCached(context.Background(), "epo", src, cacheDir)
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.True(t, second[0].Cached, "304 must serve the cached body")
	assert.Equal(t, string(first[0].Body), string(second[0].Body))

	// Cache file exists on disk with the body.
	b, err := os.ReadFile(filepath.Join(cacheDir, "epo", "Splitted-By-Protocol_vless.txt"))
	require.NoError(t, err)
	assert.Equal(t, files["/Splitted-By-Protocol/vless.txt"], string(b))
}

func TestBase64SubscriptionBodyIsCarriedVerbatim(t *testing.T) {
	raw := "vless://u@b64.example.com:443?security=tls&type=tcp"
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	files := map[string]string{"/subscriptions/v2ray/super-sub.txt": enc}
	cl := newTestServer(t, files)
	src := config.Source{Repo: "owner/repo", Discovery: "github-contents", Include: []string{"super-sub.txt"}}
	got, err := cl.Source(context.Background(), "matin", src)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, enc, string(got[0].Body), "fetch carries bytes verbatim; base64 decoding is parse's job")
}

func TestConcurrentFetchesAreBounded(t *testing.T) {
	var inFlight, maxInFlight atomic.Int32
	files := map[string]string{}
	paths := make([]string, 0, 8)
	for i := range 8 {
		p := fmt.Sprintf("/Splitted-By-Protocol/file%d.txt", i)
		files[p] = fmt.Sprintf("vless://u@f%d.example.com:443?security=tls&type=tcp", i)
		paths = append(paths, fmt.Sprintf("Splitted-By-Protocol/file%d.txt", i))
	}
	tree := `{"tree":[{"path":"Splitted-By-Protocol/file0.txt","type":"blob"},{"path":"Splitted-By-Protocol/file1.txt","type":"blob"},{"path":"Splitted-By-Protocol/file2.txt","type":"blob"},{"path":"Splitted-By-Protocol/file3.txt","type":"blob"},{"path":"Splitted-By-Protocol/file4.txt","type":"blob"},{"path":"Splitted-By-Protocol/file5.txt","type":"blob"},{"path":"Splitted-By-Protocol/file6.txt","type":"blob"},{"path":"Splitted-By-Protocol/file7.txt","type":"blob"}]}`
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/git/trees/{ref}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(tree))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		cur := inFlight.Add(1)
		for {
			old := maxInFlight.Load()
			if cur <= old || maxInFlight.CompareAndSwap(old, cur) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		_, _ = w.Write([]byte(files[req.URL.Path]))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cl := fetch.NewClient(fetch.ClientConfig{APIBase: srv.URL, RawBase: srv.URL, Timeout: 5 * time.Second, Retries: 1, Concurrency: 3})
	src := config.Source{Repo: "o/r", Discovery: "github-contents", Include: paths}
	got, err := cl.Source(context.Background(), "s", src)
	require.NoError(t, err)
	assert.Len(t, got, 8)
	assert.LessOrEqual(t, maxInFlight.Load(), int32(3), "concurrency must be bounded by config")
}

// TestDiscoverRefusesTruncatedTree pins the trees-API truncation contract:
// GitHub serves `"truncated": true` when the recursive listing hit its size
// cap — treating it as a complete listing would silently drop source files
// (fix-round-1 finding #2), so discovery must fail loud with an actionable
// message.
func TestDiscoverRefusesTruncatedTree(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"truncated":true,"tree":[
			{"path":"sub.txt","type":"blob"}
		]}`))
	}))
	t.Cleanup(srv.Close)

	cl := fetch.NewClient(fetch.ClientConfig{APIBase: srv.URL, RawBase: srv.URL, Timeout: 5 * time.Second})
	_, err := cl.Discover(context.Background(), config.Source{
		Repo:      "owner/repo",
		Discovery: "github-contents",
		Include:   []string{"sub.txt"},
	})
	require.Error(t, err, "a truncated tree must never pass as a complete listing")
	assert.Contains(t, err.Error(), "truncated")
	assert.Contains(t, err.Error(), "include", "message must point at the actionable fix")
}

// TestSourceCachedCancelledContextIsLoud pins the stage-level contract: a
// cancelled wave must surface as an error, never as a silently truncated
// file list with zero-value entries.
func TestSourceCachedCancelledContextIsLoud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tree":[
			{"path":"a.txt","type":"blob"},
			{"path":"b.txt","type":"blob"}
		]}`))
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cl := fetch.NewClient(fetch.ClientConfig{APIBase: srv.URL, RawBase: srv.URL, Timeout: 5 * time.Second})
	files, err := cl.SourceCached(ctx, "src", config.Source{
		Repo:      "owner/repo",
		Discovery: "github-contents",
		Include:   []string{"a.txt", "b.txt"},
	}, t.TempDir())
	require.ErrorIs(t, err, context.Canceled, "cancelled wave must be loud")
	for _, f := range files {
		assert.NotEmpty(t, f.Path, "no zero-value entry may leak past a cancelled wave")
	}
}

// TestSafePathIsTheSingleCacheNameMapping pins the path→cache-name mapping
// that fetch writes and the cli parse stage reads back — one definition, no
// mirrored copies (review finding 10).
func TestSafePathIsTheSingleCacheNameMapping(t *testing.T) {
	assert.Equal(t, "dir_sub.txt", fetch.SafePath("dir/sub.txt"))
	assert.Equal(t, "a___b.txt", fetch.SafePath("a/../b.txt")) // "/" and ".." both map to "_", sequentially
	assert.Equal(t, "plain.txt", fetch.SafePath("plain.txt"))
	assert.NotContains(t, fetch.SafePath("../../etc/passwd"), "/", "flat name stays inside the cache dir")
}

// TestCacheSidecarModeIs0600 pins the cache-hardening: the etag sidecar is
// pipeline state on the owner's disk and is written 0600, not 0644 (review
// finding 11).
func TestCacheSidecarModeIs0600(t *testing.T) {
	// One server, two shapes: the trees listing (APIBase) and the raw file
	// with an ETag (RawBase) — the second wave revalidates via If-None-Match.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tree":[{"path":"vless.txt","type":"blob"}]}`))
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("body\n"))
	}))
	t.Cleanup(srv.Close)
	cl := fetch.NewClient(fetch.ClientConfig{APIBase: srv.URL, RawBase: srv.URL, Timeout: 5 * time.Second})
	cacheDir := t.TempDir()
	_, err := cl.SourceCached(context.Background(), "src", config.Source{
		Repo: "owner/repo", Discovery: "github-contents", Include: []string{"vless.txt"},
	}, cacheDir)
	require.NoError(t, err)

	meta := filepath.Join(cacheDir, "src", "vless.txt.meta.json")
	st, err := os.Stat(meta)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), st.Mode().Perm(), "cache sidecar must be 0600")
}
