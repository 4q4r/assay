package fetch_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/fetch"

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
	got, err := cl.Source(context.Background(), "fixture-source", src)
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
	got, err := cl.Source(context.Background(), "fixture-source", src)
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
	first, err := cl.SourceCached(context.Background(), "epo", src, cacheDir, 0)
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.False(t, first[0].Cached)

	second, err := cl.SourceCached(context.Background(), "epo", src, cacheDir, 0)
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.True(t, second[0].Cached, "304 must serve the cached body")
	assert.Equal(t, string(first[0].Body), string(second[0].Body))

	// Cache file exists on disk with the body.
	b, err := os.ReadFile(filepath.Join(cacheDir, "epo", "Splitted-By-Protocol_vless.txt"))
	require.NoError(t, err)
	assert.Equal(t, files["/Splitted-By-Protocol/vless.txt"], string(b))
}

// countingRawServer returns a client whose raw-file endpoint counts every
// body GET (the "fetch-call counter" the cache_max_age pins reference) plus
// the counter itself.
func countingRawServer(t *testing.T, files map[string]string) (*fetch.Client, *atomic.Int32) {
	t.Helper()
	var rawGETs atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tree":[{"path":"vless.txt","type":"blob"}]}`))
	})
	mux.HandleFunc("/raw/", func(w http.ResponseWriter, r *http.Request) {
		rawGETs.Add(1)
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cl := fetch.NewClient(fetch.ClientConfig{
		APIBase: srv.URL, RawBase: srv.URL + "/raw", Timeout: 5 * time.Second, Retries: 1,
	})
	return cl, &rawGETs
}

// TestCacheFreshSkipsNetwork pins Gap-0: when a source's cached body file is
// younger than fetch.cache_max_age, the network fetch for that file is
// skipped ENTIRELY (fetch-call counter stays 0), the cached body is served,
// and the skip is logged ("cache fresh, skipping").
func TestCacheFreshSkipsNetwork(t *testing.T) {
	cl, rawGETs := countingRawServer(t, map[string]string{"/raw/owner/repo/HEAD/vless.txt": "vless://u@a.example.com:443?security=tls&type=tcp"})
	logBuf := &bytes.Buffer{}
	cl.LogOut = logBuf
	cacheDir := t.TempDir()
	src := config.Source{Repo: "owner/repo", Discovery: "github-contents", Include: []string{"vless.txt"}}

	first, err := cl.SourceCached(context.Background(), "src", src, cacheDir, time.Hour)
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.Equal(t, int32(1), rawGETs.Load(), "first wave must fetch (cold cache)")

	second, err := cl.SourceCached(context.Background(), "src", src, cacheDir, time.Hour)
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.Equal(t, int32(1), rawGETs.Load(),
		"fresh cache: the raw GET counter must stay at 0 new calls — no network fetch at all")
	assert.True(t, second[0].Cached, "fresh-served body is flagged cached")
	assert.Equal(t, "vless://u@a.example.com:443?security=tls&type=tcp", string(second[0].Body))
	assert.Contains(t, logBuf.String(), "cache fresh, skipping", "the skip must be logged")
}

// TestCacheStaleRefetches pins the stale arm: a cached body OLDER than the
// window goes through the normal conditional GET + cache write path.
func TestCacheStaleRefetches(t *testing.T) {
	cl, rawGETs := countingRawServer(t, map[string]string{"/raw/owner/repo/HEAD/vless.txt": "vless://u@a.example.com:443?security=tls&type=tcp"})
	cacheDir := t.TempDir()
	src := config.Source{Repo: "owner/repo", Discovery: "github-contents", Include: []string{"vless.txt"}}

	_, err := cl.SourceCached(context.Background(), "src", src, cacheDir, time.Hour)
	require.NoError(t, err)
	stale := time.Now().Add(-2 * time.Hour)
	cachePath := filepath.Join(cacheDir, "src", "vless.txt")
	require.NoError(t, os.Chtimes(cachePath, stale, stale), "age the cache body past the window")

	_, err = cl.SourceCached(context.Background(), "src", src, cacheDir, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int32(2), rawGETs.Load(), "stale cache must fetch again (conditional GET + cache write)")
}

// TestCacheMissingFetches pins the missing arm: no cache file → normal fetch.
func TestCacheMissingFetches(t *testing.T) {
	cl, rawGETs := countingRawServer(t, map[string]string{"/raw/owner/repo/HEAD/vless.txt": "vless://u@a.example.com:443?security=tls&type=tcp"})
	cacheDir := t.TempDir()
	src := config.Source{Repo: "owner/repo", Discovery: "github-contents", Include: []string{"vless.txt"}}

	_, err := cl.SourceCached(context.Background(), "src", src, cacheDir, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int32(1), rawGETs.Load(), "no cache file → fetch as today")
}

// TestCacheZeroWindowAlwaysFetches pins the owner zero-semantics: an explicit
// cache_max_age = "0s" means ALWAYS fetch, never skip.
func TestCacheZeroWindowAlwaysFetches(t *testing.T) {
	cl, rawGETs := countingRawServer(t, map[string]string{"/raw/owner/repo/HEAD/vless.txt": "vless://u@a.example.com:443?security=tls&type=tcp"})
	cacheDir := t.TempDir()
	src := config.Source{Repo: "owner/repo", Discovery: "github-contents", Include: []string{"vless.txt"}}

	for wave := 1; wave <= 2; wave++ {
		_, err := cl.SourceCached(context.Background(), "src", src, cacheDir, 0)
		require.NoError(t, err)
		assert.Equal(t, int32(wave), rawGETs.Load(), "window 0s: wave %d must fetch (always)", wave)
	}
}

// TestUserAgentFromConfig pins [http].user_agent: the configured string is
// sent verbatim on every pipeline request (raw fetch, API discovery), and the
// zero-value ClientConfig falls back to today's exact UA string.
func TestUserAgentFromConfig(t *testing.T) {
	var mu sync.Mutex
	gotRaw, gotAPI := "", ""
	capture := func(sink *string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			*sink = r.Header.Get("User-Agent")
			mu.Unlock()
			if strings.Contains(r.URL.Path, "/repos/") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"tree":[{"path":"vless.txt","type":"blob"}]}`))
				return
			}
			_, _ = w.Write([]byte("vless://u@a.example.com:443?security=tls&type=tcp"))
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/repos/", capture(&gotAPI))
	mux.Handle("/raw/", capture(&gotRaw))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cl := fetch.NewClient(fetch.ClientConfig{
		APIBase: srv.URL, RawBase: srv.URL + "/raw", Timeout: 5 * time.Second,
		UserAgent: "custom-agent/7",
	})
	src := config.Source{Repo: "owner/repo", Discovery: "github-contents", Include: []string{"vless.txt"}}
	_, err := cl.SourceCached(context.Background(), "src", src, t.TempDir(), 0)
	require.NoError(t, err)
	assert.Equal(t, "custom-agent/7", gotRaw, "raw fetch must carry the configured UA")
	assert.Equal(t, "custom-agent/7", gotAPI, "API discovery must carry the configured UA")

	// Zero-value UA → today's exact default (behavior preservation).
	defUA := ""
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defUA = r.Header.Get("User-Agent")
		mu.Unlock()
		http.NotFound(w, r)
	}))
	t.Cleanup(srv2.Close)
	cl2 := fetch.NewClient(fetch.ClientConfig{APIBase: srv2.URL, RawBase: srv2.URL, Timeout: 5 * time.Second})
	_, err = cl2.Fetch(context.Background(), "o/r", "f.txt")
	require.Error(t, err, "404 from the bare handler is fine — only the UA matters")
	assert.Equal(t, config.DefaultUserAgent, defUA, "empty ClientConfig.UserAgent must default to today's exact UA")
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
	}, t.TempDir(), 0)
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
	}, cacheDir, 0)
	require.NoError(t, err)

	meta := filepath.Join(cacheDir, "src", "vless.txt.meta.json")
	st, err := os.Stat(meta)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), st.Mode().Perm(), "cache sidecar must be 0600")
}

// TestCacheFutureMtimeIsStaleAndRefetches pins the clock-skew clamp (M-1): a
// cache file with a FUTURE mtime (skewed clock) must read as STALE — the
// freshness window measures the file's age, and a negative age is not "fresh"
// (the unclamped comparison treated it as fresh for the whole skewed window,
// silently extending freshness by the skew amount).
func TestCacheFutureMtimeIsStaleAndRefetches(t *testing.T) {
	cl, rawGETs := countingRawServer(t, map[string]string{"/raw/owner/repo/HEAD/vless.txt": "vless://u@a.example.com:443?security=tls&type=tcp"})
	cacheDir := t.TempDir()
	src := config.Source{Repo: "owner/repo", Discovery: "github-contents", Include: []string{"vless.txt"}}

	first, err := cl.SourceCached(context.Background(), "src", src, cacheDir, time.Hour)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, int32(1), rawGETs.Load(), "first wave must fetch (cold cache)")

	// Synthetic skew: pretend the cache file was written two hours in the
	// future — older-than-now it is not, so "younger than maxAge" must not hold.
	cp := filepath.Join(cacheDir, "src", fetch.SafePath("vless.txt"))
	future := time.Now().Add(2 * time.Hour)
	require.NoError(t, os.Chtimes(cp, future, future))

	logBuf := &bytes.Buffer{}
	cl.LogOut = logBuf
	second, err := cl.SourceCached(context.Background(), "src", src, cacheDir, time.Hour)
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.Equal(t, int32(2), rawGETs.Load(),
		"a future mtime must be treated as stale: the fetch must happen")
	assert.False(t, second[0].Cached, "the refetched body is not the cached one")
	assert.NotContains(t, logBuf.String(), "cache fresh, skipping",
		"the freshness skip must not fire for a negatively-aged file")
}
