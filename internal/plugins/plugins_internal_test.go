package plugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"public_vpn/internal/fetch"
)

// runSource executes a plugin source directly (bypassing compile) — the
// engine-level contract under test.
func runSource(t *testing.T, code string) ([]Node, error) {
	t.Helper()
	eng := newEngine(engineOptions{Log: io.Discard})
	return eng.Run(context.Background(), &Plugin{ID: "test", Path: "test.lua", Code: []byte(code)})
}

func runMustNodes(t *testing.T, code string) []Node {
	t.Helper()
	nodes, err := runSource(t, code)
	if err != nil {
		t.Fatalf("plugin run failed: %v", err)
	}
	return nodes
}

func TestNodeClassContract(t *testing.T) {
	t.Run("constructor output is collected", func(t *testing.T) {
		nodes := runMustNodes(t, `return function()
			return { publicvpn.node{ raw = "vless://a@h:1?s=1#m" } }
		end`)
		if len(nodes) != 1 || nodes[0].Raw != "vless://a@h:1?s=1#m" {
			t.Fatalf("unexpected nodes: %+v", nodes)
		}
	})
	t.Run("plain table with raw is accepted", func(t *testing.T) {
		nodes := runMustNodes(t, `return function()
			return { { raw = "vless://a@h:1" }, publicvpn.node{ raw = "vless://b@h:2" } }
		end`)
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes, got %d", len(nodes))
		}
	})
	t.Run("optional hints and source carried", func(t *testing.T) {
		nodes := runMustNodes(t, `return function()
			return { publicvpn.node{
				raw = "vless://a@h:1", source = "other", remark = "r",
				scheme = "VLESS", host = "h", port = 1 } }
		end`)
		n := nodes[0]
		if n.Source != "other" || n.Remark != "r" || n.Scheme != "vless" ||
			n.Host != "h" || n.Port != 1 {
			t.Fatalf("hints lost: %+v", n)
		}
	})
	t.Run("constructor rejects missing raw loud", func(t *testing.T) {
		_, err := runSource(t, `return function()
			return { publicvpn.node{ remark = "no raw" } }
		end`)
		if err == nil || !strings.Contains(err.Error(), "raw (non-empty string) is required") {
			t.Fatalf("expected loud raw-required error, got: %v", err)
		}
	})
	t.Run("non-node element fails loud with plugin and index", func(t *testing.T) {
		_, err := runSource(t, `return function()
			return { publicvpn.node{ raw = "vless://a@h:1" }, "oops" }
		end`)
		var le *LoadError
		if !errors.As(err, &le) || le.Plugin != "test" || le.Index != 2 {
			t.Fatalf("expected LoadError plugin=test index=2, got: %v", err)
		}
		if !strings.Contains(err.Error(), "not a publicvpn.node (got string)") {
			t.Fatalf("error must name the offending type: %v", err)
		}
	})
	t.Run("nil hole in result array fails loud with index", func(t *testing.T) {
		_, err := runSource(t, `return function()
			local t = {}
			t[1] = publicvpn.node{ raw = "vless://a@h:1" }
			t[3] = publicvpn.node{ raw = "vless://b@h:2" }
			return t
		end`)
		var le *LoadError
		if !errors.As(err, &le) || le.Index != 2 {
			t.Fatalf("expected LoadError index=2 for the sparse hole, got: %v", err)
		}
	})
	t.Run("collector rejects a plain table with empty raw, with index", func(t *testing.T) {
		_, err := runSource(t, `return function()
			return { { raw = "   " } }
		end`)
		var le *LoadError
		if !errors.As(err, &le) || le.Index != 1 || !strings.Contains(err.Error(), "node.raw is required") {
			t.Fatalf("expected loud empty-raw error at index 1, got: %v", err)
		}
	})
	t.Run("port hint out of range fails loud", func(t *testing.T) {
		_, err := runSource(t, `return function()
			return { publicvpn.node{ raw = "vless://a@h:1", port = 99999 } }
		end`)
		if err == nil || !strings.Contains(err.Error(), "port hint 99999") {
			t.Fatalf("expected loud port-range error, got: %v", err)
		}
	})
	t.Run("discover returning a string fails loud", func(t *testing.T) {
		_, err := runSource(t, `return function() return "not a table" end`)
		if err == nil || !strings.Contains(err.Error(), "discover returned string") {
			t.Fatalf("expected loud return-type error, got: %v", err)
		}
	})
	t.Run("chunk returning a non-function fails loud at load", func(t *testing.T) {
		_, err := Compile("bad", "bad.lua", []byte(`return 42`), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "must return its discover function") {
			t.Fatalf("expected loud shape error, got: %v", err)
		}
	})
	t.Run("discover runtime error attributes the plugin", func(t *testing.T) {
		_, err := runSource(t, `return function() error("boom") end`)
		if err == nil || !strings.Contains(err.Error(), `plugin "test"`) || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected plugin-attributed error, got: %v", err)
		}
	})
	t.Run("metatable marker exposes the class to authors", func(t *testing.T) {
		eng := newEngine(engineOptions{Log: io.Discard})
		l := eng.newState(context.Background(), "test")
		defer l.Close()
		if err := l.DoString(`assert(getmetatable(publicvpn.node{raw="x"}) == "publicvpn.node")`); err != nil {
			t.Fatalf("node class marker broken: %v", err)
		}
	})
}

// TestNonIntegerPortHintFailsLoud pins the N-1 fix: a fractional port hint
// (443.7) used to truncate to 443 via a silent int() conversion — a hint
// nobody intended. The rejection is loud and names the param and the value.
func TestNonIntegerPortHintFailsLoud(t *testing.T) {
	_, err := runSource(t, `return function()
		return { publicvpn.node{ raw = "vless://a@h:1", port = 443.7 } }
	end`)
	if err == nil || !strings.Contains(err.Error(), "port") || !strings.Contains(err.Error(), "443.7") {
		t.Fatalf("expected loud non-integer port error naming port and 443.7, got: %v", err)
	}
}

func TestHostHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/get":
			if r.Header.Get("X-Probe") != "1" || r.Header.Get("User-Agent") == "" {
				http.Error(w, "missing headers", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("hello"))
		case "/post":
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			if string(body) != "payload" {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			w.Header().Set("X-Reply", "yes")
			_, _ = w.Write([]byte("posted:" + string(body)))
		case "/redirect":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			_, _ = w.Write([]byte("landed"))
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
		case "/plain":
			_, _ = w.Write([]byte("ok"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Run("GET with headers", func(t *testing.T) {
		nodes := runMustNodes(t, fmt.Sprintf(`return function()
			local r = publicvpn.http{ url = "%s/get", headers = { ["X-Probe"] = "1" } }
			assert(r.status == 200, "status " .. r.status)
			assert(r.body == "hello", "body " .. r.body)
			assert(r.headers["X-Reply"] == nil, "unexpected header")
			return {}
		end`, srv.URL))
		_ = nodes
	})
	t.Run("User-Agent defaults from the engine", func(t *testing.T) {
		eng := newEngine(engineOptions{Log: io.Discard, UserAgent: "ua-test"})
		_, err := eng.Run(context.Background(), &Plugin{
			ID: "t", Path: "t.lua",
			Code: []byte(fmt.Sprintf(`return function()
				local r = publicvpn.http{ url = "%s/get", headers = { ["X-Probe"] = "1" } }
				assert(r.status == 200)
				return {}
			end`, srv.URL)),
		})
		if err != nil {
			t.Fatalf("engine User-Agent not applied: %v", err)
		}
	})
	t.Run("POST with body", func(t *testing.T) {
		runMustNodes(t, fmt.Sprintf(`return function()
			local r = publicvpn.http{ url = "%s/post", method = "POST", body = "payload" }
			assert(r.status == 200, "status " .. r.status)
			assert(r.body == "posted:payload", "body " .. r.body)
			assert(r.headers["X-Reply"] == "yes", "missing response header")
			return {}
		end`, srv.URL))
	})
	t.Run("redirects followed and capped", func(t *testing.T) {
		runMustNodes(t, fmt.Sprintf(`return function()
			local r = publicvpn.http{ url = "%s/redirect" }
			assert(r.status == 200 and r.body == "landed", "default follow broken")
			local capped = publicvpn.http{ url = "%s/redirect", max_redirects = 0 }
			assert(capped.status == 302, "cap not honored: " .. capped.status)
			return {}
		end`, srv.URL, srv.URL))
	})
	t.Run("timeout is loud", func(t *testing.T) {
		_, err := runSource(t, fmt.Sprintf(`return function()
			return { publicvpn.http{ url = "%s/slow", timeout = 0.2 } }
		end`, srv.URL))
		deadline := strings.Contains(err.Error(), "context deadline exceeded")
		timeout := strings.Contains(err.Error(), "Timeout")
		if err == nil || (!deadline && !timeout) {
			t.Fatalf("expected loud timeout error, got: %v", err)
		}
	})
	t.Run("max_body_bytes exceeded is loud", func(t *testing.T) {
		_, err := runSource(t, fmt.Sprintf(`return function()
			return { publicvpn.http{ url = "%s/big", max_body_bytes = 1024 } }
		end`, srv.URL))
		if err == nil || !strings.Contains(err.Error(), "exceeds max_body_bytes") {
			t.Fatalf("expected loud body-limit error, got: %v", err)
		}
	})
	t.Run("non-2xx is a value, not an error", func(t *testing.T) {
		runMustNodes(t, fmt.Sprintf(`return function()
			local r = publicvpn.http{ url = "%s/missing" }
			assert(r.status == 404, "expected 404, got " .. r.status)
			return {}
		end`, srv.URL))
	})
	t.Run("L5: ambient proxy env is ignored", func(t *testing.T) {
		t.Setenv("http_proxy", "127.0.0.1:1")
		t.Setenv("https_proxy", "127.0.0.1:1")
		runMustNodes(t, fmt.Sprintf(`return function()
			local r = publicvpn.http{ url = "%s/plain" }
			assert(r.status == 200, "proxied? status " .. r.status)
			return {}
		end`, srv.URL))
	})
	t.Run("engine transport is Proxy-nil (white-box)", func(t *testing.T) {
		eng := NewEngine(fetch.ClientConfig{UserAgent: "ua"}, io.Discard)
		if eng.opt.HTTPTransport == nil || eng.opt.HTTPTransport.Proxy != nil {
			t.Fatal("plugin HTTP transport must carry Proxy == nil (landmine L5)")
		}
	})
	t.Run("missing url is loud", func(t *testing.T) {
		_, err := runSource(t, `return function() return { publicvpn.http{} } end`)
		if err == nil || !strings.Contains(err.Error(), "url (non-empty string) is required") {
			t.Fatalf("expected loud url error, got: %v", err)
		}
	})
}

func TestHostGitHubFiles(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/api/repos/owner/repo/git/trees/HEAD", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tree":[
			{"path":"sub/a.txt","type":"blob"},
			{"path":"sub/b.txt","type":"blob"},
			{"path":"README.md","type":"blob"},
			{"path":"sub","type":"tree"}
		],"truncated":false}`))
	})
	mux.HandleFunc("/api/repos/owner/repo/git/trees/trunc", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tree":[],"truncated":true}`))
	})
	mux.HandleFunc("/owner/repo/HEAD/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/HEAD/sub/a.txt":
			_, _ = w.Write([]byte("vless://a@h:1#a\n"))
		case "/owner/repo/HEAD/sub/b.txt":
			_, _ = w.Write([]byte("vless://b@h:2#b\n"))
		case "/owner/repo/HEAD/index.json":
			_, _ = w.Write([]byte(`{"files":["` + srv.URL + `/owner/repo/HEAD/sub/a.txt"]}`))
		default:
			http.NotFound(w, r)
		}
	})

	engine := func() *Engine {
		return NewEngine(fetch.ClientConfig{
			APIBase: srv.URL + "/api", RawBase: srv.URL,
			UserAgent: "ua-test", Timeout: 5 * time.Second, Retries: 0,
		}, io.Discard)
	}

	t.Run("contents discovery honors include", func(t *testing.T) {
		_, err := engine().Run(context.Background(), &Plugin{ID: "t", Path: "t.lua", Code: []byte(`
			return function()
				local files = publicvpn.github_files{ repo = "owner/repo", include = { "sub/" } }
				assert(#files == 2, "expected 2 files, got " .. #files)
				assert(files[1].path == "sub/a.txt", files[1].path)
				assert(files[1].content == "vless://a@h:1#a\n", files[1].content)
				return {}
			end`)})
		if err != nil {
			t.Fatalf("github_files contents path: %v", err)
		}
	})
	t.Run("manifest discovery", func(t *testing.T) {
		_, err := engine().Run(context.Background(), &Plugin{ID: "t", Path: "t.lua", Code: []byte(`
			return function()
				local files = publicvpn.github_files{ repo = "owner/repo", manifest = "index.json" }
				assert(#files == 1, "expected 1 file, got " .. #files)
				assert(files[1].path == "sub/a.txt", files[1].path)
				return {}
			end`)})
		if err != nil {
			t.Fatalf("github_files manifest path: %v", err)
		}
	})
	t.Run("truncated tree fails loud", func(t *testing.T) {
		truncSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"tree":[],"truncated":true}`))
		}))
		defer truncSrv.Close()
		eng := NewEngine(fetch.ClientConfig{
			APIBase: truncSrv.URL + "/api", RawBase: truncSrv.URL + "/raw",
			UserAgent: "ua-test", Timeout: 5 * time.Second, Retries: 0,
		}, io.Discard)
		_, err := eng.Run(context.Background(), &Plugin{ID: "t", Path: "t.lua", Code: []byte(`
			return function()
				return { publicvpn.github_files{ repo = "owner/repo" } }
			end`)})
		if err == nil || !strings.Contains(err.Error(), "truncated") {
			t.Fatalf("expected loud truncated-tree error, got: %v", err)
		}
	})
	t.Run("no matches fails loud", func(t *testing.T) {
		_, err := engine().Run(context.Background(), &Plugin{ID: "t", Path: "t.lua", Code: []byte(`
			return function()
				return { publicvpn.github_files{ repo = "owner/repo", include = { "nomatch/" } } }
			end`)})
		if err == nil || !strings.Contains(err.Error(), "no files matched") {
			t.Fatalf("expected loud no-match error, got: %v", err)
		}
	})
}

func TestHostBase64AndJSON(t *testing.T) {
	t.Run("base64 round-trip + flexible decode", func(t *testing.T) {
		runMustNodes(t, `return function()
			local enc = publicvpn.base64.encode("hello")
			assert(enc == "aGVsbG8=", "encode: " .. enc)
			assert(publicvpn.base64.decode(enc) == "hello")
			assert(publicvpn.base64.decode("aGVsbG8") == "hello", "raw std decode")
			assert(publicvpn.base64.decode("-8") == "\251", "url-safe decode")
			return {}
		end`)
	})
	t.Run("base64 decode invalid is loud", func(t *testing.T) {
		_, err := runSource(t, `return function()
			return { publicvpn.base64.decode("!!!") }
		end`)
		if err == nil || !strings.Contains(err.Error(), "not valid base64") {
			t.Fatalf("expected loud base64 error, got: %v", err)
		}
	})
	t.Run("json decode shape", func(t *testing.T) {
		runMustNodes(t, `return function()
			local d = publicvpn.json.decode('{"subscriptions":[{"id":"a","url":"u"}],"n":2,"ok":true,"x":null}')
			assert(d.subscriptions[1].id == "a", "nested decode")
			assert(d.n == 2 and d.ok == true and d.x == nil)
			return {}
		end`)
	})
	t.Run("json round-trip", func(t *testing.T) {
		runMustNodes(t, `return function()
			local t = { a = { 1, 2, 3 }, b = "s", c = false }
			local enc = publicvpn.json.encode(t)
			local back = publicvpn.json.decode(enc)
			assert(back.a[2] == 2 and back.b == "s" and back.c == false)
			return {}
		end`)
	})
	t.Run("json decode invalid is loud", func(t *testing.T) {
		_, err := runSource(t, `return function()
			return { publicvpn.json.decode("{oops") }
		end`)
		if err == nil || !strings.Contains(err.Error(), "publicvpn.json.decode") {
			t.Fatalf("expected loud json error, got: %v", err)
		}
	})
}

func TestSandbox(t *testing.T) {
	// A plugin touching os/io/package fails LOUD with the documented error —
	// the surface is exactly the host API. Load-check catches breaches in
	// the chunk itself; the discover function runs in the SAME sandbox, so
	// the modules are absent at run time too (covered below).
	for _, snippet := range []string{
		`local _ = os.execute`,
		`local _ = io.open`,
		`local _ = require("nofile")`,
		`dofile("/etc/passwd")`,
		`loadfile("/etc/passwd")`,
	} {
		code := snippet + "\nreturn function() end"
		_, err := Compile("sandbox", "sandbox.lua", []byte(code), io.Discard)
		if err == nil {
			t.Fatalf("sandbox breach not blocked: %s", snippet)
		}
	}
	t.Run("os absent inside the discover function too", func(t *testing.T) {
		_, err := runSource(t, `return function()
			os.execute("true")
			return {}
		end`)
		if err == nil {
			t.Fatal("expected loud os-absent error at run time")
		}
	})
	t.Run("io absent inside the discover function too", func(t *testing.T) {
		_, err := runSource(t, `return function()
			io.open("/etc/passwd")
			return {}
		end`)
		if err == nil {
			t.Fatal("expected loud io-absent error at run time")
		}
	})
	t.Run("print removed, documented log works", func(t *testing.T) {
		var out strings.Builder
		eng := newEngine(engineOptions{Log: &out})
		_, err := eng.Run(context.Background(), &Plugin{ID: "t", Path: "t.lua", Code: []byte(`
			return function()
				publicvpn.log("count", 3, false)
				return {}
			end`)})
		if err != nil {
			t.Fatalf("log failed: %v", err)
		}
		if out.String() != "plugin t: count 3 false\n" {
			t.Fatalf("unexpected log output: %q", out.String())
		}
		_, err = eng.Run(context.Background(), &Plugin{ID: "t", Path: "t.lua", Code: []byte(`
			return function()
				print("nope")
				return {}
			end`)})
		if err == nil {
			t.Fatal("print must be absent from the sandbox")
		}
	})
	t.Run("host functions are the whole publicvpn table", func(t *testing.T) {
		runMustNodes(t, `return function()
			local expect = { node=true, http=true, github_files=true, log=true,
				base64=true, json=true }
			for k, _ in pairs(publicvpn) do
				assert(expect[k], "undocumented host symbol: " .. tostring(k))
			end
			return {}
		end`)
	})
}

func TestLoadCheckBlocksNetwork(t *testing.T) {
	// A plugin doing network work in the chunk itself fails the load check
	// loud — fetches belong inside the returned discover function.
	_, err := Compile("eager", "eager.lua", []byte(`
		local r = publicvpn.http{ url = "http://127.0.0.1:1/" }
		return function() return {} end`), io.Discard)
	if err == nil || !strings.Contains(err.Error(),
		"network is not available while the plugin is being loaded") {
		t.Fatalf("expected loud load-check network refusal, got: %v", err)
	}
}

// TestGopherLuaInlineGmatchWorkaround pins the gopher-lua v1.1.2 VM bug the
// default plugins work around: a for-in iterator fed an INLINE call-chain
// expression (fn() .. "x"):gmatch(...) panics with a nil dereference — even
// for pure-stdlib pcall results. The plugins assign the loop text to a local
// BEFORE iterating; this test fails loud if a gopher-lua upgrade changes the
// contract in either direction (the workaround stays valid either way).
func TestGopherLuaInlineGmatchWorkaround(t *testing.T) {
	eng := newEngine(engineOptions{Log: io.Discard})
	l := eng.newState(context.Background(), "t")
	defer l.Close()
	inline := `local function bl()
		local ok, d = pcall(publicvpn.base64.decode, "dmxlc3M6Ly9h")
		return d
	end
	local n = 0
	for w in (bl() .. "X\n"):gmatch("([^\n]*)\n") do n = n + 1 end
	return n`
	err := l.DoString(inline)
	require.Error(t, err, "gopher-lua v1.1.2 panics on inline call-chain for-in — if this passes, upstream fixed the VM and the plugin comments can be relaxed")

	assigned := `local function bl()
		local ok, d = pcall(publicvpn.base64.decode, "dmxlc3M6Ly9h")
		return d
	end
	local n = 0
	local text = bl() .. "X\n"
	for w in text:gmatch("([^\n]*)\n") do n = n + 1 end
	return n`
	require.NoError(t, l.DoString(assigned), "assign-then-iterate must work")
}

func TestCompileSyntaxErrorNamesPlugin(t *testing.T) {
	_, err := Compile("broken", "broken.lua", []byte(`return function( end`), io.Discard)
	var le *LoadError
	if !errors.As(err, &le) || le.Plugin != "broken" || !strings.Contains(err.Error(), "syntax") {
		t.Fatalf("expected plugin-attributed syntax error, got: %v", err)
	}
}
