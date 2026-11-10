package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"assay/internal/config"
	"assay/internal/fetch"

	lua "github.com/yuin/gopher-lua"
)

// Default host-API limits for assay.http (documented in README; the
// pipeline's own fetch limits are separate knobs).
const (
	DefaultHTTPTimeout      = 30 * time.Second
	DefaultHTTPMaxRedirects = 10
	DefaultHTTPMaxBody      = 8 << 20 // 8 MiB
)

// nodeMTKey is the registry slot of the per-state node-class metatable. The
// marker exists for plugin authors (getmetatable(node) == "assay.node");
// Go-side validation reads the fields uniformly (the collector accepts the
// marker table OR a plain table with valid fields — one canonical shape).
const nodeMTKey = "__assay_node_mt"

// engineOptions configures an Engine. Production engines carry live network
// clients; the load check builds one with noNetwork=true.
type engineOptions struct {
	// GitHub drives the assay.github_files helper (D9 contents API +
	// manifest discovery + raw downloads, mirrors and token supported).
	GitHub *fetch.Client
	// HTTPTransport is the shared generic transport for assay.http. It
	// MUST carry Proxy=nil (landmine L5 — plugin traffic never rides the
	// owner's VPN); NewEngine builds it that way and a white-box test pins it.
	HTTPTransport *http.Transport
	// Timeout / MaxRedirects / MaxBodyBytes are the assay.http defaults.
	Timeout      time.Duration
	MaxRedirects int
	MaxBodyBytes int64
	UserAgent    string
	Log          io.Writer // assay.log sink; nil = io.Discard
	noNetwork    bool      // load-check mode: network host fns raise loud
}

// Engine is the per-process host runtime: it owns the host clients and
// executes plugins. One Engine is shared by all plugins in a process; each
// Run gets a fresh sandboxed Lua state bound to ctx (no cross-plugin state, no leaks).
type Engine struct {
	opt engineOptions
}

// NewEngine builds a production engine. Both clients are Proxy=nil by
// construction (L5): plugin fetches go direct, exactly like every pipeline
// client (the in-process equivalent of env -u http_proxy).
func NewEngine(cfg fetch.ClientConfig, log io.Writer) *Engine {
	if cfg.UserAgent == "" {
		cfg.UserAgent = config.DefaultUserAgent
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newEngine(engineOptions{
		GitHub:        fetch.NewClient(cfg),
		HTTPTransport: transport,
		Timeout:       DefaultHTTPTimeout,
		MaxRedirects:  DefaultHTTPMaxRedirects,
		MaxBodyBytes:  DefaultHTTPMaxBody,
		UserAgent:     cfg.UserAgent,
		Log:           log,
	})
}

func newEngine(opt engineOptions) *Engine {
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultHTTPTimeout
	}
	if opt.MaxRedirects <= 0 {
		opt.MaxRedirects = DefaultHTTPMaxRedirects
	}
	if opt.MaxBodyBytes <= 0 {
		opt.MaxBodyBytes = DefaultHTTPMaxBody
	}
	if opt.Log == nil {
		opt.Log = io.Discard
	}
	if opt.UserAgent == "" {
		opt.UserAgent = config.DefaultUserAgent
	}
	if opt.HTTPTransport == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		opt.HTTPTransport = transport
	}
	return &Engine{opt: opt}
}

// Node is one record a plugin hands to the pipeline. Raw is REQUIRED — Go
// owns URI normalization/parse/dedupe; scheme/host/port are optional
// pre-parse hints the pipeline may consume (validated structurally and
// reported; the parsed URI always wins). Source, when set, regroups the node
// under another source id ([filter].source_cap applies per source); empty =
// the plugin's own id. Remark names the node when the raw link carries no
// fragment of its own.
type Node struct {
	Raw    string
	Source string
	Remark string
	Scheme string
	Host   string
	Port   int
}

// strippedGlobals are the global names removed from every sandbox. os/io/
// package/debug are never opened at all (SkipOpenLibs); the base-library
// entries listed here ARE opened by OpenBase and must be removed explicitly
// (verified against gopher-lua v1.1.2 baselib.go: dofile/loadfile read the
// filesystem, print writes to process stdout, require/module drive the
// package loader, newproxy is an undocumented userdata constructor).
var strippedGlobals = []string{
	"dofile", "loadfile", "print", "require", "module", "newproxy", "_printregs",
}

// newState builds one sandboxed Lua state with the full host API registered.
// Opened libraries: base, string, table, math — all pure computation. Never
// opened: os, io, package, debug, coroutine.
//
//nolint:contextcheck // fallback to background context if caller passes nil
func (e *Engine) newState(ctx context.Context, pluginID string) *lua.LState {
	if ctx == nil {
		ctx = context.Background()
	}
	l := lua.NewState(lua.Options{SkipOpenLibs: true})
	l.SetContext(ctx)
	_ = lua.OpenBase(l)
	_ = lua.OpenString(l)
	_ = lua.OpenTable(l)
	_ = lua.OpenMath(l)
	for _, name := range strippedGlobals {
		l.SetField(l.Get(lua.GlobalsIndex), name, lua.LNil)
	}
	mt := l.NewTable()
	mt.RawSetString("__metatable", lua.LString("assay.node"))
	l.SetField(l.Get(lua.RegistryIndex), nodeMTKey, mt)

	l.RegisterModule("assay", map[string]lua.LGFunction{
		"node": func(ls *lua.LState) int { return e.hostNode(ls, mt) },
		"http": func(ls *lua.LState) int { return e.hostHTTP(ctx, ls, pluginID) },
		"github_files": func(ls *lua.LState) int {
			return e.hostGitHubFiles(ctx, ls, pluginID)
		},
		"log": func(ls *lua.LState) int { return e.hostLog(ls, pluginID) },
	})
	pub := l.GetField(l.Get(lua.GlobalsIndex), "assay").(*lua.LTable)
	base64Tbl := l.NewTable()
	base64Tbl.RawSetString("encode", l.NewFunction(e.hostBase64Encode))
	base64Tbl.RawSetString("decode", l.NewFunction(e.hostBase64Decode))
	pub.RawSetString("base64", base64Tbl)
	jsonTbl := l.NewTable()
	jsonTbl.RawSetString("decode", l.NewFunction(e.hostJSONDecode))
	jsonTbl.RawSetString("encode", l.NewFunction(e.hostJSONEncode))
	pub.RawSetString("json", jsonTbl)
	return l
}

// Run executes one plugin snapshot: fresh sandbox, chunk execution (must be
// side-effect-free and return the discover function), discover call, node
// collection. Every failure is a loud, plugin-attributed error.
//
// Scoped panic breaker (F11, the recorded W10 gopher-lua landmine): the Lua
// runtime can PANIC on plugin-controlled input, and a panic escaping this
// seam would kill the whole daemon and re-crash-loop via the watchdog with
// no breaker path. ONLY this execution seam converts a panic into a loud,
// plugin-attributed error — never a blanket recover elsewhere: the fetch
// boundary (runAllPlugins) then feeds the error into the registry's
// RecordFailure breaker and the wave continues.
//
//nolint:contextcheck,nonamedreturns // background-context fallback; the deferred recover must write the named results
func (e *Engine) Run(ctx context.Context, p *Plugin) (nodes []Node, err error) {
	defer func() {
		if r := recover(); r != nil {
			nodes, err = nil, pluginErrf(p.ID, "lua runtime panic: %v", r)
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	l := e.newState(ctx, p.ID)
	defer l.Close()
	chunk, err := l.Load(bytes.NewReader(p.Code), "@"+p.Path)
	if err != nil {
		return nil, pluginErrf(p.ID, "syntax: %v", err)
	}
	if err := l.CallByParam(lua.P{Fn: chunk, NRet: 1, Protect: true}); err != nil {
		return nil, pluginErrf(p.ID, "load: %v", err)
	}
	discover := l.Get(-1)
	l.Pop(1)
	fn, ok := discover.(*lua.LFunction)
	if !ok {
		return nil, pluginErrf(p.ID,
			"the file must return its discover function (side-effect-free chunk), got %s",
			discover.Type().String())
	}
	if err := l.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}); err != nil {
		return nil, pluginErrf(p.ID, "%v", err)
	}
	ret := l.Get(-1)
	l.Pop(1)
	tbl, ok := ret.(*lua.LTable)
	if !ok {
		return nil, pluginErrf(p.ID, "discover returned %s, expected a table of assay.node",
			ret.Type().String())
	}
	return collectNodes(p.ID, tbl)
}

func collectNodes(id string, tbl *lua.LTable) ([]Node, error) {
	nodes := make([]Node, 0, tbl.Len())
	for i := 1; i <= tbl.MaxN(); i++ {
		v := tbl.RawGetInt(i)
		if v == lua.LNil {
			return nil, pluginIdxErrf(id, i, "nil element (the result array must be dense)")
		}
		n, err := nodeFromValue(id, i, v)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// nodeFromValue accepts the canonical node object (constructor marker) or a
// plain table carrying at least a non-empty raw string. Anything else is a
// loud error naming the plugin and the offending index. Structural hint
// validation happens here: port must be in range, string hints must be
// strings (non-strings read as empty and are dropped).
func nodeFromValue(id string, idx int, v lua.LValue) (Node, error) {
	tbl, ok := v.(*lua.LTable)
	if !ok {
		return Node{}, pluginIdxErrf(id, idx, "not an assay.node (got %s)", v.Type().String())
	}
	str := func(field string) string {
		if s, ok := tbl.RawGetString(field).(lua.LString); ok {
			return string(s)
		}
		return ""
	}
	n := Node{
		Raw:    strings.TrimSpace(str("raw")),
		Source: strings.TrimSpace(str("source")),
		Remark: str("remark"),
		Scheme: strings.ToLower(strings.TrimSpace(str("scheme"))),
		Host:   strings.TrimSpace(str("host")),
	}
	if num, ok := tbl.RawGetString("port").(lua.LNumber); ok {
		// Loud param-named rejection instead of a silent int() truncation:
		// a port hint of 443.7 meant something else than 443.
		if num != lua.LNumber(math.Trunc(float64(num))) {
			return Node{}, pluginIdxErrf(id, idx, "port hint %v is not an integer", num)
		}
		n.Port = int(num)
	}
	if n.Raw == "" {
		return Node{}, pluginIdxErrf(id, idx, "node.raw is required (non-empty string)")
	}
	if n.Port != 0 && (n.Port < 1 || n.Port > 65535) {
		return Node{}, pluginIdxErrf(id, idx, "port hint %d out of range 1..65535", n.Port)
	}
	return n, nil
}

// hostNode is the assay.node constructor: validates the record at
// construction time (loud, before it ever reaches the pipeline) and returns
// the table marked with the node-class metatable.
func (e *Engine) hostNode(l *lua.LState, mt *lua.LTable) int {
	v := l.Get(1)
	tbl, ok := v.(*lua.LTable)
	if !ok {
		l.RaiseError("assay.node: expected a table argument, got %s", v.Type().String())
		return 0
	}
	raw, _ := tbl.RawGetString("raw").(lua.LString)
	if strings.TrimSpace(string(raw)) == "" {
		l.RaiseError("assay.node: raw (non-empty string) is required")
		return 0
	}
	tbl.Metatable = mt
	l.Push(tbl)
	return 1
}

func (e *Engine) hostHTTP(ctx context.Context, l *lua.LState, _ string) int {
	if e.opt.noNetwork {
		l.RaiseError("assay.http: network is not available while the plugin is being " +
			"loaded — perform fetches inside the returned discover function")
		return 0
	}
	tbl, ok := l.Get(1).(*lua.LTable)
	if !ok {
		l.RaiseError("assay.http: expected a table argument, got %s", l.Get(1).Type().String())
		return 0
	}
	url, _ := tbl.RawGetString("url").(lua.LString)
	if url == "" {
		l.RaiseError("assay.http: url (non-empty string) is required")
		return 0
	}
	method, _ := tbl.RawGetString("method").(lua.LString)
	if method == "" {
		method = http.MethodGet
	}
	body, _ := tbl.RawGetString("body").(lua.LString)
	timeout := durationField(tbl, "timeout", e.opt.Timeout)
	maxRedirects := redirectField(tbl, "max_redirects", e.opt.MaxRedirects)
	maxBody := int64Field(tbl, "max_body_bytes", e.opt.MaxBodyBytes)

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(string(method)),
		string(url), strings.NewReader(string(body)))
	if err != nil {
		l.RaiseError("assay.http: %v", err)
		return 0
	}
	req.Header.Set("User-Agent", e.opt.UserAgent)
	if hdrs, ok := tbl.RawGetString("headers").(*lua.LTable); ok {
		hdrs.ForEach(func(k, v lua.LValue) {
			if ks, ok := k.(lua.LString); ok {
				req.Header.Set(string(ks), v.String())
			}
		})
	}
	client := &http.Client{
		Transport: e.opt.HTTPTransport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := client.Do(req.WithContext(callCtx))
	if err != nil {
		l.RaiseError("assay.http: %v", err)
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		l.RaiseError("assay.http: read body: %v", err)
		return 0
	}
	if int64(len(payload)) > maxBody {
		l.RaiseError("assay.http: response body exceeds max_body_bytes (%d)", maxBody)
		return 0
	}
	headers := l.NewTable()
	for k, vs := range resp.Header {
		headers.RawSetString(k, lua.LString(strings.Join(vs, ", ")))
	}
	out := l.NewTable()
	out.RawSetString("status", lua.LNumber(resp.StatusCode))
	out.RawSetString("headers", headers)
	out.RawSetString("body", lua.LString(payload))
	l.Push(out)
	return 1
}

func (e *Engine) hostGitHubFiles(ctx context.Context, l *lua.LState, pluginID string) int {
	if e.opt.noNetwork {
		l.RaiseError("assay.github_files: network is not available while the plugin is " +
			"being loaded — perform fetches inside the returned discover function")
		return 0
	}
	if e.opt.GitHub == nil {
		l.RaiseError("assay.github_files: no GitHub client configured")
		return 0
	}
	tbl, ok := l.Get(1).(*lua.LTable)
	if !ok {
		l.RaiseError("assay.github_files: expected a table argument, got %s",
			l.Get(1).Type().String())
		return 0
	}
	repo, _ := tbl.RawGetString("repo").(lua.LString)
	if repo == "" {
		l.RaiseError("assay.github_files: repo (non-empty string) is required")
		return 0
	}
	manifest, _ := tbl.RawGetString("manifest").(lua.LString)
	src := config.Source{Repo: string(repo), Manifest: string(manifest)}
	if src.Manifest != "" {
		src.Discovery = "manifest"
	} else {
		src.Discovery = "github-contents"
	}
	if inc, ok := tbl.RawGetString("include").(*lua.LTable); ok {
		inc.ForEach(func(_, v lua.LValue) {
			src.Include = append(src.Include, v.String())
		})
	}
	files, err := e.opt.GitHub.Source(ctx, pluginID, src)
	if err != nil {
		l.RaiseError("assay.github_files: %v", err)
		return 0
	}
	out := l.NewTable()
	for _, f := range files {
		row := l.NewTable()
		row.RawSetString("path", lua.LString(f.Path))
		row.RawSetString("content", lua.LString(f.Body))
		out.Append(row)
	}
	l.Push(out)
	return 1
}

func (e *Engine) hostLog(l *lua.LState, pluginID string) int {
	parts := make([]string, 0, l.GetTop())
	for i := 1; i <= l.GetTop(); i++ {
		parts = append(parts, l.ToStringMeta(l.Get(i)).String())
	}
	_, _ = fmt.Fprintf(e.opt.Log, "plugin %s: %s\n", pluginID, strings.Join(parts, " "))
	return 0
}

func (e *Engine) hostBase64Encode(l *lua.LState) int {
	s := l.CheckString(1)
	l.Push(lua.LString(base64.StdEncoding.EncodeToString([]byte(s))))
	return 1
}

// hostBase64Decode mirrors the pipeline's flexible decode: standard and
// URL-safe alphabets, padding optional (the same spellings parse.go accepts
// for share-link payloads).
func (e *Engine) hostBase64Decode(l *lua.LState) int {
	s := l.CheckString(1)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(s); err == nil {
			l.Push(lua.LString(decoded))
			return 1
		}
	}
	l.RaiseError("assay.base64.decode: input is not valid base64 (std/url, padding optional)")
	return 0
}

func (e *Engine) hostJSONDecode(l *lua.LState) int {
	s := l.CheckString(1)
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		l.RaiseError("assay.json.decode: %v", err)
		return 0
	}
	l.Push(toLuaValue(l, v))
	return 1
}

func (e *Engine) hostJSONEncode(l *lua.LState) int {
	v, err := toJSONValue(l.Get(1))
	if err != nil {
		l.RaiseError("assay.json.encode: %v", err)
		return 0
	}
	b, err := json.Marshal(v)
	if err != nil {
		l.RaiseError("assay.json.encode: %v", err)
		return 0
	}
	l.Push(lua.LString(b))
	return 1
}

//nolint:ireturn // LValue is the gopher-lua value interface — returning it IS the API.
func toLuaValue(l *lua.LState, v any) lua.LValue {
	switch t := v.(type) {
	case nil:
		return lua.LNil
	case bool:
		return lua.LBool(t)
	case float64:
		return lua.LNumber(t)
	case string:
		return lua.LString(t)
	case []any:
		out := l.NewTable()
		for i, item := range t {
			out.RawSetInt(i+1, toLuaValue(l, item))
		}
		return out
	case map[string]any:
		out := l.NewTable()
		for k, item := range t {
			out.RawSetString(k, toLuaValue(l, item))
		}
		return out
	default:
		return lua.LString(fmt.Sprintf("%v", t))
	}
}

func toJSONValue(v lua.LValue) (any, error) {
	switch t := v.(type) {
	case *lua.LNilType:
		return nil, nil
	case lua.LBool:
		return bool(t), nil
	case lua.LNumber:
		return float64(t), nil
	case lua.LString:
		return string(t), nil
	case *lua.LTable:
		if t.MaxN() > 0 && t.Len() == t.MaxN() {
			out := make([]any, 0, t.Len())
			for i := 1; i <= t.MaxN(); i++ {
				item, err := toJSONValue(t.RawGetInt(i))
				if err != nil {
					return nil, err
				}
				out = append(out, item)
			}
			return out, nil
		}
		out := make(map[string]any)
		var convErr error
		t.ForEach(func(k, val lua.LValue) {
			if convErr != nil {
				return
			}
			key, ok := k.(lua.LString)
			if !ok {
				convErr = fmt.Errorf("object keys must be strings, got %s", k.Type().String())
				return
			}
			item, err := toJSONValue(val)
			if err != nil {
				convErr = err
				return
			}
			out[string(key)] = item
		})
		if convErr != nil {
			return nil, convErr
		}
		return out, nil
	default:
		return nil, fmt.Errorf("cannot encode %s", v.Type().String())
	}
}

func durationField(tbl *lua.LTable, key string, def time.Duration) time.Duration {
	if n, ok := tbl.RawGetString(key).(lua.LNumber); ok && n > 0 {
		return time.Duration(float64(n) * float64(time.Second))
	}
	return def
}

// redirectField reads max_redirects where 0 is a MEANINGFUL value (follow
// none): a present number >= 0 wins, anything else falls back to the default.
func redirectField(tbl *lua.LTable, key string, def int) int {
	if n, ok := tbl.RawGetString(key).(lua.LNumber); ok && n >= 0 {
		return int(n)
	}
	return def
}

func int64Field(tbl *lua.LTable, key string, def int64) int64 {
	if n, ok := tbl.RawGetString(key).(lua.LNumber); ok && n > 0 {
		return int64(n)
	}
	return def
}
