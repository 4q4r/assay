// Package plugins implements the W10 source-ingest plugin layer: every .lua
// file in the plugins dir is a sandboxed gopher-lua (pure-Go Lua 5.1, no
// cgo) program that discovers raw proxy links and hands them to the pipeline
// as publicvpn.node records. Go keeps owning URI normalization, parsing, and
// dedupe (internal/model, internal/parse); a plugin only fetches and
// iterates.
//
// Plugin contract (one canonical shape):
//
//   - The chunk itself must stay side-effect-free; it returns the plugin's
//     discover function.
//   - The discover function runs the actual discovery (network fetches live
//     here) and returns a Lua array of publicvpn.node records (possibly
//     empty). Returning anything else fails the plugin loud.
//   - The sandbox exposes ONLY the documented host API (see host.go): the
//     Lua state opens no os/io/package modules and the base library is
//     stripped of dofile/loadfile/print/require/module/newproxy.
package plugins

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

// Plugin is one compiled plugin: an immutable snapshot of its code. Registry
// swaps replace the *Plugin pointer, so a running wave always sees a stable
// snapshot (race-free by construction; pinned by -race tests).
type Plugin struct {
	ID   string // file stem — the pipeline source id (cap grouping, node.Source)
	Path string // absolute file path (traceability in the fetch manifest)
	Code []byte // immutable source snapshot
}

// IDFromPath maps a plugin file path to its id: the file stem. Only top-level
// *.lua files are plugins (the watchdog is non-recursive; nested dirs are
// ignored by design).
func IDFromPath(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// LoadError marks plugin-level failures with the plugin id and, where known,
// the offending result index — every plugin error is loud and attributed.
type LoadError struct {
	Plugin string
	Index  int // 0 = not tied to one result element
	Err    error
}

func (e *LoadError) Error() string {
	if e.Index > 0 {
		return fmt.Sprintf("plugin %q: result[%d]: %v", e.Plugin, e.Index, e.Err)
	}
	return fmt.Sprintf("plugin %q: %v", e.Plugin, e.Err)
}

func (e *LoadError) Unwrap() error { return e.Err }

func pluginErrf(id string, format string, a ...any) error {
	return &LoadError{Plugin: id, Err: fmt.Errorf(format, a...)}
}

func pluginIdxErrf(id string, idx int, format string, a ...any) error {
	return &LoadError{Plugin: id, Index: idx, Err: fmt.Errorf(format, a...)}
}

// Compile validates one plugin snapshot the same way a run will execute it:
// the chunk runs against a full sandbox + host whose NETWORK surface is
// loud-disabled (side-effect-free load check), and the returned value must
// be the discover function. This is what the watchdog runs before swapping a
// reload into the registry (last-good semantics live in the watchdog).
func Compile(id, path string, code []byte, log io.Writer) (*Plugin, error) {
	eng := newEngine(engineOptions{Log: log, noNetwork: true})
	l := eng.newState(context.Background(), id)
	defer l.Close()
	chunk, err := l.Load(bytes.NewReader(code), "@"+path)
	if err != nil {
		return nil, pluginErrf(id, "syntax: %v", err)
	}
	if err := l.CallByParam(lua.P{Fn: chunk, NRet: 1, Protect: true}); err != nil {
		return nil, pluginErrf(id, "load: %v", err)
	}
	ret := l.Get(-1)
	l.Pop(1)
	if _, ok := ret.(*lua.LFunction); !ok {
		return nil, pluginErrf(id,
			"the file must return its discover function (side-effect-free chunk), got %s",
			ret.Type().String())
	}
	return &Plugin{ID: id, Path: path, Code: code}, nil
}
