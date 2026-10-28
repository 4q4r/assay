package plugins

import (
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Registry is the in-memory plugin set. It is safe for concurrent use: the
// watchdog swaps plugins under the write lock while waves read snapshots
// under the read lock. A wave takes ONE snapshot at its start and runs
// against it — mid-wave reloads never affect a running wave (pinned by
// -race tests).
type Registry struct {
	mu     sync.RWMutex
	byID   map[string]*Plugin
	broken map[string]error // last loud failure per plugin id (status/debug)
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: map[string]*Plugin{}, broken: map[string]error{}}
}

// Snapshot returns the current plugins sorted by id (deterministic wave
// order — identical inputs must always run identically).
func (r *Registry) Snapshot() []*Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Plugin, 0, len(r.byID))
	for _, p := range r.byID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Set upserts a compiled plugin; reports whether it replaced a previous
// version.
func (r *Registry) Set(p *Plugin) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, existed := r.byID[p.ID]
	r.byID[p.ID] = p
	delete(r.broken, p.ID)
	return existed
}

// Remove disables a plugin (watchdog removal event = source off).
func (r *Registry) Remove(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, existed := r.byID[id]
	delete(r.byID, id)
	delete(r.broken, id)
	return existed
}

// Len reports the number of live plugins.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// noteBroken records a loud reload failure (the previous version stays
// active — last-good semantics).
func (r *Registry) noteBroken(id string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.broken[id] = err
}

// Broken lists the currently broken plugin ids with their errors (watchdog
// status surface).
func (r *Registry) Broken() map[string]error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]error, len(r.broken))
	maps.Copy(out, r.broken)
	return out
}

// Get returns one plugin by id.
func (r *Registry) Get(id string) (*Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byID[id]
	return p, ok
}

// EnsureDefaults materializes the embedded default plugins on FIRST RUN
// only: a missing plugins dir is created and every default written into it.
// An existing dir is never touched — owner edits and removals persist (a
// removed default stays removed; deleting the whole dir restores all
// defaults on the next run). Files are written 0600 (they are owner-editable
// pipeline configuration).
func EnsureDefaults(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat plugins dir %s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create plugins dir %s: %w", dir, err)
	}
	for name, code := range defaultSources() {
		path := filepath.Join(dir, name)
		// 0600: plugin files are owner-editable pipeline state, same mode
		// class as every other pipeline artifact (review finding 11).
		if err := os.WriteFile(path, code, 0o600); err != nil {
			return fmt.Errorf("materialize default plugin %s: %w", name, err)
		}
	}
	return nil
}

// defaultSources reads the embedded defaults into a name → code map.
func defaultSources() map[string][]byte {
	out := map[string][]byte{}
	entries, err := Defaults.ReadDir("defaults")
	if err != nil {
		return out
	}
	for _, entry := range entries {
		code, err := Defaults.ReadFile("defaults/" + entry.Name())
		if err != nil {
			continue
		}
		out[entry.Name()] = code
	}
	return out
}

// LoadDir compiles every top-level *.lua file in dir into a fresh registry.
// A broken plugin is LOUD (logged with its Lua error) but not fatal — one
// bad provider must never kill the wave; only an unreadable dir fails. An
// empty registry is the caller's decision point (the fetch stage fails loud
// on zero plugins).
func LoadDir(dir string, log io.Writer) (*Registry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read plugins dir %s: %w", dir, err)
	}
	reg := NewRegistry()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".lua") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		code, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read plugin %s: %w", path, err)
		}
		p, err := Compile(IDFromPath(path), path, code, log)
		if err != nil {
			note := fmt.Sprintf("plugin %s BROKEN — source disabled until the file is fixed: %v",
				entry.Name(), err)
			_, _ = fmt.Fprintln(log, "WARNING: "+note)
			reg.noteBroken(IDFromPath(path), err)
			continue
		}
		reg.Set(p)
	}
	return reg, nil
}
