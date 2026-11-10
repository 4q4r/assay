package plugins

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestEmbeddedDefaultsCompile(t *testing.T) {
	for name, code := range defaultSources() {
		t.Run(name, func(t *testing.T) {
			id := IDFromPath(name)
			p, err := Compile(id, name, code, io.Discard)
			if err != nil {
				t.Fatalf("embedded default %s does not compile: %v", name, err)
			}
			if p.ID != id {
				t.Fatalf("id mismatch: %q vs %q", p.ID, id)
			}
		})
	}
	// Fresh-clone contract: the embed glob is compile-load-bearing (a
	// zero-match glob is a build error) and the tracked sample template is
	// the ONE default a fresh clone receives. The set may be larger on a
	// tree that carries additional untracked plugins in the same dir (embed
	// reads disk) — the contract pins only what ships: non-empty + sample.
	if len(defaultSources()) == 0 {
		t.Fatal("embedded defaults are empty — the go:embed glob is compile-load-bearing")
	}
	if _, ok := defaultSources()["sample.lua"]; !ok {
		t.Fatal("tracked sample.lua missing from the embedded defaults — " +
			"fresh clones would get no default source")
	}
}

func TestEnsureDefaults(t *testing.T) {
	t.Run("first run materializes everything embedded", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "plugins")
		if err := EnsureDefaults(dir); err != nil {
			t.Fatalf("EnsureDefaults: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != len(defaultSources()) {
			t.Fatalf("expected %d materialized defaults (one per embedded source), got %d",
				len(defaultSources()), len(entries))
		}
		if _, err := os.Stat(filepath.Join(dir, "sample.lua")); err != nil {
			t.Fatalf("tracked sample.lua did not materialize: %v", err)
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("default plugin %s written %v, want 0600", entry.Name(), info.Mode().Perm())
			}
		}
	})
	t.Run("existing dir is never touched", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "plugins")
		if err := EnsureDefaults(dir); err != nil {
			t.Fatal(err)
		}
		// sample.lua is the one default guaranteed to be embedded on every
		// tree (tracked in-repo) — owner-edit semantics are pinned on it.
		ownerEdited := filepath.Join(dir, "sample.lua")
		if err := os.WriteFile(ownerEdited, []byte("-- owner edit\nreturn function() end"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := EnsureDefaults(dir); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(ownerEdited)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "-- owner edit\nreturn function() end" {
			t.Fatalf("owner edit was overwritten: %q", b)
		}
		if err := os.Remove(ownerEdited); err != nil {
			t.Fatal(err)
		}
		if err := EnsureDefaults(dir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(ownerEdited); !os.IsNotExist(err) {
			t.Fatal("removed default was re-materialized — removal must persist")
		}
	})
}

func TestLoadDir(t *testing.T) {
	t.Run("broken plugin is loud, healthy plugins continue", func(t *testing.T) {
		dir := t.TempDir()
		write := func(name, code string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, name), []byte(code), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write("good.lua", "return function() end")
		write("broken.lua", "return function( end")
		write("notes.txt", "not a plugin")
		var log bytes.Buffer
		reg, err := LoadDir(dir, &log)
		if err != nil {
			t.Fatalf("LoadDir: %v", err)
		}
		if reg.Len() != 1 {
			t.Fatalf("expected 1 healthy plugin, got %d", reg.Len())
		}
		if _, ok := reg.Get("good"); !ok {
			t.Fatal("healthy plugin missing from registry")
		}
		broken := reg.Broken()
		if _, ok := broken["broken"]; !ok {
			t.Fatalf("broken plugin not recorded: %v", broken)
		}
		if !strings.Contains(log.String(), "broken.lua BROKEN") {
			t.Fatalf("expected loud broken-plugin warning, log: %q", log.String())
		}
	})
	t.Run("unreadable dir fails loud", func(t *testing.T) {
		_, err := LoadDir(filepath.Join(t.TempDir(), "absent"), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "read plugins dir") {
			t.Fatalf("expected loud dir error, got: %v", err)
		}
	})
	t.Run("nested dirs and non-lua ignored", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "sub", "nested.lua"), []byte("return function() end"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "top.lua"), []byte("return function() end"), 0o600); err != nil {
			t.Fatal(err)
		}
		reg, err := LoadDir(dir, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if reg.Len() != 1 {
			t.Fatalf("nested plugins must be ignored, got %d", reg.Len())
		}
	})
	t.Run("snapshot sorted by id", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"c.lua", "a.lua", "b.lua"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("return function() end"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		reg, err := LoadDir(dir, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		snap := reg.Snapshot()
		if len(snap) != 3 || snap[0].ID != "a" || snap[1].ID != "b" || snap[2].ID != "c" {
			ids := make([]string, 0, len(snap))
			for _, p := range snap {
				ids = append(ids, p.ID)
			}
			t.Fatalf("snapshot not sorted: %v", ids)
		}
	})
}

// TestRegistrySnapshotRace is -race evidence for the hot-reload contract:
// watchdog-style Set/Remove concurrent with wave-style Snapshot/Get readers.
// The wave's snapshot holds stable *Plugin pointers — swaps replace the map
// entry, never mutate a live snapshot.
func TestRegistrySnapshotRace(t *testing.T) {
	reg := NewRegistry()
	plugin := func(id string) *Plugin {
		return &Plugin{ID: id, Path: id + ".lua", Code: []byte("return function() end")}
	}
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			for i := range 200 {
				reg.Set(plugin("p" + string(rune('a'+w))))
				if i%3 == 0 {
					reg.Remove("p" + string(rune('a'+w)))
				}
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for range 200 {
				snap := reg.Snapshot()
				for _, p := range snap {
					if p.ID == "" || len(p.Code) == 0 {
						t.Error("snapshot exposed a partial plugin")
					}
				}
				_, _ = reg.Get("pa")
				_ = reg.Broken()
				_ = reg.Len()
			}
		})
	}
	wg.Wait()
}

func TestRegistryRemoveReportsPresence(t *testing.T) {
	reg := NewRegistry()
	if reg.Set(&Plugin{ID: "x", Path: "x.lua", Code: []byte("return function() end")}) {
		t.Fatal("first Set must report replaced=false")
	}
	if !reg.Set(&Plugin{ID: "x", Path: "x.lua", Code: []byte("return function() end")}) {
		t.Fatal("second Set must report replaced=true")
	}
	if !reg.Remove("x") {
		t.Fatal("Remove of a present plugin must report true")
	}
	if reg.Remove("x") {
		t.Fatal("Remove of an absent plugin must report false")
	}
}
