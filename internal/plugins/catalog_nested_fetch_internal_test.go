package plugins

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// catalogDocFixture mirrors a JSON catalog document: subscriptions carry
// id + url; one subscription is deliberately broken to pin the
// per-subscription isolation the documented catalog pattern promises.
const catalogDocFixture = `{
  "updated": "10.11.2026",
  "subscriptions": [
    {"id": "good-sub", "category": "white", "url": "%s/subs/good.txt"},
    {"id": "bad-sub", "category": "black", "url": "%s/subs/broken"},
    {"id": "plain-sub", "category": "white", "url": "%s/subs/plain.txt"}
  ],
  "proxies": [
    {"addr": "x", "url": "https://t.me/proxy?server=1.2.3.4&port=443&secret=ee"}
  ]
}`

// catalogFetchFixtureLua is the hermetic nested-fetch fixture: json.decode
// of a catalog document, nested per-subscription fetches, whole-body
// base64 or plain URI bodies, per-sub failure isolation, and remark
// tagging by subscription id (the catalog pattern documented in
// sample.lua).
func catalogFetchFixtureLua(srv string) string {
	//nolint:dupword // Lua `end` keywords close nested blocks — consecutive identical words inside the raw string are Lua syntax
	return strings.ReplaceAll(`local CATALOG_URL = "{{SRV}}/data.json"

local function collect()
  local ok, resp = pcall(assay.http, { url = CATALOG_URL, timeout = 30 })
  if not ok then
    error("catalog fetch failed: " .. tostring(resp))
  end
  if resp.status ~= 200 then
    error("catalog fetch returned HTTP " .. tostring(resp.status))
  end
  local catalog = assay.json.decode(resp.body)
  local nodes = {}
  for _, sub in ipairs(catalog.subscriptions) do
    local rok, subresp = pcall(assay.http, { url = sub.url, timeout = 10 })
    if not rok then
      -- Per-entry isolation: one dead subscription is logged loud, the
      -- rest of the catalog still lands.
      assay.log("skip subscription ", sub.id, ": ", tostring(subresp))
    elseif subresp.status ~= 200 then
      assay.log("skip subscription ", sub.id, ": HTTP ", tostring(subresp.status))
    else
      local body = subresp.body
      local trimmed = body:gsub("^%s+", ""):gsub("%s+$", "")
      if not trimmed:find("://", 1, true) then
        -- Whitespace-flattened base64 retry: line-wrapped subscriptions
        -- must not be misclassified as junk for interior newlines.
        local dok, decoded = pcall(assay.base64.decode, trimmed:gsub("%s+", ""))
        if dok and decoded:find("://", 1, true) then
          trimmed = decoded
        end
      end
      -- Empty lines, comments (#) and // notes drop; everything else is
      -- kept as a raw candidate (Go's parse stage owns rejection).
      for line in (trimmed .. "\n"):gmatch("([^\r\n]*)\n") do
        line = line:gsub("^%s+", ""):gsub("%s+$", "")
        if line ~= "" and not line:find("^#") and not line:find("^//") then
          nodes[#nodes + 1] = assay.node{ raw = line, remark = sub.id }
        end
      end
    end
  end
  return nodes
end

return collect
`, "{{SRV}}", srv)
}

// TestCatalogNestedFetchFixture pins the JSON-catalog contract through the
// documented sample.lua pattern: nested fetches, per-subscription failure
// isolation (the dead subscription is logged, the others still land), and
// remark tagging by subscription id.
func TestCatalogNestedFetchFixture(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/data.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, catalogDocFixture, srv.URL, srv.URL, srv.URL)
	})
	mux.HandleFunc("/subs/good.txt", func(w http.ResponseWriter, _ *http.Request) {
		// Base64 payload — exercises the plugin's decode path too.
		_, _ = w.Write([]byte("dmxlc3M6Ly9hQGdvb2QuaG9zdDo0NDM/cz0xI2dvb2QxCmRsZXNzOi8vYkBnb29kLmhvc3Q6NDQzI2dvb2Qy\n"))
	})
	mux.HandleFunc("/subs/broken", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "dead upstream", http.StatusInternalServerError)
	})
	mux.HandleFunc("/subs/plain.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://c@plain.host:8443?s=1#p1\nnot-a-link-line\n\n# comment\n"))
	})

	code := catalogFetchFixtureLua(srv.URL)
	eng := newEngine(engineOptions{Log: io.Discard})
	p := &Plugin{ID: "catalog-fixture", Path: "catalog-fixture.lua", Code: []byte(code)}
	nodes, err := eng.Run(context.Background(), p)
	require.NoError(t, err)

	// good.txt (base64): 2 links; plain.txt: both lines kept as raw
	// candidates (Go's parse stage owns rejection); broken: isolated.
	require.Len(t, nodes, 4, "2 base64-decoded + 1 plain + 1 junk candidate")
	good := 0
	plain := 0
	for _, n := range nodes {
		switch {
		case strings.Contains(n.Raw, "good.host"):
			good++
			assert.Equal(t, "good-sub", n.Remark, "nodes carry their subscription id as remark")
		case strings.Contains(n.Raw, "plain.host"):
			plain++
			assert.Equal(t, "plain-sub", n.Remark)
		}
	}
	assert.Equal(t, 2, good, "both base64-decoded links collected")
	assert.Equal(t, 1, plain)
}
