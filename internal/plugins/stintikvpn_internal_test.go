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

// stintikFixture mirrors the REAL docs/data.json shape (verified 2026-10-28):
// subscriptions carry id + url; one subscription is deliberately broken to
// pin the per-subscription isolation the plugin promises.
const stintikFixture = `{
  "updated": "17.10.2026",
  "subscriptions": [
    {"id": "good-sub", "category": "white", "url": "%s/subs/good.txt"},
    {"id": "bad-sub", "category": "black", "url": "%s/subs/broken"},
    {"id": "plain-sub", "category": "white", "url": "%s/subs/plain.txt"}
  ],
  "proxies": [
    {"addr": "x", "url": "https://t.me/proxy?server=1.2.3.4&port=443&secret=ee"}
  ]
}`

// TestStintikVPNPluginFixture runs the real embedded stintikvpn.lua against
// an httptest fixture of its data.json contract: nested fetches, per-sub
// failure isolation (the dead subscription is logged, the others still
// land), and remark tagging by subscription id.
func TestStintikVPNPluginFixture(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/data.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, stintikFixture, srv.URL, srv.URL, srv.URL)
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

	code := string(defaultSources()["stintikvpn.lua"])
	require.NotEmpty(t, code)
	realURL := "https://raw.githubusercontent.com/Stintik-123/StintikVPN/main/docs/data.json"
	code = strings.Replace(code, realURL, srv.URL+"/data.json", 1)

	eng := newEngine(engineOptions{Log: io.Discard})
	p := &Plugin{ID: "stintikvpn", Path: "stintikvpn.lua", Code: []byte(code)}
	nodes, err := eng.Run(context.Background(), p)
	require.NoError(t, err)

	// good.txt (base64): 2 links; plain.txt: vless kept, junk lines kept as
	// raw candidates (Go's parse stage owns rejection); broken: isolated.
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
