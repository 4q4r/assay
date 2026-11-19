package cli

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"assay/internal/config"
	"assay/internal/fetch"
	"assay/internal/model"
	"assay/internal/parse"
	"assay/internal/store"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// The F3 fused parse+filter fixture: two sources over the REAL stage runners
// (runParse writes nodes.jsonl, runFilter reads it and writes filtered.jsonl
// — the W17 stage files, unchanged). The corpus exercises every line-level
// pre-reject class (duplicate / no-tls-security / insecure), the filter-only
// classes (vmess no-tls, private host, cross-source key-duplicate), the
// scanner equivalence traps (duplicate query keys, case-variant keys and
// schemes, percent-escapes, first-value-wins), and the exactness corners
// (a malformed line's duplicate must stay malformed — the dedup map only
// records lines that reached the full parse).
//
// Corpus map (sourceA plain text with mixed CRLF; sourceB a whole-body
// base64 payload):
//
//	L1  vless reality            KEEP
//	L2  vless reality            KEEP
//	L3  = L1 exactly             pre-reject: duplicate (same source)
//	L4  vless security=none      pre-reject: no-tls-security
//	L5  security=none&security=reality (first value wins)   pre-reject: no-tls-security
//	L6  Security=tls&security=reality (min-value fold → reality)          KEEP
//	L7  vless reality + insecure=1                          pre-reject: insecure
//	L8  insecure=TRUE&insecure=1 (min-value fold → "1")     pre-reject: insecure
//	L9  trojan (tls by definition)                          KEEP
//	L10 trojan security=none                                pre-reject: no-tls-security
//	L11 hysteria2 security=tls (+insecure=0 — not insecure)  KEEP
//	L12 hy2:// alias without security params                 pre-reject: no-tls-security
//	L13 ss SIP002 with security=tls                          KEEP
//	L14 vmess JSON with tls                                  KEEP (full parse — not pre-rejectable)
//	L15 vmess JSON without tls                               filter drop: no-tls-security
//	L16 vless reality @ 127.0.0.1                            filter drop: private
//	L17 vless reality @ bad port                             malformed
//	L18 = L17 exactly                                        malformed (dedup must NOT catch it)
//	L19 tuic://                                              parse-rejected scheme
//	L20 blank / # / // / whitespace                          Blank ×4
//	L21 security=%72eality (percent-escape → reality)        KEEP
//	L22 same params as L6, different string                  parses → filter drop: duplicate
//	L23 VLESS:// ?SECURITY=REALITY (value case-sensitive)    pre-reject: no-tls-security
//
//	B1  = L1 exactly (OTHER source)   parses → filter drop: duplicate (key-dup)
//	B2  vless security=tls            KEEP
//	B3  = B2 exactly                  pre-reject: duplicate (same source)
//	B4  vless security=none           pre-reject: no-tls-security
//
// Counts: 10 pre-rejects (8 in sourceA, 2 in sourceB); 13 parsed nodes
// post-fusion (23 pre-fusion: the 10 pre-rejects fully parsed before);
// 15 full parses post-fusion (13 nodes + the two malformed lines, which
// stay malformed because the dedup map only records full-parse survivors);
// 9 kept in filtered.jsonl — the SAME 9 the pre-fusion tree kept (content
// parity), because every pre-rejected line was a filter drop with a disjoint
// identity key.
func vmessFixtureLink(t *testing.T, add, id, ps, tls string) string {
	t.Helper()
	payload := map[string]string{
		"v": "2", "ps": ps, "add": add, "port": "443", "id": id, "net": "ws",
	}
	if tls != "" {
		payload["tls"] = tls
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

// fusedFixture seeds the fetch cache + manifest for the corpus and loads the
// config (defaults materialized: all five protocols allowed, insecure off).
func fusedFixture(t *testing.T, dir string) *config.Config {
	t.Helper()
	tomlPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(tomlPath, []byte("data_dir = '"+dir+"'\n"), 0o644))
	cfg, err := config.Load(tomlPath)
	require.NoError(t, err)
	p := newPaths(cfg)
	require.NoError(t, os.MkdirAll(p.cacheDir, 0o750))

	linkL1 := "vless://uuid-1111@de1.example.com:443?security=reality&sni=one.example&pbk=PBK1&sid=0001&fp=chrome#n1"
	linkB2 := "vless://uuid-b1@deb1.example.com:443?security=tls&type=ws#b1"
	linkL14 := vmessFixtureLink(t, "vm1.example.com", "uuid-aaaa", "vm1", "tls")
	linkL15 := vmessFixtureLink(t, "vm2.example.com", "uuid-bbbb", "vm2", "")

	sourceA := strings.Join([]string{
		linkL1,
		"vless://uuid-2222@de2.example.com:443?security=reality&sni=two.example&pbk=PBK2&sid=0002#n2",
		linkL1, // L3: exact duplicate
		"vless://uuid-3333@de3.example.com:443?security=none&sni=three.example#n3",
		"vless://uuid-4444@de4.example.com:443?security=none&security=reality#n4",
		"vless://uuid-5555@de5.example.com:443?Security=tls&security=reality#n5",
		"vless://uuid-6666@de6.example.com:443?security=reality&insecure=1#n6",
		"vless://uuid-7777@de7.example.com:443?security=reality&insecure=TRUE&insecure=1#n7",
		"trojan://pass-8888@de8.example.com:443?type=tcp#n8",
		"trojan://pass-9999@de9.example.com:443?security=none#n9",
		"hysteria2://auth-abcd@hy1.example.com:8443?sni=hy.example&insecure=0&security=tls#n10",
		"hy2://auth-ef12@hy2.example.com:8443?sni=hy2.example#n11",
		"ss://YWVzLTI1Ni1nY206cHc@ss1.example.com:8388?sni=ss.example&security=tls#n12",
		linkL14, linkL15,
		"vless://uuid-priv@127.0.0.1:443?security=reality#n13",
		"vless://uuid-bad@de-bad.example.com:notaport?security=reality#n14",
		"vless://uuid-bad@de-bad.example.com:notaport?security=reality#n14", // L18: dup of the malformed line
		"tuic://uuid@t.example.com:443?congestion_control=bbr",
		"", "# comment", "// comment", "   ",
		"vless://uuid-esc@esc.example.com:443?security=%72eality&sni=w%77w.example#n15",
		"vless://uuid-5555@de5.example.com:443?security=reality&Security=tls#n16",
		"VLESS://uuid-lc@lc.example.com:443?SECURITY=REALITY#n17",
	}, "\r\n") + "\r\n"
	sourceB := strings.Join([]string{
		linkL1, // B1: cross-source duplicate of L1 (parses; filter drops by key)
		linkB2,
		linkB2, // B3: exact duplicate
		"vless://uuid-b2@deb2.example.com:443?security=none#b2",
	}, "\n")
	sourceBB64 := base64.StdEncoding.EncodeToString([]byte(sourceB))

	for _, id := range []string{"src-a", "src-b"} {
		require.NoError(t, os.MkdirAll(filepath.Join(p.cacheDir, id), 0o750))
	}
	require.NoError(t, os.WriteFile(filepath.Join(p.cacheDir, "src-a", "links.txt"), []byte(sourceA), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(p.cacheDir, "src-b", "links.txt"), []byte(sourceBB64), 0o600))

	manifest := fetchManifest{
		FetchedAt: time.Time{},
		Sources: map[string][]fetch.FetchedFile{
			"src-a": {{Source: "src-a", Path: "links.txt"}},
			"src-b": {{Source: "src-b", Path: "links.txt"}},
		},
	}
	//nolint:musttag // fetchManifest has JSON tags; musttag false positive
	mb, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, store.WriteManifest(p.manifest, mb))
	return cfg
}

// runFusedFixtureStages runs the real parse + filter stages over the fixture.
func runFusedFixtureStages(t *testing.T, cfg *config.Config) {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetOut(&strings.Builder{})
	require.NoError(t, runParse(cmd, cfg))
	require.NoError(t, runFilter(cmd, cfg, 0))
}

// TestFusedParseFilterLinePreRejectCounts is the F3 impact instrument: the
// fused pipeline must pre-reject the cheap classes at RAW-LINE level — one
// full parse per survivor (plus the unmarked malformed lines), at most one
// full-body materialization per body (the base64 decode), and O(1) work per
// pre-rejected line. RED on the pre-fusion tree: 25 full parses, 5 full-body
// copies (the cached-body string conversions + the ReplaceAll CRLF pass ×2
// + the base64 decode), zero pre-rejects.
func TestFusedParseFilterLinePreRejectCounts(t *testing.T) {
	dir := t.TempDir()
	cfg := fusedFixture(t, dir)

	parse.WithSeam(func(seam *parse.Seam) {
		runFusedFixtureStages(t, cfg)
		require.Equal(t, int64(1), seam.BodyCopies.Load(),
			"exactly one full-body materialization (the sourceB base64 decode); sourceA must scan its bytes in place")
		require.Equal(t, int64(15), seam.FullParses.Load(),
			"one full parse per pre-reject survivor (13 nodes) plus the two malformed lines; rejected links must never reach Link()")
		require.Equal(t, int64(10), seam.PreRejects.Load(),
			"8 sourceA + 2 sourceB line-level pre-rejects (5 no-tls, 2 insecure, 3 duplicates)")
	})

	p := newPaths(cfg)
	nodes, err := store.ReadNodes(p.nodes)
	require.NoError(t, err)
	require.Len(t, nodes, 13, "nodes.jsonl carries only full-parse survivors (pre-fusion: 23)")
	filtered, err := store.ReadNodes(p.filtered)
	require.NoError(t, err)
	require.Len(t, filtered, 9, "the kept set is identical to the pre-fusion tree's")
	keptHosts := make([]string, 0, len(filtered))
	for _, n := range filtered {
		keptHosts = append(keptHosts, n.Host)
	}
	require.Equal(t, []string{
		"de1.example.com", "de2.example.com", "de5.example.com", "de8.example.com",
		"hy1.example.com", "ss1.example.com", "vm1.example.com", "esc.example.com",
		"deb1.example.com",
	}, keptHosts, "the kept set is the pre-fusion kept set, order included")
}

// normalizeNodeJSONL canonicalizes a nodes/filtered JSONL file for golden
// comparison: the only wall-clock bytes a parse/filter output carries are
// FirstSeen/LastSeen, so each line is decoded, the stamps zeroed, and the
// record re-marshaled (deterministic field/map order).
func normalizeNodeJSONL(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b strings.Builder
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var n model.Node
		require.NoError(t, json.Unmarshal([]byte(line), &n), "line: %s", line)
		n.FirstSeen = time.Time{}
		n.LastSeen = time.Time{}
		nb, err := json.Marshal(&n)
		require.NoError(t, err)
		b.Write(nb)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

var updateF3Goldens = flag.Bool("update-f3-goldens", false,
	"regenerate the F3 parse/filter parity goldens (deliberate contract change)")

// TestFusedParseFilterParityAgainstGoldens pins the F3 refactor's observable
// store contract over the fixture corpus.
//
// Golden provenance: f3-nodes.jsonl and f3-filtered.jsonl were generated on
// the PRE-F3 tree (perf/alloc-f3 @ 8cc4763, before the fused parse+filter
// wave) as the pre-change truth. After the fusion:
//
//   - filtered.jsonl MUST remain byte-identical (modulo the normalized
//     wall-clock stamps): every pre-rejected line is a filter drop whose
//     identity key is disjoint from every kept node's key, so removing them
//     from the filter input cannot change the kept set, its order, or the
//     dedup/cap winners. This is the content-parity proof.
//   - nodes.jsonl was DELIBERATELY REGENERATED: the pre-rejected lines never
//     build model.Node records anymore, so the parse stage's file carries
//     only full-parse survivors (23 → 13 lines here; incident-scale ~148k →
//     ~89k). The W17 checkpoint contract is intact: the file is still
//     written once at parse-stage end, filter still resumes from it, and
//     the dropped lines are exactly the lines filter would have dropped
//     (same classes, counted at line level instead).
//
// Any future change to the parse/filter path not accompanied by a deliberate
// regeneration fails here.
func TestFusedParseFilterParityAgainstGoldens(t *testing.T) {
	dir := t.TempDir()
	cfg := fusedFixture(t, dir)
	runFusedFixtureStages(t, cfg)
	p := newPaths(cfg)

	type pair struct {
		livePath string
		golden   string
	}
	for _, pr := range []pair{
		{p.nodes, "f3-nodes.jsonl"},
		{p.filtered, "f3-filtered.jsonl"},
	} {
		got, err := os.ReadFile(pr.livePath)
		require.NoError(t, err, "source %s", pr.livePath)
		got = normalizeNodeJSONL(t, got)
		goldenPath := filepath.Join("testdata", "allocparity", pr.golden)
		if *updateF3Goldens {
			require.NoError(t, os.WriteFile(goldenPath, got, 0o644), "golden %s", pr.golden)
			continue
		}
		want, err := os.ReadFile(goldenPath)
		require.NoError(t, err, "golden %s", pr.golden)
		require.Equal(t, strings.ReplaceAll(string(want), "\r\n", "\n"), string(got),
			"%s must match the pinned golden (see the provenance note above)", pr.golden)
	}
}
