package filter_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"assay/internal/filter"
	"assay/internal/model"
	"assay/internal/parse"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// classOf maps a filter.Run drop reason to its funnel class — the same
// contains-rules internal/cli's classifyDrop applies. The equivalence test
// needs it locally: the prefilter returns classes, filter.Run returns
// reasons, and the pin asserts they agree.
func classOf(reason string) string {
	switch {
	case strings.Contains(reason, "insecure"):
		return "insecure"
	case strings.Contains(reason, "allowlist"):
		return "scheme-not-allowed"
	case strings.Contains(reason, "private/loopback"):
		return "private"
	case strings.Contains(reason, "duplicate"):
		return "duplicate"
	case strings.Contains(reason, "cap"):
		return "source-cap"
	case strings.Contains(reason, "reality/tls"):
		return "no-tls-security"
	default:
		return "invalid"
	}
}

// trimmedLine replicates the parse scan's trim so the prefilter verdict and
// the Link parse see the same line.
func trimmedLine(line string) string {
	return strings.TrimSpace(line)
}

// TestPrefilterMatchesFilterVerdicts is the F3 equivalence pin: for every
// corpus line the full parse accepts, the raw-line prefilter verdict must
// equal the filter stage's verdict class for the parsed node. A pre-reject
// is a drop the filter would have made with the same class; a keep is a
// node the filter admits. This is what makes removing pre-rejected lines
// from the filter input content-neutral.
func TestPrefilterMatchesFilterVerdicts(t *testing.T) {
	corpus := []string{
		// security-class spectrum
		"vless://u1@a1.example.com:443?security=reality&pbk=x#r1",
		"vless://u2@a2.example.com:443?security=tls#r2",
		"vless://u3@a3.example.com:443?type=tcp#no-sec",
		"vless://u4@a4.example.com:443?security=none#none",
		"vless://u5@a5.example.com:443?tls=tls#tlsparam",
		"vless://u6@a6.example.com:443?tls=reality#realityparam",
		"vless://u7@a7.example.com:443#noquery",
		"trojan://pw@t1.example.com:443#trojan-def",
		"trojan://pw@t2.example.com:443?security=none#trojan-none",
		"trojan://pw@t3.example.com:443?type=tcp&security=reality&pbk=p#trojan-reality",
		"hysteria2://auth@h1.example.com:443?sni=s&security=tls#hy2-tls",
		"hysteria2://auth@h2.example.com:443?sni=s#hy2-nosec",
		"hy2://auth@h3.example.com:443?security=tls#alias-tls",
		"hy2://auth@h4.example.com:443#alias-nosec",
		"ss://YWVzLTI1Ni1nY206cHc@ss1.example.com:8388?sni=s&security=tls#ss-tls",
		"ss://YWVzLTI1Ni1nY206cHc@ss2.example.com:8388?sni=s#ss-nosec",
		// insecure spectrum (values case-sensitive in the source, folded in the test)
		"vless://u8@a8.example.com:443?security=reality&allowinsecure=1#ins1",
		"vless://u9@a9.example.com:443?security=reality&insecure=true#ins2",
		"vless://u10@a10.example.com:443?security=reality&insecure=TRUE#ins3",
		"vless://u11@a11.example.com:443?security=reality&insecure=0#ins0",
		"vless://u12@a12.example.com:443?security=reality&insecure=false#insf",
		"vless://u13@a13.example.com:443?security=reality&AllowInsecure=True#inscase",
		// duplicate-key / case-variant folding traps
		"vless://u14@a14.example.com:443?security=none&security=reality#firstwins",
		"vless://u15@a15.example.com:443?security=reality&security=none#firstnone",
		"vless://u16@a16.example.com:443?Security=none&security=reality#casefold-none",
		"vless://u17@a17.example.com:443?Security=tls&security=reality#casefold-reality",
		"vless://u18@a18.example.com:443?security=&security=none#emptyfirst",
		"vless://u19@a19.example.com:443?security=REALITY#valuecase",
		"vless://u20@a20.example.com:443?SECURITY=REALITY#keycase-valuecase",
		"vless://u21@a21.example.com:443?SECURITY=reality#keycase-valueok",
		// percent-escapes
		"vless://u22@a22.example.com:443?security=%72eality#esc-reality",
		"vless://u23@a23.example.com:443?security=re%61lity&insecure=%31#esc-insecure",
		"vless://u24@a24.example.com:443?security=tls&sni=w%77w.example+cdn#esc-plus",
		"vless://u25@a25.example.com:443?security=%74ls#esc-tls",
		// fragment interaction
		"vless://u26@a26.example.com:443#frag?security=none",
		"vless://u27@a27.example.com:443?security=none#q#frag",
		// empty pairs / missing '=' / '+' in values
		"vless://u28@a28.example.com:443?&security=tls&&type=tcp#emptypairs",
		"vless://u29@a29.example.com:443?security#novalue",
		"vless://u30@a30.example.com:443?security=tls&type=xhttp#ok",
		// uppercase scheme
		"VLESS://u31@a31.example.com:443?security=reality#upperscheme",
		"VLESS://u32@a32.example.com:443?security=none#upperscheme-none",
		// CRLF/whitespace padding (the parse trim normalizes these)
		"  vless://u33@a33.example.com:443?security=none#padded  \r",
		// vmess lines: the prefilter has NO opinion (base64 payload) —
		// whatever the filter decides, the prefilter must keep the line.
		vmessLink(t, "vm1.example.com", "uuid-vm1", "tls"),
		vmessLink(t, "vm2.example.com", "uuid-vm2", ""),
	}

	for _, line := range corpus {
		trimmed := trimmedLine(line)
		scheme := schemeByteFor(trimmed)

		t.Run(line, func(t *testing.T) {
			// Fresh prefilter per case; both sides run the FULL protocol
			// allowlist (the production default after config materializes
			// [filter].protocols) so the scheme-not-allowed attribution
			// never interferes — the allowlist guard has its own pin.
			fullOpts := []filter.Option{filter.WithProtocols(
				[]string{"vless", "vmess", "trojan", "ss", "hysteria2"})}
			pre := filter.NewPrefilter(fullOpts...)
			preClass := pre.PreReject(scheme, []byte(trimmed))

			n, err := parse.Link("t", trimmed)
			if err != nil {
				// Malformed lines carry no filter obligation — the prefilter
				// may or may not fire first; both count as malformed-or-prereject
				// in the funnel and neither reaches a store file.
				return
			}
			kept, dropped := filter.Run([]*model.Node{n}, fullOpts...)
			if !isURLFormScheme(scheme) {
				// vmess: no line-level opinion by design — the prefilter
				// must keep it, and the filter verdict is the unchanged
				// post-parse truth whatever it is.
				require.Empty(t, preClass, "vmess lines never pre-reject")
				return
			}
			if preClass == "" {
				assert.Len(t, kept, 1,
					"prefilter keep must be a filter keep (line %q → node security %q)", trimmed, n.Security)
				require.Empty(t, dropped)
				return
			}
			require.Empty(t, kept,
				"prefilter reject %q must be a filter reject for line %q", preClass, trimmed)
			require.Len(t, dropped, 1)
			assert.Equal(t, preClass, classOf(dropped[0].Reason),
				"the pre-reject class must equal the filter drop class for line %q", trimmed)
		})
	}
}

// isURLFormScheme reports whether the (parse-extracted) scheme belongs to
// the raw-scannable set the prefilter forms verdicts for; hy2 normalizes to
// hysteria2 exactly like the prefilter does.
func isURLFormScheme(scheme []byte) bool {
	switch string(scheme) {
	case "vless", "trojan", "ss", "hysteria2", "hy2":
		return true
	}
	return false
}

// TestPrefilterDedupIsScopedAndSeenAware pins the dedup map's semantics:
// within one Prefilter, the second occurrence of an exact string pre-rejects
// as duplicate only after it reached the full parse once (MarkSeen); a
// malformed line's duplicate stays malformed; a different Prefilter (the
// next source) knows nothing of the first source's lines; and two different
// strings with the same identity key are NOT a raw pre-reject — the filter
// stage owns that class.
func TestPrefilterDedupIsScopedAndSeenAware(t *testing.T) {
	link := "vless://dupe@dup.example.com:443?security=reality#d"
	scheme := schemeByteFor(link)

	pre := filter.NewPrefilter()
	require.Empty(t, pre.PreReject(scheme, []byte(link)), "first sight is not a duplicate")
	require.Empty(t, pre.PreReject(scheme, []byte("  "+link+"  ")),
		"whitespace padding trims to the same raw line — still unseen until MarkSeen")
	pre.MarkSeen(strings.TrimSpace(link))
	require.Equal(t, "duplicate", pre.PreReject(scheme, []byte(link)),
		"a marked line's second occurrence pre-rejects as duplicate")

	// A malformed line is never marked: its duplicates keep parsing (and
	// stay malformed) instead of shifting to the duplicate class.
	bad := "vless://bad@bad.example.com:notaport?security=reality#x"
	badScheme := schemeByteFor(bad)
	pre2 := filter.NewPrefilter()
	require.Empty(t, pre2.PreReject(badScheme, []byte(bad)))
	_, _ = parse.Link("t", bad) // the full parse FAILS — no MarkSeen happens
	require.Empty(t, pre2.PreReject(badScheme, []byte(bad)),
		"an unmarked (malformed) line stays eligible; its duplicate keeps the malformed class")

	// Source scoping: a fresh Prefilter (the next source) re-accepts the
	// same string, so the cross-source duplicate reaches filter and the
	// FIRST source's node remains the dedup winner.
	pre3 := filter.NewPrefilter()
	require.Empty(t, pre3.PreReject(scheme, []byte(link)),
		"another source's prefilter knows nothing of this source's lines")

	// Same identity key, different string: a raw-level KEEP (the filter
	// stage owns the key-duplicate class, exactly as pre-F3).
	variant := "vless://dupe@dup.example.com:443?security=reality&Security=reality#d"
	require.Empty(t, pre.PreReject(schemeByteFor(variant), []byte(variant)),
		"different raw strings are never raw-duplicates")
	pre.MarkSeen(strings.TrimSpace(variant))
	n1, err := parse.Link("t", link)
	require.NoError(t, err)
	n2, err := parse.Link("t", variant)
	require.NoError(t, err)
	require.Equal(t, n1.Key, n2.Key, "the two spellings share the identity key")
	kept, dropped := filter.Run([]*model.Node{n1, n2})
	require.Len(t, kept, 1)
	require.Len(t, dropped, 1)
	require.Contains(t, dropped[0].Reason, "duplicate",
		"the same-key different-string pair drops at the filter stage, class intact")
}

// TestPrefilterHonorsFilterPolicy pins the policy coupling: the allowlist
// guard returns no opinion for excluded schemes (the filter stage keeps the
// scheme-not-allowed attribution), and WithAllowInsecure admits insecure
// links at line level exactly like filter.Run does.
func TestPrefilterHonorsFilterPolicy(t *testing.T) {
	ssNoTLS := "ss://YWVzLTI1Ni1nY206cHc@ssx.example.com:8388?sni=s#ss-nosec"

	// Default allowlist (vless/vmess/trojan): an ss line gets NO pre-reject
	// even though it would fail the security check — the scheme allowlist
	// fires FIRST in filter.reject, so the funnel class stays
	// scheme-not-allowed.
	pre := filter.NewPrefilter()
	require.Empty(t, pre.PreReject(schemeByteFor(ssNoTLS), []byte(ssNoTLS)),
		"an allowlist-excluded scheme gets no line-level verdict")

	// Full allowlist: the same line pre-rejects as no-tls-security.
	preFull := filter.NewPrefilter(filter.WithProtocols(
		[]string{"vless", "vmess", "trojan", "ss", "hysteria2"}))
	require.Equal(t, "no-tls-security", preFull.PreReject(schemeByteFor(ssNoTLS), []byte(ssNoTLS)))

	// allow_insecure=true admits insecure lines (same policy as filter.Run).
	insecure := "vless://i@i.example.com:443?security=reality&insecure=1#i"
	preInsec := filter.NewPrefilter(filter.WithAllowInsecure(true))
	require.Empty(t, preInsec.PreReject(schemeByteFor(insecure), []byte(insecure)),
		"WithAllowInsecure removes the insecure pre-reject")
	n, err := parse.Link("t", insecure)
	require.NoError(t, err)
	kept, dropped := filter.Run([]*model.Node{n}, filter.WithAllowInsecure(true))
	require.Len(t, kept, 1)
	require.Empty(t, dropped, "the filter admits the same line under the same policy")
}

// vmessLink builds a vmess base64-JSON link (tls "" = field omitted, the
// no-tls-security drop class).
func vmessLink(t *testing.T, add, id, tls string) string {
	t.Helper()
	payload := map[string]string{"v": "2", "add": add, "port": "443", "id": id}
	if tls != "" {
		payload["tls"] = tls
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

// schemeByteFor extracts the lowercased scheme bytes the parse scan hands to
// the prefilter.
func schemeByteFor(line string) []byte {
	scheme, _, _ := strings.Cut(line, "://")
	return []byte(strings.ToLower(scheme))
}

// TestPreRejectPathAllocatesNothing pins the O(1) claim at its strongest
// constant: a raw-line pre-reject (the no-tls-security path — the live
// funnel's biggest class) allocates ZERO on the scan. The seam exists so
// the 2/3-dropped share of the corpus never pays per-link allocations; a
// regression here shows up directly in the wave's allocation churn.
func TestPreRejectPathAllocatesNothing(t *testing.T) {
	pre := filter.NewPrefilter(filter.WithProtocols(
		[]string{"vless", "vmess", "trojan", "ss", "hysteria2"}))
	line := "vless://u@n.example.com:443?type=tcp&security=none&sni=donor.example#drop"
	scheme := schemeByteFor(line)
	lineBytes := []byte(line) // converted outside the measured closure
	warm := pre.PreReject(scheme, lineBytes)
	require.Equal(t, "no-tls-security", warm, "the corpus line is the reject class under test")

	var sink string
	allocs := testing.AllocsPerRun(100, func() {
		sink = pre.PreReject(scheme, lineBytes)
	})
	_ = sink
	require.LessOrEqual(t, allocs, float64(1),
		"the raw-line reject path must be allocation-free (got %v allocs/run)", allocs)
}
