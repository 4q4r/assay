// The line-level prefilter (allocation audit F3): filter policy evaluated on
// the RAW share-link line so the cheaply-rejectable classes (exact-string
// duplicates, no reality/tls security, allowInsecure) never pay the full
// parse — no url.Parse, no Params map, no SHA-256 identity key. The verdicts
// reproduce filter.Run's reject chain (allowlist → security → insecure →
// dedup) exactly, so a pre-rejected line is a line the filter stage would
// have dropped with the same class, and a kept line is one the filter stage
// still sees (private hosts, vmess payloads, per-source caps and the scheme
// allowlist attribution stay where they were).

package filter

import (
	"bytes"
	"net/url"
	"strings"
	"unicode/utf8"

	"assay/internal/parse"
)

// Compile-time seam check: the filter package implements the consumer-side
// interface parse defines (stack-and-tools go-design ruling).
var _ parse.LinePrefilter = (*Prefilter)(nil)

// Pre-reject classes — the same vocabulary classifyDrop (internal/cli) maps
// filter.Run reasons to, so pre-reject and filter drops aggregate into
// identical funnel buckets.
const (
	PreRejectDuplicate   = "duplicate"
	PreRejectNoTLSSec    = "no-tls-security"
	PreRejectInsecureTLS = "insecure"
)

var (
	hy2Scheme       = []byte("hy2")
	hysteria2Scheme = []byte("hysteria2")
	trojanScheme    = []byte("trojan")
	eqSep           = []byte("=")

	securityParam      = []byte("security")
	tlsParam           = []byte("tls")
	allowInsecureParam = []byte("allowinsecure")
	insecureParam      = []byte("insecure")

	// urlFormSchemes are the schemes whose transport/security params ride
	// the URL query and are therefore raw-scannable. vmess is EXCLUDED by
	// design: its params live inside a base64 JSON payload, so no
	// prefix/pattern-level check exists — vmess lines keep the full-parse
	// path and the filter stage drops them by class exactly as before.
	urlFormSchemes = map[string]bool{
		"vless": true, "trojan": true, "ss": true, "hysteria2": true,
	}
)

// Prefilter implements parse.LinePrefilter over the filter policy. One
// Prefilter per SOURCE (the raw-line dedup map spans the source's files
// exactly like filter.Run's per-source cap accounting); not safe for
// concurrent use.
type Prefilter struct {
	allowed       map[string]bool
	allowInsecure bool
	seen          map[string]struct{}
}

// NewPrefilter builds a prefilter from the same options filter.Run takes
// (SourceCap is deliberately absent: caps need the parsed nodes' counts and
// stay a filter-stage decision).
func NewPrefilter(opts ...Option) *Prefilter {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	allowed := o.AllowedProtocols
	if allowed == nil {
		allowed = defaultProtocols
	}
	return &Prefilter{
		allowed:       allowed,
		allowInsecure: o.AllowInsecure,
		seen:          make(map[string]struct{}),
	}
}

// PreReject returns the drop class for a raw line that must not reach the
// full parse, or "" when the line proceeds. The check order mirrors
// filter.reject so the class attribution is identical for every line the
// full parse accepts: allowlist guard → security → insecure → dedup. The
// allowlist guard returns no OPINION (not a verdict) for schemes outside
// [filter].protocols — those lines full-parse and the filter stage drops
// them as scheme-not-allowed, keeping the funnel classes intact.
func (p *Prefilter) PreReject(scheme, line []byte) string {
	sch := scheme
	if bytes.Equal(sch, hy2Scheme) {
		// The parse normalizes hy2:// to hysteria2 (NewNode's scheme), and
		// the allowlist keys on the normalized spelling.
		sch = hysteria2Scheme
	}
	if !urlFormSchemes[string(sch)] || !p.allowed[string(sch)] {
		return ""
	}
	sec, tls, allowInsecure, insecure := scanQuery(rawQuery(line))
	// The security class NewNode derives from the params: security wins,
	// trojan is TLS by definition, else the tls param.
	class := sec
	if len(class) == 0 {
		if bytes.Equal(sch, trojanScheme) {
			class = tlsClassValue
		} else {
			class = tls
		}
	}
	if !bytes.Equal(class, realityClassValue) && !bytes.Equal(class, tlsClassValue) {
		return PreRejectNoTLSSec
	}
	if !p.allowInsecure && (isInsecureValue(allowInsecure) || isInsecureValue(insecure)) {
		return PreRejectInsecureTLS
	}
	if _, dup := p.seen[string(line)]; dup {
		return PreRejectDuplicate
	}
	return ""
}

// MarkSeen records a line that reached (and survived) the full parse — the
// dedup map only accumulates full-parse survivors, so a malformed line's
// duplicates stay malformed instead of shifting to the duplicate class.
func (p *Prefilter) MarkSeen(line string) {
	p.seen[line] = struct{}{}
}

var (
	realityClassValue = []byte("reality")
	tlsClassValue     = []byte("tls")
)

// isInsecureValue mirrors insecure()'s membership test for one folded param
// value (nil when the key is absent): strings.ToLower(v) ∈ {1, true}. Pure
// ASCII takes the zero-alloc EqualFold path; the Unicode fold is identical
// for the ASCII membership set, but a non-ASCII byte falls back to the
// strings.ToLower reference behavior anyway.
func isInsecureValue(v []byte) bool {
	if !isASCII(v) {
		switch strings.ToLower(string(v)) {
		case "1", "true":
			return true
		}
		return false
	}
	return bytes.EqualFold(v, oneValue) || bytes.EqualFold(v, trueValue)
}

var (
	oneValue  = []byte("1")
	trueValue = []byte("true")
)

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// rawQuery returns the query slice of a share-link line, mirroring net/url's
// split order (fragment split first, then the query inside the rest), or nil
// when the line carries no query.
func rawQuery(line []byte) []byte {
	if end := bytes.IndexByte(line, '#'); end >= 0 {
		line = line[:end]
	}
	i := bytes.IndexByte(line, '?')
	if i < 0 {
		return nil
	}
	return line[i+1:]
}

// queryParam is one target key's first-occurrence value: the UNESCAPED
// original-case key spelling and its value. Both are slices into the query —
// the scan never copies them (fixed entry array, byte comparisons).
type queryParam struct {
	key []byte
	val []byte
}

// scanMaxEntries covers the realistic spellings of the four target keys on
// one line; a line carrying MORE distinct spellings (crafted only) spills
// into a map so the folding semantics never degrade.
const scanMaxEntries = 8

// scanQuery extracts the filter-relevant params from a raw query without
// building the param map the full parse constructs. The four returns are, in
// order: the security param, the tls param, the allowinsecure param, the
// insecure param — each nil when the key is absent (downstream that behaves
// as absent, matching the empty params lookup in model.NewNode). Every
// return is a sub-slice of q, valid for the lifetime of the line. For each
// target key it reproduces linkTarget's folding exactly: the value is the
// FIRST query occurrence per exact key spelling (net/url's Values keeps
// index 0), and the case-variant spellings fold to their lexicographic
// minimum (linkTarget's determinism rule). Values are query-unescaped; pairs
// whose key or value fails to unescape are skipped, exactly like
// net/url.ParseQuery. The reject path allocates nothing: the entry array is
// stack data, keys and values stay slices, and the fold compares bytes.
func scanQuery(q []byte) ([]byte, []byte, []byte, []byte) {
	var fixed [scanMaxEntries]queryParam // frame data: the reject path never escapes it
	entries := fixed[:0]
	var overflow map[string][]byte
	rest := q
	for len(rest) > 0 {
		var pair []byte
		if i := bytes.IndexByte(rest, '&'); i >= 0 {
			pair, rest = rest[:i], rest[i+1:]
		} else {
			pair, rest = rest, nil
		}
		if len(pair) == 0 {
			continue // ParseQuery skips empty pairs
		}
		keyB, valueB, _ := bytes.Cut(pair, eqSep)
		if !isTargetParam(keyB) {
			continue
		}
		// The entry keys hold the UNESCAPED ORIGINAL-case spelling: two case
		// variants ("Security=" / "security=") are distinct exact keys to
		// linkTarget — each keeps its own first-occurrence value, and the
		// fold merges them by minimum. Collapsing them here would let the
		// second spelling's value be lost as a "duplicate".
		key, err := unescapeQuery(keyB)
		if err != nil {
			continue
		}
		value, err := unescapeQuery(valueB)
		if err != nil {
			continue
		}
		if firstSeen(entries, overflow, key) {
			continue // only the first occurrence per exact spelling counts
		}
		if len(entries) < scanMaxEntries {
			entries = append(entries, queryParam{key: key, val: value})
			continue
		}
		if overflow == nil {
			overflow = make(map[string][]byte, 4)
		}
		overflow[string(key)] = value
	}
	return foldEntries(entries, overflow, securityParam), foldEntries(entries, overflow, tlsParam),
		foldEntries(entries, overflow, allowInsecureParam), foldEntries(entries, overflow, insecureParam)
}

// firstSeen reports whether the exact key spelling was already recorded.
func firstSeen(entries []queryParam, overflow map[string][]byte, key []byte) bool {
	for _, e := range entries {
		if bytes.Equal(e.key, key) {
			return true
		}
	}
	_, ok := overflow[string(key)]
	return ok
}

// foldEntries folds the first-occurrence values of every exact key spelling
// case-insensitively equal to target into their lexicographic minimum —
// linkTarget's determinism rule across case-variant spellings, which makes
// the fold independent of scan order. Nil when the key is absent.
func foldEntries(entries []queryParam, overflow map[string][]byte, target []byte) []byte {
	var lo []byte
	found := false
	for _, e := range entries {
		if !asciiEqFold(e.key, target) {
			continue
		}
		if !found || bytes.Compare(e.val, lo) < 0 {
			lo = e.val
			found = true
		}
	}
	for k, v := range overflow {
		if !asciiEqFold([]byte(k), target) {
			continue
		}
		if !found || bytes.Compare(v, lo) < 0 {
			lo = v
			found = true
		}
	}
	return lo
}

// asciiEqFold is a zero-alloc ASCII case-insensitive comparison with a
// strings.ToLower fallback for non-ASCII keys (the reference behavior of
// linkTarget's strings.ToLower(key) — a Unicode variant spelling such as
// the Kelvin sign must fold exactly the same way).
func asciiEqFold(a, b []byte) bool {
	ascii := isASCII(a) && isASCII(b)
	if ascii {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if lowerByte(a[i]) != lowerByte(b[i]) {
				return false
			}
		}
		return true
	}
	return strings.ToLower(string(a)) == string(b)
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// isTargetParam byte-compares a query key against the four filter-relevant
// params, case-insensitively for ASCII (linkTarget lowercases keys) — no
// allocation on the scan fast path.
func isTargetParam(key []byte) bool {
	return asciiEqFold(key, securityParam) || asciiEqFold(key, tlsParam) ||
		asciiEqFold(key, allowInsecureParam) || asciiEqFold(key, insecureParam)
}

// unescapeQuery query-unescapes a key/value slice. Fast path: bytes without
// '%' or '+' are already the unescaped form and return as the same slice.
func unescapeQuery(b []byte) ([]byte, error) {
	if !bytes.ContainsAny(b, "%+") {
		return b, nil
	}
	s, err := url.QueryUnescape(string(b))
	return []byte(s), err
}
