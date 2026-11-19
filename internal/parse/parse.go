// Package parse turns raw fetched source bodies into normalized nodes.
// It accepts vless/vmess/trojan/ss/hysteria2 links (hy2:// alias —
// core-verified against xray 26.3.27), rejects schemes outside xray-core
// (tuic, hysteria v1, ssr, socks/http/https), and never fails fatally on
// malformed lines — they are counted and reported. Protocol acceptance is a
// FILTER policy ([filter].protocols allowlist — W14 default: every rendered
// protocol): parse normalizes everything it can. Since the allocation-audit
// F3 wave, the scan can consult a LinePrefilter on the RAW line so the
// cheaply-rejectable classes never pay the full parse.
package parse

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"assay/internal/model"
)

// Accepted schemes (xray-core client protocols only).
const (
	SchemeVLESS     = "vless"
	SchemeVMESS     = "vmess"
	SchemeTrojan    = "trojan"
	SchemeSS        = "ss"
	SchemeHysteria2 = "hysteria2"
)

// rejectedSchemes are counted per kind. ss is PARSED (acceptance is a filter
// policy — [filter].protocols, default vless,vmess,trojan); hysteria2 (and
// its documented hy2:// alias) is PARSED the same way — the xray 26.3.27
// core ships a real hysteria2 client (proxy/hysteria, version == 2 verified
// against the binary and the tagged source, 2026-10-28). hysteria v1 links
// stay rejected: the core refuses version != 2, and the v1 wire protocol is
// a different protocol entirely.
var rejectedSchemes = map[string]bool{
	"tuic": true, "hysteria": true,
	"ssr": true, "socks": true, "http": true, "https": true,
}

var (
	schemeSep      = []byte("://")
	commentSlashes = []byte("//")
)

// Result aggregates one parse wave over one or many source bodies.
type Result struct {
	Nodes         []*model.Node
	Rejected      int            // links with a scheme outside xray-core
	RejectedKinds map[string]int // scheme -> count
	Malformed     int            // accepted-scheme links that failed to parse
	Blank         int            // blank/comment lines
	// PreRejected counts links rejected by the LinePrefilter on the RAW
	// line — before any per-link allocation (the F3 fused pre-reject). The
	// classes use the same vocabulary as the filter stage's drop report
	// (duplicate / no-tls-security / insecure), so the two stages aggregate
	// into identical funnel buckets.
	PreRejected      int
	PreRejectedKinds map[string]int
}

// LinePrefilter is the fused-filter seam (allocation audit F3): cheap
// verdicts on the RAW accepted-scheme link line BEFORE the full parse
// allocates. parse defines the seam at its consumer (the scan loop); the
// filter package implements it from the filter policy, so rejection policy
// stays in filter and the stage contracts stay intact.
type LinePrefilter interface {
	// PreReject returns the drop class for a raw line that must not reach
	// the full parse; "" means proceed. scheme is the lowercased scheme the
	// scan already extracted; line is the trimmed raw line. Both are
	// sub-slices of the body — implementations must not retain them.
	PreReject(scheme, line []byte) string
	// MarkSeen records a line that reached the full parse, feeding the
	// raw-line dedup. Called only after a SUCCESSFUL Link, so a malformed
	// line's duplicates keep their malformed class instead of shifting to
	// duplicate.
	MarkSeen(line string)
}

// IsSupported reports whether a line starts with an accepted scheme.
func IsSupported(line string) bool {
	s := schemeOf(line)
	return s == SchemeVLESS || s == SchemeVMESS || s == SchemeTrojan || s == SchemeSS ||
		s == SchemeHysteria2 || s == "hy2"
}

func schemeOf(line string) string {
	scheme, _, ok := strings.Cut(line, "://")
	if !ok {
		return ""
	}
	return strings.ToLower(scheme)
}

// schemeOfBytes is the zero-copy byte variant of schemeOf over a line slice.
// Unlike strings.ToLower — which returns the input unchanged when no upper
// byte is present — bytes.ToLower ALWAYS allocates a copy, so the fast path
// here hands back the input slice untouched and only mixed-case spellings
// pay the copy.
func schemeOfBytes(line []byte) []byte {
	scheme, _, ok := bytes.Cut(line, schemeSep)
	if !ok {
		return nil
	}
	if !hasUpperByte(scheme) {
		return scheme
	}
	return bytes.ToLower(scheme)
}

func hasUpperByte(b []byte) bool {
	for _, c := range b {
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// isSupportedScheme is the byte variant of IsSupported's scheme test.
func isSupportedScheme(scheme []byte) bool {
	switch string(scheme) {
	case SchemeVLESS, SchemeVMESS, SchemeTrojan, SchemeSS, SchemeHysteria2, "hy2":
		return true
	}
	return false
}

// linesSeq yields the newline-separated segments of body with EXACTLY
// strings.Split semantics: a trailing newline produces one final empty
// segment, and an empty body yields a single empty segment (the blank-line
// counts the pre-F3 tree produced must be reproduced verbatim).
func linesSeq(body []byte) func(func([]byte) bool) {
	return func(yield func([]byte) bool) {
		rest := body
		for {
			var raw []byte
			i := bytes.IndexByte(rest, '\n')
			if i >= 0 {
				raw, rest = rest[:i], rest[i+1:]
			} else {
				raw, rest = rest, nil
			}
			if !yield(raw) {
				return
			}
			if i < 0 {
				return
			}
		}
	}
}

// Lines parses a whole fetched body. Base64 bodies are detected and decoded
// first; the remaining lines are scanned in place (zero-copy byte slices) —
// the only copies are the base64 decode (one per base64 body) and the one
// line string per pre-reject SURVIVOR that reaches the string-based full
// parse. A non-nil pre rejects the cheap classes at raw-line level before
// any per-link work; nil keeps the pure-parse behavior.
func Lines(source string, body []byte, pre LinePrefilter) *Result {
	res := &Result{RejectedKinds: map[string]int{}, PreRejectedKinds: map[string]int{}}
	if s := seam(); s != nil {
		s.LinesInvocations.Add(1)
	}
	if decoded, ok := decodeIfBase64Bytes(body); ok {
		body = decoded
		// F3 instrument: the whole-body base64 decode is the one full-body
		// materialization a body can pay (plain bodies scan in place).
		if s := seam(); s != nil {
			s.BodyCopies.Add(1)
		}
	}
	for raw := range linesSeq(body) {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 || line[0] == '#' || bytes.HasPrefix(line, commentSlashes) {
			res.Blank++
			continue
		}
		scheme := schemeOfBytes(line)
		if len(scheme) == 0 {
			res.Malformed++
			continue
		}
		if rejectedSchemes[string(scheme)] {
			res.Rejected++
			res.RejectedKinds[string(scheme)]++
			continue
		}
		if !isSupportedScheme(scheme) {
			res.Malformed++
			continue
		}
		acceptLine(source, scheme, line, pre, res)
	}
	return res
}

// acceptLine applies the F3 prefilter seam and the full parse to one
// accepted-scheme line. A pre-reject is counted by class and allocates
// nothing; a survivor pays the one line-string copy the string-based full
// parse needs (net/url) and is marked seen on success, so a prefilter dedup
// never records lines the full parse rejected.
func acceptLine(source string, scheme, line []byte, pre LinePrefilter, res *Result) {
	if pre != nil {
		if class := pre.PreReject(scheme, line); class != "" {
			res.PreRejected++
			res.PreRejectedKinds[class]++
			if s := seam(); s != nil {
				s.PreRejects.Add(1)
			}
			return
		}
	}
	lineStr := string(line)
	n, err := Link(source, lineStr)
	if s := seam(); s != nil {
		s.FullParses.Add(1)
	}
	if err != nil {
		res.Malformed++
		return
	}
	if pre != nil {
		pre.MarkSeen(lineStr)
	}
	res.Nodes = append(res.Nodes, n)
}

// decodeIfBase64Bytes decodes a whole-body base64 payload: subscription
// files are often a single base64 blob of newline-separated links. Detection
// is strict — the body must have no link scheme at all, decode cleanly, and
// the decoded text must contain at least one scheme.
func decodeIfBase64Bytes(body []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Contains(trimmed, schemeSep) {
		return body, false
	}
	decoded, err := decodeFlexibleBytes(trimmed)
	if err != nil || !bytes.Contains(decoded, schemeSep) {
		return body, false
	}
	return decoded, true
}

// decodeFlexibleBytes is decodeFlexible's whole-body variant: same encoder
// ladder, but it decodes into one pre-sized buffer instead of a string
// round-trip.
func decodeFlexibleBytes(s []byte) ([]byte, error) {
	var lastErr error
	for _, enc := range base64Encodings {
		dst := make([]byte, enc.DecodedLen(len(s)))
		n, err := enc.Decode(dst, s)
		if err == nil {
			return dst[:n], nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// splitLines is gone (allocation audit F3): linesSeq scans the body in
// place, and CRLF handling lives in the TrimSpace the scan already applies
// to every line — a trailing \r is whitespace, so both encodings yield
// identical trimmed lines without the full-body ReplaceAll pass.

// Link parses a single share-link URI into a normalized node.
func Link(source, line string) (*model.Node, error) {
	scheme := schemeOf(line)
	switch scheme {
	case SchemeVLESS, SchemeTrojan:
		return parseUserinfoLink(source, scheme, line)
	case SchemeVMESS:
		return parseVMESS(source, line)
	case SchemeSS:
		return parseSS(source, line)
	case "hy2", SchemeHysteria2:
		// hy2:// is the documented alias of hysteria2:// — both normalize to
		// the one scheme so the dedupe identity is shared.
		return parseHysteria2(source, line)
	default:
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
}

// parseHysteria2 normalizes a hysteria2:// / hy2:// share link (official URI
// scheme, v2.hysteria.network/docs/developers/URI-Scheme):
// [auth@]host:port?obfs&obfs-password&sni&insecure&pinSHA256&ech#name.
// auth is OPTIONAL per the spec (unlike vless/trojan userinfo), so an empty
// credential parses; the renderer passes it through 1:1. All query params
// land in Params verbatim (L9) — obfs/obfs-password cannot be expressed by
// the xray core and fail the RENDER loud (material transport behavior),
// never the parse.
func parseHysteria2(source, line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("parse uri: %w", err)
	}
	cred := ""
	if u.User != nil {
		cred = u.User.Username()
	}
	host, port, params, frag, err := linkTarget(u)
	if err != nil {
		return nil, err
	}
	n := model.NewNode(source, SchemeHysteria2, cred, host, port, params)
	n.Fragment = frag
	n.LastSeen = time.Now().UTC()
	return n, nil
}

func parseUserinfoLink(source, scheme, line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("parse uri: %w", err)
	}
	cred := u.User.Username()
	if cred == "" {
		return nil, errors.New("empty credential")
	}
	host, port, params, frag, err := linkTarget(u)
	if err != nil {
		return nil, err
	}
	n := model.NewNode(source, scheme, cred, host, port, params)
	// u.Fragment is already percent-decoded by url.Parse; a second unescape
	// would corrupt literal % sequences (review finding 13).
	n.Fragment = frag
	n.LastSeen = time.Now().UTC()
	return n, nil
}

// linkTarget extracts host/port/params/fragment from a parsed share-link URL
// with the shared validation and dedupe rules (case-variant spellings keep
// the lexicographically smaller value so the winner never depends on Go's
// randomized map iteration — review finding 13).
func linkTarget(u *url.URL) (string, int, map[string]string, string, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, nil, "", errors.New("empty host")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, nil, "", fmt.Errorf("invalid port %q", u.Port())
	}
	params := map[string]string{}
	for k, v := range u.Query() {
		if len(v) == 0 {
			continue
		}
		key := strings.ToLower(k)
		if existing, seen := params[key]; seen {
			if existing <= v[0] {
				continue
			}
		}
		params[key] = v[0]
	}
	return host, port, params, u.Fragment, nil
}

// parseSS handles the real-world shadowsocks share-link encodings:
//   - SIP002: ss://base64(method:password)@host:port?plugin=...#tag (the
//     userinfo may also be plaintext method:password);
//   - legacy: ss://base64(method:password@host:port)#tag (no @ in the body).
//
// method/password land in Params verbatim (L9); the credential for the
// identity key is method:password. Plugin params (if any) pass through
// untouched — rendering them is a loud failure (core 26.3.27 has no SIP003
// outbound plugin support; verified against the binary and source).
func parseSS(source, line string) (*model.Node, error) {
	rest := strings.TrimPrefix(line, "ss://")
	frag := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		frag = rest[i+1:]
		rest = rest[:i]
		decoded, decErr := url.PathUnescape(frag)
		if decErr == nil {
			frag = decoded
		}
	}
	if !strings.Contains(rest, "@") {
		// Legacy whole-link base64: ss://base64(method:password@host:port).
		decoded, err := decodeFlexible(rest)
		if err != nil {
			return nil, fmt.Errorf("ss legacy base64: %w", err)
		}
		return parseSSBody(source, decoded, frag)
	}
	return parseSSBody(source, rest, frag)
}

// parseSSBody parses "userinfo@host:port?query" where userinfo is
// [base64url(]method:password[)]. The target side is parsed scheme-less
// ("//host:port?query") so base64 "+/" characters in the userinfo can never
// mangle the host/query split.
func parseSSBody(source, body, frag string) (*model.Node, error) {
	userinfo, target, ok := strings.Cut(body, "@")
	if !ok || userinfo == "" || target == "" {
		return nil, errors.New("ss body is not userinfo@host:port")
	}
	method, password, err := ssCredential(userinfo)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse("//" + target)
	if err != nil {
		return nil, fmt.Errorf("parse ss target: %w", err)
	}
	host, port, params, _, err := linkTarget(u)
	if err != nil {
		return nil, err
	}
	params["method"] = method
	params["password"] = password
	n := model.NewNode(source, SchemeSS, method+":"+password, host, port, params)
	n.Fragment = frag
	n.LastSeen = time.Now().UTC()
	return n, nil
}

// ssCredential decodes the SIP002 userinfo: base64url(method:password) when
// it is a clean base64 payload, else plaintext "method:password".
func ssCredential(userinfo string) (string, string, error) {
	if decoded, derr := decodeFlexible(userinfo); derr == nil {
		if m, p, ok := strings.Cut(decoded, ":"); ok && m != "" {
			return m, p, nil
		}
	}
	m, p, ok := strings.Cut(userinfo, ":")
	if !ok || m == "" || p == "" {
		return "", "", errors.New("ss userinfo is neither base64(method:password) nor method:password")
	}
	return m, p, nil
}

// parseVMESS handles the two real-world vmess encodings: base64(JSON) (the
// standard) and base64("uuid@host:port?query") (an aggregator variant).
func parseVMESS(source, line string) (*model.Node, error) {
	payload, err := decodeFlexible(strings.TrimPrefix(line, "vmess://"))
	if err != nil {
		return nil, fmt.Errorf("vmess base64: %w", err)
	}
	payload = strings.TrimSpace(payload)
	if strings.HasPrefix(payload, "{") {
		return parseVMESSJSON(source, payload)
	}
	if i := strings.Index(payload, "@"); i > 0 {
		return parseUserinfoLink(source, SchemeVMESS, "vmess://"+payload)
	}
	return nil, errors.New("vmess payload is neither JSON nor userinfo")
}

func parseVMESSJSON(source, payload string) (*model.Node, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		return nil, fmt.Errorf("vmess json: %w", err)
	}
	get := vmessFieldGetter(raw)
	host := get("add")
	if host == "" {
		return nil, errors.New("vmess json: empty add")
	}
	port, err := strconv.Atoi(get("port"))
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("vmess json: invalid port %q", get("port"))
	}
	id := get("id")
	if id == "" {
		return nil, errors.New("vmess json: empty id")
	}
	params := vmessParams(raw, get)
	n := model.NewNode(source, SchemeVMESS, id, host, port, params)
	n.Fragment = get("ps")
	n.LastSeen = time.Now().UTC()
	return n, nil
}

// vmessFieldGetter renders vmess JSON values (string or number) as strings.
func vmessFieldGetter(raw map[string]any) func(string) string {
	return func(k string) string {
		switch v := raw[k].(type) {
		case string:
			return v
		case float64:
			if v == float64(int64(v)) {
				return strconv.FormatInt(int64(v), 10)
			}
			return strconv.FormatFloat(v, 'f', -1, 64)
		default:
			return ""
		}
	}
}

// vmessParams maps vmess JSON vocabulary onto the common param names so the
// filter and renderer see one shape.
func vmessParams(raw map[string]any, get func(string) string) map[string]string {
	params := map[string]string{
		"net": get("net"),
		"tls": strings.ToLower(get("tls")),
		"sni": get("sni"),
	}
	if raw["host"] != nil {
		params["host"] = get("host")
	}
	if raw["path"] != nil {
		params["path"] = get("path")
	}
	if raw["type"] != nil {
		params["type"] = get("type")
	}
	params["aid"] = get("aid")
	if params["aid"] == "" {
		params["aid"] = "0"
	}
	for _, key := range []string{"scy", "alpn", "fp", "pbk", "sid", "spx", "pqv"} {
		if raw[key] != nil {
			params[key] = get(key)
		}
	}
	// Network precedence: vmess JSON carries the transport in "net" (the
	// equivalent of vless's type= query param); vmess "type" is the legacy
	// header-obfuscation field and must NEVER win as the network — so net
	// overwrites type unconditionally. Downstream (render.networkOf) reads
	// type with net as fallback, and the two hold the same value here.
	// The header-obfuscation datum itself (tcp http-obfs) is preserved as
	// headerType so tcp+type=http links render their header block.
	if h := params["type"]; h != "" && h != "none" && params["net"] != h {
		params["headerType"] = h
	}
	if net := params["net"]; net != "" {
		params["type"] = net
	}
	switch {
	case params["tls"] == "reality" || params["pbk"] != "":
		params["security"] = "reality"
	case params["tls"] == "tls":
		params["security"] = "tls"
	}
	return params
}

// base64Encodings is the standard-or-URL-safe, padding-optional decoder
// ladder shared by decodeFlexible (per-link payloads) and
// decodeFlexibleBytes (whole bodies).
var base64Encodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
	base64.URLEncoding,
	base64.RawURLEncoding,
}

// decodeFlexible decodes standard or URL-safe base64, padding optional.
func decodeFlexible(s string) (string, error) {
	s = strings.TrimSpace(s)
	var lastErr error
	for _, enc := range base64Encodings {
		b, err := enc.DecodeString(s)
		if err == nil {
			return string(b), nil
		}
		lastErr = err
	}
	return "", lastErr
}

// IsPrivateHost reports whether a host is an IP literal in a non-routable
// range, a loopback name, or an mDNS name — the filter-stage drop set.
func IsPrivateHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || strings.HasSuffix(h, ".localhost") ||
		strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return true
	}
	addr, err := netip.ParseAddr(strings.Trim(h, "[]"))
	if err != nil {
		return false // hostname, not an IP literal — probe stage decides reachability
	}
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() ||
		addr.IsInterfaceLocalMulticast()
}
