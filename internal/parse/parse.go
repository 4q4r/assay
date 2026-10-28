// Package parse turns raw fetched source bodies into normalized nodes.
// It accepts vless/vmess/trojan/ss links, rejects schemes outside xray-core
// (tuic/hy2/hysteria/hysteria2/ssr), and never fails fatally on malformed
// lines — they are counted and reported. Protocol acceptance is a FILTER
// policy ([filter].protocols allowlist): parse normalizes everything it can.
package parse

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"public_vpn/internal/model"
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

// Result aggregates one parse wave over one or many source bodies.
type Result struct {
	Nodes         []*model.Node
	Rejected      int            // links with a scheme outside xray-core
	RejectedKinds map[string]int // scheme -> count
	Malformed     int            // accepted-scheme links that failed to parse
	Blank         int            // blank/comment lines
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

// Lines parses a whole fetched body. Base64 bodies are detected and decoded
// first; remaining lines are parsed one by one.
func Lines(source, body string) *Result {
	res := &Result{RejectedKinds: map[string]int{}}
	body = decodeIfBase64(body)
	for _, raw := range splitLines(body) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			res.Blank++
			continue
		}
		scheme := schemeOf(line)
		if scheme == "" {
			res.Malformed++
			continue
		}
		if rejectedSchemes[scheme] {
			res.Rejected++
			res.RejectedKinds[scheme]++
			continue
		}
		if !IsSupported(line) {
			res.Malformed++
			continue
		}
		n, err := Link(source, line)
		if err != nil {
			res.Malformed++
			continue
		}
		res.Nodes = append(res.Nodes, n)
	}
	return res
}

// decodeIfBase64 decodes a whole-body base64 payload: subscription files are
// often a single base64 blob of newline-separated links. Detection is strict —
// the body must have no link scheme at all, decode cleanly, and the decoded
// text must contain at least one scheme.
func decodeIfBase64(body string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || strings.Contains(trimmed, "://") {
		return body
	}
	decoded, err := decodeFlexible(trimmed)
	if err != nil || !strings.Contains(decoded, "://") {
		return body
	}
	return decoded
}

// splitLines handles LF and CRLF.
func splitLines(body string) []string {
	return strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
}

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

// decodeFlexible decodes standard or URL-safe base64, padding optional.
func decodeFlexible(s string) (string, error) {
	s = strings.TrimSpace(s)
	encoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encoders {
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
