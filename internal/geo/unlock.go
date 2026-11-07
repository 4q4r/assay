package geo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"public_vpn/internal/checker"
	"public_vpn/internal/model"
)

// Phase-1 IP quality & media unlock battery: runs for EVERY node the probe
// proved alive (per-wave per-alive-node — no eligibility gating, no
// freshness gates). On a fresh verdict the record stores the battery's
// version; the CURRENT battery version gates the stored verdicts' staleness
// (a verdict written by an older battery is stale on sight — the v1→v2
// migration semantics; freshUnlock pins the data contract). The battery
// probes ChatGPT / Netflix / YouTube / Disney+ / TikTok unlocks plus IP
// quality THROUGH that exit's own hot tunnel (the SAME instance the probe
// just proved — owner order 2026-11-07 «сразу на чеке»: the separate
// geo/unlock stages, their 24h freshness gates, the exit-IP cache and the
// eligibility layers are REMOVED; classification is per-wave per-alive-node
// and the geo-base records refresh every wave). Probe semantics are the
// ip.check.place reference (xykt/IPQuality); failures are non-fatal — the
// verdict records "unknown" and the wave never hangs (per-request budgets).

const (
	// UnlockTTL is the freshness window of one exit IP's quality + media
	// verdicts (the spec's 7-day cache: a re-check of the same exit inside
	// the window costs zero network calls). Only fully definite verdicts
	// get the full window; unknown-carrying ones take UnlockUnknownTTL.
	UnlockTTL = 7 * 24 * time.Hour
	// UnlockUnknownTTL bounds how long a verdict carrying any unknown or
	// unchecked media field stays cached (owner order 2026-11-06): a
	// dead-tunnel-at-probe-time exit used to poison its verdicts with
	// "unknown" for the full 7-day window and stayed unclassified for a
	// week even once its tunnel recovered. Unknown-carrying verdicts now go
	// stale after a day; fully definite ones keep UnlockTTL.
	UnlockUnknownTTL = 24 * time.Hour
	// UnlockBatteryVersion is the CURRENT unlock battery's version. Verdicts
	// stamped with a lower version are stale REGARDLESS of their TTL
	// (freshUnlock): the v1 battery scored hijack exits "yes" (no exit-echo
	// consensus, no hijack detector, no contract checks), so every pre-v2
	// cached definite verdict is re-probed exactly once by the first wave
	// after the upgrade — the one-time migration sweep — and v2 verdicts
	// then serve their normal windows.
	UnlockBatteryVersion = 2
	// unlockRequestTimeout bounds ONE probe request (the spec's 3s): every
	// request carries its own context budget, so no slow service hangs a
	// wave.
	unlockRequestTimeout = 3 * time.Second
	// unlockRetryStagger is the inter-attempt delay of the retry-once
	// wrapper: an endpoint that failed transport-level gets ONE re-shot
	// after this stagger; a pass after exactly one failure is the OK_FLAKY
	// class (the research: ~25% of the unknown mass was unstable links, not
	// policy), both passes failing is the deterministic class.
	unlockRetryStagger = 500 * time.Millisecond
	// unlockBodyLimit bounds HTML-ish probe bodies (title/premium/home
	// pages); unlockJSONLimit bounds the JSON endpoints.
	unlockBodyLimit = 4 << 20
	unlockJSONLimit = 256 << 10
	// unlockClockSkew tolerates a CheckedAt slightly in the future (clock
	// difference between the writing and the reading wave).
	unlockClockSkew = time.Minute
)

// Reference probe material (xykt/IPQuality ref/cookies.txt): the published
// Disney+ SPA token and fixed device/token/graphql request bodies plus the
// YouTube consent cookies. This is public CLIENT-side material shipped to
// every browser — not a credential.
const (
	//nolint:gosec // public SPA token from the reference's ref/cookies.txt — client material, not a credential
	disneyBearer = "ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84"
	// disneyTokenBody carries DISNEYASSERTION — replaced with the assertion
	// the /devices step returns (reference cookies.txt line 1).
	disneyTokenBody = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" +
		"&latitude=0&longitude=0&platform=browser&subject_token=DISNEYASSERTION" +
		"&subject_token_type=urn%3Abamtech%3Aparams%3Aoauth%3Atoken-type%3Adevice"
	// disneyGraphQLBody carries ILOVEDISNEY — replaced with the token
	// response's refresh_token (reference cookies.txt line 8; \n stays
	// literal, the JSON escape).
	disneyGraphQLBody = `{"query":"mutation refreshToken($input: RefreshTokenInput!) {\n` +
		`            refreshToken(refreshToken: $input) {\n` +
		`                activeSession {\n                    sessionId\n                }\n` +
		`            }\n        }","variables":{"input":{"refreshToken":"ILOVEDISNEY"}}}`
	disneyDeviceBody = `{"deviceFamily":"browser","applicationRuntime":"chrome",` +
		`"deviceProfile":"windows","attributes":{}}`
	youtubeCookies = "YSC=BiCUU3-5Gdk; CONSENT=YES+cb.20220301-11-p0.en+FX+700; GPS=1; " +
		"VISITOR_INFO1_LIVE=4VwPMkB7W5A; PREF=tz=Asia.Shanghai; _gcl_au=1.1.1809531354.1646633279"
)

// Reference markers the classifiers grep for.
const (
	unsupportedCountryMarker  = "unsupported_country"
	netflixUnavailableMarker  = "Oh no!"
	youtubeCNMarker           = "www.google.cn"
	youtubeNoPremiumMarker    = "Premium is not available in your country"
	tikTokChallengeMarker     = "Please wait..."
	disneyForbiddenLocation   = "forbidden-location"
	disneyForbidden403Marker  = "403 ERROR"
	headerAuthorization       = "Authorization"
	headerAcceptLanguage      = "Accept-Language"
	headerCookie              = "Cookie"
	headerOrigin              = "Origin"
	headerReferer             = "Referer"
	platformOpenAIOrigin      = "https://platform.openai.com"
	platformOpenAIReferer     = "https://platform.openai.com/"
	disneyDeviceContentType   = "application/json; charset=UTF-8"
	jsonContentType           = "application/json"
	formURLEncodedContentType = "application/x-www-form-urlencoded"
)

// UnlockEndpoints are the Phase-1 probe URLs — a test seam (nil = the
// production defaults), exactly like Input.SelfURL. The v2 battery extends
// the set with the exit-truth channels (cftrace primary echo, the ipify /
// ip.sb consensus echoes, the ip-api body-contract hijack probe, the OS
// connectivity-check tunnel-alive gate, the DNS-authoritative TCP channel
// and the STUN server for hysteria2): the *Server/*Name fields are
// host:port strings where "" disables the channel (tests stay hermetic;
// production defaults fill them).
type UnlockEndpoints struct {
	ChatGPCTrace      string
	ChatGPTCompliance string
	NetflixTitleA     string
	NetflixTitleB     string
	YouTubePremium    string
	TikTokHome        string
	TikTokExplore     string
	DisneyDevices     string
	DisneyAuth        string
	DisneyGraphQL     string
	IPInfoWidget      string
	// CFTrace is the PRIMARY exit-IP echo: www.cloudflare.com/cdn-cgi/trace
	// through the tunnel (ip= is the connecting IP; colo=/loc= evidence).
	CFTrace string
	// EchoIPify / EchoIPSB are consensus echoes 2 and 3 (api.ipify.org and
	// api.ip.sb/ip, plain-text IPs over HTTPS).
	EchoIPify string
	EchoIPSB  string
	// IPAPIContract is the plain-HTTP ip-api answer the hijack detector
	// body-contracts: a 200 whose JSON lacks a parseable query-field IP is
	// the fake-answer hijack signature (the 24-byte magiclampcloud shape).
	IPAPIContract string
	// AlivePrimary / AliveFallback are the OS connectivity-check endpoints
	// the tunnel-alive gate rides (gstatic generate_204, msft
	// connecttest.txt) — the highest blocking cost an operator can pay.
	AlivePrimary  string
	AliveFallback string
	// DNSServer is the DNS-over-TCP authoritative echo target
	// (216.239.32.10:53) and DNSName the TXT owner
	// (o-o.myaddr.l.google.com); "" disables the channel.
	DNSServer string
	DNSName   string
	// STUNServer is the RFC 5389 Binding target for hysteria2 nodes
	// (stun.l.google.com:19302); "" disables the channel.
	STUNServer string
}

func defaultUnlockEndpoints() UnlockEndpoints {
	return UnlockEndpoints{
		ChatGPCTrace:      "https://chatgpt.com/cdn-cgi/trace",
		ChatGPTCompliance: "https://api.openai.com/compliance/cookie_requirements",
		NetflixTitleA:     "https://www.netflix.com/title/81280792",
		NetflixTitleB:     "https://www.netflix.com/title/70143836",
		YouTubePremium:    "https://www.youtube.com/premium",
		TikTokHome:        "https://www.tiktok.com/",
		TikTokExplore:     "https://www.tiktok.com/explore",
		DisneyDevices:     "https://disney.api.edge.bamgrid.com/devices",
		DisneyAuth:        "https://disney.api.edge.bamgrid.com/token",
		DisneyGraphQL:     "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql",
		IPInfoWidget:      "https://ipinfo.io/widget/demo/",
		CFTrace:           "https://www.cloudflare.com/cdn-cgi/trace",
		EchoIPify:         "https://api.ipify.org",
		EchoIPSB:          "https://api.ip.sb/ip",
		IPAPIContract:     "http://ip-api.com/json/",
		AlivePrimary:      "https://connectivitycheck.gstatic.com/generate_204",
		AliveFallback:     "https://www.msftconnecttest.com/connecttest.txt",
		DNSServer:         "216.239.32.10:53",
		DNSName:           "o-o.myaddr.l.google.com",
		STUNServer:        "stun.l.google.com:19302",
	}
}

// Echo channel names (the evidence classes recorded per source).
const (
	echoCFTrace = "cftrace"
	echoIPify   = "ipify"
	echoIPSB    = "ipsb"
	echoIPAPI   = "ipapi"
	// Echo outcome classes.
	echoOK     = "ok"
	echoHijack = "hijack"
	echoBad    = "suspect" // contract violation: the answer is not a parseable exit IP
	echoErr    = "err"     // transport/rate-limit failure — recorded, non-fatal, NOT hijack
)

// EchoResult is ONE echo channel's outcome for one exit: the parsed exit IP
// ("" when the channel failed or the body broke its contract) and the
// outcome class.
type EchoResult struct {
	Source string
	IP     string
	Class  string
	Detail string
}

// ExitEvidence is one battery run's evidence bundle for ONE exit. It is the
// in-memory shape; the verdict-shaped subset folds into the persisted
// MediaUnlockStatus (stampEvidence).
type ExitEvidence struct {
	TunnelAlive   bool
	Echo          []EchoResult
	ConsensusIP   string // pinned when ≥2 echo sources agree
	Consensus     int    // agreeing echo sources
	Rotating      bool   // echo IPs span >1 distinct /24
	Hijack        bool
	HijackReasons []string
	CFColo        string
	CFLoc         string
	DNSIP         string
	StunIP        string
	FlakyCount    int // endpoints recovered on the retry pass (OK_FLAKY)
}

// flag marks a hijack reason (evidence list) and raises the exit-level flag.
func (e *ExitEvidence) flag(reason string) {
	e.Hijack = true
	e.HijackReasons = append(e.HijackReasons, reason)
}

// IPQuality is the Phase-1 quality verdict for one exit IP. ScamalyticsScore
// and AbuseScore stay -1 (unchecked): Phase 1 probes no such source — the
// WorstAbuse thresholds are the mapping contract for when one is added.
type IPQuality struct {
	RiskScore        int
	IsResidential    bool
	IsHosting        bool
	IsProxy          bool
	IsMobile         bool
	ScamalyticsScore int
	AbuseScore       int
	IPType           string
}

// IPInfoWidget is the ipinfo.io widget/demo answer shape (verified live
// against https://ipinfo.io/widget/demo/<ip>): the ASN type plus the privacy
// block — the honest proxy/vpn/tor/hosting evidence the free /json tier
// lacks.
type IPInfoWidget struct {
	Data struct {
		ASN struct {
			Type string `json:"type"`
		} `json:"asn"`
		Privacy struct {
			VPN     bool `json:"vpn"`
			Proxy   bool `json:"proxy"`
			Tor     bool `json:"tor"`
			Hosting bool `json:"hosting"`
		} `json:"privacy"`
		IsMobile    bool `json:"is_mobile"`
		IsHosting   bool `json:"is_hosting"`
		IsAnonymous bool `json:"is_anonymous"`
	} `json:"data"`
}

// ParseIPInfoWidget decodes one widget answer; invalid JSON is an error.
func ParseIPInfoWidget(body string) (*IPInfoWidget, error) {
	var out IPInfoWidget
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return nil, fmt.Errorf("decode ipinfo widget: %w", err)
	}
	return &out, nil
}

// ParseCDNTrace extracts the `loc=` value of a cdn-cgi/trace body (the
// exit's country as Cloudflare sees it); "" when the line is absent.
func ParseCDNTrace(body string) string {
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if val, ok := strings.CutPrefix(line, "loc="); ok {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

// ParseChatGPTCompliance reports whether the compliance answer carries the
// unsupported_country marker (true = the exit's country is unsupported).
func ParseChatGPTCompliance(body string) bool {
	return strings.Contains(body, unsupportedCountryMarker)
}

// CFTraceEvidence is the parsed cdn-cgi/trace contract: ip= is the
// connecting (exit) IP, colo=/loc= the Cloudflare evidence fields.
type CFTraceEvidence struct {
	IP   string
	Colo string
	Loc  string
}

// ParseCFTrace extracts the key=value lines of a cdn-cgi/trace body. ok is
// the BODY CONTRACT: a trace that does not carry a parseable ip= line is
// not evidence — through a hijacking exit it is the fake-body signature
// (suspect class), never an exit answer. A parseable ip= is stored in the
// CANONICAL net.ParseIP text form (raw otherwise): textual variants of one
// address must not split the echoConsensus buckets — parsePlainIPEcho
// normalizes the same way.
func ParseCFTrace(body string) (CFTraceEvidence, bool) {
	var ev CFTraceEvidence
	for line := range strings.SplitSeq(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			ev.IP = strings.TrimSpace(v)
		case "colo":
			ev.Colo = strings.TrimSpace(v)
		case "loc":
			ev.Loc = strings.TrimSpace(v)
		}
	}
	ip := net.ParseIP(ev.IP)
	if ip == nil {
		return ev, false
	}
	ev.IP = ip.String()
	return ev, true
}

// hijackTLSError reports whether a transport error is a TLS-LAYER intercept
// signature observed through the tunnel: a certificate the system pool
// rejects (the MITM presented its own cert), or PLAINTEXT answered where
// TLS was mandated ("server gave HTTP response to HTTPS client",
// tls.RecordHeaderError — the magiclampcloud plain-HTTP-on-:443 shape).
// Timeouts, resets and EOFs are NOT hijack evidence — those are the
// dead-tunnel / flaky-link classes.
func hijackTLSError(err error) bool {
	if err == nil {
		return false
	}
	// The x509/tls error types carry VALUE receivers in the current
	// toolchain (and historically shipped pointer-typed wraps), so both
	// shapes are matched — a MITM signature must classify regardless of how
	// the transport wrapped it.
	var certErr x509.CertificateInvalidError
	var certErrPtr *x509.CertificateInvalidError
	var hostErr x509.HostnameError
	var hostErrPtr *x509.HostnameError
	var authErr x509.UnknownAuthorityError
	var recordErr tls.RecordHeaderError
	if errors.As(err, &certErr) || errors.As(err, &certErrPtr) ||
		errors.As(err, &hostErr) || errors.As(err, &hostErrPtr) ||
		errors.As(err, &authErr) || errors.As(err, &recordErr) {
		return true
	}
	return strings.Contains(err.Error(), "server gave HTTP response to HTTPS client")
}

// parsePlainIPEcho contracts a plain-text IP echo body (ipify / ip.sb):
// the trimmed body must be exactly a parseable IP — anything else is the
// suspect/garbage class.
func parsePlainIPEcho(body string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(body))
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// validateIPAPIBody contracts the plain-HTTP ip-api answer (hijack
// detector, HTTP family): the body MUST decode as JSON carrying a query
// field with a parseable IP — the hijacked 24-byte fake answer had no
// contract fields. Returns the query IP when the contract held.
func validateIPAPIBody(body string) (string, bool) {
	var resp struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return "", false
	}
	ip := net.ParseIP(strings.TrimSpace(resp.Query))
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// echoConsensusOut is the consensus verdict over the echo outcomes.
type echoConsensusOut struct {
	IP       string // pinned when ≥2 echo sources agree ("" otherwise)
	Agree    int    // agreeing echo sources
	Rotating bool   // echo IPs span >1 distinct /24
}

// echoConsensus folds the echo outcomes into the exit-IP verdict: ≥2
// sources agreeing on the exact IP pin it (consensus = the agree count,
// the minority is noted in the echo list), no agreement pins nothing, and
// echo IPs spanning MORE THAN ONE distinct /24 raise the ROTATING flag —
// those exits serve different egresses per request, so a single IP must
// never become the classification identity.
func echoConsensus(echoes []EchoResult) echoConsensusOut {
	counts := map[string]int{}
	order := []string{}
	var nets []string
	seen24 := map[string]bool{}
	for _, e := range echoes {
		if e.Class != echoOK || e.IP == "" {
			continue
		}
		if _, ok := counts[e.IP]; !ok {
			order = append(order, e.IP)
		}
		counts[e.IP]++
		slash24 := "v6:" + e.IP
		if p := net.ParseIP(e.IP); p != nil {
			if v4 := p.To4(); v4 != nil {
				slash24 = v4.Mask(net.CIDRMask(24, 32)).String()
			}
		}
		if !seen24[slash24] {
			seen24[slash24] = true
			nets = append(nets, slash24)
		}
	}
	for _, candidate := range order {
		if counts[candidate] >= 2 {
			return echoConsensusOut{IP: candidate, Agree: counts[candidate], Rotating: len(nets) > 1}
		}
	}
	return echoConsensusOut{Rotating: len(nets) > 1}
}

// ClassifyChatGPT maps the two probe outcomes onto the stored vocabulary.
// Both rungs must succeed to evaluate (a failed reachability or compliance
// rung = no evidence = unknown). The reference's webonly/blocked branches
// need its ios.chat.openai.com VPN signal, which is unusable from datacenter
// exits (verified live: 403, Cloudflare `dc` block), so an unsupported
// country maps to apponly and the other two values stay reserved.
func ClassifyChatGPT(unsupported, traceOK, complianceOK bool) string {
	if !traceOK || !complianceOK {
		return model.UnlockUnknown
	}
	if unsupported {
		return model.UnlockAppOnly
	}
	return model.UnlockYes
}

// netflixRegionRe / netflixCountryRe implement the reference's greedy sed
// explicitly: the LAST `"id":"…"` on the body that is followed by a
// `"countryName":"…"` (Go's regexp cannot express greedy-backtrack
// "last pair wins" with a leading .*, so the scan is done by hand).
var (
	netflixRegionRe  = regexp.MustCompile(`"id":"([^"]*)"`)
	netflixCountryRe = regexp.MustCompile(`"countryName":"[^"]*"`)
)

// ExtractNetflixRegion pulls the catalog region out of a title page; ""
// when the page carries no id/countryName pair.
func ExtractNetflixRegion(body string) string {
	ids := netflixRegionRe.FindAllStringSubmatchIndex(body, -1)
	for _, id := range slices.Backward(ids) {
		if netflixCountryRe.MatchString(body[id[1]:]) {
			return body[id[2]:id[3]]
		}
	}
	return ""
}

// isDefiniteBlock: the statuses that are a definite geo-block answer (the
// reference's `-f` collapses every HTTP >=400 into "Failed"; the stored
// vocabulary has no failed value, so these map to blocked and any other
// non-200 stays unknown).
func isDefiniteBlock(status int) bool {
	return status == http.StatusForbidden || status == http.StatusUnavailableForLegalReasons
}

// ClassifyNetflix maps the two title-page probes: either title in catalog =
// full unlock, both hitting the "Oh no!" page = originals-only.
func ClassifyNetflix(errA, errB error, statusA, statusB int, bodyA, bodyB string) string {
	if errA != nil || errB != nil {
		return model.UnlockUnknown
	}
	if isDefiniteBlock(statusA) || isDefiniteBlock(statusB) {
		return model.UnlockBlocked
	}
	if statusA != http.StatusOK || statusB != http.StatusOK {
		return model.UnlockUnknown
	}
	// Empty or whitespace-stripped 200 bodies carry no catalog evidence —
	// fail-unknown, strictly more conservative (the owner's fail-closed
	// ruling): a transparent-proxy 200 with a stripped body must never
	// fabricate full-unlock evidence (adversarial review F5).
	if strings.TrimSpace(bodyA) == "" || strings.TrimSpace(bodyB) == "" {
		return model.UnlockUnknown
	}
	blockedA := strings.Contains(bodyA, netflixUnavailableMarker)
	blockedB := strings.Contains(bodyB, netflixUnavailableMarker)
	if blockedA && blockedB {
		return model.UnlockNetflixOriginals
	}
	return model.UnlockNetflixFull
}

var youTubeRegionRe = regexp.MustCompile(`"contentRegion":"([^"]*)"`)

func extractContentRegion(body string) string {
	if m := youTubeRegionRe.FindStringSubmatch(body); m != nil {
		return strings.ToUpper(m[1])
	}
	return ""
}

// ClassifyYouTube maps the premium page: a CN redirect or an explicit
// "not available" marker = blocked, otherwise the parsed contentRegion
// (ISO-2) is the verdict; a 200 page without region evidence = unknown.
func ClassifyYouTube(body string, status int, err error) string {
	if err != nil {
		return model.UnlockUnknown
	}
	if isDefiniteBlock(status) {
		return model.UnlockBlocked
	}
	if status != http.StatusOK {
		return model.UnlockUnknown
	}
	if strings.Contains(body, youtubeCNMarker) || strings.Contains(body, youtubeNoPremiumMarker) {
		return model.UnlockBlocked
	}
	if region := extractContentRegion(body); region != "" {
		return region
	}
	return model.UnlockUnknown
}

var tikTokRegionRe = regexp.MustCompile(`"region":"([^"]*)"`)

// ExtractTikTokRegion pulls the first `"region":"XX"` value of a TikTok
// page; "" when absent.
func ExtractTikTokRegion(body string) string {
	if m := tikTokRegionRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// ParseDisneySession reads the bamgrid graphql session answer
// (.extensions.sdk.session.location.countryCode + inSupportedLocation).
// ok = false only when the body is not JSON at all (infrastructure
// failure); a valid JSON without the session path carries country "" —
// the reference's jq-null case, classified as blocked.
func ParseDisneySession(body string) (string, bool, bool) {
	var resp struct {
		Extensions struct {
			SDK struct {
				Session struct {
					Location struct {
						CountryCode string `json:"countryCode"`
					} `json:"location"`
					InSupportedLocation bool `json:"inSupportedLocation"`
				} `json:"session"`
			} `json:"sdk"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return "", false, false
	}
	return resp.Extensions.SDK.Session.Location.CountryCode,
		resp.Extensions.SDK.Session.InSupportedLocation, true
}

// ClassifyDisney maps the session answer: JP is the reference's special
// yes-case, a known supported country = yes. The reference's "pending"
// (country known, not yet supported) collapses to blocked — the Phase-1
// vocabulary is yes/blocked only; a session-less valid answer = blocked.
func ClassifyDisney(country string, inSupported, ok bool) string {
	if !ok {
		return model.UnlockUnknown
	}
	if country == "JP" || (country != "" && inSupported) {
		return model.UnlockYes
	}
	return model.UnlockBlocked
}

// ComputeRiskScore maps evidence onto the spec's exact ranges:
// proxy → 70 + round(30·abuse) (70..100), hosting → 25 + round(15·abuse)
// (25..40), clean → round(15·abuse) (0..15). abuse ∈ [0,1] is the worst
// normalized abuse signal (0 when no source is checked).
func ComputeRiskScore(proxy, hosting bool, abuse float64) int {
	abuse = math.Min(1, math.Max(0, abuse))
	switch {
	case proxy:
		return 70 + int(math.Round(30*abuse))
	case hosting:
		return 25 + int(math.Round(15*abuse))
	default:
		return int(math.Round(15 * abuse))
	}
}

// BandScore normalizes a 0..100 source score onto [0,1] with the reference
// thresholds (Scamalytics <20/<60/<90, AbuseIPDB <25/<75, IPQS <75/<85/<90):
// below the first → 0, then 0.5, 0.75, top band → 1. The weight table is
// truncated to len(thresholds)+1 bands, so a two-threshold source tops out
// at 0.75.
func BandScore(score int, thresholds []int) float64 {
	weights := [...]float64{0, 0.5, 0.75, 1}
	band := 0
	for _, t := range thresholds {
		if score >= t {
			band++
		}
	}
	if band >= len(weights) {
		return weights[len(weights)-1]
	}
	return weights[band]
}

// WorstAbuse normalizes the three reference abuse sources and returns the
// worst present value (-1 = unchecked source, skipped; 0 when none checked).
func WorstAbuse(scamalytics, abuseIPDB, ipqs int) float64 {
	worst := 0.0
	if scamalytics >= 0 {
		worst = math.Max(worst, BandScore(scamalytics, []int{20, 60, 90}))
	}
	if abuseIPDB >= 0 {
		worst = math.Max(worst, BandScore(abuseIPDB, []int{25, 75}))
	}
	if ipqs >= 0 {
		worst = math.Max(worst, BandScore(ipqs, []int{75, 85, 90}))
	}
	return worst
}

func ipTypeOf(isMobile, isHosting bool, asnType string) string {
	switch {
	case isMobile:
		return model.IPTypeMobile
	case isHosting:
		return model.IPTypeDataCenter
	case asnType == "business" || asnType == "education":
		return model.IPTypeBusiness
	case asnType == "isp":
		return model.IPTypeResidential
	default:
		return model.IPTypeUnknown
	}
}

// ComputeIPQuality folds the through-tunnel evidence (the representative
// report's ip-api answer and the in-tunnel widget answer) into the verdict.
// Both inputs nil = no evidence = nil (the caller leaves the record
// untouched). A proxy exit keeps its underlying network type: IPType
// describes the network, IsProxy the usage.
func ComputeIPQuality(g *Response, w *IPInfoWidget) *IPQuality {
	if g == nil && w == nil {
		return nil
	}
	var isHosting, isProxy, isMobile bool
	if g != nil {
		isHosting, isProxy, isMobile = g.Hosting, g.Proxy, g.Mobile
	}
	asnType := ""
	if w != nil {
		asnType = strings.ToLower(w.Data.ASN.Type)
		isHosting = isHosting || w.Data.Privacy.Hosting || w.Data.IsHosting || asnType == "hosting"
		isProxy = isProxy || w.Data.Privacy.Proxy || w.Data.Privacy.VPN || w.Data.Privacy.Tor
		isMobile = isMobile || w.Data.IsMobile
	}
	// The widget's asn.type is the only honest isp evidence: ip-api's isp
	// STRING exists on every IP including datacenters.
	isp := asnType == "isp"
	return &IPQuality{
		RiskScore:        ComputeRiskScore(isProxy, isHosting, WorstAbuse(-1, -1, -1)),
		IsResidential:    !isHosting && !isProxy && (isp || isMobile),
		IsHosting:        isHosting,
		IsProxy:          isProxy,
		IsMobile:         isMobile,
		ScamalyticsScore: -1,
		AbuseScore:       -1,
		IPType:           ipTypeOf(isMobile, isHosting, asnType),
	}
}

// unlockProbe is ONE exit's probe session: the through-tunnel clients (the
// TLS-validated HTTP battery client and the checker tunnel client for the
// DNS/STUN channels), the ONE pipeline user agent, the endpoint set, the
// shared pacing, the clock and the exit identity — every rung of every
// service rides the same temp socks instance. tlsRoots is the test seam for
// the certificate pool (nil = the SYSTEM pool — production validates every
// HTTPS answer against the real WebPKI; a fixture self-signed cert fails
// validation exactly like a MITM).
type unlockProbe struct {
	cl     *http.Client
	tc     *checker.TunnelClient // DNS-over-TCP + STUN channels; nil = disabled
	ua     string
	ep     UnlockEndpoints
	pac    *pacer
	sleep  func(ctx context.Context, d time.Duration) error
	now    func() time.Time
	exitIP string
	scheme string // the representative node's scheme (STUN rides hysteria2/hy2 only)
	flaky  int    // endpoints recovered on the retry pass (OK_FLAKY count)
}

// buildUnlockClient builds the battery's HTTP client: the ONLY transport
// path is the temp instance's socks endpoint (socks5h — hostnames resolve
// at the exit), certificate validation is ALWAYS on against roots (nil =
// the system pool), and Proxy is nil — the L5 landmine guard: the ambient
// http_proxy of the owner's shell must never carry unlock traffic.
func buildUnlockClient(socksAddr string, timeout time.Duration, roots *x509.CertPool) (*http.Client, error) {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks dialer: %w", err)
	}
	dialer, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks dialer: no context support")
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			Proxy:       nil, // L5: NEVER http.ProxyFromEnvironment here
			TLSClientConfig: &tls.Config{
				RootCAs:    roots, // nil = system pool (production)
				MinVersion: tls.VersionTLS12,
			},
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   true, // 1–2 requests per instance: reuse buys nothing
		},
		Timeout: timeout,
	}, nil
}

// getRetry is the retry-once wrapper (item 7): a TRANSPORT-level failure
// gets exactly one re-shot after the ~500ms stagger (the pacer re-slots the
// attempt); a recovered pass counts the endpoint OK_FLAKY. HTTP statuses
// are DATA (the classifiers interpret them) and are never retried.
func (p *unlockProbe) getRetry(ctx context.Context, endpoint string, headers map[string]string) (int, string, error) {
	st, body, err := p.do(ctx, http.MethodGet, endpoint, "", "", headers, unlockBodyLimit)
	if err == nil {
		return st, body, nil
	}
	if ctx.Err() != nil {
		return st, body, err
	}
	if p.sleep != nil {
		if serr := p.sleep(ctx, unlockRetryStagger); serr != nil {
			return st, body, err
		}
	}
	st, body, err = p.do(ctx, http.MethodGet, endpoint, "", "", headers, unlockBodyLimit)
	if err == nil {
		p.flaky++ // the OK_FLAKY count: this endpoint recovered on the retry pass
		return st, body, nil
	}
	return st, body, err
}

func (p *unlockProbe) postJSON(
	ctx context.Context, endpoint, body string, headers map[string]string,
) (int, string, error) {
	return p.do(ctx, http.MethodPost, endpoint, jsonContentType, body, headers, unlockJSONLimit)
}

func (p *unlockProbe) postForm(
	ctx context.Context, endpoint, body string, headers map[string]string,
) (int, string, error) {
	return p.do(ctx, http.MethodPost, endpoint, formURLEncodedContentType, body, headers, unlockBodyLimit)
}

// do performs ONE probe request: its own pacing slot and 3s context budget,
// a bounded body read, the pipeline UA and the caller's headers. A non-2xx
// status is DATA (the classifiers interpret it), not an error — only
// transport failures are err.
func (p *unlockProbe) do(ctx context.Context, method, endpoint, contentType, body string,
	headers map[string]string, limit int64,
) (int, string, error) {
	if err := p.pac.wait(ctx); err != nil {
		return 0, "", err
	}
	reqCtx, cancel := context.WithTimeout(ctx, unlockRequestTimeout)
	defer cancel()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, endpoint, rdr)
	if err != nil {
		return 0, "", err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", p.ua)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := p.cl.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(b), nil
}

// chatgpt runs the trace + compliance pair with the retry-once wrapper. A
// TLS-layer intercept signature on either rung is the HIJACK class: the
// exit intercepts TLS, so "yes" is unreachable by construction — the
// verdict is blocked (the second return flags the exit-level hijack).
func (p *unlockProbe) chatgpt(ctx context.Context) (string, bool) {
	st, body, err := p.getRetry(ctx, p.ep.ChatGPCTrace, nil)
	traceHijack := err != nil && hijackTLSError(err)
	traceOK := err == nil && st == http.StatusOK
	if traceOK {
		// The trace's loc= line is the reachability proof (the reference
		// greps it): an unparseable trace is no evidence.
		traceOK = ParseCDNTrace(body) != ""
	}
	st, body, err = p.getRetry(ctx, p.ep.ChatGPTCompliance, map[string]string{
		headerAuthorization: "Bearer null",
		headerOrigin:        platformOpenAIOrigin,
		headerReferer:       platformOpenAIReferer,
	})
	complianceHijack := err != nil && hijackTLSError(err)
	complianceOK := err == nil && st == http.StatusOK
	unsupported := complianceOK && ParseChatGPTCompliance(body)
	if traceHijack || complianceHijack {
		return model.UnlockBlocked, true
	}
	return ClassifyChatGPT(unsupported, traceOK, complianceOK), false
}

// netflix runs the two title probes with retry-once. A TLS intercept
// signature is the hijack class — blocked, never yes/full.
func (p *unlockProbe) netflix(ctx context.Context) (string, bool) {
	stA, bodyA, errA := p.getRetry(ctx, p.ep.NetflixTitleA, nil)
	stB, bodyB, errB := p.getRetry(ctx, p.ep.NetflixTitleB, nil)
	if (errA != nil && hijackTLSError(errA)) || (errB != nil && hijackTLSError(errB)) {
		return model.UnlockBlocked, true
	}
	return ClassifyNetflix(errA, errB, stA, stB, bodyA, bodyB), false
}

func (p *unlockProbe) youtube(ctx context.Context) string {
	st, body, err := p.getRetry(ctx, p.ep.YouTubePremium, map[string]string{
		headerAcceptLanguage: "en",
		headerCookie:         youtubeCookies,
	})
	return ClassifyYouTube(body, st, err)
}

func (p *unlockProbe) tiktok(ctx context.Context) string {
	st, body, err := p.getRetry(ctx, p.ep.TikTokHome, nil)
	if err != nil {
		return model.UnlockUnknown
	}
	if strings.Contains(body, tikTokChallengeMarker) {
		// The reference retries the challenge page against /explore.
		if st2, body2, err2 := p.getRetry(ctx, p.ep.TikTokExplore, nil); err2 == nil && body2 != "" {
			st, body = st2, body2
		}
	}
	if ExtractTikTokRegion(body) != "" {
		return model.UnlockYes
	}
	// Header-variant fallback (the reference's browser-shaped second
	// attempt): an exit that only answers that shape gets the IDC verdict.
	// No manual Accept-Encoding: the transport then declares gzip itself
	// and decompresses the answer transparently — a manual header makes the
	// server's gzipped body arrive compressed, the region literal stays
	// byte-absent, and the verdict fabricates (adversarial review F2).
	if st == http.StatusOK {
		_, body3, err3 := p.getRetry(ctx, p.ep.TikTokHome, map[string]string{
			"Accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			headerAcceptLanguage: "en",
		})
		if err3 == nil && ExtractTikTokRegion(body3) != "" {
			return model.UnlockTikTokIDC
		}
	}
	if isDefiniteBlock(st) {
		return model.UnlockBlocked
	}
	// A 200 page without extractable region evidence carries no definite
	// answer — fail-unknown (mirrors ClassifyYouTube), never a fabricated
	// block (adversarial review F2).
	return model.UnlockUnknown
}

func parseDisneyAssertion(body string) string {
	var resp struct {
		Assertion string `json:"assertion"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return ""
	}
	return resp.Assertion
}

func parseDisneyRefreshToken(body string) string {
	var resp struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return ""
	}
	return resp.RefreshToken
}

// isDisneyForbidden: the token step's definite block answers (the
// reference's jq forbidden-location + `403 ERROR` grep).
func isDisneyForbidden(body string) bool {
	if strings.Contains(body, disneyForbidden403Marker) {
		return true
	}
	var resp struct {
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return false
	}
	return resp.ErrorDescription == disneyForbiddenLocation
}

func (p *unlockProbe) disney(ctx context.Context) string {
	// Devices/token ride the Bearer form; the graphql step carries the raw
	// token WITHOUT the Bearer prefix (the reference's exact headers).
	auth := map[string]string{headerAuthorization: "Bearer " + disneyBearer}
	authPlain := map[string]string{headerAuthorization: disneyBearer}
	st, body, err := p.postJSON(ctx, p.ep.DisneyDevices, disneyDeviceBody,
		map[string]string{headerAuthorization: auth[headerAuthorization], "Content-Type": disneyDeviceContentType})
	if err != nil || st != http.StatusOK {
		return model.UnlockUnknown
	}
	assertion := parseDisneyAssertion(body)
	if assertion == "" {
		return model.UnlockUnknown
	}
	st, body, err = p.postForm(ctx, p.ep.DisneyAuth,
		strings.ReplaceAll(disneyTokenBody, "DISNEYASSERTION", assertion), auth)
	// The forbidden-content check precedes the generic non-200 fallback:
	// the reference's 403 forbidden-location answer is a DEFINITE block,
	// not unknown (adversarial review F4).
	if err == nil && isDisneyForbidden(body) {
		return model.UnlockBlocked
	}
	if err != nil || st != http.StatusOK {
		return model.UnlockUnknown
	}
	refresh := parseDisneyRefreshToken(body)
	if refresh == "" {
		return model.UnlockUnknown
	}
	st, body, err = p.postJSON(ctx, p.ep.DisneyGraphQL,
		strings.ReplaceAll(disneyGraphQLBody, "ILOVEDISNEY", refresh), authPlain)
	if err != nil || st != http.StatusOK {
		return model.UnlockUnknown
	}
	country, inSupported, ok := ParseDisneySession(body)
	return ClassifyDisney(country, inSupported, ok)
}

func (p *unlockProbe) ipinfo(ctx context.Context) *IPInfoWidget {
	st, body, err := p.getRetry(ctx, p.ep.IPInfoWidget+p.exitIP, nil)
	if err != nil || st != http.StatusOK {
		return nil
	}
	w, perr := ParseIPInfoWidget(body)
	if perr != nil {
		return nil
	}
	return w
}

// tunnelAlive is the tunnel-alive gate (item 5): the OS connectivity-check
// endpoints — connectivitycheck.gstatic.com/generate_204 primary,
// msftconnecttest.com/connecttest.txt fallback. Blocking THESE breaks the
// operating system's own internet detection — the maximum blocking cost an
// operator can pay, so an exit failing both (after the retry-once wrapper)
// is dead-now: the battery records all-unknown verdicts and skips the rest
// of the probe set. A TLS intercept signature through the gate is the
// opposite of dead — the tunnel DELIVERED bytes to the endpoint — so it
// keeps the exit alive AND raises the hijack evidence.
func (p *unlockProbe) tunnelAlive(ctx context.Context, ev *ExitEvidence) bool {
	hijackedOrOK := func(err error, ok bool) bool {
		if err != nil && hijackTLSError(err) {
			ev.flag("alive gate: TLS intercept signature: " + err.Error())
			return true
		}
		return ok
	}
	if p.ep.AlivePrimary != "" {
		st, _, err := p.getRetry(ctx, p.ep.AlivePrimary, nil)
		if hijackedOrOK(err, err == nil && st == http.StatusNoContent) {
			return true
		}
	}
	if p.ep.AliveFallback != "" {
		st, body, err := p.getRetry(ctx, p.ep.AliveFallback, nil)
		if hijackedOrOK(err, err == nil && st == http.StatusOK &&
			strings.Contains(body, "Microsoft Connect Test")) {
			return true
		}
	}
	return false
}

// cfTraceEcho is the PRIMARY echo (item 1): GET www.cloudflare.com/cdn-cgi/
// trace through the tunnel; ip= is the connecting IP, colo=/loc= are stored
// as evidence. A TLS intercept is the hijack class; a body without a
// parseable ip= line is the contract-suspect (fake-trace/garbage) class.
func (p *unlockProbe) cfTraceEcho(ctx context.Context, ev *ExitEvidence) EchoResult {
	res := EchoResult{Source: echoCFTrace, Class: echoErr}
	st, body, err := p.getRetry(ctx, p.ep.CFTrace, nil)
	if err != nil {
		res.Detail = err.Error()
		if hijackTLSError(err) {
			res.Class = echoHijack
			ev.flag("cftrace: TLS intercept signature: " + err.Error())
		}
		return res
	}
	if st != http.StatusOK {
		res.Detail = fmt.Sprintf("status %d", st)
		return res
	}
	parsed, ok := ParseCFTrace(body)
	if !ok {
		res.Class = echoBad
		res.Detail = "trace body contract: no parseable ip= line"
		ev.flag("cftrace: " + res.Detail)
		return res
	}
	res.IP, res.Class = parsed.IP, echoOK
	res.Detail = "colo=" + parsed.Colo + " loc=" + parsed.Loc
	ev.CFColo, ev.CFLoc = parsed.Colo, parsed.Loc
	return res
}

// plainEcho contracts one plain-text IP echo (ipify / ip.sb, item 2). A TLS
// intercept is the hijack class; a non-IP body is the suspect class.
func (p *unlockProbe) plainEcho(ctx context.Context, source, endpoint string, ev *ExitEvidence) EchoResult {
	res := EchoResult{Source: source, Class: echoErr}
	st, body, err := p.getRetry(ctx, endpoint, nil)
	if err != nil {
		res.Detail = err.Error()
		if hijackTLSError(err) {
			res.Class = echoHijack
			ev.flag(source + ": TLS intercept signature: " + err.Error())
		}
		return res
	}
	if st != http.StatusOK {
		res.Detail = fmt.Sprintf("status %d", st)
		return res
	}
	ip, ok := parsePlainIPEcho(body)
	if !ok {
		res.Class = echoBad
		res.Detail = "body contract: not a parseable IP"
		ev.flag(source + ": " + res.Detail)
		return res
	}
	res.IP, res.Class = ip, echoOK
	return res
}

// ipAPIEcho is the HTTP-family hijack probe (item 3): the free-tier ip-api
// answer is plain HTTP, so certificate validation cannot protect it — the
// BODY CONTRACT does. A 200 whose JSON lacks a parseable query-field IP is
// the fake-answer hijack signature. Transport errors and rate limits are
// recorded non-fatally — never hijack.
func (p *unlockProbe) ipAPIEcho(ctx context.Context, ev *ExitEvidence) EchoResult {
	res := EchoResult{Source: echoIPAPI, Class: echoErr}
	st, body, err := p.getRetry(ctx, p.ep.IPAPIContract, nil)
	if err != nil {
		res.Detail = err.Error()
		return res
	}
	if st == http.StatusTooManyRequests {
		res.Detail = "rate-limited (429)"
		return res
	}
	if st != http.StatusOK {
		res.Detail = fmt.Sprintf("status %d", st)
		return res
	}
	ip, ok := validateIPAPIBody(body)
	if !ok {
		res.Class = echoHijack
		res.Detail = fmt.Sprintf("ip-api body contract: no parseable query-field IP (%d bytes)", len(body))
		ev.flag("ip-api: " + res.Detail + " — hijack/garbage class")
		return res
	}
	res.IP, res.Class = ip, echoOK
	return res
}

// dnsChannel is the DNS-authoritative second channel (item 4): TXT
// o-o.myaddr.l.google.com at 216.239.32.10:53 queried over FRAMED TCP
// through the tunnel — an independent failure envelope from HTTPS (port-53
// egress filtering on some paths is expected and recorded non-fatally).
func (p *unlockProbe) dnsChannel(ctx context.Context, ev *ExitEvidence) {
	if p.tc == nil || p.ep.DNSServer == "" {
		return
	}
	name := p.ep.DNSName
	if name == "" {
		name = "o-o.myaddr.l.google.com"
	}
	txts, err := p.tc.DNSOverTCP(ctx, p.ep.DNSServer, name, 16)
	if err != nil {
		return // recorded non-fatal: the evidence simply stays empty
	}
	if ip, ok := extractIPv4Token(txts); ok {
		ev.DNSIP = ip
	}
}

// stunChannel is the hysteria2 transport-level echo (item 6): one RFC 5389
// Binding to the STUN server through the socks UDP path; the
// XOR-MAPPED-ADDRESS is the exit IP as the transport sees it. Runs only on
// hysteria2/hy2 nodes (the UDP-enabled instances); every failure is
// recorded non-fatally.
func (p *unlockProbe) stunChannel(ctx context.Context, ev *ExitEvidence) {
	if p.tc == nil || p.ep.STUNServer == "" {
		return
	}
	if p.scheme != "hysteria2" && p.scheme != "hy2" {
		return
	}
	ip, err := p.tc.STUNBinding(ctx, p.ep.STUNServer)
	if err == nil {
		ev.StunIP = ip
	}
}

// ipv4TokenRe extracts the first dotted-quad literal out of a free-form
// string (the authoritative TXT answer embeds the resolver-facing IP in
// its character-strings).
var ipv4TokenRe = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)

// extractIPv4Token returns the first dotted-quad literal that parses as an
// IPv4 address.
func extractIPv4Token(s string) (string, bool) {
	for _, m := range ipv4TokenRe.FindAllString(s, -1) {
		if p := net.ParseIP(m); p != nil && p.To4() != nil {
			return p.String(), true
		}
	}
	return "", false
}

// probeUnlockSet runs the v2 battery for ONE exit through ONE tunnel
// client. Flow: the tunnel-alive gate first (dead tunnels are recorded
// all-unknown without burning the full battery); then the exit-echo
// channels (cftrace primary + ipify/ip.sb consensus, the ip-api body
// contract) whose TLS/body-contract signatures raise the exit-level HIJACK
// flag; then the media probes; then the DNS-authoritative and STUN
// evidence channels. Failures are non-fatal: the verdict records unknown
// and the wave keeps moving. The exit-level hijack forces EVERY media
// verdict to blocked (a cert/body-contract intercept proves the answers
// are not the services' own — "yes" is unreachable by construction, which
// kills the poisoned-verdict class the v1 battery fabricated). CheckedAt
// is stamped whenever the probes actually ran — an all-unknown outcome
// caches for UnlockUnknownTTL (24h), a definite outcome for UnlockTTL, and
// the verdict carries the current battery version (freshUnlock re-probes
// anything older than it: the migration semantics). A canceled context
// returns nil (a partial verdict must not be cached as checked).
func probeUnlockSet(ctx context.Context, p *unlockProbe) (*model.MediaUnlockStatus, *IPInfoWidget, *ExitEvidence) {
	ev := &ExitEvidence{}
	st := &model.MediaUnlockStatus{}
	stamp := func() *model.MediaUnlockStatus {
		ev.FlakyCount = p.flaky // the OK_FLAKY counter: endpoints recovered on the retry pass
		st.CheckedAt = p.now().UTC().Format(time.RFC3339)
		stampEvidence(st, ev)
		return st
	}
	// Tunnel-alive gate: the OS connectivity-check endpoints.
	ev.TunnelAlive = p.tunnelAlive(ctx, ev)
	if !ev.TunnelAlive {
		st.ChatGPT, st.Netflix, st.YouTubeRegion = model.UnlockUnknown, model.UnlockUnknown, model.UnlockUnknown
		st.Disney, st.TikTok = model.UnlockUnknown, model.UnlockUnknown
		if ctx.Err() != nil {
			return nil, nil, nil
		}
		return stamp(), nil, ev
	}
	// Exit-echo channels: the consensus + the exit-level hijack evidence.
	if p.ep.CFTrace != "" {
		ev.Echo = append(ev.Echo, p.cfTraceEcho(ctx, ev))
	}
	if p.ep.EchoIPify != "" {
		ev.Echo = append(ev.Echo, p.plainEcho(ctx, echoIPify, p.ep.EchoIPify, ev))
	}
	if p.ep.EchoIPSB != "" {
		ev.Echo = append(ev.Echo, p.plainEcho(ctx, echoIPSB, p.ep.EchoIPSB, ev))
	}
	consensus := echoConsensus(ev.Echo)
	ev.ConsensusIP, ev.Consensus, ev.Rotating = consensus.IP, consensus.Agree, consensus.Rotating
	// The ip-api body-contract probe is HIJACK evidence, never a consensus
	// vote: the 3-source consensus is the HTTPS echo family (cftrace +
	// ipify + ip.sb), and the plain-HTTP contract answer rides a different
	// trust envelope.
	if p.ep.IPAPIContract != "" {
		ev.Echo = append(ev.Echo, p.ipAPIEcho(ctx, ev))
	}
	// Media battery.
	chatgpt, chatHijack := p.chatgpt(ctx)
	netflix, netHijack := p.netflix(ctx)
	st.ChatGPT, st.Netflix = chatgpt, netflix
	st.YouTubeRegion = p.youtube(ctx)
	st.Disney = p.disney(ctx)
	st.TikTok = p.tiktok(ctx)
	if chatHijack {
		ev.flag("chatgpt: TLS intercept signature (trace/compliance)")
	}
	if netHijack {
		ev.flag("netflix: TLS intercept signature (title pages)")
	}
	widget := p.ipinfo(ctx)
	// Independent evidence channels (recorded, non-fatal).
	p.dnsChannel(ctx, ev)
	p.stunChannel(ctx, ev)
	if ctx.Err() != nil {
		return nil, nil, nil
	}
	// Exit-level hijack: every media verdict becomes blocked — unknown ≠
	// hijack ≠ blocked stay three distinct honest classes.
	if ev.Hijack {
		st.ChatGPT = model.UnlockBlocked
		st.Netflix = model.UnlockBlocked
		st.YouTubeRegion = model.UnlockBlocked
		st.Disney = model.UnlockBlocked
		st.TikTok = model.UnlockBlocked
	}
	return stamp(), widget, ev
}

// stampEvidence folds the verdict-shaped evidence subset into the stored
// verdict: the battery version (the migration anchor — verdicts older than
// the current battery are stale on sight) plus the echo/hijack/DNS/STUN
// evidence the status line and pool consumers read.
func stampEvidence(st *model.MediaUnlockStatus, ev *ExitEvidence) {
	st.BatteryVersion = UnlockBatteryVersion
	st.ExitIP = ev.ConsensusIP
	st.ConsensusCount = ev.Consensus
	st.Rotating = ev.Rotating
	st.Hijack = ev.Hijack
	st.CFColo = ev.CFColo
	st.CFLoc = ev.CFLoc
	st.DNSIP = ev.DNSIP
	st.StunIP = ev.StunIP
}

// unlockVerdictUnknown reports whether ANY media field of the verdict is
// unknown or unchecked (""): such a verdict carries no definite answer for
// that service. The five fields come from ONE probe pass — they age
// together, so the whole verdict shares one TTL.
func unlockVerdictUnknown(st *model.MediaUnlockStatus) bool {
	if st == nil {
		return true
	}
	for _, v := range []string{st.ChatGPT, st.Netflix, st.YouTubeRegion, st.Disney, st.TikTok} {
		if v == "" || v == model.UnlockUnknown {
			return true
		}
	}
	return false
}

// unlockTTL is the freshness window of ONE verdict: unknown-carrying
// verdicts expire after UnlockUnknownTTL, fully definite ones (blocked
// answers included — those are definite answers) after UnlockTTL. The TTL is
// derived from the verdict's own stored content, which is written once at
// probe time — the write path therefore stamps it correctly without an
// extra timestamp field, and the cold geo-base half (which persists only
// CheckedAt + the fields) carries the same semantics on reload.
func unlockTTL(st *model.MediaUnlockStatus) time.Duration {
	if unlockVerdictUnknown(st) {
		return UnlockUnknownTTL
	}
	return UnlockTTL
}

// freshUnlock reports whether a cached verdict is inside its own freshness
// window: the battery version must be the CURRENT one (the migration rule —
// verdicts written by an older battery are stale regardless of their age or
// definiteness: v1 definite verdicts may be hijack-poisoned, and the
// one-time re-classification sweep re-probes every pre-v2 entry exactly
// once), CheckedAt must parse, must not sit further in the future than the
// skew tolerance, and must be at most unlockTTL(st) old (7 days for fully
// definite verdicts, 24 hours for unknown-carrying ones).
func freshUnlock(st *model.MediaUnlockStatus, now time.Time) bool {
	if st == nil || st.CheckedAt == "" {
		return false
	}
	if st.BatteryVersion < UnlockBatteryVersion {
		return false
	}
	t, err := time.Parse(time.RFC3339, st.CheckedAt)
	if err != nil {
		return false
	}
	if t.Sub(now) > unlockClockSkew {
		return false
	}
	return now.Sub(t) <= unlockTTL(st)
}

func logUnlock(w io.Writer, exitIP string, status *model.MediaUnlockStatus, q *IPQuality, ev *ExitEvidence) {
	if w == nil {
		return
	}
	risk, ipType := -1, "unchecked"
	if q != nil {
		risk, ipType = q.RiskScore, q.IPType
	}
	_, _ = fmt.Fprintf(w,
		"unlock: %s chatgpt=%s netflix=%s youtube=%s disney=%s tiktok=%s risk=%d type=%s\n",
		exitIP, status.ChatGPT, status.Netflix, status.YouTubeRegion, status.Disney, status.TikTok,
		risk, ipType)
	if ev == nil {
		return
	}
	// Evidence tail: the v2 battery's exit-truth channels. A hijack-flagged
	// exit is excluded from the service pools by construction (its media
	// verdicts are blocked, never yes/full).
	flags := fmt.Sprintf("battery=v%d alive=%t consensus=%d", status.BatteryVersion, ev.TunnelAlive, ev.Consensus)
	if status.ExitIP != "" {
		flags += " exit=" + status.ExitIP
	}
	if status.Rotating {
		flags += " rotating=true"
	}
	if status.Hijack {
		flags += " hijack=true (" + strings.Join(ev.HijackReasons, "; ") + ")"
	}
	if ev.FlakyCount > 0 {
		flags += fmt.Sprintf(" ok_flaky=%d", ev.FlakyCount)
	}
	if status.CFColo != "" || status.CFLoc != "" {
		flags += " cf_colo=" + status.CFColo + " cf_loc=" + status.CFLoc
	}
	if status.DNSIP != "" {
		flags += " dns_ip=" + status.DNSIP
	}
	if status.StunIP != "" {
		flags += " stun_ip=" + status.StunIP
	}
	_, _ = fmt.Fprintf(w, "unlock: %s evidence %s\n", exitIP, flags)
}
