package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"public_vpn/internal/model"
	"public_vpn/internal/store"
)

// Phase-1 IP quality & media unlock engine: once per distinct exit IP whose
// cached verdict is older than UnlockTTL, the stage probes ChatGPT / Netflix
// / YouTube / Disney+ / TikTok unlocks plus IP quality THROUGH that exit's
// own tunnel (the same temp-socks contract as the geo ladder), caches the
// verdict by exit IP (hot ExitGeoEntry + the geo-base.jsonl cold half), and
// folds it into every geo record sharing the exit. Probe semantics are the
// ip.check.place reference (xykt/IPQuality); failures are non-fatal — the
// verdict records "unknown" and the wave never hangs (per-request budgets).

const (
	// UnlockTTL is the freshness window of one exit IP's quality + media
	// verdicts (the spec's 7-day cache: a re-check of the same exit inside
	// the window costs zero network calls).
	UnlockTTL = 7 * 24 * time.Hour
	// unlockRequestTimeout bounds ONE probe request (the spec's 3s): every
	// request carries its own context budget, so no slow service hangs a
	// wave.
	unlockRequestTimeout = 3 * time.Second
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
// production defaults), exactly like Input.SelfURL.
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
	}
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

// unlockProbe is ONE exit's probe session: the through-tunnel client, the
// ONE pipeline user agent, the endpoint set, the shared pacing and the
// clock — every rung of every service rides the same temp socks instance.
type unlockProbe struct {
	cl     *http.Client
	ua     string
	ep     UnlockEndpoints
	pac    *pacer
	now    func() time.Time
	exitIP string
}

func (p *unlockProbe) get(ctx context.Context, endpoint string, headers map[string]string) (int, string, error) {
	return p.do(ctx, http.MethodGet, endpoint, "", "", headers, unlockBodyLimit)
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

func (p *unlockProbe) chatgpt(ctx context.Context) string {
	st, body, err := p.get(ctx, p.ep.ChatGPCTrace, nil)
	traceOK := err == nil && st == http.StatusOK
	if traceOK {
		// The trace's loc= line is the reachability proof (the reference
		// greps it): an unparseable trace is no evidence.
		traceOK = ParseCDNTrace(body) != ""
	}
	st, body, err = p.get(ctx, p.ep.ChatGPTCompliance, map[string]string{
		headerAuthorization: "Bearer null",
		headerOrigin:        platformOpenAIOrigin,
		headerReferer:       platformOpenAIReferer,
	})
	complianceOK := err == nil && st == http.StatusOK
	unsupported := complianceOK && ParseChatGPTCompliance(body)
	return ClassifyChatGPT(unsupported, traceOK, complianceOK)
}

func (p *unlockProbe) netflix(ctx context.Context) string {
	stA, bodyA, errA := p.get(ctx, p.ep.NetflixTitleA, nil)
	stB, bodyB, errB := p.get(ctx, p.ep.NetflixTitleB, nil)
	return ClassifyNetflix(errA, errB, stA, stB, bodyA, bodyB)
}

func (p *unlockProbe) youtube(ctx context.Context) string {
	st, body, err := p.get(ctx, p.ep.YouTubePremium, map[string]string{
		headerAcceptLanguage: "en",
		headerCookie:         youtubeCookies,
	})
	return ClassifyYouTube(body, st, err)
}

func (p *unlockProbe) tiktok(ctx context.Context) string {
	st, body, err := p.get(ctx, p.ep.TikTokHome, nil)
	if err != nil {
		return model.UnlockUnknown
	}
	if strings.Contains(body, tikTokChallengeMarker) {
		// The reference retries the challenge page against /explore.
		if st2, body2, err2 := p.get(ctx, p.ep.TikTokExplore, nil); err2 == nil && body2 != "" {
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
		_, body3, err3 := p.get(ctx, p.ep.TikTokHome, map[string]string{
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
	st, body, err := p.get(ctx, p.ep.IPInfoWidget+p.exitIP, nil)
	if err != nil || st != http.StatusOK {
		return nil
	}
	w, perr := ParseIPInfoWidget(body)
	if perr != nil {
		return nil
	}
	return w
}

// probeUnlockSet runs every Phase-1 probe for ONE exit through ONE tunnel
// client. Failures are non-fatal: the service's verdict becomes unknown and
// the wave keeps moving. CheckedAt is stamped whenever the probes actually
// ran — caching an all-unknown outcome for 7 days is the spec'd behavior (a
// broken exit must not be hammered every wave). A canceled context returns
// nil (a partial verdict must not be cached as checked).
func probeUnlockSet(ctx context.Context, p *unlockProbe) (*model.MediaUnlockStatus, *IPInfoWidget) {
	st := &model.MediaUnlockStatus{
		ChatGPT:       p.chatgpt(ctx),
		Netflix:       p.netflix(ctx),
		YouTubeRegion: p.youtube(ctx),
		Disney:        p.disney(ctx),
		TikTok:        p.tiktok(ctx),
	}
	widget := p.ipinfo(ctx)
	if ctx.Err() != nil {
		return nil, nil
	}
	st.CheckedAt = p.now().UTC().Format(time.RFC3339)
	return st, widget
}

// freshUnlock reports whether a cached verdict is inside the 7-day window:
// CheckedAt must parse, must not sit further in the future than the skew
// tolerance, and must be at most UnlockTTL old.
func freshUnlock(st *model.MediaUnlockStatus, now time.Time) bool {
	if st == nil || st.CheckedAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, st.CheckedAt)
	if err != nil {
		return false
	}
	if t.Sub(now) > unlockClockSkew {
		return false
	}
	return now.Sub(t) <= UnlockTTL
}

// loadColdUnlocks indexes the freshest unlock state per exit IP from
// geo-base.jsonl — the durable half of the 7-day cache (the hot entry's LRU
// lease is much shorter). CheckedAt is RFC3339 UTC: lexicographic compare.
func loadColdUnlocks(dataDir string, progress io.Writer) map[string]*model.MediaUnlockStatus {
	out := map[string]*model.MediaUnlockStatus{}
	records, err := store.ReadGeo(filepath.Join(dataDir, "geo-base.jsonl"))
	if err != nil {
		if progress != nil {
			_, _ = fmt.Fprintf(progress, "unlock: cold cache read failed (%v) — probing fresh\n", err)
		}
		return out
	}
	for _, r := range records {
		if r == nil || r.IP == "" || r.MediaUnlocks.CheckedAt == "" {
			continue
		}
		cur, ok := out[r.IP]
		if !ok || r.MediaUnlocks.CheckedAt > cur.CheckedAt {
			st := r.MediaUnlocks
			out[r.IP] = &st
		}
	}
	return out
}

// unlockGroup is one distinct exit IP and the report indexes sharing it.
type unlockGroup struct {
	exitIP string
	inds   []int
}

func groupByExit(reports []NodeReport, idx exitIPIndex) []unlockGroup {
	order := make([]string, 0, len(reports))
	byExit := make(map[string][]int, len(reports))
	for i := range reports {
		exit := idx.byNode[reports[i].Key]
		if exit == "" {
			continue
		}
		if _, ok := byExit[exit]; !ok {
			order = append(order, exit)
		}
		byExit[exit] = append(byExit[exit], i)
	}
	groups := make([]unlockGroup, 0, len(order))
	for _, exit := range order {
		groups = append(groups, unlockGroup{exitIP: exit, inds: byExit[exit]})
	}
	return groups
}

// unlockStage carries one unlock wave's shared inputs.
type unlockStage struct {
	in    Input
	r     *Reporter
	cold  map[string]*model.MediaUnlockStatus
	nodes map[string]*model.Node
	ep    UnlockEndpoints
	pac   *pacer
	now   func() time.Time
}

// attachUnlock gives every report of the exit group its own copy of the
// verdict (each report folds into its record separately).
func attachUnlock(reports []NodeReport, inds []int, status *model.MediaUnlockStatus, q *IPQuality) {
	if status == nil {
		return
	}
	for _, i := range inds {
		cp := *status
		reports[i].Unlocks = &cp
		reports[i].Quality = q
	}
}

// storeUnlock merges the verdict into the hot exit-IP cache, preserving the
// geo facts the ladder already cached for that exit (clone-then-replace).
func (st *unlockStage) storeUnlock(exitIP string, rep NodeReport, status *model.MediaUnlockStatus, q *IPQuality) {
	if st.r.Cache == nil || exitIP == "" || status == nil {
		return
	}
	var entry *ExitGeoEntry
	if old, ok := st.r.Cache.Get(exitIP); ok && old != nil {
		cp := *old
		entry = &cp
	} else {
		entry = nodeReportToEntry(exitIP, rep)
	}
	cp := *status
	entry.MediaUnlocks = &cp
	entry.Report.Unlocks = &cp
	entry.Report.Quality = q
	_ = st.r.Cache.Set(exitIP, entry)
}

func logUnlock(w io.Writer, exitIP string, status *model.MediaUnlockStatus, q *IPQuality) {
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
}

// runUnlockGroup drives ONE exit: hot cache hit → cold geo-base hit → probe
// through a fresh temp instance of the representative node. Infrastructure
// failures attach and cache NOTHING (the next wave retries); probe failures
// are recorded as unknown.
func runUnlockGroup(ctx context.Context, st *unlockStage, reports []NodeReport, g unlockGroup) {
	rep := reports[g.inds[0]]
	if st.r.Cache != nil {
		if e, ok := st.r.Cache.Get(g.exitIP); ok && e != nil && freshUnlock(e.MediaUnlocks, st.now()) {
			attachUnlock(reports, g.inds, e.MediaUnlocks, e.Report.Quality)
			return
		}
	}
	if c, ok := st.cold[g.exitIP]; ok && freshUnlock(c, st.now()) {
		attachUnlock(reports, g.inds, c, nil)
		st.storeUnlock(g.exitIP, rep, c, nil)
		return
	}
	node := st.nodes[rep.Key]
	if node == nil {
		return
	}
	inst, err := st.r.Factory(ctx, node)
	if err != nil {
		return // infrastructure failure: nothing to attach, nothing cached
	}
	defer func() { _ = inst.Close() }()
	cl, err := NewTunnelClient(inst.Addr(), st.r.Timeout)
	if err != nil {
		return
	}
	status, widget := probeUnlockSet(ctx, &unlockProbe{
		cl: cl, ua: st.r.userAgent(), ep: st.ep, pac: st.pac, now: st.now, exitIP: g.exitIP,
	})
	if status == nil {
		return // canceled mid-wave
	}
	q := ComputeIPQuality(rep.Geo, widget)
	attachUnlock(reports, g.inds, status, q)
	st.storeUnlock(g.exitIP, rep, status, q)
	logUnlock(st.r.Progress, g.exitIP, status, q)
}

// runUnlockWave probes quality + media once per distinct exit IP whose
// cached verdict is older than UnlockTTL, attaching copies to every report
// sharing the exit. Gated by [geo].unlock_probes (default off = zero
// production behavior change); it never fails a wave.
func runUnlockWave(ctx context.Context, in Input, r *Reporter, reports []NodeReport, idx exitIPIndex) {
	if !in.Cfg.UnlockProbes || len(reports) == 0 {
		return
	}
	groups := groupByExit(reports, idx)
	if len(groups) == 0 {
		return
	}
	nodes := make(map[string]*model.Node, len(in.Nodes))
	for _, n := range in.Nodes {
		nodes[n.Key] = n
	}
	ep := defaultUnlockEndpoints()
	if in.UnlockEndpoints != nil {
		ep = *in.UnlockEndpoints
	}
	now := r.nowFn()
	st := &unlockStage{
		in: in, r: r, cold: loadColdUnlocks(in.DataDir, r.Progress), nodes: nodes,
		ep: ep, pac: &pacer{minDelay: r.MinDelay, now: now, sleep: r.sleepFn()}, now: now,
	}
	concurrency := r.SelfReportConcurrency
	if concurrency <= 0 {
		concurrency = DefaultSelfReportConcurrency
	}
	workers := min(concurrency, len(groups))
	var next atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(groups) {
					return
				}
				if ctx.Err() != nil {
					return
				}
				runUnlockGroup(ctx, st, reports, groups[i])
			}
		}()
	}
	wg.Wait()
}
