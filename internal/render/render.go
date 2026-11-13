// Package render implements the xray client-config renderer: pool outbounds
// + per-country/city leastLoad balancers + owner pool routes + Plan A
// observatory under the hard gates L1 (never an observatory whose selector
// can match zero tags) and L2 (balancers require coverage). Every link
// auth/transport param passes through 1:1 (L9); every pool outbound gets
// sockopt.tcpMaxSeg 1440 and client fingerprint firefox. Phase 3 adds the
// service-quality balancer tree (pool_clean / pool_chatgpt / pool_netflix /
// pool_youtube with country and city variants) rendered ONLY when qualifying
// nodes exist — membership rides the Phase-1 unlock evidence (GeoRecord
// RiskScore/MediaUnlocks) joined through model.GeoIdentity; nodes without
// evidence never enter an unlock pool (fail-closed). Since the self-held-core
// pivot (D3) there is ONE render target: the fully generated own live config
// (RenderOwnConfig) — the foreign template merge is gone.
package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"assay/internal/config"
	"assay/internal/model"
)

// PoolRoute is one owner-configured routing rule into the pool (D2: the pool
// only carries explicitly routed traffic). Balancer is the route TARGET: a
// rendered `pool_*` balancer tag — a country (pool_<cc>), a city
// (pool_<cc>_<city>), the unknown-geo pseudo-location (pool_unknown, W16),
// the pool-wide balancer (pool_all, W16), a service-quality pool (Phase 3:
// pool_clean / pool_chatgpt / pool_netflix / pool_youtube, their
// pool_<cc>_<svc> country and pool_<cc>_<city>_<svc> city variants) — or a
// direct `pool-<cc>-NN` outbound tag (D5: a single-node city renders no city
// balancer; unknown-geo nodes are pool-xx-NN). A rendered-target prefix that
// was not rendered degrades the rule to block with a warning (no live nodes
// there); any other target fails the render loud (D6 namespace wall).
type PoolRoute struct {
	Balancer string   `toml:"balancer"`
	Domains  []string `toml:"domains"`
}

// materialParams are link parameters that change transport behavior when they
// cannot be rendered: early-data sizing, and the xhttp `extra` JSON-object
// passthrough (hardening fields like noGRPCHeader/xmux live there). Their
// silent loss must fail the render, not warn (review finding 5; W5 M-2 adds
// extra).
var materialParams = map[string]bool{
	"ed":            true,
	"early-data":    true,
	"extra":         true,
	"obfs":          true, // hysteria2 salamander/gecko obfs — no xray equivalent (W7 item 10)
	"obfs-password": true, // ditto; dropping either silently changes the wire format
}

// networkAliases maps every link spelling of a renderable transport onto its
// canonical xray network name (TransportProtocol.Build normalizes the same
// set; verified against Xray-core v26.3.27 source and `xray run -test`).
// Canonical xray network names the renderer emits.
const (
	networkTCP         = "tcp"
	networkWS          = "ws"
	networkHTTPUpgrade = "httpupgrade"
	networkGRPC        = "grpc"
	networkKCP         = "kcp"
	networkXHTTP       = "xhttp"
)

// networkAliases maps every link spelling of a renderable transport onto its
// canonical xray network name (TransportProtocol.Build normalizes the same
// set; verified against Xray-core v26.3.27 source and `xray run -test`).
var networkAliases = map[string]string{
	"tcp": networkTCP, "raw": networkTCP,
	"ws": networkWS, "websocket": networkWS,
	"httpupgrade": networkHTTPUpgrade,
	"grpc":        networkGRPC,
	"kcp":         networkKCP, "mkcp": networkKCP,
	"xhttp": networkXHTTP, "splithttp": networkXHTTP,
}

// removedNetworks are transports the 26.3.27 core REJECTS at config build
// (PrintRemovedFeatureError) — rendering them would fail the -test gate, so
// the renderer refuses them loud with the migration note instead.
var removedNetworks = map[string]string{
	"http": "the HTTP/2 transport was removed from xray 26.3.27 (migrated to XHTTP stream-one H2 & H3)",
	"h2":   "the HTTP/2 transport was removed from xray 26.3.27 (migrated to XHTTP stream-one H2 & H3)",
	"h3":   "the H3 transport was removed from xray 26.3.27 (migrated to XHTTP stream-one H3)",
	"quic": "the QUIC transport was removed from xray 26.3.27 (migrated to XHTTP stream-one H3)",
}

// realityNetworks mirrors the core's REALITY restriction ("REALITY only
// supports RAW, XHTTP and gRPC for now" — StreamConfig.Build).
var realityNetworks = map[string]bool{networkTCP: true, networkXHTTP: true, networkGRPC: true}

// wsEarlyDataHeader is the FIXED early-data header of the xray websocket
// transport (dialer.go: header.Set("Sec-WebSocket-Protocol", ...)); xray has
// no config field for it, so an ehs link param may only carry this value.
const wsEarlyDataHeader = "Sec-WebSocket-Protocol"

// tcpHTTPObfuscation renders the canonical http-obfs request header block for
// tcp type=http links (host/path from the link; the standard header set every
// major client emits — validated with `xray run -test` on 26.3.27).
func tcpHTTPObfuscation(host, path string) map[string]any {
	// The canonical http-obfs UA string (v2ray-family default, byte-exact).
	const ua = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"
	headers := map[string]any{
		"User-Agent":      []any{ua},
		"Accept-Encoding": []any{"gzip, deflate"},
		"Connection":      []any{"keep-alive"},
		"Pragma":          "no-cache",
	}
	if host != "" {
		headers["Host"] = []any{host}
	}
	request := map[string]any{"version": "1.1", "method": "GET", "path": []any{path}}
	if path == "" {
		request["path"] = []any{"/"}
	}
	return map[string]any{"type": "http", "request": map[string]any{
		"version": request["version"], "method": request["method"],
		"path": request["path"], "headers": headers,
	}}
}

// appendEarlyData appends ed=<n> to a ws/httpupgrade path exactly the way the
// core consumes it (both transports parse the ed query parameter OUT of the
// configured path — WebSocketConfig.Build / HttpUpgradeConfig.Build).
func appendEarlyData(path, ed string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "ed=" + ed
}

// Config carries the render knobs. Zero-value fields fall back to the W6
// defaults (config.Default*) so direct callers keep the historical shape
// byte-for-byte; config.Load always fills them with the same values (one
// literal per default — no layer drift).
type Config struct {
	// ObservatoryInterval is the Plan-A pool observatory probeInterval — a
	// STRING PASSTHROUGH rendered verbatim when set, so any duration spelling
	// the core accepts works. ABSENT (empty, the W19 default) = ADAPTIVE: the
	// render computes the interval from the active count (max(60s,
	// ceil(N×200ms)) — probes/sec ≤ 5, code-owned budget, no new knob).
	// Deliberately unbounded (owner ruling — the ≥30s recommendation is
	// rejected); garbage values fail the xray -test gate loud.
	ObservatoryInterval string
	// TCPMaxSeg is the sockopt.tcpMaxSeg value emitted MANDATORILY on every
	// rendered streamSettings (the owner-calibrated anti-TSPU clamp — the
	// emission never becomes optional, only the value is configurable).
	// Negative values are structurally invalid; otherwise unbounded.
	TCPMaxSeg int
	// TLSFingerprint is the uTLS client fingerprint on tls/reality settings
	// (default firefox). NO allowlist — a bad value fails the xray -test gate
	// loud and safe.
	TLSFingerprint string
	// BalancerTolerance is the leastLoad tolerance on country AND city pool
	// balancers (default 0.2). Deliberately unbounded (owner ruling).
	BalancerTolerance float64
}

const (
	poolOutboundPrefix = "pool-"
	poolBalancerPrefix = "pool_"
	keySelector        = "selector"
	keyFallbackTag     = "fallbackTag"
	keyStrategy        = "strategy"
)

// Phase-3 service-quality pool surface (owner-approved balancer tree,
// 2026-11-04). The tags are render-owned names: the pool_ namespace wall (D6)
// keeps them separate from the Germans' proxy- balancers, and nothing outside
// the renderer needs to construct them (pool_routes targets are validated
// against the rendered set, not against a name list).
const (
	// poolCleanBalancerTag is the GLOBAL clean service pool: the selection's
	// clean nodes (sn.IsClean) whose CHECKED RiskScore sits in the approved
	// 0–25 band; unchecked (-1, probes off) falls back to flags-only.
	poolCleanBalancerTag = "pool_clean"
	// poolChatGPTBalancerTag is the global ChatGPT service pool: exits whose
	// MediaUnlocks.ChatGPT is exactly "yes" (webonly/apponly excluded per
	// owner ruling 2026-11-04).
	poolChatGPTBalancerTag = "pool_chatgpt"
	// poolNetflixBalTag is the global Netflix service pool: MediaUnlocks.
	// Netflix exactly "full" (originals excluded per owner ruling).
	poolNetflixBalTag = "pool_netflix"
	// poolYouTubeBalancerTag is the global YouTube service pool: a CHECKED
	// non-blocked region (ISO-2). Global-only by owner ruling — no country
	// or city variants.
	poolYouTubeBalancerTag = "pool_youtube"
	// cleanRiskBand is the owner-approved clean RiskScore ceiling (0–25).
	cleanRiskBand = 25
)

// serviceKind names one unlock-service pool family. clean is a flag+risk
// family (its own predicate); the others read MediaUnlocks vocabulary.
type serviceKind string

const (
	serviceChatGPT serviceKind = "chatgpt"
	serviceNetflix serviceKind = "netflix"
	serviceYouTube serviceKind = "youtube"
	serviceClean   serviceKind = "clean"
)

// blockOutboundTag is the blackhole outbound (present in every own config).
//
// SECURITY INVARIANT (owner ruling, W9): every pool_* balancer emitted by the
// renderer is pinned to fallbackTag "block", and this is deliberately NOT a
// configuration knob. Semantics, verified against the tagged xray-core
// v26.3.27 source: app/router/balancing.go — Balancer.PickOutbound returns
// the fallbackTag WITHOUT error when the strategy yields an empty pick (log
// line "fallback to [<tag>], due to empty tag returned"); strategy_leastload.go
// qualifies only nodes that are Alive, within maxRTT, and covered by the
// observatory — zero qualified nodes (all pool nodes down or uncovered) means
// an empty pick. The picked "block" outbound (proxy/blackhole) interrupts the
// link, so the connection dies in place and nothing exits the machine. There
// is no error loop: one deterministic pick per routed connection, and the
// empty-tag error branch is only reachable without a fallbackTag. A
// configurable fallback could be set to direct (or removed) and reopen the
// naked-exit hole — traffic routed to a location silently leaving from the
// machine's real IP — so the value is hard-coded here, never plumbed from
// config.
const blockOutboundTag = "block"

// normalizeKnobs applies the W6 default fallbacks: a zero knob value means
// "owner-mandated default" (the same values config.Load fills in — the
// defaults live once in config, referenced here, so they cannot drift).
func normalizeKnobs(c Config) Config {
	// ObservatoryInterval: intentionally NOT defaulted here (W19) — an empty
	// value means ADAPTIVE pacing, resolved at the emission site from the
	// active count; a set value passes through verbatim.
	if c.TCPMaxSeg == 0 {
		c.TCPMaxSeg = config.DefaultTCPMaxSeg
	}
	if c.TLSFingerprint == "" {
		c.TLSFingerprint = config.DefaultTLSFingerprint
	}
	if c.BalancerTolerance == 0 {
		c.BalancerTolerance = config.DefaultBalancerTolerance
	}
	return c
}

// W19 load engineering: the pool observatory re-probes EVERY rendered pool
// outbound once per interval, so the sustained daemon-side probe load is
// ≈ N/interval probes per second — the one cost that would otherwise grow
// linearly with the pool forever. The adaptive interval keeps that load at
// or below a constant budget without a new knob (owner ruling: code-owned
// constant + README math; the wave wall time stays honestly O(N) — every
// alive node IS probed — and that trade-off is owner-accepted).
const (
	// ObservatoryProbeTargetPerSec is the sustained pool-probe budget the
	// adaptive interval guarantees regardless of pool size.
	ObservatoryProbeTargetPerSec = 5.0
	// MinObservatoryInterval is the adaptive floor: pools at or below 300
	// active nodes keep the historical fixed 60s cadence (the pre-W19
	// default; 259 alive → 60s exactly as before).
	MinObservatoryInterval = 60 * time.Second
)

// AdaptiveObservatoryInterval computes the pool observatory probeInterval
// from the active pool size: max(60s, ceil(N × 200ms)), where 200ms per node
// = 1/ObservatoryProbeTargetPerSec — probes/sec never exceeds the budget.
// The result is rounded up to whole seconds (xray parses Go durations).
func AdaptiveObservatoryInterval(active int) time.Duration {
	perNode := time.Duration(float64(time.Second) / ObservatoryProbeTargetPerSec)
	d := max(time.Duration(max(active, 0))*perNode, MinObservatoryInterval)
	if r := d % time.Second; r > 0 {
		d += time.Second - r // ceil to whole seconds
	}
	return d
}

// observatoryInterval resolves the emitted probeInterval: an explicit
// observatory_interval wins verbatim (no floor — owner ruling); an empty
// knob means adaptive pacing from the active count (W19).
func observatoryInterval(verbatim string, active int) string {
	if verbatim != "" {
		return verbatim
	}
	return AdaptiveObservatoryInterval(active).String()
}

// ensureAPIStats renders the api/stats service block bound to 127.0.0.1 only
// (the own render is the only caller; the port is [core].api_port).
//
// The services list is the hot-apply gate (2026-11-13 plan T1): RoutingService
// serves the adrules/lsrules/bi API surface `assay apply` execs through the
// core binary; HandlerService is registered for future outbound work (it is
// deliberately NOT exercised by any V1 code path). The exact strings are
// load-bearing: infra/conf/api.go matches names case-INSENSITIVELY and
// SILENTLY IGNORES unrecognized strings — a typo would quietly leave the
// service unregistered (plan R2), which is why the list is pinned by test.
func ensureAPIStats(m map[string]any, statsPort int) {
	if _, ok := m["api"]; !ok {
		m["api"] = map[string]any{
			"tag": "api",
			"services": []any{
				"StatsService",
				"RoutingService",
				"HandlerService",
			},
		}
	}
	// dokodemo-door inbound for the API, loopback only.
	apiIn := map[string]any{
		"tag":      APIInboundTag,
		"listen":   "127.0.0.1",
		keyPort:    statsPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{keyAddress: "127.0.0.1"},
	}
	replaced := false
	inbounds := toAnySlice(m["inbounds"])
	for i, inb := range inbounds {
		im, ok := inb.(map[string]any)
		if ok && im["tag"] == APIInboundTag {
			inbounds[i] = apiIn
			replaced = true
		}
	}
	if !replaced {
		inbounds = append(inbounds, apiIn)
	}
	m["inbounds"] = inbounds

	// The api routing rule goes FIRST: it only matches the api inbound, so it
	// cannot shadow any user traffic rule.
	routing, _ := m["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
		m["routing"] = routing
	}
	rules := toAnySlice(routing["rules"])
	for _, r := range rules {
		if rm, ok := r.(map[string]any); ok && rm["outboundTag"] == "api" {
			return // already present (re-render)
		}
	}
	apiRule := map[string]any{
		"type":        "field",
		"inboundTag":  []any{APIInboundTag},
		"outboundTag": "api",
	}
	routing["rules"] = append([]any{apiRule}, rules...)
}

// ensureStatsAndPolicy makes the traffic counters the W4 stats stage polls
// actually exist. Two hard prerequisites, verified against Xray-core source:
//   - without a "stats" object the core registers stats.NoopManager and
//     GetOrRegisterCounter returns nil — no counters ever;
//   - without policy.system.statsOutboundUplink/Downlink the outbound
//     handler's getStatCounter never registers the per-tag counters.
//
// The emission is unconditional (the api/stats block it feeds is
// unconditional since W3).
func ensureStatsAndPolicy(m map[string]any) {
	if _, ok := m["stats"]; !ok {
		m["stats"] = map[string]any{}
	}
	policy, ok := m["policy"].(map[string]any)
	if !ok {
		policy = map[string]any{}
		m["policy"] = policy
	}
	system, ok := policy["system"].(map[string]any)
	if !ok {
		system = map[string]any{}
		policy["system"] = system
	}
	system["statsOutboundUplink"] = true
	system["statsOutboundDownlink"] = true
}

// leastLoad renders the shared balancer strategy object every pool balancer
// layer emits (expected 1 pick; tolerance = the balancer_tolerance knob).
func leastLoad(tolerance float64) map[string]any {
	return map[string]any{
		"type": "leastLoad",
		"settings": map[string]any{
			"expected":  1,
			"tolerance": tolerance,
		},
	}
}

// addBalancers renders pool_<cc> for every country in the selection and
// pool_<cc>_<city-slug> for cities with >= 2 live nodes (D5; the city
// grouping folds case variants through model.CityKey, M-b). The clean set
// mirrors the same structure over clean-family nodes only
// (cleanServicePoolQualifies — the shared flags+risk predicate; owner
// ruling 2026-11-04: one rule for the whole clean family): every
// country with >= 1 clean node gets pool_<cc>_clean, cities with >= 2 clean
// nodes get pool_<cc>_<city-slug>_clean, and pool_all_clean renders when the
// selection has any clean-family node (owner ruling 2026-11-04: the ENTIRE
// clean family — the pool-wide tier qualifies through the same
// cleanServicePoolQualifies predicate; the pool-wide mirror of pool_all,
// not a service tier). W16 adds two
// balancers (owner item 14):
//   - pool_unknown — the unknown-geo pseudo-location: rendered when ≥1 node
//     with empty geo is in the selection; its selector is the xx pseudo-code
//     prefix (pool-xx- — the D5 tag grammar is untouched; the BALANCER
//     grouping is a render-time concern over resolved geo presence);
//   - pool_all — the pool-wide balancer («общий балансир»): selector over
//     the whole pool- namespace, rendered whenever ≥1 pool node exists.
//
// Phase 3 appends the service-quality tree via addServiceBalancers: the
// global pools pool_clean/pool_chatgpt/pool_netflix/pool_youtube plus the
// country and city chatgpt/netflix variants — each rendered ONLY when ≥1
// selected node qualifies under the Phase-1 evidence joined through
// geoByKey (fail-closed: no evidence, no membership).
//
// Every balancer here — including the new ones — is pinned to fallbackTag
// blockOutboundTag (see that const for the security invariant and the
// verified xray semantics). L2 coverage holds for all of them: the Plan A
// observatory's subjectSelector is the pool- prefix, which covers every
// pool outbound exactly like the country outbounds, and leastLoad only picks
// observatory-covered nodes. tolerance is the [render].balancer_tolerance
// knob, applied to every balancer layer.
//
//nolint:gocognit,gocyclo,cyclop,funlen,maintidx // inherently branchy clean/all separation.
func addBalancers(
	m map[string]any, sel *model.Selection, nodesByKey map[string]*model.Node,
	geoByKey map[string]*model.GeoRecord, tolerance float64,
) []string {
	routing, _ := m["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
		m["routing"] = routing
	}
	existing := toAnySlice(routing["balancers"])

	// onlyCleanMode: when every selected node is clean, the clean-* balancers
	// are redundant (identical selectors to the all balancers) — skip them and
	// render only the common (all) balancers, per the owner's only_clean
	// request ("балансиры только общие, так как все чистые будут").
	onlyCleanMode := true
	for _, sn := range sel.Nodes {
		if !sn.IsClean {
			onlyCleanMode = false
			break
		}
	}
	if len(sel.Nodes) == 0 {
		onlyCleanMode = false
	}

	// Split nodes by country into clean and all sets
	byCountryClean := map[string][]model.SelectedNode{} // country -> clean nodes
	byCountryAll := map[string][]model.SelectedNode{}   // country -> all nodes
	byCityClean := map[string][]model.SelectedNode{}    // "cc|city" -> clean nodes
	byCityAll := map[string][]model.SelectedNode{}      // "cc|city" -> all nodes

	for _, sn := range sel.Nodes {
		byCountryAll[sn.Country] = append(byCountryAll[sn.Country], sn)
		cityKey := sn.Country + "|" + model.CityKey(sn.City)
		byCityAll[cityKey] = append(byCityAll[cityKey], sn)
		// Owner ruling 2026-11-04 (option 2): the whole clean-pool family
		// shares ONE predicate — the country/city clean tiers qualify through
		// cleanServicePoolQualifies exactly like the global pool_clean, so a
		// CHECKED RiskScore above the approved band drops the node from every
		// clean balancer (unchecked evidence keeps flags-only membership).
		if cleanServicePoolQualifies(sn, serviceGeoRecord(nodesByKey, geoByKey, sn)) {
			byCountryClean[sn.Country] = append(byCountryClean[sn.Country], sn)
			byCityClean[cityKey] = append(byCityClean[cityKey], sn)
		}
	}

	// Collect all countries that have either clean or all nodes
	countrySet := map[string]bool{}
	for cc := range byCountryAll {
		countrySet[cc] = true
	}
	for cc := range byCountryClean {
		countrySet[cc] = true
	}
	countries := make([]string, 0, len(countrySet))
	for cc := range countrySet {
		countries = append(countries, cc)
	}
	sort.Strings(countries)

	var rendered []string
	for _, cc := range countries {
		// Clean country balancer (clean nodes only, >= 1): mirrors the ALL
		// country rule so a country whose only node is clean keeps its balancer.
		cleanNodes := byCountryClean[cc]
		if !onlyCleanMode && len(cleanNodes) >= 1 {
			tag := model.CleanCountryBalancerTag(cc)
			if cc == "" {
				tag = "pool_unknown_clean"
			}
			// Build selector from clean node tags
			selectors := make([]any, len(cleanNodes))
			for i, sn := range cleanNodes {
				selectors[i] = sn.Tag
			}
			existing = append(existing, map[string]any{
				keyTag:         tag,
				keySelector:    selectors,
				keyFallbackTag: blockOutboundTag,
				keyStrategy:    leastLoad(tolerance),
			})
			rendered = append(rendered, tag)
		}

		// All country balancer (all nodes, >= 1): the owner requirement is
		// «1 балансир для clean … и 1 для всех (как сейчас)» — every country
		// with at least one node keeps its country balancer, including the
		// unknown-geo pseudo-location (W16).
		allNodes := byCountryAll[cc]
		if len(allNodes) >= 1 {
			tag := model.CountryBalancerTag(cc)
			selector := poolOutboundPrefix + cc + "-"
			if cc == "" {
				tag = model.UnknownBalancerTag
				selector = poolOutboundPrefix + model.UnknownCountryCode + "-"
			}
			existing = append(existing, map[string]any{
				keyTag:         tag,
				keySelector:    []any{selector},
				keyFallbackTag: blockOutboundTag,
				keyStrategy:    leastLoad(tolerance),
			})
			rendered = append(rendered, tag)
		}

		// City balancers for this country
		// Collect cities from both clean and all sets
		citySet := map[string]bool{}
		for cityKey := range byCityAll {
			if strings.HasPrefix(cityKey, cc+"|") {
				citySet[cityKey] = true
			}
		}
		for cityKey := range byCityClean {
			if strings.HasPrefix(cityKey, cc+"|") {
				citySet[cityKey] = true
			}
		}

		cities := make([]string, 0, len(citySet))
		for cityKey := range citySet {
			cities = append(cities, cityKey)
		}
		sort.Strings(cities)

		for _, cityKey := range cities {
			// Extract city name from key
			parts := strings.SplitN(cityKey, "|", 2)
			if len(parts) != 2 {
				continue
			}
			city := parts[1]
			if city == "" {
				continue
			}

			// Clean city balancer (clean nodes only, >= 2)
			cleanCityNodes := byCityClean[cityKey]
			if !onlyCleanMode && len(cleanCityNodes) >= 2 {
				selectors := make([]any, len(cleanCityNodes))
				for i, sn := range cleanCityNodes {
					selectors[i] = sn.Tag
				}
				// Use the display spelling from the first clean node for the tag
				displayCity := cleanCityNodes[0].City
				// Find the deterministic display spelling across all clean nodes in this city
				for _, sn := range cleanCityNodes[1:] {
					displayCity = model.CityDisplay(displayCity, sn.City)
				}
				ctag := model.CleanCityBalancerTag(cc, displayCity)
				existing = append(existing, map[string]any{
					keyTag:         ctag,
					keySelector:    selectors,
					keyFallbackTag: blockOutboundTag,
					keyStrategy:    leastLoad(tolerance),
				})
				rendered = append(rendered, ctag)
			}

			// All city balancer (all nodes, >= 2)
			allCityNodes := byCityAll[cityKey]
			if len(allCityNodes) >= 2 {
				selectors := make([]any, len(allCityNodes))
				for i, sn := range allCityNodes {
					selectors[i] = sn.Tag
				}
				// Use the display spelling from the first node for the tag
				displayCity := allCityNodes[0].City
				for _, sn := range allCityNodes[1:] {
					displayCity = model.CityDisplay(displayCity, sn.City)
				}
				ctag := model.CityBalancerTag(cc, displayCity)
				existing = append(existing, map[string]any{
					keyTag:         ctag,
					keySelector:    selectors,
					keyFallbackTag: blockOutboundTag,
					keyStrategy:    leastLoad(tolerance),
				})
				rendered = append(rendered, ctag)
			}
		}
	}

	// pool_all — the pool-wide balancer over ALL pool outbounds: always rendered when ≥1 pool node exists.
	if len(sel.Nodes) > 0 {
		existing = append(existing, map[string]any{
			keyTag:         model.PoolAllBalancerTag,
			keySelector:    []any{poolOutboundPrefix},
			keyFallbackTag: blockOutboundTag,
			keyStrategy:    leastLoad(tolerance),
		})
		rendered = append(rendered, model.PoolAllBalancerTag)
	}

	// pool_all_clean — the pool-wide balancer over CLEAN pool outbounds:
	// rendered when clean-family nodes exist. Owner ruling 2026-11-04
	// («ENTIRE clean family»): the fourth tier qualifies through the SAME
	// cleanServicePoolQualifies predicate as the global/country/city tiers
	// (flags + RiskScore <= cleanRiskBand when checked); unchecked evidence
	// keeps flags-only membership.
	cleanCount := 0
	for _, sn := range sel.Nodes {
		if cleanServicePoolQualifies(sn, serviceGeoRecord(nodesByKey, geoByKey, sn)) {
			cleanCount++
		}
	}
	if !onlyCleanMode && cleanCount > 0 {
		// Build selector from clean-family node tags
		cleanSelectors := make([]any, 0, cleanCount)
		for _, sn := range sel.Nodes {
			if cleanServicePoolQualifies(sn, serviceGeoRecord(nodesByKey, geoByKey, sn)) {
				cleanSelectors = append(cleanSelectors, sn.Tag)
			}
		}
		existing = append(existing, map[string]any{
			keyTag:         model.CleanPoolAllBalancerTag,
			keySelector:    cleanSelectors,
			keyFallbackTag: blockOutboundTag,
			keyStrategy:    leastLoad(tolerance),
		})
		rendered = append(rendered, model.CleanPoolAllBalancerTag)
	}

	// Phase 3: the service-quality tree rides the same rendered-balancers
	// list, so pool_routes may target service pools exactly like country
	// pools (validation and graceful degradation are shared machinery).
	existing, serviceTags := addServiceBalancers(
		existing, sel, nodesByKey, geoByKey, tolerance, onlyCleanMode)
	rendered = append(rendered, serviceTags...)

	routing["balancers"] = existing
	return rendered
}

// serviceScope is one service-pool grouping bucket: a country (cityKey "")
// or a folded city inside a country (cityKey = model.CityKey). The kind is
// part of the key, so one map holds every country/city service pool.
type serviceScope struct {
	cc      string
	cityKey string
	kind    serviceKind
}

// servicePool is one service balancer ready for emission: its tag and the
// explicit outbound-tag selector list (selection order — the same convention
// the clean/city balancers use; leastLoad needs no further ordering).
type servicePool struct {
	tag       string
	selectors []string
}

// cityGroupKey identifies a folded city bucket for display-spelling folding.
type cityGroupKey struct {
	cc      string
	cityKey string
}

// addServiceBalancers renders the Phase-3 service-quality pool tree and
// returns the extended balancer list plus the tags it rendered (pool_routes
// validation consumes the latter like any other balancer target). Tier and
// membership rules (owner-approved 2026-11-04):
//
//   - pool_clean (GLOBAL only): sn.IsClean && (RiskScore unchecked ||
//     RiskScore <= cleanRiskBand) — the same cleanServicePoolQualifies
//     predicate the country/city clean tiers run (owner ruling 2026-11-04:
//     one rule for the whole clean family). Skipped in only-clean mode —
//     when every
//     selected node is clean its selector is identical to pool_all's, and
//     the owner's only-clean ruling («балансиры только общие») already
//     suppresses the redundant clean-* layer there.
//   - pool_chatgpt / pool_netflix: GLOBAL + country (pool_<cc>_<svc>) +
//     city (pool_<cc>_<city>_<svc>) tiers, >= 1 qualifying node each (the
//     >= 2 minimum stays ONLY on the pre-existing base city pools).
//     Membership is the exact vocabulary verdict: ChatGPT == "yes"
//     (webonly/apponly excluded), Netflix == "full" (originals excluded).
//   - pool_youtube: GLOBAL only; membership is a CHECKED, non-blocked
//     region (the engine stores ISO-2, "blocked" or "unknown").
//
// Unknown-geo nodes (empty country) qualify for the GLOBAL tiers only —
// there is no pool__<svc> country tag for the xx pseudo-location.
// Everything is fail-closed: a node whose geo record is missing, or whose
// verdict is unchecked/unknown, never enters an unlock pool. Emission is
// deterministic: qualifying pools are sorted by tag (the tag embeds
// cc → city-slug → kind, so the order mirrors the existing country/city
// sort scheme), and each balancer is pinned to fallbackTag block with the
// shared leastLoad strategy.
func addServiceBalancers(
	existing []any, sel *model.Selection, nodesByKey map[string]*model.Node,
	geoByKey map[string]*model.GeoRecord, tolerance float64, onlyClean bool,
) ([]any, []string) {
	pools := collectServicePools(sel, nodesByKey, geoByKey, onlyClean)

	rendered := make([]string, 0, len(pools))
	for _, p := range pools {
		selectors := make([]any, len(p.selectors))
		for i, t := range p.selectors {
			selectors[i] = t
		}
		existing = append(existing, map[string]any{
			keyTag:         p.tag,
			keySelector:    selectors,
			keyFallbackTag: blockOutboundTag,
			keyStrategy:    leastLoad(tolerance),
		})
		rendered = append(rendered, p.tag)
	}
	return existing, rendered
}

// collectServicePools buckets the qualifying nodes per tier and returns the
// qualifying service pools sorted by tag (the emission order; tags are
// unique across tiers by grammar, so the sort is the determinism).
func collectServicePools(
	sel *model.Selection, nodesByKey map[string]*model.Node,
	geoByKey map[string]*model.GeoRecord, onlyClean bool,
) []servicePool {
	global := map[serviceKind][]string{}  // kind -> qualifying outbound tags
	scoped := map[serviceScope][]string{} // country/city tier buckets
	display := map[cityGroupKey]string{}  // folded city -> display spelling
	for _, sn := range sel.Nodes {
		gr := serviceGeoRecord(nodesByKey, geoByKey, sn)
		if !onlyClean && cleanServicePoolQualifies(sn, gr) {
			global[serviceClean] = append(global[serviceClean], sn.Tag)
		}
		if gr == nil {
			continue // no unlock evidence: every unlock pool stays closed
		}
		// Country/city tiers exist only for the chatgpt/netflix pair;
		// youtube is global-only by owner ruling.
		for _, kind := range []serviceKind{serviceChatGPT, serviceNetflix} {
			if !serviceKindQualifies(kind, gr.MediaUnlocks) {
				continue
			}
			global[kind] = append(global[kind], sn.Tag)
			if sn.Country == "" {
				continue // the xx pseudo-location has no country/city tier
			}
			// The country scope (cityKey "") and the folded city scope are
			// separate buckets of the same map; the empty cityKey marks the
			// country tier at emission time.
			countryScope := serviceScope{cc: sn.Country, kind: kind}
			scoped[countryScope] = append(scoped[countryScope], sn.Tag)
			cityKey := model.CityKey(sn.City)
			if cityKey == "" {
				continue
			}
			cityScope := serviceScope{cc: sn.Country, cityKey: cityKey, kind: kind}
			scoped[cityScope] = append(scoped[cityScope], sn.Tag)
			gk := cityGroupKey{cc: sn.Country, cityKey: cityKey}
			display[gk] = model.CityDisplay(display[gk], sn.City)
		}
		if serviceKindQualifies(serviceYouTube, gr.MediaUnlocks) {
			global[serviceYouTube] = append(global[serviceYouTube], sn.Tag)
		}
	}

	var pools []servicePool
	for kind, tags := range global {
		if len(tags) > 0 {
			pools = append(pools, servicePool{tag: globalServiceTag(kind), selectors: tags})
		}
	}
	for scope, tags := range scoped {
		if len(tags) == 0 {
			continue
		}
		if scope.cityKey == "" {
			pools = append(pools, servicePool{
				tag:       model.CountryBalancerTag(scope.cc) + "_" + string(scope.kind),
				selectors: tags,
			})
			continue
		}
		city := display[cityGroupKey{cc: scope.cc, cityKey: scope.cityKey}]
		pools = append(pools, servicePool{
			tag:       model.CityBalancerTag(scope.cc, city) + "_" + string(scope.kind),
			selectors: tags,
		})
	}
	// Map iteration order is nondeterministic; the tag sort restores the
	// byte-deterministic output (tags are unique across tiers by grammar).
	sort.Slice(pools, func(i, j int) bool { return pools[i].tag < pools[j].tag })
	return pools
}

// serviceGeoRecord joins a selected node onto its geo record through the
// W19 identity (scheme|lower(host)|port — the same key the pipeline's geo
// map and every store join use, so a multi-parse-record identity shares the
// one exit-IP truth). nil = no record or no evidence map (probes off).
func serviceGeoRecord(
	nodesByKey map[string]*model.Node, geoByKey map[string]*model.GeoRecord, sn model.SelectedNode,
) *model.GeoRecord {
	n := nodesByKey[sn.Key]
	if n == nil || len(geoByKey) == 0 {
		return nil
	}
	return geoByKey[model.GeoIdentity(&model.GeoRecord{Scheme: n.Scheme, Host: n.Host, Port: n.Port})]
}

// cleanServicePoolQualifies is clean-FAMILY membership (owner ruling
// 2026-11-04, option 2): the global pool_clean, the W16 country/city
// clean tiers (pool_<cc>_clean, pool_<cc>_<city>_clean, including the
// pool_unknown_clean xx pseudo-location), and the pool-wide pool_all_clean
// all qualify through this one predicate — the flags verdict
// (sn.IsClean: not hosting, not proxy) plus
// the approved risk band when the score is CHECKED. RiskScore < 0
// (unchecked, probes off) or a missing geo record keeps flags-only
// membership per the owner-approved scheme; unchecked evidence never
// fabricates a score.
func cleanServicePoolQualifies(sn model.SelectedNode, gr *model.GeoRecord) bool {
	if !sn.IsClean {
		return false
	}
	if gr == nil || gr.RiskScore < 0 {
		return true
	}
	return gr.RiskScore <= cleanRiskBand
}

// serviceKindQualifies maps one unlock pool family onto its exact
// MediaUnlocks verdict. Everything except the exact positive verdict fails
// closed: webonly/apponly are NOT chatgpt unlocks (owner ruling
// 2026-11-04), originals are NOT netflix full, and a checked-but-unknown or
// blocked region is not a youtube unlock.
func serviceKindQualifies(kind serviceKind, mu model.MediaUnlockStatus) bool {
	switch kind {
	case serviceClean:
		// The flags+risk family never reads MediaUnlocks — its predicate is
		// cleanServicePoolQualifies; listed here so the kind enum stays
		// exhaustively mapped and can never silently fall to the default.
		return false
	case serviceChatGPT:
		return mu.ChatGPT == model.UnlockYes
	case serviceNetflix:
		return mu.Netflix == model.UnlockNetflixFull
	case serviceYouTube:
		return mu.YouTubeRegion != "" &&
			mu.YouTubeRegion != model.UnlockBlocked &&
			mu.YouTubeRegion != model.UnlockUnknown
	default:
		return false
	}
}

// globalServiceTag maps a service kind onto its global balancer tag.
func globalServiceTag(kind serviceKind) string {
	switch kind {
	case serviceClean:
		return poolCleanBalancerTag
	case serviceChatGPT:
		return poolChatGPTBalancerTag
	case serviceNetflix:
		return poolNetflixBalTag
	case serviceYouTube:
		return poolYouTubeBalancerTag
	default:
		return ""
	}
}

// addPoolRules inserts owner-configured pool routes after the last
// user-traffic rule and before the catch-all (DESIGN.md §4.7). A route target
// is either a rendered pool_* balancer (emitted as balancerTag) or a rendered
// pool-<cc>-NN outbound tag (emitted as outboundTag — D5 single-node city);
// anything else fails loud (D6 namespace wall, unknown target). Every rule
// carries inboundTag: inboundTags — the caller's GENERATED inbound tags (the
// own config's in/in-http pair and its per-country in-<cc> set; the tags are
// render-owned truth).
func addPoolRules(
	m map[string]any, routes []PoolRoute, renderedBalancers []string, renderedOutbounds map[string]bool,
	inboundTags []string,
) ([]string, error) {
	if len(routes) == 0 {
		return nil, nil
	}
	validBalancer := map[string]bool{}
	for _, b := range renderedBalancers {
		validBalancer[b] = true
	}
	routing, _ := m["routing"].(map[string]any)
	rules := toAnySlice(routing["rules"])

	var poolRules []any
	var blocked []string
	for i, route := range routes {
		domains := make([]any, len(route.Domains))
		for j, d := range route.Domains {
			domains[j] = d
		}
		tagged := make([]any, len(inboundTags))
		for j, t := range inboundTags {
			tagged[j] = t
		}
		rule := map[string]any{
			"type":       "field",
			"inboundTag": tagged,
			"domain":     domains,
			// The hot-apply ruleTag (plan T1/R6): a pure function of the route
			// set in render order — identical routes re-render to identical
			// tags, tags are unique per rule, and a balancer-target degradation
			// to block keeps the tag (only the outboundTag changes). This is
			// what `assay apply` verifies the running core against and what a
			// future targeted `rmrules` would address; the api rule and the
			// catch-all stay untagged (render-owned / the terminator).
			"ruleTag": fmt.Sprintf("pool-route-%d", i),
		}
		switch {
		case strings.HasPrefix(route.Balancer, poolBalancerPrefix):
			if !validBalancer[route.Balancer] {
				// Graceful degradation: the target balancer was not rendered
				// (no live nodes there). Drop traffic to block instead of
				// crashing the whole render.
				rule["outboundTag"] = blockOutboundTag
				blocked = append(blocked, fmt.Sprintf("pool route balancer %q not rendered -> block", route.Balancer))
			} else {
				rule["balancerTag"] = route.Balancer
			}
		case strings.HasPrefix(route.Balancer, poolOutboundPrefix):
			if !renderedOutbounds[route.Balancer] {
				rule["outboundTag"] = blockOutboundTag
				blocked = append(blocked, fmt.Sprintf("pool route outbound %q not rendered -> block", route.Balancer))
			} else {
				rule["outboundTag"] = route.Balancer
			}
		default:
			return nil, fmt.Errorf(
				"render: pool route target %q must be a pool_ balancer or a pool-<cc>-NN outbound tag (namespace wall D6)",
				route.Balancer)
		}
		poolRules = append(poolRules, rule)
	}

	// Insert before the catch-all class: every rule of the trailing balancerTag
	// run (the trailing catch-all block may be several rules deep) sits AFTER
	// the pool rules, so pool domain rules are never shadowed by them.
	insertAt := len(rules)
	for insertAt > 0 {
		last, ok := rules[insertAt-1].(map[string]any)
		if !ok {
			break
		}
		if _, isBalancer := last["balancerTag"]; !isBalancer {
			break
		}
		insertAt--
	}
	updated := make([]any, 0, len(rules)+len(poolRules))
	updated = append(updated, rules[:insertAt]...)
	updated = append(updated, poolRules...)
	updated = append(updated, rules[insertAt:]...)
	routing["rules"] = updated
	return blocked, nil
}

// Repeated dial-block vocabulary as constants (goconst): the xray outbound
// settings keys every protocol dial shares, plus the balancer-object key the
// balancer builder emits.
const (
	keyAddress = "address"
	keyPort    = "port"
	keyTag     = "tag"
)

// buildOutbound converts one node into a complete xray outbound. Auth and
// transport params are copied 1:1 from the link (L9); only sockopt.tcpMaxSeg
// and the client TLS fingerprint are owner-mandated overrides (values from
// the W6 render knobs, defaults preserved). It returns the names of link
// params that could NOT be placed in the outbound, so the caller can surface
// them instead of dropping silently.
func buildOutbound(n *model.Node, tag string, cfg Config) (map[string]any, []string, error) {
	consumed := map[string]bool{}
	stream, err := buildStreamSettings(n, consumed, cfg)
	if err != nil {
		return nil, nil, err
	}
	settings, err := buildDialSettings(n, consumed)
	if err != nil {
		return nil, nil, err
	}
	dropped := make([]string, 0)
	for k := range n.Params {
		if !consumed[k] {
			if materialParams[k] {
				return nil, nil, fmt.Errorf(
					"render: outbound %s (%s): link param %q=%q is not renderable for security=%q network=%q "+
						"and changes transport behavior — refusing the silent drop (L9)",
					tag, n.Host, k, n.Params[k], stream["security"], stream["network"])
			}
			dropped = append(dropped, k)
		}
	}
	sort.Strings(dropped)
	return map[string]any{
		"tag":            tag,
		"protocol":       protocolName(n.Scheme),
		"settings":       settings,
		"streamSettings": stream,
	}, dropped, nil
}

// BuildOutbound is the exported seam for out-of-band consumers that need one
// node's rendered xray outbound — the site checker (W8) embeds it into a
// temporary single-node xray config. It is the SAME builder the live renderer
// uses (one literal, no drift): identical params handling, L9 drop report and
// tcpMaxSeg/fingerprint hardening. The tag is caller-owned (the temp config's
// outbound tag; no pool/proxy namespace applies to throwaway instances).
func BuildOutbound(n *model.Node, tag string, cfg Config) (map[string]any, []string, error) {
	return buildOutbound(n, tag, cfg)
}

// protocolName maps the link scheme onto the xray outbound protocol name
// (the ss share scheme renders as protocol "shadowsocks"; the hysteria2
// share scheme renders as protocol "hysteria" — the core's hysteria2 client,
// version == 2, verified against 26.3.27).
func protocolName(scheme string) string {
	if scheme == "ss" {
		return "shadowsocks"
	}
	if scheme == "hysteria2" {
		return "hysteria"
	}
	return scheme
}

// buildStreamSettings renders network/security/sockopt; security-specific
// settings (tls/reality) and network-specific settings (ws/xhttp/grpc/http-
// upgrade/kcp/tcp-header) carry the link's own params verbatim. Every param
// consulted is recorded in consumed so unrendered params surface in the drop
// report.
func buildStreamSettings(n *model.Node, consumed map[string]bool, cfg Config) (map[string]any, error) {
	// hysteria2 is scheme-driven, not param-driven: the transport is ALWAYS
	// hysteria (QUIC) and security is ALWAYS tls — the QUIC dialer errors
	// "tls config is nil" at runtime otherwise (dialer.go Dial), while -test
	// would happily pass a no-TLS variant. Rendered below, bypassing the
	// param-driven network/security resolution.
	if n.Scheme == "hysteria2" {
		return buildHysteria2StreamSettings(n, consumed, cfg), nil
	}
	network, err := networkOf(n, consumed)
	if err != nil {
		return nil, err
	}
	security := securityOf(n, consumed)
	if security == "reality" && !realityNetworks[network] {
		return nil, fmt.Errorf(
			"render: outbound with security=reality requires network tcp/xhttp/grpc (core restriction), got %q — "+
				"the param cannot render, refusing the silent drop (L9)", network)
	}
	stream := map[string]any{
		"network":  network,
		"security": security,
		"sockopt":  map[string]any{"tcpMaxSeg": cfg.TCPMaxSeg},
	}
	switch security {
	case "tls":
		stream["tlsSettings"] = buildTLSSettings(n.Params, consumed, cfg.TLSFingerprint)
	case "reality":
		rs, err := buildRealitySettings(n.Params, consumed, cfg.TLSFingerprint)
		if err != nil {
			return nil, err
		}
		stream["realitySettings"] = rs
	}
	if err := applyNetworkSettings(stream, n.Params, consumed); err != nil {
		return nil, err
	}
	return stream, nil
}

// buildHysteria2StreamSettings renders the verified hysteria2 construct
// (W7 item 10; probes 8/10b/11 passed `xray run -test` on 26.3.27):
//
//	{"network": "hysteria", "security": "tls",
//	 "hysteriaSettings": {"version": 2, "auth": <credential>},
//	 "tlsSettings": {...}}
//
// NO sockopt: tcpMaxSeg is TCP-gated in the core (isTCPSocket,
// transport/internet/sockopt_linux.go) and this transport dials UDP — the
// emission would be inert noise, and hysteria2 is not stream-based.
// The auth credential is the link's userinfo (may be empty — the official
// URI spec marks it optional; never fabricated).
func buildHysteria2StreamSettings(n *model.Node, consumed map[string]bool, cfg Config) map[string]any {
	tls := buildTLSSettings(n.Params, consumed, cfg.TLSFingerprint)
	return map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"hysteriaSettings": map[string]any{"version": 2, "auth": n.UUID},
		"tlsSettings":      tls,
	}
}

func buildTLSSettings(p map[string]string, consumed map[string]bool, fingerprint string) map[string]any {
	tls := map[string]any{"fingerprint": fingerprint}
	// The link's own fp is the same datum (TLS fingerprint) with a mandated
	// value: the owner override to firefox is deliberate policy, not a drop.
	consumed["fp"] = true
	if v := p["sni"]; v != "" {
		consumed["sni"] = true
		tls["serverName"] = v
	}
	if v := p["alpn"]; v != "" {
		consumed["alpn"] = true
		tls["alpn"] = strings.Split(v, ",")
	}
	// pinSHA256 (hysteria2) → pinnedPeerCertSha256: the SAME datum (hex or
	// OpenSSL colon-hex, core strips colons, must decode to 32 bytes). An
	// invalid value fails the xray -test gate loud.
	if v := p["pinsha256"]; v != "" {
		consumed["pinsha256"] = true
		tls["pinnedPeerCertSha256"] = v
	}
	// ech → echConfigList: the same base64 ECH-config-list datum.
	if v := p["ech"]; v != "" {
		consumed["ech"] = true
		tls["echConfigList"] = v
	}
	// allowInsecure/insecure are deliberately NOT consumed: this core removed
	// the feature (config build errors; migrated to pinnedPeerCertSha256), so
	// the params cannot render. Leaving them unconsumed surfaces them in the
	// DroppedParams report — reachable only when [filter].allow_insecure
	// admitted the link (denial in filter, capability-limitation surfaced in
	// renderer).
	return tls
}

func buildRealitySettings(p map[string]string, consumed map[string]bool, fingerprint string) (map[string]any, error) {
	rs := map[string]any{"fingerprint": fingerprint}
	consumed["fp"] = true // owner-mandated firefox override, same datum (see buildTLSSettings)
	if v := p["sni"]; v != "" {
		consumed["sni"] = true
		rs["serverName"] = v
	}
	if p["pbk"] == "" {
		return nil, errors.New("render: reality node has no pbk (auth material missing)")
	}
	consumed["pbk"] = true
	rs["publicKey"] = p["pbk"]
	if v := p["sid"]; v != "" {
		consumed["sid"] = true
		rs["shortId"] = v
	}
	if v := p["spx"]; v != "" {
		consumed["spx"] = true
		rs["spiderX"] = v
	}
	if v := p["pqv"]; v != "" {
		consumed["pqv"] = true
		rs["mldsa65Verify"] = v
	}
	return rs, nil
}

// applyNetworkSettings renders the transport-specific settings block for the
// outbound's network. Behavior per network (all verified against Xray-core
// v26.3.27 source + `xray run -test` on the real binary):
//   - tcp: headerType=http renders the http-obfs request block; seed-style
//     header types other than http/none are refused loud;
//   - ws / httpupgrade: path, host (the independent field — headers.Host is
//     deprecated upstream), ed appended into the path query (the core parses
//     it out of the path), ehs only as the fixed Sec-WebSocket-Protocol;
//   - grpc: serviceName, mode=multi → multiMode;
//   - kcp: header/seed were REMOVED from the core (migrated to finalmask /
//     mkcp-original / mkcp-aes128gcm) — links carrying them fail loud;
//   - xhttp: mode/path/host plus an extra JSON-object passthrough;
//   - http/h2/h3/quic/unknown: refused loud with the param named.
func applyNetworkSettings(stream map[string]any, p map[string]string, consumed map[string]bool) error {
	switch stream["network"] {
	case networkTCP:
		return applyTCPSettings(stream, p, consumed)
	case networkWS:
		return applyWSSettings(stream, p, consumed)
	case networkHTTPUpgrade:
		return applyHTTPUpgradeSettings(stream, p, consumed)
	case networkGRPC:
		return applyGRPCSettings(stream, p, consumed)
	case networkKCP:
		return applyKCPSettings(p, consumed)
	case networkXHTTP:
		applyXHTTPSettings(stream, p, consumed)
	}
	return nil
}

func applyTCPSettings(stream map[string]any, p map[string]string, consumed map[string]bool) error {
	headerType := strings.ToLower(p["headerType"])
	consumed["headerType"] = true
	switch headerType {
	case "", "none":
		return nil
	case "http":
		stream["tcpSettings"] = map[string]any{"header": tcpHTTPObfuscation(p["host"], p["path"])}
		consumed["host"] = true
		consumed["path"] = true
		return nil
	default:
		return fmt.Errorf(
			"render: tcp header type %q is not renderable (xray supports none|http) — "+
				"refusing the silent drop of param headerType=%q (L9)", headerType, p["headerType"])
	}
}

func applyWSSettings(stream map[string]any, p map[string]string, consumed map[string]bool) error {
	ws := map[string]any{}
	if v := p["path"]; v != "" {
		consumed["path"] = true
		ws["path"] = v
	}
	if v := p["ed"]; v != "" {
		consumed["ed"] = true
		base := ws["path"]
		if s, ok := base.(string); !ok || s == "" {
			base = "/"
		}
		ws["path"] = appendEarlyData(base.(string), v)
	}
	if v := p["ehs"]; v != "" {
		consumed["ehs"] = true
		if v != wsEarlyDataHeader {
			return fmt.Errorf(
				"render: ws earlyDataHeaderName %q is not renderable — the xray websocket transport always uses "+
					"the fixed %q header (no config field); a different value would change semantics, refusing (L9)",
				v, wsEarlyDataHeader)
		}
	}
	if v := p["host"]; v != "" {
		consumed["host"] = true
		ws["host"] = v
	}
	if len(ws) > 0 {
		stream["wsSettings"] = ws
	}
	return nil
}

func applyHTTPUpgradeSettings(stream map[string]any, p map[string]string, consumed map[string]bool) error {
	hu := map[string]any{}
	if v := p["path"]; v != "" {
		consumed["path"] = true
		hu["path"] = v
	}
	if v := p["ed"]; v != "" {
		consumed["ed"] = true
		base := hu["path"]
		if s, ok := base.(string); !ok || s == "" {
			base = "/"
		}
		hu["path"] = appendEarlyData(base.(string), v)
	}
	if v := p["ehs"]; v != "" {
		consumed["ehs"] = true
		if v != wsEarlyDataHeader {
			return fmt.Errorf(
				"render: httpupgrade earlyDataHeaderName %q is not renderable — the core always uses %q; refusing (L9)",
				v, wsEarlyDataHeader)
		}
	}
	if v := p["host"]; v != "" {
		consumed["host"] = true
		hu["host"] = v
	}
	if len(hu) > 0 {
		stream["httpupgradeSettings"] = hu
	}
	return nil
}

func applyGRPCSettings(stream map[string]any, p map[string]string, consumed map[string]bool) error {
	gs := map[string]any{}
	if v := p["serviceName"]; v != "" {
		consumed["serviceName"] = true
		gs["serviceName"] = v
	}
	if v := p["mode"]; v != "" {
		consumed["mode"] = true
		switch strings.ToLower(v) {
		case "multi":
			gs["multiMode"] = true
		case "gun":
			// gun is the default (multiMode=false) — the datum renders as the
			// absence of multiMode.
		default:
			return fmt.Errorf(
				"render: grpc mode %q is not renderable (xray grpc modes: gun|multi) — refusing the silent drop (L9)", v)
		}
	}
	if len(gs) > 0 {
		stream["grpcSettings"] = gs
	}
	return nil
}

// applyKCPSettings consumes nothing: mKCP header obfuscation and seed were
// REMOVED from the 26.3.27 core (config build errors: "The feature mkcp
// header & seed has been removed and migrated to finalmask/udp header-* &
// mkcp-original & mkcp-aes128gcm") — a link carrying them cannot be expressed
// by this core and must fail loud instead of rendering a silently different
// transport.
func applyKCPSettings(p map[string]string, _ map[string]bool) error {
	for _, k := range []string{"seed", "headerType"} {
		if v := p[k]; v != "" {
			return fmt.Errorf(
				"render: mKCP param %s=%q is not renderable — the feature was removed from xray 26.3.27 "+
					"(migrated to finalmask/udp header-* & mkcp-original & mkcp-aes128gcm), refusing the silent drop (L9)",
				k, v)
		}
	}
	return nil
}

func applyXHTTPSettings(stream map[string]any, p map[string]string, consumed map[string]bool) {
	xs := map[string]any{}
	for _, k := range []string{"host", "path", "mode"} {
		if v := p[k]; v != "" {
			consumed[k] = true
			xs[k] = v
		}
	}
	if v := p["extra"]; v != "" {
		var extra map[string]any
		// A nil map after a successful unmarshal means the JSON value was
		// `null` — still not an object, still behavior-changing material:
		// leave it unconsumed so materialParams fails the render loud (M-2).
		if err := json.Unmarshal([]byte(v), &extra); err == nil && extra != nil {
			consumed["extra"] = true
			// Parsed into a map so the deterministic sorted-key marshal
			// applies; a JSON object passthrough is what xhttpSettings.extra
			// expects (json.RawMessage field in the core's SplitHTTPConfig).
			xs["extra"] = extra
		}
		// An extra value that is not a JSON object stays unconsumed → it
		// fails the render loud via materialParams (M-2), it is never
		// silently dropped.
	}
	if len(xs) > 0 {
		stream["xhttpSettings"] = xs
	}
}

// buildDialSettings renders the protocol-specific dial block.
func buildDialSettings(n *model.Node, consumed map[string]bool) (map[string]any, error) {
	switch n.Scheme {
	case "vless":
		return buildVLESSDial(n, consumed), nil
	case "trojan":
		return buildTrojanDial(n), nil
	case "vmess":
		return buildVMESSDial(n, consumed)
	case "ss":
		return buildSSDial(n, consumed)
	case "hysteria2":
		return buildHysteria2Dial(n)
	default:
		return nil, fmt.Errorf("render: unsupported scheme %q", n.Scheme)
	}
}

// buildHysteria2Dial renders the verified outbound settings shape:
// {"version": 2, "address": H, "port": P} (infra/conf/hysteria.go:
// HysteriaClientConfig — version MUST be 2, address+port are flat). The
// empty-host guard is defensive: a record with a lost host would hit the
// core's own nil-pointer PANIC (HysteriaClientConfig.Build → Address.Build,
// probed 2026-10-28: SIGSEGV) — the renderer refuses loud instead.
func buildHysteria2Dial(n *model.Node) (map[string]any, error) {
	if n.Host == "" {
		return nil, errors.New(
			"render: hysteria2 outbound has an empty host — refusing: the core's own builder panics on a nil address (L9)")
	}
	return map[string]any{"version": 2, keyAddress: n.Host, keyPort: n.Port}, nil
}

// buildSSDial renders the shadowsocks outbound (verified against Xray-core
// v26.3.27 infra/conf/shadowsocks.go: servers[0] carries method/password;
// there are NO plugin/pluginOpts fields — a SIP003 plugin param on the link
// cannot be expressed by this core and fails loud instead of rendering a
// silently different transport). Method and password are auth material: an
// empty one fails the render (M-f precedent).
func buildSSDial(n *model.Node, consumed map[string]bool) (map[string]any, error) {
	if v := n.Params["plugin"]; v != "" {
		return nil, fmt.Errorf(
			"render: shadowsocks outbound %s: link param %q=%q is not renderable — the xray 26.3.27 "+
				"shadowsocks outbound has no SIP003 plugin support (no plugin/pluginOpts config fields), "+
				"and dropping the plugin would silently change the transport; refusing (L9)", n.Host, "plugin", v)
	}
	method := n.Params["method"]
	consumed["method"] = true
	password := n.Params["password"]
	consumed["password"] = true
	if method == "" || password == "" {
		return nil, fmt.Errorf(
			"render: shadowsocks outbound %s: method/password missing from the link record — "+
				"auth material, refusing to render an empty credential (L9)", n.Host)
	}
	return map[string]any{"servers": []any{map[string]any{
		keyAddress: n.Host,
		keyPort:    n.Port,
		"method":   method,
		"password": password,
	}}}, nil
}

func buildVLESSDial(n *model.Node, consumed map[string]bool) map[string]any {
	user := map[string]any{"id": n.UUID, "encryption": "none"}
	if v := n.Params["flow"]; v != "" {
		consumed["flow"] = true
		user["flow"] = v
	}
	return map[string]any{"vnext": []any{map[string]any{
		keyAddress: n.Host,
		keyPort:    n.Port,
		"users":    []any{user},
	}}}
}

func buildTrojanDial(n *model.Node) map[string]any {
	return map[string]any{"servers": []any{map[string]any{
		keyAddress: n.Host,
		keyPort:    n.Port,
		"password": n.UUID,
	}}}
}

func buildVMESSDial(n *model.Node, consumed map[string]bool) (map[string]any, error) {
	aid := 0
	if v := n.Params["aid"]; v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			// aid is auth-adjacent material: a value we cannot parse must fail
			// the render loud (L9) — silently rendering alterId 0 would break
			// the handshake in the field. Consumed only on success, so an
			// unplaced aid can never vanish from the reporting path.
			return nil, fmt.Errorf(
				"render: vmess outbound %s: link param %q=%q is not a number — refusing silent alterId 0 (L9)",
				n.Host, "aid", v)
		}
		consumed["aid"] = true
		aid = parsed
	}
	security := n.Params["scy"]
	if security == "" {
		security = "auto"
	} else {
		consumed["scy"] = true
	}
	return map[string]any{"vnext": []any{map[string]any{
		keyAddress: n.Host,
		keyPort:    n.Port,
		"users":    []any{map[string]any{"id": n.UUID, "alterId": aid, "security": security}},
	}}}, nil
}

// networkOf resolves the link's transport into a canonical renderable
// network name. Spellings outside the renderable set fail loud with the
// param named — removed transports (http/h2/h3/quic on 26.3.27) carry their
// upstream migration note, unknown values a plain unsupported error (L9: the
// network choice IS transport behavior; a silent fallback would change it).
func networkOf(n *model.Node, consumed map[string]bool) (string, error) {
	raw := n.Params["type"]
	if raw == "" {
		raw = n.Params["net"]
	}
	consumed["type"] = true
	consumed["net"] = true
	if raw == "" {
		return networkTCP, nil
	}
	canonical, ok := networkAliases[strings.ToLower(raw)]
	if !ok {
		if reason, removed := removedNetworks[strings.ToLower(raw)]; removed {
			return "", fmt.Errorf(
				"render: outbound (host %s): link param type=%q is not renderable — %s, "+
					"refusing the silent drop (L9)", n.Host, raw, reason)
		}
		return "", fmt.Errorf(
			"render: outbound %s: link param type=%q names a transport the renderer does not support "+
				"(supported: tcp/raw, ws/websocket, httpupgrade, grpc, kcp/mkcp, xhttp/splithttp) — refusing (L9)",
			n.Host, raw)
	}
	return canonical, nil
}

func securityOf(n *model.Node, consumed map[string]bool) string {
	if n.Security == "tls" || n.Security == "reality" {
		// Both spellings feed NewNode's security resolution (params.security,
		// params.tls, trojan-is-tls) — the same datum either way.
		consumed["security"] = true
		consumed["tls"] = true
		return n.Security
	}
	if n.Scheme == "trojan" {
		consumed["security"] = true
		consumed["tls"] = true
		return "tls" // trojan is TLS by definition
	}
	consumed["security"] = true
	consumed["tls"] = true
	return "none"
}

// toAnySlice coerces a stored interface value into an []any (empty when nil).
func toAnySlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return []any{}
}

// ---- Own-target generation (self-held core pivot) ----

// RouteRule is the S6 pool-route rule type of the own-target generation —
// the re-homed [render].pool_routes entries (the design's name; the same
// shape and semantics as the pre-pivot PoolRoute).
type RouteRule = PoolRoute

// Own inbound tag grammar (D2): the base socks/http pair plus per-country
// socks ports tagged in-<cc> (cc = the ISO code, or the xx pseudo-location),
// and the reserved stats/API dokodemo-door inbound. Exported: the status
// core block (internal/cli) classifies the live config's inbounds against
// this exact grammar — one definition of the tag contract.
const (
	SocksInboundTag     = "in"
	HTTPInboundTag      = "in-http"
	PerCountryTagPrefix = "in-"
	APIInboundTag       = "api-in"
)

// IsPerCountryInboundTag reports the D2 per-country socks inbound shape:
// in-<cc> with a two-letter lowercase suffix — the exact tags
// addPerCountryInbounds generates.
func IsPerCountryInboundTag(tag string) bool {
	if !strings.HasPrefix(tag, PerCountryTagPrefix) || len(tag) != len(PerCountryTagPrefix)+2 {
		return false
	}
	for i := len(PerCountryTagPrefix); i < len(tag); i++ {
		if c := tag[i]; c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// Repeated object-key vocabulary of the own-target generation (goconst).
const (
	keyProtocol = "protocol"
	keyRuleType = "type"
)

// normalizeCore applies the [core] defaults to a directly-constructed
// CoreConfig — the same constants applyCoreDefaults materializes (one
// default, one literal, no layer drift). Pipeline callers arrive
// pre-normalized from config.Load; direct callers get the same shape.
func normalizeCore(c config.CoreConfig) config.CoreConfig {
	if c.SocksPort == 0 {
		c.SocksPort = config.DefaultCoreSocksPort
	}
	if c.HTTPPort == 0 {
		c.HTTPPort = config.DefaultCoreHTTPPort
	}
	if c.APIPort == 0 {
		c.APIPort = config.DefaultCoreAPIPort
	}
	if c.Loglevel == "" {
		c.Loglevel = config.DefaultCoreLoglevel
	}
	return c
}

// ownSocksInbound renders one socks5 inbound on the loopback bind (D2/N1)
// with the canonical inbound shape (auth noauth, udp on, sniffing
// route-only — domain rules need sniffing, routeOnly keeps it out of the
// destination resolution).
func ownSocksInbound(tag string, port int) map[string]any {
	return map[string]any{
		keyTag:      tag,
		"listen":    config.CoreBindAddress,
		keyPort:     port,
		keyProtocol: "socks",
		"settings":  map[string]any{"auth": "noauth", "udp": true},
		"sniffing":  map[string]any{"enabled": true, "routeOnly": true},
	}
}

// ownHTTPInbound is the http twin of ownSocksInbound.
func ownHTTPInbound(tag string, port int) map[string]any {
	return map[string]any{
		keyTag:      tag,
		"listen":    config.CoreBindAddress,
		keyPort:     port,
		keyProtocol: "http",
		"settings":  map[string]any{},
		"sniffing":  map[string]any{"enabled": true, "routeOnly": true},
	}
}

// addPerCountryInbounds renders the D2 option layer: one socks inbound per
// alive-country balancer (the xx pseudo-location included — its balancer is
// pool_unknown) plus the routing rule that sends that inbound's traffic
// wholesale to its balancer. Ports walk up from the socks port and skip the
// reserved ports (the generated http inbound and the api dokodemo-door) so
// generated inbounds can never collide. Returns the extended
// rule and inbound lists (deterministic: countries sorted).
func addPerCountryInbounds(
	m map[string]any, sel *model.Selection, core config.CoreConfig, rules []any,
) ([]any, []any) {
	ccSet := map[string]bool{}
	for _, sn := range sel.Nodes {
		cc := sn.Country
		if cc == "" {
			cc = model.UnknownCountryCode
		}
		ccSet[cc] = true
	}
	ccs := make([]string, 0, len(ccSet))
	for cc := range ccSet {
		ccs = append(ccs, cc)
	}
	sort.Strings(ccs)

	inbounds := toAnySlice(m["inbounds"])
	port := core.SocksPort
	for _, cc := range ccs {
		port++
		// Skip every reserved port: the generated http inbound AND the api
		// dokodemo-door (a bind collision passes -test and only surfaces as
		// a core crash-loop — review M2).
		for port == core.HTTPPort || port == core.APIPort {
			port++
		}
		tag := PerCountryTagPrefix + cc
		inbounds = append(inbounds, ownSocksInbound(tag, port))
		balancer := model.CountryBalancerTag(cc)
		if cc == model.UnknownCountryCode {
			balancer = model.UnknownBalancerTag
		}
		rules = append(rules, map[string]any{
			keyRuleType:   "field",
			"inboundTag":  []any{tag},
			"balancerTag": balancer,
		})
	}
	return rules, inbounds
}

// RenderOwnConfig generates assay's OWN live config (the self-held core
// pivot: 2026-11-10 design D2/D7/S6/S7) — the artifact the core manager
// spawns (`<data>/rendered/live.json`). Structure: the S7 log block
// (loglevel from [core].loglevel, access: none), own proxy inbounds (socks
// + http on the loopback bind; per-country socks ports when the D2 option is
// on and a pool exists), outbounds (direct/block + pool), the shared
// balancer tree (as today), the Plan A observatory (only with a pool — the
// 26.3.27 empty-coverage busy-loop landmine, L1, is respected structurally),
// the stats/policy blocks (build facts: the counters need both), the api
// service on [core].api_port, and routing: the S6 owner domain rules between
// the api rule and the catch-all; catch-all → pool_all leastLoad when a
// selection exists, → block in the bootstrap/empty posture per D7 (an empty
// pool NEVER routes to direct, A4).
//
// An EMPTY (or nil — normalized to empty at the entry) SELECTION is the
// bootstrap posture — the render-level layer of the two-layer D7 empty-pool
// contract. Whether the artifact gets written (bootstrap on first run,
// keep-last-good otherwise) is the PIPELINE layer.
//
// The nodes/geo maps are the same unchanged inputs the template merge
// consumes (SelectedNode carries no link params — the outbounds and the
// evidence join runs through them); knobs carries the surviving [render]
// knobs (tcp_max_seg, tls_fingerprint, balancer_tolerance,
// observatory_interval). A pool route whose target balancer/outbound was not
// rendered (no live nodes there) degrades to the block outbound — the same
// graceful fail-closed semantics of the pool-route layer — and is REPORTED
// through the returned warnings slice (the T4 report-channel widening of
// the T3 review's M1: fail-closed stays, the loudness is back); a target
// outside the pool_/pool- namespace still fails loud (D6).
//
//nolint:revive // the plan's binding name (RenderOwnConfig sel,core,poolRoutes) — the stutter is the contract.
func RenderOwnConfig(
	sel *model.Selection, core config.CoreConfig, poolRoutes []RouteRule,
	nodes map[string]*model.Node, geoByKey map[string]*model.GeoRecord, knobs Config,
) ([]byte, []string, error) {
	core = normalizeCore(core)
	cfg := normalizeKnobs(knobs)
	if sel == nil {
		// Nil-tolerance promise: a nil selection IS the bootstrap posture —
		// normalized once here so every downstream consumer (the pool loop,
		// addBalancers, addPerCountryInbounds) sees a real selection and the
		// function never panics on its exported seam (review I-1).
		sel = &model.Selection{}
	}
	poolCount := len(sel.Nodes)

	outbounds := []any{
		map[string]any{keyTag: "direct", "protocol": "freedom"},
		map[string]any{keyTag: blockOutboundTag, "protocol": "blackhole"},
	}
	renderedOutbounds := map[string]bool{}
	// droppedWarnings accumulates the non-material param drop report (T7
	// disposition C1 — SURFACE chosen): the renderer's contract comment
	// (buildTLSSettings) and config.example's [filter] block both promise
	// a loud drop-report entry, and the warnings channel is the same loud
	// grammar the pool-route degradations use. Material params keep
	// failing the render loud (L9) — this carries only the remainder.
	droppedWarnings := make([]string, 0)
	for _, sn := range sel.Nodes {
		n, ok := nodes[sn.Key]
		if !ok {
			return nil, nil, fmt.Errorf("render: selected node %s (tag %s) has no node record", sn.Key, sn.Tag)
		}
		ob, dropped, err := buildOutbound(n, sn.Tag, cfg)
		if err != nil {
			return nil, nil, err
		}
		if len(dropped) > 0 {
			droppedWarnings = append(droppedWarnings, fmt.Sprintf(
				"render: outbound %s (%s): non-material link params not renderable and dropped: %s "+
					"(capability limitation; material params fail the render loud)",
				sn.Tag, n.Host, strings.Join(dropped, ", ")))
		}
		if renderedOutbounds[sn.Tag] {
			return nil, nil, fmt.Errorf("render: outbound tag %q rendered twice (selection collision)", sn.Tag)
		}
		outbounds = append(outbounds, ob)
		renderedOutbounds[sn.Tag] = true
	}

	m := map[string]any{
		"log": map[string]any{
			"loglevel": core.Loglevel,
			"access":   "none", // S7: the 272k-lines/8h journald-flood lesson
		},
		"inbounds": []any{
			ownSocksInbound(SocksInboundTag, core.SocksPort),
			ownHTTPInbound(HTTPInboundTag, core.HTTPPort),
		},
		"outbounds": outbounds,
		"routing":   map[string]any{"rules": []any{}},
	}

	var renderedBalancers []string
	if poolCount > 0 {
		// The shared balancer tree renders exactly as the pool layer always did
		// (country/city/all/clean/service tiers) — balancers as today.
		renderedBalancers = addBalancers(m, sel, nodes, geoByKey, cfg.BalancerTolerance)
		m["observatory"] = map[string]any{
			"subjectSelector":   []any{poolOutboundPrefix},
			"probeInterval":     observatoryInterval(cfg.ObservatoryInterval, poolCount),
			"enableConcurrency": true,
		}
	}

	// The stats/API service block: dokodemo-door inbound on api_port, the api
	// routing rule FIRST (it only matches its own inbound), and the
	// stats/policy blocks the per-tag counters require (build facts).
	ensureAPIStats(m, core.APIPort)
	ensureStatsAndPolicy(m)

	// S6: owner domain rules matched against the GENERATED inbound tags,
	// inserted after the api rule. Unrendered targets degrade to block (the
	// graceful fail-closed semantics of the pool-route layer) and surface
	// through the returned warnings (the T4 report-channel widening — the
	// same strings the pool-route layer reports).
	blocked, err := addPoolRules(m, poolRoutes, renderedBalancers, renderedOutbounds,
		[]string{SocksInboundTag, HTTPInboundTag})
	if err != nil {
		return nil, nil, err
	}

	routing, _ := m["routing"].(map[string]any)
	rules := toAnySlice(routing["rules"])
	if core.PerCountryInbounds && poolCount > 0 {
		var inbounds []any
		rules, inbounds = addPerCountryInbounds(m, sel, core, rules)
		m["inbounds"] = inbounds
	}

	// The catch-all closes the rule list: pool_all leastLoad with a pool,
	// the block blackhole in the bootstrap/empty posture (D7/A4).
	catchAll := map[string]any{keyRuleType: "field", "network": "tcp,udp"}
	if poolCount > 0 {
		catchAll["balancerTag"] = model.PoolAllBalancerTag
	} else {
		catchAll["outboundTag"] = blockOutboundTag
	}
	rules = append(rules, catchAll)
	routing["rules"] = rules

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return b, append(droppedWarnings, blocked...), nil
}
