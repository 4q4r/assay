// Package render implements the W3 xray client-config renderer: template +
// pool outbounds + per-country/city leastLoad balancers + owner pool routes +
// Plan A observatory, under the hard gates L1 (never an observatory whose
// selector can match zero tags) and L2 (balancers require coverage). Every
// link auth/transport param passes through 1:1 (L9); every pool outbound gets
// sockopt.tcpMaxSeg 1440 and client fingerprint firefox.
package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"public_vpn/internal/model"
)

// PoolRoute is one owner-configured routing rule into a pool balancer (D2:
// the pool only carries explicitly routed traffic).
type PoolRoute struct {
	Balancer string   `toml:"balancer"`
	Domains  []string `toml:"domains"`
}

// ParamWarning reports the link parameters of one outbound that the renderer
// could not place into the config. They are surfaced, never silently dropped
// (L9 hygiene; review finding 5).
type ParamWarning struct {
	Tag    string   `json:"tag"`
	Host   string   `json:"host"`
	Params []string `json:"params"`
}

// Result carries the rendered config and the structured drop report.
type Result struct {
	Config        []byte
	DroppedParams []ParamWarning
}

// materialParams are link parameters that change transport behavior when they
// cannot be rendered (early-data sizing). Their silent loss must fail the
// render, not warn (review finding 5).
var materialParams = map[string]bool{
	"ed":         true,
	"early-data": true,
}

// Config carries the render knobs.
type Config struct {
	StatsPort  int
	PoolRoutes []PoolRoute
}

// Input bundles render dependencies.
type Input struct {
	Template   []byte
	Selection  *model.Selection
	NodesByKey map[string]*model.Node
	Cfg        Config
}

const (
	tcpMaxSeg          = 1440
	clientFingerprint  = "firefox"
	poolOutboundPrefix = "pool-"
	poolBalancerPrefix = "pool_"
)

// Render produces the complete xray config JSON (one document, no merge
// stacking — L3). Output is byte-deterministic: maps marshal with sorted keys.
// Link parameters that cannot be rendered are reported in the result — never
// silently dropped; material ones (early-data) fail the render.
func Render(in Input) (Result, error) {
	var m map[string]any
	if err := json.Unmarshal(in.Template, &m); err != nil {
		return Result{}, fmt.Errorf("decode template: %w", err)
	}
	if err := stripPoolArtifacts(m); err != nil {
		return Result{}, err
	}
	ensureAPIStats(m, in.Cfg.StatsPort)
	ensureStatsAndPolicy(m)

	poolCount := len(in.Selection.Nodes)
	if poolCount == 0 {
		// L1/L2: nothing pool-related may render; the template passes through.
		b, err := json.MarshalIndent(m, "", "  ")
		return Result{Config: b}, err
	}

	byTag := map[string]bool{}
	for _, o := range toAnySlice(m["outbounds"]) {
		if om, ok := o.(map[string]any); ok {
			if tag, _ := om["tag"].(string); tag != "" {
				byTag[tag] = true
			}
		}
	}

	var dropped []ParamWarning
	for _, sn := range in.Selection.Nodes {
		n, ok := in.NodesByKey[sn.Key]
		if !ok {
			return Result{}, fmt.Errorf("render: selected node %s (tag %s) has no node record", sn.Key, sn.Tag)
		}
		ob, unparsed, err := buildOutbound(n, sn.Tag)
		if err != nil {
			return Result{}, err
		}
		if len(unparsed) > 0 {
			dropped = append(dropped, ParamWarning{Tag: sn.Tag, Host: n.Host, Params: unparsed})
		}
		if byTag[sn.Tag] {
			return Result{}, fmt.Errorf("render: outbound tag %q already exists in template (namespace collision)", sn.Tag)
		}
		m["outbounds"] = append(toAnySlice(m["outbounds"]), ob)
		byTag[sn.Tag] = true
	}

	renderedBalancers := addBalancers(m, in.Selection)

	// Plan A: legacy observatory covering exactly the pool namespace. The
	// burstObservatory (Germans) is untouched — verified coexistence.
	m["observatory"] = map[string]any{
		"subjectSelector":   []any{poolOutboundPrefix},
		"probeInterval":     "60s",
		"enableConcurrency": true,
	}

	if err := addPoolRules(m, in.Cfg.PoolRoutes, renderedBalancers); err != nil {
		return Result{}, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	return Result{Config: b, DroppedParams: dropped}, err
}

// stripPoolArtifacts removes every pool-owned artifact from a (possibly
// previously rendered) template so re-renders are idempotent.
func stripPoolArtifacts(m map[string]any) error {
	stripPoolOutbounds(m)
	stripPoolRouting(m)
	return stripForeignObservatory(m)
}

func stripPoolOutbounds(m map[string]any) {
	raw, ok := m["outbounds"].([]any)
	if !ok {
		return
	}
	kept := make([]any, 0, len(raw))
	for _, o := range raw {
		if om, isMap := o.(map[string]any); isMap {
			if tag, _ := om["tag"].(string); strings.HasPrefix(tag, poolOutboundPrefix) {
				continue
			}
		}
		kept = append(kept, o)
	}
	m["outbounds"] = kept
}

func stripPoolRouting(m map[string]any) {
	routing, _ := m["routing"].(map[string]any)
	if routing == nil {
		return
	}
	if raw, ok := routing["balancers"].([]any); ok {
		kept := make([]any, 0, len(raw))
		for _, b := range raw {
			if bm, isMap := b.(map[string]any); isMap {
				if tag, _ := bm["tag"].(string); strings.HasPrefix(tag, poolBalancerPrefix) {
					continue
				}
			}
			kept = append(kept, b)
		}
		routing["balancers"] = kept
	}
	if raw, ok := routing["rules"].([]any); ok {
		kept := make([]any, 0, len(raw))
		for _, r := range raw {
			if rm, isMap := r.(map[string]any); isMap {
				if bt, _ := rm["balancerTag"].(string); strings.HasPrefix(bt, poolBalancerPrefix) {
					continue
				}
			}
			kept = append(kept, r)
		}
		routing["rules"] = kept
	}
}

// stripForeignObservatory removes OUR legacy observatory (re-added fresh on
// re-render) and refuses every other legacy observatory. L1 defense-in-depth:
// one whose subjectSelector can match zero tags (empty array or missing
// field) busy-loops the 26.3.27 core at ~100% CPU — that refusal is
// unconditional, on any pool state; with a pool rendered, the Plan A
// observatory would simply overwrite it, but a refusal here leaves no path
// where the deadly shape reaches a rendered config.
func stripForeignObservatory(m map[string]any) error {
	obs, ok := m["observatory"].(map[string]any)
	if !ok {
		return nil
	}
	selectors := stringSlice(obs["subjectSelector"])
	if len(selectors) == 0 {
		return errors.New("render: template carries a legacy observatory with an empty subjectSelector — " +
			"it matches zero tags and busy-loops the core (L1, 26.3.27); remove it from the template " +
			"or give it a non-empty selector")
	}
	ours := true
	for _, s := range selectors {
		if !strings.HasPrefix(s, poolOutboundPrefix) {
			ours = false
			break
		}
	}
	if ours {
		delete(m, "observatory")
		return nil
	}
	return fmt.Errorf("render: template already carries a non-pool legacy observatory %v — "+
		"Plan A cannot coexist; switch to Plan B", selectors)
}

// ensureAPIStats renders the api/stats service block bound to 127.0.0.1 only.
func ensureAPIStats(m map[string]any, statsPort int) {
	if _, ok := m["api"]; !ok {
		m["api"] = map[string]any{
			"tag":      "api",
			"services": []any{"StatsService"},
		}
	}
	// dokodemo-door inbound for the API, loopback only.
	apiIn := map[string]any{
		"tag":      "api-in",
		"listen":   "127.0.0.1",
		"port":     statsPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1"},
	}
	replaced := false
	inbounds := toAnySlice(m["inbounds"])
	for i, inb := range inbounds {
		im, ok := inb.(map[string]any)
		if ok && im["tag"] == "api-in" {
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
		"inboundTag":  []any{"api-in"},
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
// The owner's live template carries neither, so the emission is additive and
// unconditional (the api/stats block it feeds is unconditional since W3),
// preserving any policy fields the template already carries.
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

// addBalancers renders pool_<cc> for every country in the selection and
// pool_<cc>_<city-slug> for cities with >= 2 live nodes (D5). Returns the
// rendered balancer tags.
func addBalancers(m map[string]any, sel *model.Selection) []string {
	routing, _ := m["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
		m["routing"] = routing
	}
	existing := toAnySlice(routing["balancers"])

	byCountry := map[string][]model.SelectedNode{} // country -> selected nodes (ordered)
	byCity := map[string][]model.SelectedNode{}    // "cc|city" -> nodes
	for _, sn := range sel.Nodes {
		byCountry[sn.Country] = append(byCountry[sn.Country], sn)
		byCity[sn.Country+"|"+sn.City] = append(byCity[sn.Country+"|"+sn.City], sn)
	}
	countries := make([]string, 0, len(byCountry))
	for cc := range byCountry {
		countries = append(countries, cc)
	}
	sort.Strings(countries)

	var rendered []string
	for _, cc := range countries {
		tag := model.CountryBalancerTag(cc)
		nodes := byCountry[cc]
		tags := make([]any, 0, 1)
		tags = append(tags, poolOutboundPrefix+cc+"-")
		existing = append(existing, map[string]any{
			"tag":      tag,
			"selector": tags,
			"strategy": map[string]any{
				"type": "leastLoad",
				"settings": map[string]any{
					"expected":  1,
					"tolerance": 0.2,
				},
			},
		})
		rendered = append(rendered, tag)

		// City balancers where they make sense (>= 2 live nodes, D5).
		cityTags := map[string][]any{}
		var cities []string
		for _, sn := range nodes {
			if sn.City == "" {
				continue
			}
			key := sn.City
			if _, seen := cityTags[key]; !seen {
				cities = append(cities, key)
			}
			cityTags[key] = append(cityTags[key], sn.Tag)
		}
		sort.Strings(cities)
		for _, city := range cities {
			selectors := cityTags[city]
			if len(selectors) < 2 {
				continue // single-node city: explicit tag override, no balancer
			}
			ctag := model.CityBalancerTag(cc, city)
			existing = append(existing, map[string]any{
				"tag":      ctag,
				"selector": selectors,
				"strategy": map[string]any{
					"type": "leastLoad",
					"settings": map[string]any{
						"expected":  1,
						"tolerance": 0.2,
					},
				},
			})
			rendered = append(rendered, ctag)
		}
	}
	routing["balancers"] = existing
	return rendered
}

// addPoolRules inserts owner-configured pool routes after the last
// user-traffic rule and before the catch-all (DESIGN.md §4.7).
func addPoolRules(m map[string]any, routes []PoolRoute, renderedBalancers []string) error {
	if len(routes) == 0 {
		return nil
	}
	valid := map[string]bool{}
	for _, b := range renderedBalancers {
		valid[b] = true
	}
	routing, _ := m["routing"].(map[string]any)
	rules := toAnySlice(routing["rules"])

	var poolRules []any
	for _, route := range routes {
		if !strings.HasPrefix(route.Balancer, poolBalancerPrefix) {
			return fmt.Errorf("render: pool route balancer %q must be a pool_ balancer (namespace wall D6)", route.Balancer)
		}
		if !valid[route.Balancer] {
			return fmt.Errorf("render: pool route references balancer %q which was not rendered (no live nodes there?)",
				route.Balancer)
		}
		domains := make([]any, len(route.Domains))
		for i, d := range route.Domains {
			domains[i] = d
		}
		poolRules = append(poolRules, map[string]any{
			"type":        "field",
			"inboundTag":  []any{"socks-in", "http-in"},
			"domain":      domains,
			"balancerTag": route.Balancer,
		})
	}

	// Insert before the catch-all class: every rule of the trailing balancerTag
	// run (the template's catch-all block may be several rules deep) sits AFTER
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
	return nil
}

// buildOutbound converts one node into a complete xray outbound. Auth and
// transport params are copied 1:1 from the link (L9); only sockopt.tcpMaxSeg
// and the client TLS fingerprint are owner-mandated overrides. It returns the
// names of link params that could NOT be placed in the outbound, so the
// caller can surface them instead of dropping silently.
func buildOutbound(n *model.Node, tag string) (map[string]any, []string, error) {
	consumed := map[string]bool{}
	stream, err := buildStreamSettings(n, consumed)
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
						"and changes behavior (early-data) — refusing the silent drop (L9)",
					tag, n.Host, k, n.Params[k], stream["security"], stream["network"])
			}
			dropped = append(dropped, k)
		}
	}
	sort.Strings(dropped)
	return map[string]any{
		"tag":            tag,
		"protocol":       n.Scheme,
		"settings":       settings,
		"streamSettings": stream,
	}, dropped, nil
}

// buildStreamSettings renders network/security/sockopt; security-specific
// settings (tls/reality) and network-specific settings (ws/xhttp/grpc/http)
// carry the link's own params verbatim. Every param consulted is recorded in
// consumed so unrendered params surface in the drop report.
func buildStreamSettings(n *model.Node, consumed map[string]bool) (map[string]any, error) {
	stream := map[string]any{
		"network":  networkOf(n, consumed),
		"security": securityOf(n, consumed),
		"sockopt":  map[string]any{"tcpMaxSeg": tcpMaxSeg},
	}
	switch stream["security"] {
	case "tls":
		stream["tlsSettings"] = buildTLSSettings(n.Params, consumed)
	case "reality":
		rs, err := buildRealitySettings(n.Params, consumed)
		if err != nil {
			return nil, err
		}
		stream["realitySettings"] = rs
	}
	applyNetworkSettings(stream, n.Params, consumed)
	return stream, nil
}

func buildTLSSettings(p map[string]string, consumed map[string]bool) map[string]any {
	tls := map[string]any{"fingerprint": clientFingerprint}
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
	return tls
}

func buildRealitySettings(p map[string]string, consumed map[string]bool) (map[string]any, error) {
	rs := map[string]any{"fingerprint": clientFingerprint}
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

func applyNetworkSettings(stream map[string]any, p map[string]string, consumed map[string]bool) {
	switch stream["network"] {
	case "ws":
		ws := map[string]any{}
		if v := p["path"]; v != "" {
			consumed["path"] = true
			ws["path"] = v
		}
		if v := p["host"]; v != "" {
			consumed["host"] = true
			ws["headers"] = map[string]any{"Host": v}
		}
		stream["wsSettings"] = ws
	case "xhttp":
		xs := map[string]any{}
		for _, k := range []string{"host", "path", "mode"} {
			if v := p[k]; v != "" {
				consumed[k] = true
				xs[k] = v
			}
		}
		stream["xhttpSettings"] = xs
	case "grpc":
		gs := map[string]any{}
		if v := p["serviceName"]; v != "" {
			consumed["serviceName"] = true
			gs["serviceName"] = v
		}
		stream["grpcSettings"] = gs
	case "http":
		hs := map[string]any{}
		if v := p["path"]; v != "" {
			consumed["path"] = true
			hs["path"] = v
		}
		if v := p["host"]; v != "" {
			consumed["host"] = true
			hs["host"] = strings.Split(v, ",")
		}
		stream["httpSettings"] = hs
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
		return buildVMESSDial(n, consumed), nil
	default:
		return nil, fmt.Errorf("render: unsupported scheme %q", n.Scheme)
	}
}

func buildVLESSDial(n *model.Node, consumed map[string]bool) map[string]any {
	user := map[string]any{"id": n.UUID, "encryption": "none"}
	if v := n.Params["flow"]; v != "" {
		consumed["flow"] = true
		user["flow"] = v
	}
	return map[string]any{"vnext": []any{map[string]any{
		"address": n.Host,
		"port":    n.Port,
		"users":   []any{user},
	}}}
}

func buildTrojanDial(n *model.Node) map[string]any {
	return map[string]any{"servers": []any{map[string]any{
		"address":  n.Host,
		"port":     n.Port,
		"password": n.UUID,
	}}}
}

func buildVMESSDial(n *model.Node, consumed map[string]bool) map[string]any {
	aid := 0
	if v := n.Params["aid"]; v != "" {
		consumed["aid"] = true
		if parsed, err := strconv.Atoi(v); err == nil {
			aid = parsed
		}
	}
	security := n.Params["scy"]
	if security == "" {
		security = "auto"
	} else {
		consumed["scy"] = true
	}
	return map[string]any{"vnext": []any{map[string]any{
		"address": n.Host,
		"port":    n.Port,
		"users":   []any{map[string]any{"id": n.UUID, "alterId": aid, "security": security}},
	}}}
}

func networkOf(n *model.Node, consumed map[string]bool) string {
	if v := n.Params["type"]; v != "" {
		consumed["type"] = true
		// vmess links carry the network in "net" with type deduped to the
		// same value at parse time — mark both consumed so the identical
		// datum is not reported as dropped.
		consumed["net"] = true
		return v
	}
	if v := n.Params["net"]; v != "" {
		consumed["net"] = true
		consumed["type"] = true
		return v
	}
	return "tcp"
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

// stringSlice coerces a stored interface value into []string.
func stringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := r.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
