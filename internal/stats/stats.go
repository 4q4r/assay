// Package stats implements the W4 traffic accounting stage (DESIGN.md §4.9):
// poll the live client's StatsService via `xray api statsquery
// -pattern "outbound>>>pool-" -reset=true` and fold the per-outbound
// uplink/downlink deltas into the geo-base records' BytesUp/BytesDown.
//
// The counter contract (verified against the 26.3.27 binary and Xray-core
// source, 2026-10-28): counter names are
// "outbound>>><tag>>>traffic>>><uplink|downlink>"; the CLI reflection JSON
// marshaler omits zero-valued counters (protobuf omitempty), so a missing
// direction is a legitimate zero — never a crash (landmine L7 shape). With
// -reset=true every poll returns the DELTA since the previous poll, so
// folding is an increment. The cost is a delta-loss window: once the server
// resets its counters, a poll whose deltas never reach the base (crash or
// persist failure in between) loses that traffic permanently — never "fix"
// this by dropping -reset=true, which would return cumulative totals and
// double-count every byte already folded.
//
// The stage execs the xray binary out-of-band (loopback API only); the L5
// landmine still applies — the child runs with http_proxy/https_proxy
// stripped so a proxy env var can never reroute the API dial.
package stats

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
)

// poolOutboundPrefix is the D5/D6 namespace wall: only counters for pool-*
// outbound tags may ever fold into the cold base.
const poolOutboundPrefix = "pool-"

// Options bundles one stats poll's dependencies.
type Options struct {
	BinPath string // the xray binary (config activate.xray_bin)
	Server  string // host:port of the api-in inbound (loopback, render.stats_port)
	Pattern string // statsquery pattern, e.g. "outbound>>>pool-"
	Timeout time.Duration
}

// Delta is one outbound's traffic delta from a single poll.
type Delta struct {
	Tag  string
	Up   int64
	Down int64
}

// Result reports what one poll observed.
type Result struct {
	Deltas      []Delta
	RawCounters int    // counter entries returned before the pool- filter
	PolledAt    string // RFC3339 timestamp of the poll
}

// statEntry is one element of the statsquery JSON response. Values are JSON
// numbers (the CLI marshals the proto int64 via encoding/json).
type statEntry struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// statsResponse mirrors the QueryStatsResponse JSON envelope. The "stat" key
// is absent when the matched set is empty — treated as a zero-delta poll.
type statsResponse struct {
	Stat []statEntry `json:"stat"`
}

// Run polls the live API once. A non-zero exit or an unparseable body fails
// loud; an empty body is a valid zero-delta poll.
func Run(ctx context.Context, opts Options) (Result, error) {
	res := Result{PolledAt: time.Now().UTC().Format(time.RFC3339)}
	if opts.Timeout <= 0 {
		// Fallback for direct callers that leave Timeout unset — the SAME
		// default the pipeline passes via [maintain].stats_timeout (one knob,
		// both sites; the old 5s/10s inconsistency is gone).
		opts.Timeout = config.DefaultStatsTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	//nolint:gosec // the binary path comes from the owner's config.toml — the config file IS the trust root
	cmd := exec.CommandContext(cctx, opts.BinPath, "api", "statsquery",
		"--server="+opts.Server, "-pattern", opts.Pattern, "-reset=true")
	cmd.Env = dropProxyEnv(os.Environ()) // L5: never ride the owner's VPN, even for loopback
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return res, fmt.Errorf("xray api statsquery: %w\n%s", err, stderr.String())
	}

	var resp statsResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return res, fmt.Errorf("decode statsquery response: %w\nbody: %s", err, truncate(stdout.String(), 400))
	}
	res.RawCounters = len(resp.Stat)

	byTag := map[string]*Delta{}
	var order []string
	for _, e := range resp.Stat {
		tag, direction, ok := parseCounterName(e.Name)
		if !ok || !strings.HasPrefix(tag, poolOutboundPrefix) {
			continue // foreign namespace: never credited (D6)
		}
		d, seen := byTag[tag]
		if !seen {
			d = &Delta{Tag: tag}
			byTag[tag] = d
			order = append(order, tag)
		}
		switch direction {
		case "uplink":
			d.Up += e.Value
		case "downlink":
			d.Down += e.Value
		}
	}
	for _, tag := range order {
		res.Deltas = append(res.Deltas, *byTag[tag])
	}
	return res, nil
}

// parseCounterName splits "outbound>>><tag>>>traffic>>><uplink|downlink>".
func parseCounterName(name string) (string, string, bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || parts[0] != "outbound" || parts[2] != "traffic" {
		return "", "", false
	}
	if parts[3] != "uplink" && parts[3] != "downlink" {
		return "", "", false
	}
	if parts[1] == "" {
		return "", "", false
	}
	return parts[1], parts[3], true
}

// Fold increments the pool-tagged records with one poll's deltas. With
// -reset=true the values are deltas since the last poll, so folding is an
// accumulation; records without a tag (never selected) are untouched, a
// missing direction folds as zero, and a delta for a non-pool tag is skipped
// defensively (it can only appear through a mis-scoped pattern).
func Fold(records []*model.GeoRecord, deltas []Delta) (int, int64, int64) {
	updated, totalUp, totalDown := 0, int64(0), int64(0)
	byTag := make(map[string]Delta, len(deltas))
	for _, d := range deltas {
		byTag[d.Tag] = d
	}
	for _, r := range records {
		if !strings.HasPrefix(r.Tag, poolOutboundPrefix) {
			continue
		}
		d, ok := byTag[r.Tag]
		if !ok {
			continue
		}
		r.BytesUp += d.Up
		r.BytesDown += d.Down
		updated++
		totalUp += d.Up
		totalDown += d.Down
	}
	return updated, totalUp, totalDown
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// dropProxyEnv strips ambient proxy variables (landmine L5): the owner shell
// exports http_proxy pointing at the live client, and letting a stats/API
// dial inherit it would route the poll through the very tunnel it measures.
// Same discipline as probe.dropProxyEnv and the fetch/geo transport.Proxy=nil.
func dropProxyEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		upper := strings.ToUpper(kv)
		if strings.HasPrefix(upper, "HTTP_PROXY=") ||
			strings.HasPrefix(upper, "HTTPS_PROXY=") ||
			strings.HasPrefix(upper, "ALL_PROXY=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}
