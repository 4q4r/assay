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
	"net"
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

// Class is how a stats-stage failure must surface in the maintain wave
// (W7 item 9): INFO = an expected first-run shape, never a warning;
// WARNING = the endpoint misbehaved (accounting-only, wave continues);
// LOUD = fold/write data loss, which FAILS the wave.
type Class int

// Stats-stage failure classes (W7 item 9).
const (
	// ClassInfo marks an expected first-run shape: the wave prints an INFO
	// line and continues; the exit status is unaffected.
	ClassInfo Class = iota
	// ClassWarning marks an accounting-only failure: the wave prints the
	// "stats poll unavailable" line and continues (today's behavior).
	ClassWarning
	// ClassLoud marks traffic data loss: the wave FAILS.
	ClassLoud
)

// ClassifiedError carries a stats-stage failure together with its class.
// runMaintain switches on the class: INFO prints an INFO line, WARNING
// prints today's "stats poll unavailable" line, LOUD propagates as a real
// wave failure (data loss is never silent).
type ClassifiedError struct {
	Class Class
	Err   error
}

// NewClassified wraps err into a ClassifiedError of the given class.
func NewClassified(class Class, err error) *ClassifiedError {
	return &ClassifiedError{Class: class, Err: err}
}

func (e *ClassifiedError) Error() string { return e.Err.Error() }

// Unwrap exposes the cause to errors.Is/errors.As.
func (e *ClassifiedError) Unwrap() error { return e.Err }

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

// TargetHasAPI reports whether the activate target carries the api/stats
// shape this stage polls — the same shape render emits (ensureAPIStats:
// an `api` block, an `api-in` inbound on the configured stats port, and the
// stats/policy blocks that make the counters exist). We render the target,
// so reading it back is the honest first-run probe: a target without the
// shape means the owner has never activated a rendered config yet, and the
// poll cannot succeed no matter how it is retried. A target that does not
// exist yet is the same first-run shape (false, nil); a target that exists
// but cannot be read is an error — it must not silently read as "first run".
func TargetHasAPI(targetPath string, statsPort int) (bool, error) {
	raw, err := os.ReadFile(targetPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read activate target %s: %w", targetPath, err)
	}
	var m struct {
		API      *json.RawMessage `json:"api"`
		Stats    *json.RawMessage `json:"stats"`
		Inbounds []struct {
			Tag    string `json:"tag"`
			Listen string `json:"listen"`
			Port   int    `json:"port"`
		} `json:"inbounds"`
		Policy struct {
			System struct {
				StatsOutboundUplink   bool `json:"statsOutboundUplink"`
				StatsOutboundDownlink bool `json:"statsOutboundDownlink"`
			} `json:"system"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return false, fmt.Errorf("decode activate target %s: %w", targetPath, err)
	}
	if m.API == nil || m.Stats == nil {
		return false, nil
	}
	if !m.Policy.System.StatsOutboundUplink || !m.Policy.System.StatsOutboundDownlink {
		return false, nil
	}
	for _, inb := range m.Inbounds {
		if inb.Tag == "api-in" && inb.Port == statsPort {
			return true, nil
		}
	}
	return false, nil
}

// EndpointReachable reports whether the loopback stats endpoint accepts TCP
// connections. A connection REFUSED is the signature of "the service is not
// (yet) running the rendered config" — the expected state between an
// activation and its manual restart, classified INFO. The probe is a direct
// dial (no proxy env is ever honored by net.Dial), so landmine L5 cannot
// skew it.
func EndpointReachable(ctx context.Context, addr string) bool {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		// Every dial error — not just REFUSED — maps to the first-run INFO
		// verdict upstream. That is acceptable because the stats stage only
		// ever dials 127.0.0.1, so any failure here means "not listening
		// yet", never a network or routing problem.
		return false
	}
	_ = conn.Close()
	return true
}
