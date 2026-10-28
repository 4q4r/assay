// Package probe implements the out-of-band liveness wave (W2) on top of
// xray-knife: real-tunnel HTTP probes deliver latency, the tunnel EXIT IP
// (D8 — never the advertised host), optional throughput (--speedtest) and
// optional panel grading (--check-preset). The live client is never involved.
package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"public_vpn/internal/model"
	"public_vpn/internal/store"
)

// Options configures one probe wave.
type Options struct {
	Timeout             time.Duration // per-probe HTTP timeout
	Threads             int           // xray-knife parallelism
	URL                 string        // probe target URL
	Speedtest           bool          // -S (speed.cloudflare.com)
	SpeedtestTimeout    time.Duration // --speedtest-timeout window
	CheckPreset         string        // --check-preset (cloudflare|global|google|gstatic|streaming)
	URLSuccessThreshold float64       // --url-success-threshold
	DBPath              string        // isolated knife database (never the user default)
	WorkDir             string        // scratch dir for links/results files
	MaxPassed           int           // stop after N passed (0 = all)
}

// RawResult mirrors one xray-knife http -x jsonl record (v11.4.1 wire shape).
type RawResult struct {
	Link         string  `json:"link"`
	Status       string  `json:"status"`
	Reason       string  `json:"reason"`
	IP           string  `json:"ip"` // exit IP, or the literal string "null"
	Delay        float64 `json:"delay"`
	Download     float64 `json:"download"`
	Upload       float64 `json:"upload"`
	SuccessCount int     `json:"successCount"`
	TotalCount   int     `json:"totalCount"`
	FailureKind  string  `json:"failureKind"`
	Protocol     struct {
		Remark   string `json:"remark"`
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
		Port     string `json:"port"`
	} `json:"protocol"`
}

// Runner executes one probe batch.
type Runner interface {
	Run(ctx context.Context, links []string, opts Options) ([]RawResult, error)
}

// Run probes every node and appends outcomes to the probe log. Nodes without
// a knife result are recorded as not-alive-this-wave.
func Run(
	ctx context.Context, nodes []*model.Node, r Runner, opts Options, resultsPath string,
) ([]store.ProbeResult, error) {
	links := make([]string, 0, len(nodes))
	keyByLink := make(map[string]string, len(nodes))
	for _, n := range nodes {
		link := n.Link()
		if _, dup := keyByLink[link]; dup {
			continue // identical links probe once; both nodes take the outcome
		}
		keyByLink[link] = n.Key
		links = append(links, link)
	}
	raw, err := r.Run(ctx, links, opts)
	if err != nil {
		return nil, err
	}
	out := make([]store.ProbeResult, 0, len(nodes))
	seen := make(map[string]bool, len(raw))
	now := time.Now().UTC()
	for _, rr := range raw {
		key, ok := keyByLink[rr.Link]
		if !ok {
			return nil, fmt.Errorf("probe: unmapped result link %q (runner contract breach)", shortLink(rr.Link))
		}
		seen[key] = true
		out = append(out, store.ProbeResult{
			Key:         key,
			Host:        rr.Protocol.Address,
			Alive:       rr.Status == "passed" || rr.Status == "semi-passed",
			Status:      rr.Status,
			Reason:      rr.Reason,
			ExitIP:      normalizeIP(rr.IP),
			RTTMs:       rr.Delay,
			SpeedBPS:    int64(rr.Download),
			Checks:      rr.SuccessCount,
			TotalChecks: rr.TotalCount,
			FailureKind: rr.FailureKind,
			CheckedAt:   now,
		})
	}
	for _, n := range nodes {
		if !seen[n.Key] {
			out = append(out, store.ProbeResult{Key: n.Key, Host: n.Host, Alive: false, CheckedAt: now})
		}
	}
	if resultsPath != "" {
		if err := store.AppendProbeResults(resultsPath, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func normalizeIP(s string) string {
	if s == "" || s == "null" {
		return ""
	}
	return s
}

func shortLink(link string) string {
	if i := strings.Index(link, "#"); i > 0 {
		return link[:i]
	}
	return link
}

// KnifeRunner shells out to xray-knife (out-of-band only).
type KnifeRunner struct {
	BinPath string // e.g. ~/.local/bin/xray-knife

	// TestEnv is appended to the subprocess environment verbatim. It is a
	// test seam: nil in production, so spawned knife processes carry no test
	// channels (review finding 8 — FAKE_ARGV was previously always set).
	TestEnv []string
}

// Run executes one xray-knife http batch over the links.
func (k *KnifeRunner) Run(ctx context.Context, links []string, opts Options) ([]RawResult, error) {
	if len(links) == 0 {
		return nil, nil
	}
	if opts.WorkDir == "" {
		opts.WorkDir = "."
	}
	linksPath := filepath.Join(opts.WorkDir, fmt.Sprintf("links-%d.txt", time.Now().UnixNano()))
	outPath := filepath.Join(opts.WorkDir, fmt.Sprintf("results-%d.jsonl", time.Now().UnixNano()))
	if err := os.WriteFile(linksPath, []byte(strings.Join(links, "\n")+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write links file: %w", err)
	}
	defer func() { _ = os.Remove(linksPath) }()
	defer func() { _ = os.Remove(outPath) }()

	args := []string{
		"http",
		"-f", linksPath,
		"-x", "jsonl",
		"-o", outPath,
		"-t", strconv.Itoa(opts.Threads),
		"--timeout", strconv.Itoa(int(opts.Timeout.Milliseconds())),
		"--db", opts.DBPath,
		"--quiet",
	}
	if opts.URL != "" {
		args = append(args, "-u", opts.URL)
	}
	if opts.Speedtest {
		args = append(args, "-S")
		if opts.SpeedtestTimeout > 0 {
			args = append(args, "--speedtest-timeout", strconv.Itoa(int(opts.SpeedtestTimeout.Seconds())))
		}
	}
	if opts.CheckPreset != "" {
		args = append(args, "--check-preset", opts.CheckPreset)
		args = append(args, "--url-success-threshold", strconv.FormatFloat(opts.URLSuccessThreshold, 'f', 2, 64))
	}
	if opts.MaxPassed > 0 {
		args = append(args, "--max-passed", strconv.Itoa(opts.MaxPassed))
	}

	//nolint:gosec // binary path from owner config; args constructed here
	cmd := exec.CommandContext(ctx, k.BinPath, args...)
	// L5 hygiene in-process: the knife subprocess must not inherit a proxy
	// environment, or probes would tunnel through the owner's VPN.
	cmd.Env = dropProxyEnv(os.Environ())
	cmd.Env = append(cmd.Env, k.TestEnv...)
	output, err := cmd.CombinedOutput()
	// The knife CLI signals "N of M passed" through its exit code (non-zero
	// when some/all fail) — that is a normal probe outcome, not an invocation
	// error. Only a missing/unparseable results file is a contract breach.
	results, parseErr := parseJSONLFile(outPath)
	if parseErr != nil {
		return nil, fmt.Errorf("xray-knife %s produced no usable results (err=%w): %w\n%s",
			k.BinPath, err, parseErr, tail(string(output), 800))
	}
	return results, nil
}

func parseJSONLFile(path string) ([]RawResult, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("xray-knife produced no results file at %s", path)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []RawResult
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var rr RawResult
		if err := json.Unmarshal([]byte(text), &rr); err != nil {
			return nil, fmt.Errorf("decode xray-knife jsonl line %d: %w", line, err)
		}
		out = append(out, rr)
	}
	return out, sc.Err()
}

func dropProxyEnv(env []string) []string {
	out := env[:0]
	for _, e := range env {
		upper := strings.ToUpper(e)
		if strings.HasPrefix(upper, "HTTP_PROXY=") || strings.HasPrefix(upper, "HTTPS_PROXY=") ||
			strings.HasPrefix(upper, "ALL_PROXY=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
