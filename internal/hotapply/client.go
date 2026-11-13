// Package hotapply implements the `assay apply` machinery (the 2026-11-13
// hot-apply plan T2/T3): the API client over exec of the RESOLVED core
// binary, the live/candidate diff classifier, the payload writer and the
// post-apply verifier.
//
// Version-dialect neutralization (plan R3, design against interfaces): the
// client never speaks the gRPC dialect itself — it execs `api <verb>` on the
// core binary resolved through the SINGLE knob (config.CoreXrayBin, S1), the
// same resolution the daemon used to spawn the running core. Whatever core
// version answers the API, its own CLI is the client — dialect drift is
// structurally impossible. The Runner interface is the seam tests record
// against.
package hotapply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runner execs argv with stdin and returns stdout; the error carries the
// child's stderr tail. It is the executor seam: production runs the real
// child process, tests record argv and script responses.
type Runner interface {
	Run(ctx context.Context, argv []string, stdin []byte) (stdout []byte, err error)
}

// RuleEntry is one item of the core's ListRule response
// (app/router/command/command.proto: ListRuleItem{tag, ruleTag}; proto3
// zero values may be omitted by the marshaler — missing keys parse as "").
type RuleEntry struct {
	OutboundTag string `json:"tag"`
	RuleTag     string `json:"ruleTag"`
}

// Client drives the running core's RoutingService through the core binary's
// own `xray api` CLI. The server address is the rendered api inbound
// (127.0.0.1:<[core].api_port>); the CLI's own 3s per-call timeout applies
// (the documented default), and the caller's ctx bounds the exec.
type Client struct {
	bin    string
	server string
	runner Runner
}

// NewClient builds the production client: coreBin is the RESOLVED core
// binary (config.CoreXrayBin — S1, never a hardcoded path), apiPort the
// rendered api inbound's port ([core].api_port).
func NewClient(coreBin string, apiPort int) *Client {
	return &Client{
		bin:    coreBin,
		server: fmt.Sprintf("127.0.0.1:%d", apiPort),
		runner: ExecRunner{},
	}
}

// NewClientWithRunner is the seam constructor (failure-injection tests pass a
// recorded Runner; the argv contract is identical in both modes).
func NewClientWithRunner(coreBin string, apiPort int, r Runner) *Client {
	return &Client{
		bin:    coreBin,
		server: fmt.Sprintf("127.0.0.1:%d", apiPort),
		runner: r,
	}
}

// Reachable probes the API surface BEFORE any mutation (plan §3.4): a plain
// lsrules round trip. An error means the core is down or RoutingService is
// not yet enabled (the one-time enablement restart has not happened) —
// classify with ProbeFailureKind.
func (c *Client) Reachable(ctx context.Context) error {
	_, err := c.ListRules(ctx)
	return err
}

// ListRules queries the running routing table (`api lsrules`).
func (c *Client) ListRules(ctx context.Context) ([]RuleEntry, error) {
	argv := []string{c.bin, "api", "lsrules", "--server", c.server}
	stdout, err := c.runner.Run(ctx, argv, nil)
	if err != nil {
		return nil, fmt.Errorf("exec %s api lsrules: %w", c.bin, err)
	}
	var resp struct {
		Rules []RuleEntry `json:"rules"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &resp); err != nil {
		return nil, fmt.Errorf("parse lsrules output from %s: %w (raw: %.400s)", c.bin, err, stdout)
	}
	return resp.Rules, nil
}

// ReplaceRouting hot-applies a full routing-section replace (`api adrules`
// with NO -append — plan §3.6): shouldAppend=false makes the core wipe and
// rebuild BOTH rules and balancers from the payload's routing section
// (ReloadRules). payloadPath must be the gated render's routing section
// embedded in a minimal config JSON (WritePayloadFile).
//
// R5 pins the argv shape: `-append` is structurally dead for this config
// (the rendered catch-all swallows every appended rule) and xray 26.11.9's
// rules_add.go flips shouldAppend=true for every payload file AFTER the
// first — exactly ONE payload file keeps the replace semantics on both
// pinned core versions.
func (c *Client) ReplaceRouting(ctx context.Context, payloadPath string) error {
	argv := []string{c.bin, "api", "adrules", "--server", c.server, payloadPath}
	_, err := c.runner.Run(ctx, argv, nil)
	if err != nil {
		return fmt.Errorf("exec %s api adrules: %w", c.bin, err)
	}
	return nil
}

// FailureKind classifies a Reachable/ReplaceRouting failure for the CLI's
// loud messages. The vocabulary is the core CLI's own error text
// (main/commands/all/api: "failed to dial <addr>" on dial failure;
// "unknown service xray.app.router.command.RoutingService" in the gRPC
// Unimplemented description when the enablement restart has not happened).
type FailureKind int

const (
	// FailureOther is any unrecognized failure — the generic loud message.
	FailureOther FailureKind = iota
	// CoreDown means the API inbound did not answer the dial (the core is
	// not running).
	CoreDown
	// ServiceMissing means the core runs but RoutingService is not
	// registered (services list predates the T1 render — the one-time
	// enablement restart is pending).
	ServiceMissing
)

// ProbeFailureKind classifies an error returned by the client (nil →
// FailureOther: callers check the error first; a nil error is not a
// failure).
func ProbeFailureKind(err error) FailureKind {
	if err == nil {
		return FailureOther
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "failed to dial"):
		return CoreDown
	case strings.Contains(msg, "unknown service"):
		return ServiceMissing
	default:
		return FailureOther
	}
}

// VerifyApplied is the post-apply verification (plan §3.6): the fresh
// lsrules snapshot must contain EVERY expected ruleTag and exactly wantCount
// rules. Any miss fails — no verification, no success claim (R1).
func VerifyApplied(entries []RuleEntry, wantTags []string, wantCount int) error {
	got := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.RuleTag != "" {
			got[e.RuleTag] = true
		}
	}
	if len(entries) != wantCount {
		return fmt.Errorf("verification failed: running core has %d routing rules, expected %d", len(entries), wantCount)
	}
	var missing []string
	for _, tag := range wantTags {
		if !got[tag] {
			missing = append(missing, tag)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("verification failed: ruleTag(s) absent from the running core: %s", strings.Join(missing, ", "))
	}
	return nil
}

// WritePayloadFile writes the hot-apply payload: the candidate's ENTIRE
// routing section (api rule first, pool rules, catch-all last, all
// balancers) embedded in a minimal config JSON — verbatim from the gated
// render, never hand-assembled (plan §3.5). The file is a 0600 temp file;
// the returned cleanup removes it (safe to call more than once).
func WritePayloadFile(candidate map[string]any) (string, func(), error) {
	routing, ok := candidate["routing"].(map[string]any)
	if !ok {
		return "", func() {}, errors.New("candidate render has no routing section — cannot build a hot-apply payload")
	}
	payload := map[string]any{"routing": routing}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", func() {}, fmt.Errorf("marshal hot-apply payload: %w", err)
	}
	f, err := os.CreateTemp("", "assay-apply-payload-*.json")
	if err != nil {
		return "", func() {}, fmt.Errorf("create payload temp file: %w", err)
	}
	path := f.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err = f.Chmod(0o600); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("chmod payload temp file: %w", err)
	}
	if _, err = f.Write(raw); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("write payload temp file: %w", err)
	}
	if err = f.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close payload temp file: %w", err)
	}
	return path, cleanup, nil
}

// ExecRunner is the production Runner: it execs argv[0] with argv, feeds
// stdin, returns stdout, and on failure returns an error carrying the
// child's stderr tail (the loudness contract — a swallowed API error would
// fake success).
type ExecRunner struct{}

// Run implements Runner. The child environment is stripped of ambient proxy
// variables (L5: the API exec must talk to the loopback inbound directly,
// never through the live client's own proxy), mirroring the checker's temp
// spawn discipline.
func (ExecRunner) Run(ctx context.Context, argv []string, stdin []byte) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("exec runner: empty argv")
	}
	//nolint:gosec // argv[0] is the resolved core binary (the owner config IS the trust root, S1)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = stripProxyEnv(os.Environ())
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("%w\n%s", err, tailRun(strings.TrimSpace(stderr.String())))
	}
	return stdout.Bytes(), nil
}

// tailRun keeps the last 400 bytes of a child's stderr — the diagnostics
// that matter (the failure line) live at the end.
func tailRun(s string) string {
	if len(s) <= 400 {
		return s
	}
	return "..." + s[len(s)-400:]
}

// stripProxyEnv drops ambient proxy variables (L5). Same discipline as the
// checker's dropProxyEnv; a separate copy keeps the packages decoupled (the
// alternative — an exported helper — would couple the probe fleet's hygiene
// to the hot-apply path for no shared behavior beyond four prefix checks).
func stripProxyEnv(env []string) []string {
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
