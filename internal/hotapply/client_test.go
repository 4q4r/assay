package hotapply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordedRunner is the recorded-executor seam: it records every argv and
// returns scripted responses. Every Client test runs through it — the exec
// boundary is the version-dialect seam (the binary that answers `api` is
// whatever path was resolved, never a hardcoded one).
type recordedRunner struct {
	calls [][]string
	stdin []byte
	resp  func(argv []string) ([]byte, error)
}

func (r *recordedRunner) Run(_ context.Context, argv []string, stdin []byte) ([]byte, error) {
	call := slices.Clone(argv)
	r.calls = append(r.calls, call)
	r.stdin = stdin
	if r.resp != nil {
		return r.resp(argv)
	}
	return []byte(`{"rules":[]}`), nil
}

func newTestClient(rec *recordedRunner) *Client {
	return NewClientWithRunner("/resolved/core/xray", 15491, rec)
}

// T2 DoD: the adrules exec is pinned EXACTLY — [bin, "api", "adrules",
// "--server", server, payloadPath]. R5: "-append" must NEVER appear (the
// rendered catch-all swallows appended rules — dead rules that LOOK applied),
// and the payload must be exactly ONE file (xray 26.11.9 rules_add.go flips
// shouldAppend=true after the FIRST file: a second payload file would append
// past the catch-all silently).

func TestReplaceRoutingExecsAdrulesWithoutAppend(t *testing.T) {
	rec := &recordedRunner{}
	client := newTestClient(rec)

	err := client.ReplaceRouting(context.Background(), "/tmp/payload.json")
	require.NoError(t, err)

	require.Len(t, rec.calls, 1, "exactly one exec")
	argv := rec.calls[0]
	want := []string{"/resolved/core/xray", "api", "adrules", "--server", "127.0.0.1:15491", "/tmp/payload.json"}
	assert.Equal(t, want, argv, "the adrules argv is pinned (single payload file, replace semantics)")
	assert.False(t, slices.Contains(argv, "-append"),
		"R5: -append is structurally dead behind the catch-all — it must never be passed")
	assert.False(t, slices.Contains(argv, "--append"),
		"R5: --append long form equally forbidden")
}

func TestReplaceRoutingSurfacesExecError(t *testing.T) {
	rec := &recordedRunner{resp: func([]string) ([]byte, error) {
		return nil, errors.New("adrules exited 1\nAddRule rejected: balancer pool_us not found")
	}}
	client := newTestClient(rec)

	err := client.ReplaceRouting(context.Background(), "/tmp/payload.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "balancer pool_us not found", "the stderr tail reaches the operator")
}

func TestListRulesParsesResponse(t *testing.T) {
	rec := &recordedRunner{resp: func([]string) ([]byte, error) {
		// Real ListRuleResponse shape (command.proto @ v26.3.27/v26.11.9):
		// ListRuleItem{tag, ruleTag}; proto3 empty strings may be omitted by
		// the marshaler — entries missing a key parse as "".
		return []byte(`{"rules":[{"tag":"pool_us","ruleTag":"pool-route-0"},{"tag":"block"},` +
			`{"ruleTag":"api-ghost"}]}`), nil
	}}
	client := newTestClient(rec)

	entries, err := client.ListRules(context.Background())
	require.NoError(t, err)
	want := []RuleEntry{
		{OutboundTag: "pool_us", RuleTag: "pool-route-0"},
		{OutboundTag: "block", RuleTag: ""},
		{OutboundTag: "", RuleTag: "api-ghost"},
	}
	assert.Equal(t, want, entries)
}

func TestListRulesSurfacesExecError(t *testing.T) {
	rec := &recordedRunner{resp: func([]string) ([]byte, error) {
		return nil, errors.New("failed to dial 127.0.0.1:15491")
	}}
	client := newTestClient(rec)

	_, err := client.ListRules(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to dial")
}

// Reachable is the pre-mutation probe (plan §3.4): a plain lsrules round
// trip. Any error = core down or RoutingService not yet enabled — nothing
// has been mutated.

func TestReachableIsLsRulesRoundTrip(t *testing.T) {
	rec := &recordedRunner{}
	client := newTestClient(rec)

	require.NoError(t, client.Reachable(context.Background()))
	require.Len(t, rec.calls, 1)
	assert.Equal(t,
		[]string{"/resolved/core/xray", "api", "lsrules", "--server", "127.0.0.1:15491"},
		rec.calls[0], "the probe is a plain lsrules round trip through the RESOLVED binary")
}

func TestReachableFailsLoudOnDialError(t *testing.T) {
	rec := &recordedRunner{resp: func([]string) ([]byte, error) {
		return nil, errors.New("failed to dial 127.0.0.1:15491")
	}}
	client := newTestClient(rec)

	err := client.Reachable(context.Background())
	require.Error(t, err, "core down is a first-class apply input — the probe must fail loud")
}

// ProbeFailureKind classification: the CLI's loud messages differ between
// "core is down" (start the daemon / enablement restart) and "core runs but
// RoutingService is not registered" (the one-time enablement restart has not
// happened yet). The vocabulary comes from the core binary's own CLI errors
// (main/commands/all/api: base.Fatalf "failed to dial %s" on dial failure;
// "failed to list rules: ... unknown service ..." on unregistered service).
// The real-binary shapes are pinned again by the live integration test.

func TestProbeFailureKindClassification(t *testing.T) {
	coreDown := errors.New("exec /usr/bin/xray api lsrules: exit 1\nfailed to dial 127.0.0.1:15491")
	assert.Equal(t, CoreDown, ProbeFailureKind(coreDown))

	serviceMissing := errors.New(
		"failed to list rules: rpc error: code = Unimplemented desc = unknown service xray.app.router.command.RoutingService")
	assert.Equal(t, ServiceMissing, ProbeFailureKind(serviceMissing))

	other := errors.New("context deadline exceeded")
	assert.Equal(t, FailureOther, ProbeFailureKind(other))

	assert.Equal(t, FailureOther, ProbeFailureKind(nil), "nil is not a failure kind the CLI should match")
}

// VerifyApplied is the post-apply verification (plan §3.6): lsrules must show
// EVERY expected pool-route ruleTag and the exact rule count. No verification
// = no success claim, ever (R1).

func TestVerifyApplied(t *testing.T) {
	entries := []RuleEntry{
		{OutboundTag: "api", RuleTag: ""},
		{OutboundTag: "pool_us", RuleTag: "pool-route-0"},
		{OutboundTag: "block", RuleTag: "pool-route-1"},
		{OutboundTag: "pool_all", RuleTag: ""},
	}

	err := VerifyApplied(entries, []string{"pool-route-0", "pool-route-1"}, 4)
	require.NoError(t, err)

	err = VerifyApplied(entries, []string{"pool-route-0", "pool-route-9"}, 4)
	require.Error(t, err, "a missing expected ruleTag fails the verification")
	assert.Contains(t, err.Error(), "pool-route-9", "the missing tag is named")

	err = VerifyApplied(entries, []string{"pool-route-0"}, 5)
	require.Error(t, err, "a rule-count mismatch fails the verification")
	assert.Contains(t, err.Error(), "4", "both counts are reported")

	err = VerifyApplied(entries, nil, 4)
	assert.NoError(t, err, "a render without pool routes (api + catch-all only) verifies on count alone")
}

// Payload: the candidate's ENTIRE routing section (api rule first, pool
// rules, catch-all last, all balancers) embedded in a minimal config JSON —
// verbatim from the gated render, never hand-assembled (plan §3.5). The
// temp file is 0600 (the render artifact discipline) and the cleanup removes
// it. The 0600 pin is asserted where POSIX mode bits exist; windows has no
// POSIX mode bits — ACLs own permissions there and os.Stat synthesizes 0666
// for a writable file regardless of the CreateTemp/Chmod 0600 discipline
// (run 43428880158).

func TestWritePayloadFileEmbedsEntireRoutingSection(t *testing.T) {
	routing := map[string]any{
		"rules":     []any{map[string]any{"outboundTag": "api"}},
		"balancers": []any{map[string]any{"tag": "pool_all"}},
	}
	candidate := map[string]any{
		"routing":   routing,
		"outbounds": []any{map[string]any{"tag": "direct"}},
	}

	path, cleanup, err := WritePayloadFile(candidate)
	t.Cleanup(cleanup)
	require.NoError(t, err)

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.JSONEq(t, `{"routing":{"rules":[{"outboundTag":"api"}],"balancers":[{"tag":"pool_all"}]}}`,
		string(raw), "the payload carries ONLY the routing section — verbatim, nothing else")
	st, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS != "windows" { // windows has no POSIX mode bits — ACLs own permissions there
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(), "payload file is 0600")
	}
	assert.True(t, strings.HasPrefix(filepath.Base(path), "assay-apply-payload-"), "recognizable temp name")

	cleanup()
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "cleanup removes the payload file")
}

func TestWritePayloadFileFailsLoudWithoutRouting(t *testing.T) {
	// Error paths clean up their own temp state internally; nothing to release.
	_, _, err := WritePayloadFile(map[string]any{"outbounds": []any{}})
	require.Error(t, err, "a payload without a routing section is a programming error — fail loud")
	assert.Contains(t, err.Error(), "routing")
}

// ExecRunner is the production executor: stdout returns, the child's stderr
// tail rides the error, and the exit status is preserved. Proven through the
// test-binary-as-helper pattern (hermetic, cross-platform); the RED proof is
// a mutation run (stderr capture severed → this test fails).

func TestExecRunnerCapturesStdoutStderrAndStatus(t *testing.T) {
	if os.Getenv("HOTAPPLY_EXEC_HELPER") == "1" {
		// Child side: re-executed by the parent block below with the marker
		// set and -test.run pinned to this test only.
		_, _ = fmt.Fprintln(os.Stdout, "hello-stdout")
		_, _ = fmt.Fprintln(os.Stderr, "hello-stderr-tail")
		os.Exit(3)
	}
	t.Setenv("HOTAPPLY_EXEC_HELPER", "1")
	runner := ExecRunner{}
	argv := []string{os.Args[0], "-test.run=TestExecRunnerCapturesStdoutStderrAndStatus$", "-test.count=1"}
	stdout, err := runner.Run(context.Background(), argv, nil)
	require.Error(t, err, "the helper exits 3 — a non-zero child is an error, never a success")
	assert.Contains(t, err.Error(), "exit status 3", "the exit status is preserved")
	assert.Contains(t, err.Error(), "hello-stderr-tail", "the stderr tail reaches the error")
	assert.Contains(t, string(stdout), "hello-stdout", "stdout is returned for parsing")
}
