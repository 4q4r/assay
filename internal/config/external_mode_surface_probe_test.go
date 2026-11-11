package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This file institutionalizes the review's dynamic probe (fix round 1,
// review I-1): the acceptance gate's legs are exercised against SCRATCH
// trees with planted remnants, proving the gate can actually fail. A gate
// that cannot detect the surface it exists to reject is decoration — the
// original leg-5 bug (stat'ing <root>/restart instead of
// <root>/internal/restart) was exactly that: a leg that silently never
// fired. The probe here runs the SAME surfaceViolations implementation the
// real gate runs — no parallel copy that could drift.
//
// This file is a gate CARRIER (see gateCarrierPaths): its plant literals
// name the forbidden surface by construction, so the real-tree gate
// exempts it exactly like the contract file itself.

// scratchRepo builds a minimal git repo at a fresh temp root carrying the
// given files, all TRACKED (git add -A — the commit-boundary lesson applies
// to fixtures too: git grep only sees tracked files, so an unstaged plant
// would be invisible to the very gate under test).
func scratchRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		abs := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o750))
		require.NoError(t, os.WriteFile(abs, []byte(body), 0o600))
	}
	git := exec.CommandContext(t.Context(), "git", "-C", root, "init", "-q")
	require.NoError(t, git.Run(), "scratch fixture: git init must succeed (the probe legs need a repo)")
	add := exec.CommandContext(t.Context(), "git", "-C", root, "add", "-A")
	require.NoError(t, add.Run(), "scratch fixture: the plants must be TRACKED or the gate cannot see them")
	return root
}

// plants is one planted remnant per acceptance leg, each minimal and
// unambiguous: the planted file, and the violation prefix the gate MUST
// produce for it.
var plants = []struct {
	name  string
	files map[string]string
	leg   string
	// want is the violation substring that SPECIFICALLY proves the planted
	// trigger was caught (not an incidental companion violation such as the
	// missing-[core] check any fixture-less defaults file also trips).
	want string
}{
	{
		name: "foreign-client name in a Go source (leg 1)",
		files: map[string]string{
			"cmd/old.go": "package main\n\n// xray-raw was the activation target\n",
		},
		leg:  "leg1",
		want: "leg1 foreign-client name",
	},
	{
		name: "retired TOML knob outside the parse-and-warn surface (leg 2)",
		files: map[string]string{
			"pkg/knob.go": "package pkg\n\nconst doc = \"pool_inbound_tags\"\n",
		},
		leg:  "leg2",
		want: "leg2 retired TOML knob",
	},
	{
		name: "retired Go identifier resurrected (leg 3)",
		files: map[string]string{
			"pkg/seam.go": "package pkg\n\nfunc runForeignActivateStage() {}\n",
		},
		leg:  "leg3",
		want: "leg3 retired Go identifier",
	},
	{
		name: "internal/restart package resurrected, string-clean (leg 5)",
		files: map[string]string{
			// The reviewer's exact dynamic probe: a resurrection carrying NO
			// forbidden string must still be caught by the PATH leg.
			"internal/restart/restart.go": "package restart\n",
		},
		leg:  "leg5",
		want: "leg5 internal/restart still exists",
	},
	{
		name: "embedded install defaults carrying a retired knob row (leg 6)",
		files: map[string]string{
			"internal/install/defaults_config.toml": "# materialized by assay install\n\n[core]\nsocks_port = 10810\n\ntemplate = \"/path/to/xray-template.json\"\n",
		},
		leg:  "leg6",
		want: "leg6 embedded defaults config carries a retired knob row",
	},
	{
		name: "embedded install defaults naming the foreign client's path (leg 6)",
		files: map[string]string{
			"internal/install/defaults_config.toml": "# materialized by assay install\n\n[core]\nsocks_port = 10810\n\n# the owner's live client layout lives in xray-raw/config.json\n",
		},
		leg:  "leg6",
		want: "leg6 embedded defaults config names the foreign client's path",
	},
}

// TestGrepExitDiscrimination proves review M-1's fix at the decision point
// with REAL git invocations (exec.ExitError cannot be synthesized outside
// os.StartProcess, so every class is exercised against a genuine repo):
// exit 0 (matches) and exit 1 (no matches) are the contract's pass states,
// while any other exit — here an invalid-pathspec malfunction, the same
// class as a corrupt index — surfaces as an error, never as a silent clean
// sweep.
func TestGrepExitDiscrimination(t *testing.T) {
	root := scratchRepo(t, map[string]string{"a.go": "package a\n"})

	// exit 0 = matches → the lines come back, no error.
	lines, grepErr := grepExitClassifies(
		mustGitGrepOutput(t, root, "package", "--", "*.go"))
	require.NoError(t, grepErr, "exit 0 is the matched state")
	require.NotEmpty(t, lines)

	// exit 1 = no matches → the clean no-match state, no error.
	lines, grepErr = grepExitClassifies(
		mustGitGrepOutput(t, root, "no-such-pattern-anywhere", "--", "*.go"))
	require.NoError(t, grepErr, "exit 1 is the clean no-match pass state")
	require.Empty(t, lines)

	// exit 128-class = a genuine grep malfunction (a broken invocation —
	// the same exit class as a corrupt index/bad pathspec) → a loud error
	// naming the exit-code contract, never a clean sweep.
	out, err := mustGitGrepOutput(t, root, "x", "--broken-flag")
	_, grepErr = grepExitClassifies(out, err)
	require.Error(t, grepErr, "a grep malfunction must surface as an error")
	require.Contains(t, grepErr.Error(), "malfunctioned with exit code",
		"the malfunction error must name the exit-code contract")
}

// mustGitGrepOutput runs one git grep and returns its raw stdout + error
// verbatim (no classification) — the probe's raw-feed helper.
func mustGitGrepOutput(t *testing.T, root string, args ...string) ([]byte, error) {
	t.Helper()
	full := append([]string{"-C", root, "grep", "-n"}, args...)
	return exec.CommandContext(t.Context(), "git", full...).Output()
}

// TestSurfaceGateDetectsPlantedRemnants is the gate's self-verification:
// for every planted remnant, a scratch tree carrying ONLY that plant must
// produce at least one violation prefixed by the expected leg — and the
// clean control tree must produce ZERO (no false positives, no leg firing
// on its own). A leg that cannot be made to fail here is dead weight; this
// test is that failure proof, re-proven on every run.
func TestSurfaceGateDetectsPlantedRemnants(t *testing.T) {
	gitGrepRuns(t)

	// The clean control: the same layout the real gate expects, all content
	// legitimate — zero violations (the gate must not cry wolf).
	clean := scratchRepo(t, map[string]string{
		"cmd/assay.go": "package main\n",
		"internal/install/defaults_config.toml": "" +
			"# assay default configuration\n\ndata_dir = \"/data\"\n\n[core]\nsocks_port = 10810\nhttp_port = 10811\napi_port = 15491\n",
	})
	if v := surfaceViolations(t, clean); len(v) > 0 {
		t.Fatalf("the clean control tree must pass the gate — these are FALSE POSIVES:\n%s",
			strings.Join(v, "\n"))
	}

	for _, p := range plants {
		t.Run(p.name, func(t *testing.T) {
			root := scratchRepo(t, p.files)
			violations := surfaceViolations(t, root)
			require.NotEmpty(t, violations,
				"the gate MUST fire on the planted remnant — a leg that passes here is blind")
			caught := false
			for _, v := range violations {
				if strings.HasPrefix(v, p.leg+" ") && strings.Contains(v, p.want) {
					caught = true
					t.Logf("detected: %s", v)
				}
			}
			require.True(t, caught,
				"the planted remnant must be caught by %s specifically (violation containing %q); got:\n%s",
				p.leg, p.want, strings.Join(violations, "\n"))
		})
	}
}
