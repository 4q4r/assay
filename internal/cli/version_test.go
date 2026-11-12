package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestVersionFlagRenders pins the release smoke-probe surface (R3): both
// the shorthand and the long form must print the stamped build
// coordinates "assay <version> (<commit>) <date>" and exit 0, while the
// subcommand-level -v flags (status --overlap, list --verbose) stay
// untouched.
func TestVersionFlagRenders(t *testing.T) {
	origVersion, origCommit, origDate := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = origVersion, origCommit, origDate })
	Version, Commit, Date = "v9.9.9-test", "abc1234def", "2026-11-12T00:00:00Z"

	for _, flag := range []string{"-v", "--version"} {
		t.Run(flag, func(t *testing.T) {
			root := New()
			out := &bytes.Buffer{}
			root.SetOut(out)
			root.SetErr(&bytes.Buffer{})
			root.SetArgs([]string{flag})
			if err := root.Execute(); err != nil {
				t.Fatalf("assay %s returned error: %v", flag, err)
			}
			line := out.String()
			for _, want := range []string{"assay", "v9.9.9-test", "abc1234def", "2026-11-12T00:00:00Z"} {
				if !strings.Contains(line, want) {
					t.Fatalf("assay %s output %q does not contain %q", flag, line, want)
				}
			}
		})
	}
}

// TestVersionVarsDefaultNonEmpty pins the package-level ldvar defaults:
// the smoke gate asserts a non-empty version line, which only holds if
// the fallback defaults are non-empty in non-stamped builds.
func TestVersionVarsDefaultNonEmpty(t *testing.T) {
	if Version == "" {
		t.Fatal("package Version default must be non-empty")
	}
	if Commit == "" {
		t.Fatal("package Commit default must be non-empty")
	}
	if Date == "" {
		t.Fatal("package Date default must be non-empty")
	}
}
