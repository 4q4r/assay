package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// This file is the task-6 acceptance gate (the 2026-11-10 self-held-core
// design, D3 + S4): the external activation mode is REMOVED, not hidden —
// the repository carries zero foreign-client surface outside the S4
// parse-and-warn table. TestExternalModeSurfaceZero asserts the sweep over
// the real tree; TestSurfaceGateDetectsPlantedRemnants proves the gate
// itself can detect planted remnants (the reviewer's dynamic probe,
// institutionalized — a gate that cannot fail is not a gate). The
// parse-and-warn mechanism's own behavior is pinned by the T1
// forward-contract pair (TestRetiredKeysParseAndWarn).

// retiredTomlKeys is the retired S4 surface as TOML key spellings. The
// dotted forms are unambiguous; the bare forms are unique enough that a hit
// outside the parse-and-warn table is a remnant by definition.
var retiredTomlKeys = []string{
	"activate.target",
	"activate.xray_bin",
	"activate.asset_dir",
	"activate.service_name",
	"activate.backup_dir",
	"render.template",
	"render.output_dir",
	"render.stats_port",
	"render.pool_inbound_tags",
	"maintain.auto_restart",
	"pool_inbound_tags",
	"auto_restart",
	"asset_dir",
	"service_name",
	"backup_dir",
	"stats_port",
	"output_dir",
}

// retiredGoIdentifiers is the retired surface as Go identifiers: the deleted
// struct fields (qualified by their section, so a legitimate identifier on
// an unrelated type cannot false-positive), the deleted defaults/helpers,
// and the deleted foreign-restart seam. A hit anywhere in Go sources is a
// remnant.
var retiredGoIdentifiers = []string{
	"Render.Template",
	"Render.OutputDir",
	"Render.StatsPort",
	"Render.PoolInboundTags",
	"Activate.Target",
	"Activate.XrayBin",
	"Activate.AssetDir",
	"Activate.ServiceName",
	"Maintain.AutoRestart",
	"AutoRestartEnabled",
	"DefaultServiceName",
	"DefaultPoolInboundTags",
	"restartWiring",
	"runForeignActivateStage",
	"extractSocksPort",
	"RestartHint",
	"NoRestart",
}

// gitGrepRepoRoot is the repository root relative to this package's test
// working directory (internal/config → the repo root).
const gitGrepRepoRoot = "../.."

// gateCarrierPaths are the GATE'S OWN files, relative to the repo root.
// They are the contract's carriers: the contract file necessarily names
// the forbidden surface (the patterns it asserts against) and the probe
// file necessarily contains the planted remnants the self-verification
// asserts the gate catches — so every grep leg excludes them. A hit in a
// carrier is the contract speaking, not a remnant. (Tracked-tree gotcha
// proven twice at commit boundaries: git grep ignores untracked files, so
// pre-commit runs hide self-matches that surface the moment the file is
// tracked; the exemptions are explicit, never accidental.)
var gateCarrierPaths = map[string]bool{
	"internal/config/external_mode_surface_test.go":       true,
	"internal/config/external_mode_surface_probe_test.go": true,
}

// gateCarrierLine reports whether the grep hit (path:line:content) lands
// in one of the gate's own carrier files.
func gateCarrierLine(hit string) bool {
	path, _, _ := strings.Cut(hit, ":")
	return gateCarrierPaths[path]
}

// gitGrepRuns reports whether the acceptance grep legs can run at all: the
// contract is a git grep over the working tree, so it needs both the git
// binary and a repository. Without them the legs skip loud (the environment
// gap is named, never silently ignored) — the hermetic legs still run.
func gitGrepRuns(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("acceptance grep legs cannot run: no git binary on PATH")
	}
	probe := exec.CommandContext(context.Background(), "git", "-C", gitGrepRepoRoot, "rev-parse", "--is-inside-work-tree")
	if err := probe.Run(); err != nil {
		t.Skipf("acceptance grep legs cannot run: %s is not a git work tree (%v)", gitGrepRepoRoot, err)
	}
}

// grepExitClassifies discriminates git grep's exit contract (review M-1):
// exit 0 = matches, exit 1 = NO MATCHES (the clean-sweep pass state), any
// other exit = a grep MALFUNCTION (bad pathspec, corrupt index, …) returned
// as an error — a malfunction must never masquerade as a clean sweep.
// Exported to the probe file as a method-free helper so the discrimination
// itself is unit-proven with synthetic exit codes (see
// TestGrepExitDiscrimination in external_mode_surface_probe_test.go).
func grepExitClassifies(out []byte, err error) ([]string, error) {
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, err
		}
		if code := exitErr.ExitCode(); code != 1 {
			return nil, fmt.Errorf("git grep malfunctioned with exit code %d "+
				"(1 = no matches = the pass state; anything else is a grep error): %s",
				code, strings.TrimSpace(string(out)))
		}
		return nil, nil // exit 1: zero matches — the pass state
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	return lines, nil
}

// runGitGrep executes one git grep against root and returns its stdout
// lines; a grep malfunction (any exit beyond the 0/1 contract) fails the
// test loud via grepExitClassifies.
func runGitGrep(t *testing.T, root string, args ...string) []string {
	t.Helper()
	full := append([]string{"-C", root, "grep", "-n"}, args...)
	out, err := exec.CommandContext(context.Background(), "git", full...).Output()
	lines, grepErr := grepExitClassifies(out, err)
	if grepErr != nil {
		t.Fatalf("git grep %v: %v", args, grepErr)
	}
	return lines
}

// surfaceViolations runs the grep/path legs of the acceptance contract
// against root and returns one human-readable line per violation (empty =
// clean). Both the real-tree gate (TestExternalModeSurfaceZero) and the
// planted-remnant self-verification
// (TestSurfaceGateDetectsPlantedRemnants) consume THIS ONE implementation —
// the scratch-tree probe exercises the exact logic the real gate runs, not
// a parallel copy.
//
// Legs covered here: the foreign-client grep (1), the retired TOML knobs'
// parse-and-warn scoping (2), the retired Go identifiers (3), the deleted
// foreign-restart package directory (5, review I-1: the path is
// <root>/internal/restart — the original defect stat'ed <root>/restart and
// never fired), and the embedded install defaults config (6, review I-2).
// Leg 4 (retired struct fields by reflection) is bound to the real test
// binary's compiled types and stays in TestExternalModeSurfaceZero.
func surfaceViolations(t *testing.T, root string) []string {
	t.Helper()
	var violations []string

	// Leg 1: the foreign client's name — zero hits in Go sources, cmd,
	// systemd outside this contract file.
	hits := runGitGrep(t, root, "xray-raw", "--", "*.go", "cmd/", "systemd/")
	hits = slices.DeleteFunc(hits, gateCarrierLine)
	for _, hit := range hits {
		violations = append(violations, "leg1 foreign-client name: "+hit)
	}

	// Leg 2: the retired TOML knobs may appear ONLY in the parse-and-warn
	// surface — the table's file AND the config package's tests (the T1 pins
	// must name the keys they pin; a test fixture naming a key is the
	// mechanism working, not a remnant).
	pattern := strings.Join(retiredTomlKeys, "|")
	for _, hit := range runGitGrep(t, root, "-E", pattern, "--", "*.go") {
		path, _, _ := strings.Cut(hit, ":")
		allowed := path == "internal/config/config.go" ||
			(strings.HasPrefix(path, "internal/config/") && strings.HasSuffix(path, "_test.go"))
		if !allowed {
			violations = append(violations, "leg2 retired TOML knob outside the parse-and-warn surface: "+hit)
		}
	}

	// Leg 3: the retired Go identifiers — zero hits anywhere outside this
	// contract file.
	pattern = strings.Join(retiredGoIdentifiers, "|")
	hits = runGitGrep(t, root, "-E", pattern, "--", "*.go")
	hits = slices.DeleteFunc(hits, gateCarrierLine)
	for _, hit := range hits {
		violations = append(violations, "leg3 retired Go identifier: "+hit)
	}

	// Leg 5: the foreign-restart executor package directory is GONE
	// (deleted, not emptied) — at its real path internal/restart.
	if _, err := os.Stat(filepath.Join(root, "internal", "restart")); err == nil {
		violations = append(violations,
			"leg5 internal/restart still exists — the foreign-unit allowlist executor must stay deleted (D3)")
	}

	// Leg 6: the install-materialized defaults config tells the own-core
	// story (review I-2): no foreign-client path, no retired knob rows, and
	// the [core] section present. The file is go:embed'ed by internal/install
	// and materialized by `assay install` — a shipped artifact, not a doc.
	defaultsPath := filepath.Join(root, "internal", "install", "defaults_config.toml")
	raw, err := os.ReadFile(defaultsPath)
	if err != nil {
		violations = append(violations, "leg6 embedded defaults config unreadable: "+err.Error())
		return violations
	}
	defaults := string(raw)
	if strings.Contains(defaults, "xray-raw") {
		violations = append(violations, "leg6 embedded defaults config names the foreign client's path")
	}
	for line := range strings.SplitSeq(defaults, "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "# ")
		for _, key := range []string{
			"template", "target", "output_dir", "stats_port",
			"pool_inbound_tags", "asset_dir", "service_name", "auto_restart", "backup_dir",
		} {
			if strings.HasPrefix(trimmed, key+" =") {
				violations = append(violations,
					"leg6 embedded defaults config carries a retired knob row: "+trimmed)
			}
		}
	}
	if !strings.Contains(defaults, "[core]") {
		violations = append(violations, "leg6 embedded defaults config carries no [core] section (the own-core surface must be documented)")
	}
	return violations
}

// TestExternalModeSurfaceZero is the zero-remnant acceptance contract of the
// external-mode removal (D3/S4):
//
//	leg 1 — the foreign client's name appears NOWHERE in Go sources, the
//	        cmd tree, or the systemd units;
//	leg 2 — the retired TOML knobs appear ONLY in the parse-and-warn
//	        surface: the table's file plus the config package's own pins;
//	leg 3 — the retired Go identifiers (fields, defaults, helpers, the
//	        foreign-restart seam) appear NOWHERE;
//	leg 4 — the retired struct fields are gone by reflection (hermetic);
//	leg 5 — the foreign-restart executor package directory (internal/restart)
//	        is gone;
//	leg 6 — the install-materialized defaults config carries no retired
//	        knob rows and no foreign-client path, and documents [core].
//
// Legs 1-3 and 5-6 run through the shared surfaceViolations implementation
// exactly as the acceptance contract is written; leg 4 is hermetic. The
// gate's own sensitivity is proven by TestSurfaceGateDetectsPlantedRemnants.
func TestExternalModeSurfaceZero(t *testing.T) {
	// Leg 4 (hermetic): the retired struct fields must not exist.
	for section, typ := range map[string]reflect.Type{
		"RenderConfig":   reflect.TypeFor[RenderConfig](),
		"ActivateConfig": reflect.TypeFor[ActivateConfig](),
		"MaintainConfig": reflect.TypeFor[MaintainConfig](),
	} {
		for _, name := range []string{
			"Template", "OutputDir", "StatsPort", "PoolInboundTags",
			"Target", "XrayBin", "AssetDir", "ServiceName", "AutoRestart", "BackupDir",
		} {
			if _, ok := typ.FieldByName(name); ok {
				t.Errorf("retired struct field %s.%s still exists — the external-mode removal is incomplete",
					section, name)
			}
		}
	}

	gitGrepRuns(t)
	for _, v := range surfaceViolations(t, gitGrepRepoRoot) {
		t.Error(v)
	}
}
