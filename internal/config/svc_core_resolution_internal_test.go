package config

// svc_core_resolution_internal_test.go pins the WINDOWS SERVICE CONTEXT core
// resolution guard (the live SCM diagnostics root cause, 2026-11-19): under
// the service context — svc.IsWindowsService(), the production detection
// wired through the injectable ServiceContextDetected seam — the user-local
// ~/.local/bin spot is NEVER consulted. os.UserHomeDir there resolves to the
// SYSTEM profile (C:\Windows\system32\config\systemprofile), whose
// .local\bin is the poison spot the production incident bound: a
// nonexistent path that fork/exec failed on at every bootstrap and every
// crash-supervision retry (docs/landmines-crossplatform.md §1).
//
// The service-context resolution order: an explicit [core].xray_bin
// override (the owner's knob, honored verbatim) → the MANAGED core at
// <data>/bin/xray[.exe] (the D4 layout `assay install`'s windows placement
// leg guarantees) → an existing system xray (real system-wide installs are
// fine) → the managed spot again as the canonical fill target. Interactive
// contexts (linux/darwin/interactive windows) keep the user-local spot
// FIRST — byte-unchanged by this guard.
//
// Hermeticity: every seam is injectable (ServiceContextDetected,
// UserLocalBinDir, DefaultSystemXrayPaths) — no test touches the real
// profile tree, the real $HOME/.local, or the real /usr tree.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"assay/internal/platform"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withServiceContextDetected pins the service-context detection seam for
// the test's duration: the resolution guard reads it on every call.
func withServiceContextDetected(t *testing.T, inService bool) {
	t.Helper()
	orig := ServiceContextDetected
	ServiceContextDetected = func() bool { return inService }
	t.Cleanup(func() { ServiceContextDetected = orig })
}

// writeExecFixture plants an executable file at path — the stand-in for an
// existing binary the resolution's isRegularExecutable check accepts.
func writeExecFixture(t *testing.T, path string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte("#!fixture\n"), 0o755))
	return path
}

// svcResolutionFixture arms all three resolution seams at once: a user-local
// dir (poison stand-in when in the service context), a system-path scan
// list, and a data dir. Returns the user-local path, the system path, and
// the data dir; nothing exists until writeExecFixture plants it.
func svcResolutionFixture(t *testing.T) (string, string, string) {
	t.Helper()
	userBinDir := filepath.Join(t.TempDir(), "local-bin")
	userLocal := filepath.Join(userBinDir, platform.CoreBinaryName(runtime.GOOS))
	system := filepath.Join(t.TempDir(), "system-xray", platform.CoreBinaryName(runtime.GOOS))

	origDir, origPaths := UserLocalBinDir, DefaultSystemXrayPaths
	UserLocalBinDir = func() string { return userBinDir }
	DefaultSystemXrayPaths = []string{system}
	t.Cleanup(func() { UserLocalBinDir, DefaultSystemXrayPaths = origDir, origPaths })

	return userLocal, system, t.TempDir()
}

// TestManagedCoreBinShape pins the managed spot: <data>/bin/<core binary
// name> — the D4 layout the uninstall's removeManagedCore already owns and
// the windows install placement leg fills.
func TestManagedCoreBinShape(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, "bin", platform.CoreBinaryName(runtime.GOOS))
	assert.Equal(t, want, ManagedCoreBin(dir), "the managed core spot is <data>/bin/<binary>")
	assert.Equal(t, filepath.Join(dir, "bin", "xray"), ManagedCoreBin(dir),
		"the linux binary name is xray (the §4.2 binname table)")
}

// TestResolveCoreXrayBinServiceContextPrefersManaged pins the guard's
// headline: in the service context the managed core WINS even though a
// user-local binary AND a system xray both exist — the SYSTEM-profile
// user-local spot is never consulted, and the managed spot outranks the
// system scan (the per-OS §2.2.11 contract: override or managed only, the
// windows scan list being empty in production).
func TestResolveCoreXrayBinServiceContextPrefersManaged(t *testing.T) {
	userLocal, system, dataDir := svcResolutionFixture(t)
	writeExecFixture(t, userLocal) // exists — the interactive winner, skipped in service
	writeExecFixture(t, system)    // exists — the system fall-through, outranked
	managed := writeExecFixture(t, ManagedCoreBin(dataDir))
	withServiceContextDetected(t, true)

	got := ResolveCoreXrayBin("", dataDir)
	assert.Equal(t, managed, got,
		"the service context binds the managed core, never the user-local spot")
	assert.NotEqual(t, userLocal, got, "the SYSTEM-profile user-local spot is poison — never bound")
}

// TestResolveCoreXrayBinServiceContextSystemFallthrough pins the middle of
// the service order: with the managed core ABSENT (install never ran or was
// purged), an existing system xray binds — real system-wide installs are
// fine — while the user-local spot stays skipped even though it exists.
func TestResolveCoreXrayBinServiceContextSystemFallthrough(t *testing.T) {
	userLocal, system, dataDir := svcResolutionFixture(t)
	writeExecFixture(t, userLocal) // exists — still skipped in the service context
	writeExecFixture(t, system)
	withServiceContextDetected(t, true)

	got := ResolveCoreXrayBin("", dataDir)
	assert.Equal(t, system, got, "no managed core → an existing system xray binds")
	assert.NotEqual(t, userLocal, got, "the user-local spot stays poison in the service context")
}

// TestResolveCoreXrayBinServiceContextManagedTargetWhenNothingExists pins
// the terminal: with NO binary anywhere, the service-context resolution
// lands on the managed spot as the canonical fill target — the exact path
// `assay install`'s placement leg fills. This is the production-incident
// shape (nothing exists under LocalSystem): the OLD interactive fall-through
// bound the nonexistent SYSTEM-profile user-local path here, which fork/exec
// then failed on at every retry. The manager's service gate refuses LOUD on
// this state, naming the fix.
func TestResolveCoreXrayBinServiceContextManagedTargetWhenNothingExists(t *testing.T) {
	_, _, dataDir := svcResolutionFixture(t)
	withServiceContextDetected(t, true)

	got := ResolveCoreXrayBin("", dataDir)
	assert.Equal(t, ManagedCoreBin(dataDir), got,
		"nothing exists → the managed spot is the fill target the install leg guarantees")
	assert.NotContains(t, got, "systemprofile",
		"the SYSTEM-profile user-local path can never be the resolved value")
}

// TestResolveCoreXrayBinServiceContextOverrideHonored pins the owner's knob:
// an explicit [core].xray_bin override wins verbatim in the service context
// exactly as it does interactively — the guard never touches an explicit
// value.
func TestResolveCoreXrayBinServiceContextOverrideHonored(t *testing.T) {
	_, _, dataDir := svcResolutionFixture(t)
	writeExecFixture(t, ManagedCoreBin(dataDir))
	withServiceContextDetected(t, true)

	assert.Equal(t, "/custom/xray", ResolveCoreXrayBin("/custom/xray", dataDir),
		"the explicit override is honored verbatim in the service context")
}

// TestResolveCoreXrayBinInteractiveContextUnchanged pins the flip side: with
// the service context OFF (interactive linux/darwin/interactive-windows —
// the default on every non-windows build and every CLI session), the
// user-local spot stays FIRST even when the managed core also exists — the
// guard changes nothing for interactive behavior.
func TestResolveCoreXrayBinInteractiveContextUnchanged(t *testing.T) {
	userLocal, system, dataDir := svcResolutionFixture(t)
	writeExecFixture(t, userLocal) // exists — the interactive winner
	writeExecFixture(t, ManagedCoreBin(dataDir))
	writeExecFixture(t, system)
	withServiceContextDetected(t, false)

	assert.Equal(t, userLocal, ResolveCoreXrayBin("", dataDir),
		"interactive: the user-local spot stays FIRST (unchanged precedence)")
}

// TestResolveCoreXrayBinInteractiveFallbackUnchanged pins the interactive
// fall-through byte-identically: no existing user-local binary and no
// system xray → the resolution returns the user-local INSTALL TARGET (the
// pending-install shape the next EnsureCoreBinary pass fills — today's
// fresh-install contract, untouched by the service guard).
func TestResolveCoreXrayBinInteractiveFallbackUnchanged(t *testing.T) {
	userLocal, system, dataDir := svcResolutionFixture(t)
	withServiceContextDetected(t, false)

	assert.Equal(t, userLocal, ResolveCoreXrayBin("", dataDir),
		"interactive, nothing installed: the user-local install target is the resolution (pre-fix shape)")
	assert.NotEqual(t, ManagedCoreBin(dataDir), ResolveCoreXrayBin("", dataDir),
		"interactive, nothing installed: the managed spot stays the degenerate no-home fallback only")
	_ = system
}
