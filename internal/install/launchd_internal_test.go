package install

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeLaunchctl records every launchctl invocation and replays scripted
// outputs. Tests never execute launchctl — hermetic by construction (the
// real binary exists only on macOS, and even there the executor is
// allowlist-gated).
type fakeLaunchctl struct {
	calls [][]string
	// script maps arg[0] → the (output, error) to replay for the next call
	// with that verb, in order. A verb absent from the script yields ("", nil)
	// — the "succeeds with empty output" default (bootout/print probes).
	script map[string][]scripted
}

type scripted struct {
	out string
	err error
}

func newFakeLaunchctl() *fakeLaunchctl {
	return &fakeLaunchctl{script: map[string][]scripted{}}
}

func (f *fakeLaunchctl) expect(verb string, out string, err error) {
	f.script[verb] = append(f.script[verb], scripted{out: out, err: err})
}

func (f *fakeLaunchctl) Launchctl(args ...string) (string, error) {
	f.calls = append(f.calls, args)
	if q, ok := f.script[args[0]]; ok && len(q) > 0 {
		s := q[0]
		f.script[args[0]] = q[1:]
		return s.out, s.err
	}
	return "", nil
}

// verbs reports the call sequence as a compact verb list (ordering pins).
func (f *fakeLaunchctl) verbs() []string {
	v := make([]string, len(f.calls))
	for i, c := range f.calls {
		v[i] = c[0]
	}
	return v
}

// printFixture is the minimal launchctl print(8) output shape the parser may
// rely on: `key = value` lines inside the job dictionary (launchd.info's
// documented print output; exact formatting re-verified against `man
// launchctl` on the macOS CI runner — the S1 CI leg owns that check).
const printFixture = `assay-watch = {
	state = running
	pid = 4242
	program = assay
	...
}
`

// scheduler returns a LaunchdScheduler over the fake with test-scale pacing
// (the production 500ms×10 verify loop must not stretch unit tests).
func launchdScheduler(f *fakeLaunchctl) *LaunchdScheduler {
	s := NewLaunchdScheduler(f)
	s.verifyInterval = time.Millisecond
	s.bootoutInterval = time.Millisecond
	return s
}

// launchdSpec builds a hermetic LaunchdInstallSpec under a temp home.
func launchdSpec(t *testing.T) (LaunchdInstallSpec, string, string) {
	t.Helper()
	home := t.TempDir()
	binDir := filepath.Join(home, "bin")
	dataDir := filepath.Join(home, "Library", "Application Support", "assay")
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	require.NoError(t, os.WriteFile(filepath.Join(home, "running-assay"), []byte("#!running\n"), 0o755))
	return LaunchdInstallSpec{
		RunningBinary:     filepath.Join(home, "running-assay"),
		BinDir:            binDir,
		ConfigPath:        "",
		DefaultConfigPath: filepath.Join(dataDir, "config.toml"),
		DataDir:           dataDir,
		AgentDir:          agentDir,
	}, binDir, agentDir
}

// ---------------------------------------------------------------------------
// Plist rendering — golden, mode, safety (§1.2.2/§1.2.3)
// ---------------------------------------------------------------------------

// TestRenderPlistGoldenExplicitConfig pins the full rendered agent plist for
// an explicit-config install: Label, ProgramArguments WITH -c, RunAtLoad,
// KeepAlive, ThrottleInterval=5, ProcessType=Background, log paths under
// <data>/logs — and NO EnvironmentVariables (the daemon is config-only by
// contract; launchd agents inherit a minimal environment, §1.2.2).
func TestRenderPlistGoldenExplicitConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assay-watch.plist")
	data := TemplateData{
		BinaryPath: "/Users/u/.local/bin/assay",
		ConfigPath: "/Users/u/custom/config.toml",
		LogOutPath: "/Users/u/Library/Application Support/assay/logs/watch.out.log",
		LogErrPath: "/Users/u/Library/Application Support/assay/logs/watch.err.log",
	}
	require.NoError(t, renderPlist(data, path))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	golden := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>assay-watch</string>
    <key>ProgramArguments</key>
    <array>
      <string>/Users/u/.local/bin/assay</string>
      <string>watch</string>
      <string>-c</string>
      <string>/Users/u/custom/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>/Users/u/Library/Application Support/assay/logs/watch.out.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/u/Library/Application Support/assay/logs/watch.err.log</string>
  </dict>
</plist>
`
	assert.Equal(t, golden, string(got), "the plist is a byte-pinned golden (§1.2.2)")
	assert.NotContains(t, string(got), "EnvironmentVariables",
		"no environment may leak into the agent (config-only contract)")
	assert.NotContains(t, string(got), "{{", "template placeholders must all be rendered")

	// Well-formedness: Apple's launchd parses XML — the render must decode
	// cleanly (hermetic stand-in for plutil, which exists only on macOS).
	dec := xml.NewDecoder(strings.NewReader(string(got)))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("rendered plist is not well-formed XML: %v", err)
		}
	}
}

// TestRenderPlistGoldenDefaultLocation pins the default-location render: NO
// -c in ProgramArguments — the daemon reads the default config location
// (the same TemplateData semantics as the systemd unit, units.go:68-75).
func TestRenderPlistGoldenDefaultLocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assay-watch.plist")
	data := TemplateData{
		BinaryPath: "/Users/u/.local/bin/assay",
		LogOutPath: "/Users/u/Library/Application Support/assay/logs/watch.out.log",
		LogErrPath: "/Users/u/Library/Application Support/assay/logs/watch.err.log",
	}
	require.NoError(t, renderPlist(data, path))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	s := string(got)
	assert.NotContains(t, s, "-c", "a default-location install renders plain `watch`")
	assert.Contains(t, s, "<string>watch</string>")
}

// TestRenderPlistModeIs0600 pins Apple's LaunchAgent file-mode requirement
// ("must have file mode set to 600 or 400" — Apple's Daemons and Services
// guide, §1.1): the plist lands at exactly 0600.
func TestRenderPlistModeIs0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assay-watch.plist")
	require.NoError(t, renderPlist(TemplateData{BinaryPath: "/bin/assay"}, path))
	st, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(),
		"a 0644 plist is a real-world launchd refusal class (§5.8) — mode is pinned 0600")
}

// TestRenderPlistRefusesXMLUnsafePaths pins the loud pre-write refusal of
// paths carrying XML-hostile characters (the plist is XML; a raw `&` breaks
// plutil parsing long after install printed success — the I-1 class). The
// refusal names the offending flag and writes NOTHING.
func TestRenderPlistRefusesXMLUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "assay-watch.plist")
	data := TemplateData{BinaryPath: "/bin/as&say"}
	err := renderPlist(data, path)
	require.Error(t, err, "an XML-hostile path must be refused before the write")
	assert.Contains(t, err.Error(), "&", "the refusal names the offending character")
	assert.Contains(t, err.Error(), "BinaryPath", "the refusal names the field")
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "nothing is written on refusal")
}

// ---------------------------------------------------------------------------
// LaunchctlExecutor allowlist (§1.2.5) — byte-pinned shapes, guard refusals
// ---------------------------------------------------------------------------

// TestLaunchctlAllowlistIsExactlyThePinnedShapes pins the FOUR sanctioned
// launchctl invocations byte-for-byte: bootstrap gui/<uid> <abs plist>,
// bootout gui/<uid>/assay-watch, print gui/<uid>/assay-watch,
// kickstart -k gui/<uid>/assay-watch. Everything else refuses.
func TestLaunchctlAllowlistIsExactlyThePinnedShapes(t *testing.T) {
	const uid = 501
	plist := "/Users/u/Library/LaunchAgents/assay-watch.plist"
	target := "gui/" + strconv.Itoa(uid) + "/" + LaunchdLabel

	shapes := [][]string{
		cmdLaunchdBootstrap(uid, plist),
		cmdLaunchdBootout(uid),
		cmdLaunchdPrint(uid),
		cmdLaunchdKickstart(uid),
	}
	assert.Equal(t, []string{"bootstrap", "gui/501", plist}, shapes[0])
	assert.Equal(t, []string{"bootout", target}, shapes[1])
	assert.Equal(t, []string{"print", target}, shapes[2])
	assert.Equal(t, []string{"kickstart", "-k", target}, shapes[3], "restart carries -k")
	for _, args := range shapes {
		assert.NoError(t, validateLaunchctl(args), "sanctioned shape must validate: %v", args)
	}
}

// TestLaunchctlAllowlistRefusesEverythingElse is the guard: the legacy
// load/unload pair, sudo, the system domain, foreign labels, relative paths,
// missing -k, unknown verbs, and arity drift all refuse LOUD.
func TestLaunchctlAllowlistRefusesEverythingElse(t *testing.T) {
	plist := "/Users/u/Library/LaunchAgents/assay-watch.plist"
	refusals := [][]string{
		{"load", "-w", plist},                           // legacy load — forbidden (§1.2.5)
		{"unload", plist},                               // legacy unload — forbidden
		{"bootstrap", "system/assay-watch", plist},      // the SYSTEM domain — never
		{"bootstrap", "gui/501", "relative.plist"},      // relative artifact path
		{"bootstrap", "gui/501", "/tmp/other.plist"},    // not assay's own artifact
		{"bootstrap", "gui/501"},                        // arity drift
		{"bootstrap", "gui/501/assay-watch"},            // bootstrap takes a plist, not a target
		{"sudo", "bootstrap", "gui/501", plist},         // no sudo, ever (binding constraint)
		{"bootout", "gui/501/com.other.agent"},          // foreign label
		{"bootout", "gui/501/assay-watch", "extra"},     // arity drift
		{"print", "gui/501/com.other.agent"},            // foreign unit — the W13 ruling class
		{"kickstart", "gui/501/assay-watch"},            // missing -k
		{"kickstart", "-k", "gui/501/assay-watch", "x"}, // arity drift
		{"enable", "gui/501/assay-watch"},               // not a sanctioned verb
		{"disable", "gui/501/assay-watch"},              // not a sanctioned verb
		{"kill", "gui/501/assay-watch"},                 // not a sanctioned verb
		{},                                              // empty
	}
	for _, args := range refusals {
		err := validateLaunchctl(args)
		require.Error(t, err, "must refuse: %v", args)
		assert.Contains(t, err.Error(), "allowlist", "refusals name the allowlist: %v", args)
	}
}

// TestLaunchctlExecutorRefusesBeforeSpawning pins the production executor's
// guard order: an out-of-allowlist invocation returns the refusal without
// ever spawning launchctl (observable: no such binary is invoked in the test
// environment at all — the refusal error carries the allowlist text).
func TestLaunchctlExecutorRefusesBeforeSpawning(t *testing.T) {
	_, err := LaunchctlExecutor{}.Launchctl("load", "-w", "/tmp/assay-watch.plist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowlist")
}

// ---------------------------------------------------------------------------
// Install flow (§1.2.6) — ordering, idempotent activation, loud failures
// ---------------------------------------------------------------------------

// TestLaunchdInstallFreshOrdering pins the §1.2.6 sequence on a fresh host:
// copyBinary + config materialization happen first, then the plist is
// rendered 0600, then the activation is print-probe → (not loaded: no
// bootout) → bootstrap → print-verify confirming a PID.
func TestLaunchdInstallFreshOrdering(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", "", errors.New("Load error: 2: No such file or directory")) // probe: not loaded
	f.expect("print", printFixture, nil)                                          // verify: running with PID
	s := launchdScheduler(f)
	spec, binDir, agentDir := launchdSpec(t)

	res, err := s.Install(spec)
	require.NoError(t, err)

	assert.Equal(t, []string{"print", "bootstrap", "print"}, f.verbs(),
		"fresh install: print-probe → bootstrap → print-verify (§1.2.6)")
	for _, c := range f.calls {
		if c[0] == "print" {
			assert.Equal(t, fmt.Sprintf("gui/%d/%s", os.Getuid(), LaunchdLabel), c[1],
				"the probe targets exactly the current uid's assay-watch")
		}
	}

	// Binary copied atomically (same primitive as systemd install).
	assert.Equal(t, filepath.Join(binDir, "assay"), res.BinaryPath)
	st, err := os.Stat(res.BinaryPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), st.Mode().Perm())

	// Default config materialized (default-location install).
	assert.Equal(t, spec.DefaultConfigPath, res.ConfigWritten, "the default-location install materializes the default config")

	// Plist rendered 0600 into the agent dir.
	plist := filepath.Join(agentDir, LaunchdPlistName)
	res0600 := statPerm(t, plist)
	assert.Equal(t, os.FileMode(0o600), res0600, "the agent plist is 0600 (Apple 600/400 requirement)")
	content, err := os.ReadFile(plist)
	require.NoError(t, err)
	assert.Contains(t, string(content), "<string>"+res.BinaryPath+"</string>")
	assert.Contains(t, string(content), spec.DataDir+"/logs/watch.out.log")

	assert.True(t, res.ServiceActive, "activation verified → ServiceActive")
	assert.Equal(t, []string{plist}, res.UnitPaths, "Result parity: the plist path rides UnitPaths")
}

// TestLaunchdInstallLoadedFirstBoots pins the idempotent re-install: the
// print-probe SUCCEEDS → bootout → wait for exit (print now fails) →
// bootstrap → print-verify (§1.2.6). Never two live registrations.
func TestLaunchdInstallLoadedFirstBoots(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", printFixture, nil)            // probe: ALREADY loaded
	f.expect("bootout", "", nil)                    // boot it out
	f.expect("print", "", errors.New("not loaded")) // wait-for-exit: gone
	f.expect("bootstrap", "", nil)                  // fresh bootstrap
	f.expect("print", printFixture, nil)            // verify: running
	s := launchdScheduler(f)
	spec, _, _ := launchdSpec(t)

	_, err := s.Install(spec)
	require.NoError(t, err)
	assert.Equal(t, []string{"print", "bootout", "print", "bootstrap", "print"}, f.verbs(),
		"re-install: probe → bootout → gone-probe → bootstrap → verify")
	booted := f.calls[1]
	assert.Equal(t, []string{"bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), LaunchdLabel)},
		booted, "bootout names the exact target")
}

// TestLaunchdInstallBootoutFailureIsLoud pins §1.2.6's ignore-only-if-not-
// loaded rule: a bootout failure while the probe just proved the job LOADED
// is loud (carries the exact launchctl line), never silently swallowed.
func TestLaunchdInstallBootoutFailureIsLoud(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", printFixture, nil) // probe: loaded
	f.expect("bootout", "", errors.New("bootout failed: 113: Could not terminate job"))
	s := launchdScheduler(f)
	spec, _, _ := launchdSpec(t)

	_, err := s.Install(spec)
	require.Error(t, err, "a loaded job that refuses bootout must fail the install loud")
	assert.Contains(t, err.Error(), fmt.Sprintf("launchctl bootout gui/%d/%s", os.Getuid(), LaunchdLabel),
		"the error carries the exact manual command line (owner UX rule)")
}

// TestLaunchdInstallBootstrapFailureCarriesExactLine pins the owner UX rule:
// any activation failure hands the user the EXACT launchctl line to run by
// hand (§1.2.6 "Failure anywhere = loud error carrying the exact launchctl
// line").
func TestLaunchdInstallBootstrapFailureCarriesExactLine(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", "", errors.New("not loaded"))
	f.expect("bootstrap", "", errors.New("Bootstrap failed: 5: Input/output error"))
	s := launchdScheduler(f)
	spec, _, agentDir := launchdSpec(t)

	_, err := s.Install(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(),
		fmt.Sprintf("launchctl bootstrap gui/%d ", os.Getuid())+
			filepath.Join(agentDir, LaunchdPlistName),
		"the error carries the exact manual command line")
}

// TestLaunchdInstallVerifyLoopTimesOutLoud pins the bounded verify loop
// (10×500ms production pacing): bootstrap reported success but print never
// shows a PID → the install fails loud naming the print command, never
// claims ServiceActive.
func TestLaunchdInstallVerifyLoopTimesOutLoud(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", "", errors.New("not loaded"))
	f.expect("bootstrap", "", nil)
	for range 10 {
		f.expect("print", "state = running\npid = 0\n", nil) // never a real PID
	}
	s := launchdScheduler(f)
	spec, _, _ := launchdSpec(t)

	res, err := s.Install(spec)
	require.Error(t, err, "no PID after the bounded verify loop = loud failure")
	assert.False(t, res.ServiceActive)
	assert.Contains(t, err.Error(), fmt.Sprintf("launchctl print gui/%d/%s", os.Getuid(), LaunchdLabel))
}

// ---------------------------------------------------------------------------
// Uninstall (§1.2.7)
// ---------------------------------------------------------------------------

// TestLaunchdUninstallOrdering pins the teardown: bootout (when loaded),
// plist removal, managed-core teardown, purge passthrough. No legacy
// cleanup exists on darwin (no prior darwin installs, §1.2.7).
func TestLaunchdUninstallOrdering(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", printFixture, nil) // probe: loaded
	f.expect("bootout", "", nil)
	s := launchdScheduler(f)
	home := t.TempDir()
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	dataDir := filepath.Join(home, "Library", "Application Support", "assay")
	require.NoError(t, os.MkdirAll(agentDir, 0o750))
	plist := filepath.Join(agentDir, LaunchdPlistName)
	require.NoError(t, os.WriteFile(plist, []byte("plist"), 0o600))
	// Managed core artifacts to tear down (D4).
	coreBin := filepath.Join(dataDir, "bin", "xray")
	require.NoError(t, os.MkdirAll(filepath.Dir(coreBin), 0o750))
	require.NoError(t, os.WriteFile(coreBin, []byte("x"), 0o755))

	res, err := s.Uninstall(LaunchdUninstallSpec{
		AgentDir: agentDir, DataDir: dataDir,
		PurgeConfigPath: filepath.Join(dataDir, "config.toml"),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"print", "bootout"}, f.verbs())
	assert.Equal(t, []string{LaunchdLabel}, res.DisabledUnits, "the booted-out registration is reported")
	_, statErr := os.Stat(plist)
	assert.True(t, os.IsNotExist(statErr), "the plist file is removed")
	assert.Equal(t, []string{coreBin}, res.CoreRemoved, "managed-core teardown runs unchanged")
	assert.Equal(t, []string{filepath.Join(dataDir, "config.toml")}, res.Purged)
	assert.Equal(t, []string{LaunchdPlistName}, res.RemovedUnits, "the plist removal is reported (no LEGACY units on darwin — §1.2.7)")
	assert.NotContains(t, res.RemovedUnits, RefreshTimer, "no legacy W5 timer cleanup on darwin (§1.2.7)")
}

// TestLaunchdUninstallWhenNotLoaded pins the honest skip: the probe proves
// the job NOT loaded → bootout is skipped (no fake success), the plist still
// comes off, uninstall succeeds.
func TestLaunchdUninstallWhenNotLoaded(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", "", errors.New("not loaded"))
	s := launchdScheduler(f)
	home := t.TempDir()
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	require.NoError(t, os.MkdirAll(agentDir, 0o750))
	plist := filepath.Join(agentDir, LaunchdPlistName)
	require.NoError(t, os.WriteFile(plist, []byte("plist"), 0o600))

	res, err := s.Uninstall(LaunchdUninstallSpec{AgentDir: agentDir})
	require.NoError(t, err)
	assert.Equal(t, []string{"print"}, f.verbs(), "not loaded → no bootout runs")
	assert.Empty(t, res.DisabledUnits)
	_, statErr := os.Stat(plist)
	assert.True(t, os.IsNotExist(statErr), "the stale plist still gets removed")
}

// ---------------------------------------------------------------------------
// Status (§1.2.8) — minimal parse + honest mechanism note
// ---------------------------------------------------------------------------

// TestLaunchdStatusParsesStateAndPID pins the minimal print(8) parse
// (state + pid) and the ADDENDUM §1 honesty requirement: the note names the
// self-watchdog mechanism ("self-watchdog → KeepAlive restart"), never
// claims systemd parity silently.
func TestLaunchdStatusParsesStateAndPID(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", printFixture, nil)
	s := launchdScheduler(f)

	st, err := s.Status()
	require.NoError(t, err)
	assert.True(t, st.Active)
	assert.Equal(t, 4242, st.PID)
	assert.Contains(t, st.Note, "self-watchdog", "the note names the mechanism (ADDENDUM §1)")
	assert.Contains(t, st.Note, "KeepAlive")
}

// printFixtureNoPid is the launchctl print(8) shape for a REGISTERED agent
// with no running pid right now (the KeepAlive throttle/restart window):
// the state line is there, the pid line is not.
const printFixtureNoPid = `assay-watch = {
	state = running
	program = assay
	...
}
`

// TestLaunchdStatusRegisteredWithoutRunningPid pins the §5.22 honest-status
// rule: print succeeds but parseLaunchdPID finds no running pid → the agent
// is still registered (Active=true) and the note NAMES that state instead
// of repeating the running-agent note.
func TestLaunchdStatusRegisteredWithoutRunningPid(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", printFixtureNoPid, nil)
	s := launchdScheduler(f)

	st, err := s.Status()
	require.NoError(t, err)
	assert.True(t, st.Active, "registered is active even without a running pid")
	assert.Zero(t, st.PID)
	assert.Contains(t, st.Note, "registered; no running pid right now",
		"the note names the registered-but-not-running state (§5.22)")
	assert.Contains(t, st.Note, "self-watchdog → KeepAlive restart",
		"the note still names the mechanism (ADDENDUM §1)")
}

// TestLaunchdStatusNotInstalled pins the not-registered case: print fails →
// Active=false, PID 0, no error (an uninstalled host is a normal status).
func TestLaunchdStatusNotInstalled(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", "", errors.New("Load error: 2: No such file or directory"))
	s := launchdScheduler(f)

	st, err := s.Status()
	require.NoError(t, err)
	assert.False(t, st.Active)
	assert.Zero(t, st.PID)
}

// TestLaunchdHeldRegistrationAndAvailable pins the double-install refusal
// seam (§3.1 generalizes this later; launchd already reports what it holds)
// and the availability probe (launchctl on PATH; non-darwin hosts are
// unavailable by definition).
func TestLaunchdHeldRegistrationAndAvailable(t *testing.T) {
	f := newFakeLaunchctl()
	f.expect("print", printFixture, nil)
	s := launchdScheduler(f)

	held, where := s.HeldRegistration()
	assert.True(t, held)
	assert.Contains(t, where, LaunchdLabel)

	f2 := newFakeLaunchctl()
	f2.expect("print", "", errors.New("not loaded"))
	held2, _ := launchdScheduler(f2).HeldRegistration()
	assert.False(t, held2)

	ok, reason := s.Available()
	if runtime.GOOS == "darwin" {
		assert.True(t, ok, "on darwin launchd is always the init — availability is trivially true")
	} else {
		assert.False(t, ok, "off-darwin, the launchd scheduler is unavailable by definition")
		assert.NotEmpty(t, reason)
	}
	assert.Equal(t, "launchd", s.Name())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func statPerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	require.NoError(t, err)
	return st.Mode().Perm()
}
