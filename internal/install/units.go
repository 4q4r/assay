package install

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	units "public_vpn/systemd"
)

// installedBinaryName is the fixed executable name in BinDir.
const installedBinaryName = "publicvpn"

// TemplateData is rendered into the systemd/ unit templates.
type TemplateData struct {
	BinaryPath        string
	ConfigPath        string
	RefreshInterval   string // systemd time span, from [maintain].refresh_interval
	SpeedtestInterval string // systemd time span, from [maintain].speedtest_interval
}

// Options configures Install. Paths must be absolute (the CLI layer expands
// ~); intervals come from the loaded config.
type Options struct {
	BinDir            string
	UnitDir           string
	RunningBinary     string // os.Executable() of the caller
	ConfigPath        string // required unless NoSystemd
	NoSystemd         bool
	RefreshInterval   time.Duration
	SpeedtestInterval time.Duration
	Exec              Executor // required unless NoSystemd
}

// Result reports what install did.
type Result struct {
	BinaryPath   string
	UnitPaths    []string
	TimersActive bool
	SkippedUnits bool // --no-systemd: binary copy only, units skipped
}

// Install copies the running binary into BinDir (atomic, 0755 — self-upgrade
// is a re-run), renders the four systemd user units from the repo templates
// (timers carry the configured [maintain] intervals as OnUnitActiveSec), and
// then — only then — daemon-reloads and enables the timers through the
// injected Executor.
func Install(o Options) (Result, error) {
	if o.BinDir == "" || o.RunningBinary == "" {
		return Result{}, errors.New("install: BinDir and RunningBinary are required")
	}
	binPath, err := copyBinary(o.RunningBinary, o.BinDir)
	if err != nil {
		return Result{}, err
	}
	res := Result{BinaryPath: binPath}
	if o.NoSystemd {
		res.SkippedUnits = true
		return res, nil
	}
	if o.ConfigPath == "" {
		return res, errors.New("install: --config is required to render the unit files (the units embed the config path); " +
			"use --no-systemd to install the binary without units")
	}
	if o.Exec == nil {
		return res, errors.New("install: no systemctl executor provided")
	}
	if err := UserSystemdAvailable(); err != nil {
		return res, err
	}
	if o.UnitDir == "" {
		return res, errors.New("install: UnitDir is required")
	}
	unitPaths, err := writeUnits(TemplateData{
		BinaryPath:        binPath,
		ConfigPath:        o.ConfigPath,
		RefreshInterval:   Span(o.RefreshInterval),
		SpeedtestInterval: Span(o.SpeedtestInterval),
	}, o.UnitDir)
	if err != nil {
		return res, err
	}
	res.UnitPaths = unitPaths
	if err := o.Exec.Systemctl(cmdDaemonReload()...); err != nil {
		return res, fmt.Errorf("units written but not enabled: %w", err)
	}
	if err := o.Exec.Systemctl(cmdEnableTimers()...); err != nil {
		return res, fmt.Errorf("units written and reloaded but not enabled: %w", err)
	}
	res.TimersActive = true
	return res, nil
}

// UninstallOptions configures Uninstall.
type UninstallOptions struct {
	UnitDir string
	Exec    Executor
	// Purge (destructive, CLI --purge): also remove the config file and the
	// pipeline data dir. User data is kept unless BOTH paths are given.
	PurgeConfigPath string
	PurgeDataDir    string
}

// UninstallResult reports what uninstall did.
type UninstallResult struct {
	DisabledTimers bool
	RemovedUnits   []string
	MissingUnits   []string
	Purged         []string
	SkippedDisable bool // no user systemd session — nothing to disable
}

// Uninstall disables both timers (one allowlisted invocation), removes the
// four unit files, daemon-reloads so the user manager drops its not-found
// entries for them (I-2), and reports. --purge additionally removes the
// config file and data dir; anything else on the system (the installed binary
// included) is left untouched.
func Uninstall(o UninstallOptions) (UninstallResult, error) {
	res := UninstallResult{}
	if o.UnitDir == "" {
		return res, errors.New("uninstall: UnitDir is required")
	}
	talksToManager := o.Exec != nil && UserSystemdAvailable() == nil
	if talksToManager {
		if err := o.Exec.Systemctl(cmdDisableTimers()...); err != nil {
			return res, fmt.Errorf("uninstall: disabling the timers failed: %w", err)
		}
		res.DisabledTimers = true
	} else {
		res.SkippedDisable = true
	}
	for _, name := range UnitNames() {
		path := filepath.Join(o.UnitDir, name)
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				res.MissingUnits = append(res.MissingUnits, name)
				continue
			}
			return res, fmt.Errorf("uninstall: remove %s: %w", path, err)
		}
		res.RemovedUnits = append(res.RemovedUnits, name)
	}
	// I-2 (W5 fix round): the manager must rescan after the unit files are
	// gone — without this daemon-reload the user manager keeps ghost
	// "not-found" entries for the removed units until the next unrelated
	// reload. Same session guard as the disable step: no session, no manager
	// to inform.
	if talksToManager {
		if err := o.Exec.Systemctl(cmdDaemonReload()...); err != nil {
			return res, fmt.Errorf("uninstall: unit files removed but daemon-reload failed: %w", err)
		}
	}
	for _, purge := range []string{o.PurgeConfigPath, o.PurgeDataDir} {
		if purge == "" {
			continue
		}
		if err := os.RemoveAll(purge); err != nil {
			return res, fmt.Errorf("uninstall: purge %s: %w", purge, err)
		}
		res.Purged = append(res.Purged, purge)
	}
	return res, nil
}

// copyBinary atomically copies src into dir as `publicvpn` (temp file in the
// SAME directory → fsync → rename, so a crash never leaves a half-written
// binary), mode 0755. Re-running over an existing install = self-upgrade.
func copyBinary(src, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("install: create bin dir %s: %w", dir, err)
	}
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("install: open running binary %s: %w", src, err)
	}
	defer func() { _ = in.Close() }() // read-only handle on the running image
	target := filepath.Join(dir, installedBinaryName)
	tmp, err := os.CreateTemp(dir, ".publicvpn-*")
	if err != nil {
		return "", fmt.Errorf("install: temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := io.Copy(tmp, in); err != nil {
		cleanup()
		return "", fmt.Errorf("install: copy binary: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		cleanup()
		return "", fmt.Errorf("install: chmod 0755: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("install: fsync binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("install: close binary: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("install: rename into place %s: %w", target, err)
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync() // directory fsync is best-effort on Linux
		_ = dirFile.Close()
	}
	return target, nil
}

// writeUnits renders the four embedded templates and writes them into
// unitDir (created 0750, files 0644, atomic replace — idempotent re-install).
func writeUnits(data TemplateData, unitDir string) ([]string, error) {
	tmpl, err := template.ParseFS(units.Units, "public_vpn-*.service", "public_vpn-*.timer")
	if err != nil {
		return nil, fmt.Errorf("install: parse embedded unit templates: %w", err)
	}
	if err := os.MkdirAll(unitDir, 0o750); err != nil {
		return nil, fmt.Errorf("install: create unit dir %s: %w", unitDir, err)
	}
	var written []string
	for _, name := range UnitNames() {
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
			return nil, fmt.Errorf("install: render %s: %w", name, err)
		}
		path := filepath.Join(unitDir, name)
		if err := writeFileAtomic(path, buf.Bytes(), 0o644); err != nil {
			return nil, err
		}
		written = append(written, path)
	}
	return written, nil
}

// writeFileAtomic writes data to path via a temp file in the same directory,
// fsync, and rename — readers never observe a partial file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("install: temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("install: write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("install: chmod %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("install: fsync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("install: close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("install: rename into place %s: %w", path, err)
	}
	return nil
}

// Span renders d as a systemd time span: the largest single unit that is
// exact (hours → "6h"/"168h", minutes → "5m", else seconds). systemd accepts
// concatenated unit sequences, but a single exact unit round-trips cleanly
// through ParseSpan and reads best in the unit file.
func Span(d time.Duration) string {
	switch {
	case d == 0:
		return "0"
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	default:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	}
}

// ParseSpan parses a systemd time span ("6h", "5min", "90m", "1h30m", "2d",
// "1w") back into a Duration — the read side status uses to compare the
// installed OnUnitActiveSec against the configured interval.
func ParseSpan(s string) (time.Duration, error) {
	s = string(bytes.TrimSpace([]byte(s)))
	if s == "" {
		return 0, errors.New("empty time span")
	}
	var total time.Duration
	numStart := -1
scan:
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] >= '0' && s[i] <= '9' {
			if numStart < 0 {
				numStart = i
			}
			continue
		}
		if numStart < 0 {
			if i == len(s) {
				break scan // trailing characters fully consumed
			}
			return 0, fmt.Errorf("invalid time span %q: expected a number", s)
		}
		if i == len(s) {
			return 0, fmt.Errorf("invalid time span %q: missing unit after %q", s, s[numStart:i])
		}
		n, err := strconv.Atoi(s[numStart:i])
		if err != nil {
			return 0, fmt.Errorf("invalid time span %q: %w", s, err)
		}
		unit, unitLen := spanUnit(s[i:])
		if unit == 0 {
			return 0, fmt.Errorf("invalid time span %q: missing unit after %q", s, s[numStart:i])
		}
		total += time.Duration(n) * unit
		i += unitLen - 1
		numStart = -1
	}
	return total, nil
}

// spanUnit matches a time-span unit prefix (longest match first: min before
// m); returns the unit duration and its length, (0, 0) when no unit matches.
func spanUnit(s string) (time.Duration, int) {
	for _, u := range []struct {
		name string
		d    time.Duration
	}{
		{"min", time.Minute},
		{"us", time.Microsecond},
		{"ms", time.Millisecond},
		{"s", time.Second},
		{"m", time.Minute},
		{"h", time.Hour},
		{"d", 24 * time.Hour},
		{"w", 7 * 24 * time.Hour},
	} {
		if strings.HasPrefix(s, u.name) {
			return u.d, len(u.name)
		}
	}
	return 0, 0
}
