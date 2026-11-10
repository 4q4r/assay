// Package install implements `assay install` / `uninstall`: self-install
// of the running binary plus the rendered systemd user unit (the W10 watch
// daemon, Restart=always), with the systemctl surface pinned to an exact
// allowlist. The unit is rendered from the repo's systemd/ template (single
// source of truth, go:embed). Scheduling lives in the daemon — there are no
// timers anymore; install additionally cleans up the W5 timer units left by
// older installs.
package install

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"text/template"
	"time"

	units "assay/systemd"
)

// defaultConfigTemplate is the embedded default-config TOML (single source
// of truth, go:embed): the values a configless run uses, written as TOML
// with full comments. `assay install` without -c materializes it at the
// canonical local-share path — the same file every command then resolves
// first (one file wins whole, nothing is ever merged).
//
//go:embed defaults_config.toml
var defaultConfigFS embed.FS

// installedBinaryName is the fixed executable name in BinDir.
const installedBinaryName = "assay"

// WatchService is the W10 daemon unit installed into the user unit
// directory.
const WatchService = "assay-watch.service"

// Legacy unit names from the W5 timer era: never installed again, but
// uninstall removes them and install cleans them up (existing users get the
// migration for free — stale timers would fire waves concurrently with the
// daemon and stampede the probe origin).
const (
	RefreshService   = "assay-refresh.service"
	RefreshTimer     = "assay-refresh.timer"
	SpeedtestService = "assay-speedtest.service"
	SpeedtestTimer   = "assay-speedtest.timer"
)

// UnitNames lists the unit files CURRENT install renders.
func UnitNames() []string {
	return []string{WatchService}
}

// LegacyUnitNames lists the W5-era timer units older installs may still
// carry; both install and uninstall clean them up.
func LegacyUnitNames() []string {
	return []string{RefreshService, RefreshTimer, SpeedtestService, SpeedtestTimer}
}

// AllKnownUnitNames is legacy ∪ current — the uninstall removal set.
func AllKnownUnitNames() []string {
	return append(LegacyUnitNames(), WatchService)
}

// TemplateData is rendered into the systemd unit template.
type TemplateData struct {
	BinaryPath string
	// ConfigPath embeds into ExecStart as `-c <path>`. EMPTY = the daemon
	// runs plain `watch` and reads the default config location (the
	// W13-deploy canonical user flow — the local-share config).
	ConfigPath string
}

// defaultConfigData is rendered into the embedded default-config TOML.
type defaultConfigData struct {
	DataDir string
}

// Options configures Install. Paths must be absolute (the CLI layer expands
// ~); the daemon reads intervals and the plugins dir from the config at
// runtime — no period rendering happens anymore.
type Options struct {
	BinDir        string
	UnitDir       string
	RunningBinary string // os.Executable() of the caller
	// ConfigPath is embedded into the unit's ExecStart (-c <path>). REQUIRED
	// for the explicit-config install. EMPTY = default-location install:
	// DefaultConfigPath drives materialization and the unit runs plain
	// `watch` (the daemon reads the default location).
	ConfigPath string
	// DefaultConfigPath is the canonical local-share config path to
	// materialize when absent (never overwritten; present = kept). Required
	// when ConfigPath is empty; ignored otherwise.
	DefaultConfigPath string
	// DataDir is rendered into the materialized default config (the
	// configless data dir — the local-share default).
	DataDir   string
	NoSystemd bool
	Exec      Executor // required unless NoSystemd
}

// Result reports what install did.
type Result struct {
	BinaryPath    string
	UnitPaths     []string
	LegacyCleaned []string // legacy timer units disabled + removed by this install
	ServiceActive bool
	SkippedUnits  bool // --no-systemd: binary copy only, units skipped
	// ConfigWritten is the default-config path materialized by this install
	// ("" = explicit -c install or the file already existed).
	ConfigWritten string
	// ConfigKept is the default-config path found ALREADY PRESENT (never
	// overwritten — the owner's edits win); "" when not applicable.
	ConfigKept string
}

// Install copies the running binary into BinDir (atomic, 0755 — self-upgrade
// is a re-run), materializes the default config at DefaultConfigPath when no
// explicit -c is given (never overwriting an existing file), renders the
// daemon unit from the repo template (with -c for an explicit config, plain
// `watch` for the default-location install), cleans up the legacy W5 timer
// units when present, and then — only then — daemon-reloads and enables the
// daemon through the injected Executor.
func Install(o Options) (Result, error) {
	if o.BinDir == "" || o.RunningBinary == "" {
		return Result{}, errors.New("install: BinDir and RunningBinary are required")
	}
	binPath, err := copyBinary(o.RunningBinary, o.BinDir)
	if err != nil {
		return Result{}, err
	}
	res := Result{BinaryPath: binPath}
	if err := materializeDefault(o, &res); err != nil {
		return res, err
	}
	// ConfigPath == "" with NO materialization target is still a valid
	// default-location install (the daemon reads the default location — the
	// canonical config may already be in place from an earlier install).
	if o.NoSystemd {
		res.SkippedUnits = true
		return res, nil
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
		BinaryPath: binPath,
		ConfigPath: o.ConfigPath,
	}, o.UnitDir)
	if err != nil {
		return res, err
	}
	res.UnitPaths = unitPaths
	// One-time migration: disable + remove the W5 timer units so waves fire
	// from exactly ONE scheduler (the daemon). Nothing to do when absent.
	res.LegacyCleaned, err = cleanupLegacyUnits(o.UnitDir, o.Exec)
	if err != nil {
		return res, err
	}
	if err := o.Exec.Systemctl(cmdDaemonReload()...); err != nil {
		return res, fmt.Errorf("unit written but not enabled: %w", err)
	}
	if err := o.Exec.Systemctl(cmdEnableWatch()...); err != nil {
		return res, fmt.Errorf("unit written and reloaded but not enabled: %w", err)
	}
	res.ServiceActive = true
	return res, nil
}

// MaterializeDefaultConfig writes the embedded default-config TOML (the
// values a configless run uses, fully commented) at path with the given
// data_dir. An EXISTING file is never touched — (false, nil), the caller
// reports "kept". Creation is atomic (temp file in the same directory →
// fsync → rename), mode 0600: the schema carries optional token knobs.
func MaterializeDefaultConfig(path, dataDir string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	}
	tmpl, err := template.ParseFS(defaultConfigFS, "defaults_config.toml")
	if err != nil {
		return false, fmt.Errorf("install: parse embedded default-config template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "defaults_config.toml", defaultConfigData{DataDir: dataDir}); err != nil {
		return false, fmt.Errorf("install: render default config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, fmt.Errorf("install: create config dir %s: %w", filepath.Dir(path), err)
	}
	if err := writeFileAtomic(path, buf.Bytes(), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// materializeDefault applies the default-location materialization: an
// explicit-config install does nothing; a default-location install with a
// target materializes the embedded default config there (present = kept,
// never overwritten) and records the outcome on the Result.
func materializeDefault(o Options, res *Result) error {
	if o.ConfigPath != "" || o.DefaultConfigPath == "" {
		return nil
	}
	created, err := MaterializeDefaultConfig(o.DefaultConfigPath, o.DataDir)
	if err != nil {
		return err
	}
	if created {
		res.ConfigWritten = o.DefaultConfigPath
	} else {
		res.ConfigKept = o.DefaultConfigPath
	}
	return nil
}

// cleanupLegacyUnits disables the legacy timers (only when their unit files
// still exist) and removes all four files. Returns the names actually
// removed.
func cleanupLegacyUnits(unitDir string, exec Executor) ([]string, error) {
	present := legacyUnitsPresent(unitDir)
	if len(present) == 0 {
		return nil, nil
	}
	if err := exec.Systemctl(cmdDisableLegacyTimers()...); err != nil {
		return nil, fmt.Errorf("install: disabling the legacy timer units failed: %w", err)
	}
	var removed []string
	for _, name := range present {
		if err := os.Remove(filepath.Join(unitDir, name)); err != nil {
			return removed, fmt.Errorf("install: remove legacy unit %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	return removed, nil
}

// legacyUnitsPresent returns the legacy unit names whose files exist.
func legacyUnitsPresent(unitDir string) []string {
	var present []string
	for _, name := range LegacyUnitNames() {
		if _, err := os.Stat(filepath.Join(unitDir, name)); err == nil {
			present = append(present, name)
		}
	}
	return present
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
	DisabledUnits  []string // service/timers actually disabled (present on disk)
	RemovedUnits   []string
	MissingUnits   []string
	Purged         []string
	SkippedDisable bool // no user systemd session — nothing to disable
}

// Uninstall stops the daemon and legacy timers (each only when its unit
// file still exists), removes every known unit file (current + legacy),
// daemon-reloads so the user manager drops its not-found entries (I-2), and
// reports. --purge additionally removes the config file and data dir;
// anything else on the system (the installed binary included) is left
// untouched.
func Uninstall(o UninstallOptions) (UninstallResult, error) {
	res := UninstallResult{}
	if o.UnitDir == "" {
		return res, errors.New("uninstall: UnitDir is required")
	}
	talksToManager := o.Exec != nil && UserSystemdAvailable() == nil
	if talksToManager {
		var disableErr error
		res.DisabledUnits, disableErr = disablePresentUnits(o.UnitDir, o.Exec)
		if disableErr != nil {
			return res, disableErr
		}
		if len(res.DisabledUnits) == 0 {
			res.SkippedDisable = true
		}
	} else {
		res.SkippedDisable = true
	}
	for _, name := range AllKnownUnitNames() {
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
	if talksToManager && len(res.RemovedUnits) > 0 {
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

// disablePresentUnits disables the watch service and the legacy timers —
// each allowlisted disable command runs only when at least one of its units
// is still on disk (disabling a missing unit errors). Returns the unit
// names that were disabled.
func disablePresentUnits(unitDir string, exec Executor) ([]string, error) {
	var disabled []string
	if _, err := os.Stat(filepath.Join(unitDir, WatchService)); err == nil {
		if err := exec.Systemctl(cmdDisableWatch()...); err != nil {
			return disabled, fmt.Errorf("uninstall: disabling %s failed: %w", WatchService, err)
		}
		disabled = append(disabled, WatchService)
	}
	if len(legacyUnitsPresent(unitDir)) > 0 {
		if err := exec.Systemctl(cmdDisableLegacyTimers()...); err != nil {
			return disabled, fmt.Errorf("uninstall: disabling the legacy timers failed: %w", err)
		}
		disabled = append(disabled, LegacyUnitNames()...)
	}
	return disabled, nil
}

// copyBinary atomically copies src into dir as `assay` (temp file in the
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
	tmp, err := os.CreateTemp(dir, ".assay-*")
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

// writeUnits renders the embedded template and writes it into unitDir
// (created 0750, files 0644, atomic replace — idempotent re-install).
func writeUnits(data TemplateData, unitDir string) ([]string, error) {
	tmpl, err := template.ParseFS(units.Units, "assay-*.service")
	if err != nil {
		return nil, fmt.Errorf("install: parse embedded unit template: %w", err)
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

// Span renders d as a systemd time span (kept for status/ops display of
// config intervals).
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
