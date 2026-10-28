// Package activate implements the activation step: xray run -test gate
// (L10 — a bad config must never reach the live path), date-stamped backup,
// and an atomic replace. It NEVER restarts the service — the owner does, using
// the printed command (DESIGN.md §4.8).
package activate

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Input bundles the activation dependencies.
type Input struct {
	RenderedPath string
	TargetPath   string
	XrayBin      string
	AssetDir     string // XRAY_LOCATION_ASSET for -test (geosite/geoip resolution)
	BackupDir    string // when Backup is set, date-stamped copies land here
	Backup       bool
	NoRestart    bool // documentation-only; this package never restarts regardless
}

// Result reports what happened.
type Result struct {
	TestPassed  bool
	Replaced    bool
	BackupPath  string
	RestartHint string
}

// Run executes -test → (optional) backup → atomic replace.
func Run(in Input) (Result, error) {
	res := Result{}

	// 1. -test gate on the rendered file (never the live one).
	if err := xrayTest(in); err != nil {
		return res, fmt.Errorf("-test gate failed; live config untouched: %w", err)
	}
	res.TestPassed = true

	// 2. Date-stamped backup of the CURRENT target.
	if in.Backup {
		bp, err := backupTarget(in.TargetPath, in.BackupDir)
		if err != nil {
			return res, fmt.Errorf("backup before replace: %w", err)
		}
		res.BackupPath = bp
	}

	// 3. Atomic replace: write to a temp file in the target directory, copy
	// the original mode, fsync, rename over the target.
	if err := atomicReplace(in.RenderedPath, in.TargetPath); err != nil {
		return res, fmt.Errorf("atomic replace: %w", err)
	}
	res.Replaced = true
	res.RestartHint = fmt.Sprintf(
		"activation complete: %s replaced from %s — restart manually when ready:\n	systemctl --user restart xray-raw.service",
		in.TargetPath, in.RenderedPath)
	return res, nil
}

func xrayTest(in Input) error {
	//nolint:gosec // the binary and config path come from the owner's config.toml — the config file IS the trust root
	cmd := exec.CommandContext(context.Background(), in.XrayBin, "run", "-test", "-c", in.RenderedPath)
	if in.AssetDir != "" {
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+in.AssetDir)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("xray run -test -c %s: %w\n%s", in.RenderedPath, err, stderr.String())
	}
	return nil
}

func backupTarget(target, backupDir string) (string, error) {
	if err := os.MkdirAll(backupDir, 0o750); err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	dst := filepath.Join(backupDir, filepath.Base(target)+".bak-"+stamp)
	data, err := os.ReadFile(target)
	if err != nil {
		return "", err
	}
	return dst, os.WriteFile(dst, data, 0o600) //nolint:gosec // backup path derived from owner config
}

// atomicReplace copies the rendered file into the target's directory under a
// temp name (same filesystem → rename is atomic), preserves the original
// mode, and renames over the target. Paths come from the owner's config.
func atomicReplace(src, dst string) error {
	dir := filepath.Dir(dst)
	mode := os.FileMode(0o644)
	if st, err := os.Stat(dst); err == nil {
		mode = st.Mode().Perm()
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, dst)
}
