// Package activate implements the activation step: xray run -test gate
// (L10 — a bad config must never reach the live path), date-stamped backup,
// and an atomic replace. It NEVER restarts the service — the owner does, using
// the printed command (DESIGN.md §4.8).
package activate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/store"
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
	// TestTimeout bounds the `xray run -test` child ([activate].test_timeout).
	// >0 = context.WithTimeout; 0 = NO deadline (current behavior).
	// The config layer resolves nil → DefaultTestTimeout.
	TestTimeout time.Duration
	// ServiceName is the unit named in the printed restart hint
	// ([activate].service_name); zero falls back to config.DefaultServiceName.
	ServiceName string
	// BackupKeep caps backup retention after a successful new backup write
	// ([activate].backup_keep): only the N newest .bak-<ts> files remain.
	// 0 = unlimited. Deletion failures are loud and abort BEFORE the live
	// target is replaced.
	BackupKeep int
}

// Result reports what happened.
type Result struct {
	TestPassed  bool
	Replaced    bool
	BackupPath  string
	RestartHint string
}

// Run executes -test → (optional) backup → retention → atomic replace.
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
		if err := store.KeepNewestBackups(in.BackupDir, filepath.Base(in.TargetPath), in.BackupKeep); err != nil {
			return res, fmt.Errorf("backup retention (backup_keep=%d): %w", in.BackupKeep, err)
		}
	}

	// 3. Atomic replace: write to a temp file in the target directory, copy
	// the original mode, fsync, rename over the target.
	if err := atomicReplace(in.RenderedPath, in.TargetPath); err != nil {
		return res, fmt.Errorf("atomic replace: %w", err)
	}
	res.Replaced = true
	service := in.ServiceName
	if service == "" {
		service = config.DefaultServiceName
	}
	res.RestartHint = fmt.Sprintf(
		"activation complete: %s replaced from %s — restart manually when ready:\n	systemctl --user restart %s",
		in.TargetPath, in.RenderedPath, service)
	return res, nil
}

func xrayTest(in Input) error {
	ctx := context.Background()
	if in.TestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, in.TestTimeout)
		defer cancel()
	}
	//nolint:gosec // the binary and config path come from the owner's config.toml — the config file IS the trust root
	cmd := exec.CommandContext(ctx, in.XrayBin, "run", "-test", "-c", in.RenderedPath)
	if in.TestTimeout > 0 {
		// A killed gate binary can leave its stdio pipes held open by
		// grandchildren; without a WaitDelay, Wait would block past the
		// deadline until they close. The WaitDelay equals the deadline, so
		// the gate can never exceed 2× the configured budget.
		//
		// Scope note (M-3): WaitDelay releases the PARENT, it does not kill
		// grandchildren — there is no Setpgid/process-group kill, so an
		// orphan holding the pipes can outlive the gate. That is acceptable
		// here BY DESIGN: `xray run -test` is a single-process validate-and-
		// exit invocation that spawns no descendants of its own, so the
		// scenario needs an abnormal child to begin with; the worst case is
		// a short-lived orphan that cannot affect the gate's verdict.
		cmd.WaitDelay = in.TestTimeout
	}
	if in.AssetDir != "" {
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+in.AssetDir)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Run(); err != nil {
		// M-2 discrimination: an *exec.ExitError from the child's OWN exit
		// (Exited() == true) is a real config failure even when the deadline
		// fired in the same instant — report the exit status, never the
		// "timed out" label. Only a kill (signaled, Exited() == false) or a
		// non-exit error under an already-elapsed deadline is the timeout arm.
		var exitErr *exec.ExitError
		ownExit := errors.As(err, &exitErr) && exitErr.Exited()
		if in.TestTimeout > 0 && ctx.Err() != nil && !ownExit {
			return fmt.Errorf("xray run -test -c %s: timed out after %s\n%s", in.RenderedPath, in.TestTimeout, stderr.String())
		}
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
