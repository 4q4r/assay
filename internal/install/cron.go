// cron.go carries the cron fallback installer (plan §3.2, Stage S3): a
// marked `@reboot` line in the user crontab, added/removed idempotently via
// the spool round-trip `crontab -l` → filter → `crontab -` (an empty result
// → `crontab -r`). The marker comment `# assay-watch` is the idempotency
// key. Honest posture (§3.2): no supervision — no crash restart; @reboot
// fires when cron starts (boot), not at login; on systemd distros waves then
// survive logout (semantics differ from a user unit — documented, never
// hidden).
//
// The executor surface is exactly three shapes: `crontab -l` (read),
// `crontab -` (replace the spool from stdin), `crontab -r` (remove when the
// filtered spool is empty). Foreign lines are preserved verbatim; a % in any
// embedded path would mean "newline" in a crontab command and is refused.

package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CronMarker is the idempotency marker ending every assay-watch line.
const CronMarker = "# assay-watch"

// ---------------------------------------------------------------------------
// CronExecutor — the injected crontab seam with its byte-pinned allowlist
// ---------------------------------------------------------------------------

// CronExecutor is the injected `crontab` seam: args are exactly one of the
// three pinned shapes and stdin carries the replacement spool for `-`.
type CronExecutor interface {
	Crontab(args []string, stdin string) (string, error)
}

// validateCrontab refuses everything outside the three pinned shapes:
// `crontab -l` (read), `crontab -` (write, stdin required), `crontab -r`
// (remove, stdin must be empty). The stdin rules close the two destructive
// caller bugs: an empty write would wipe the spool; content with -r is a
// logic error.
func validateCrontab(args []string, stdin string) error {
	switch {
	case equalArgs(args, []string{"-l"}):
		if stdin != "" {
			return fmt.Errorf("install: crontab invocation %v is outside the allowlist "+
				"(crontab -l carries no stdin) — refusing", args)
		}
		return nil
	case equalArgs(args, []string{"-"}):
		if stdin == "" {
			return fmt.Errorf("install: crontab invocation %v is outside the allowlist "+
				"(an empty crontab - write would wipe the spool — the write path always "+
				"carries content) — refusing", args)
		}
		return nil
	case equalArgs(args, []string{"-r"}):
		if stdin != "" {
			return fmt.Errorf("install: crontab invocation %v is outside the allowlist "+
				"(crontab -r carries no stdin — a non-empty stdin is a caller bug) — refusing", args)
		}
		return nil
	default:
		return fmt.Errorf("install: crontab invocation %v is outside the allowlist "+
			"(permitted: exactly `crontab -l`, `crontab -` (with content), `crontab -r`) — refusing", args)
	}
}

// CronExecutorImpl is the production CronExecutor: allowlist-checked
// crontab invocations.
type CronExecutorImpl struct{}

// Crontab validates args + stdin against the allowlist and executes crontab,
// feeding stdin for the `-` write shape.
func (CronExecutorImpl) Crontab(args []string, stdin string) (string, error) {
	if err := validateCrontab(args, stdin); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// args are allowlist-checked above; the binary name is the constant
	// "crontab" — G204's variable-args warning is the seam's entire purpose.
	cmd := exec.CommandContext(ctx, "crontab", args...) //nolint:gosec // allowlist-validated, see validateCrontab
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("crontab %v failed: %w\n%s\n"+
			"(run by hand: crontab -e to inspect the user spool)", args, err, out)
	}
	return string(out), nil
}

// cronUsable is the §3.1.5 detection probe: crontab usable = `crontab -l`
// exits 0, OR fails with the "no crontab for user" family (the spool is
// simply absent — crontab itself works). Anything else (binary missing,
// permission denial) is unusable.
func cronUsable(exec CronExecutor) error {
	_, err := exec.Crontab([]string{"-l"}, "")
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "no crontab for") {
		return nil
	}
	return fmt.Errorf("crontab is not usable: %w", err)
}

// ---------------------------------------------------------------------------
// CronScheduler
// ---------------------------------------------------------------------------

// CronScheduler installs/uninstalls/inspects the marked @reboot line through
// the injected CronExecutor.
type CronScheduler struct {
	exec CronExecutor

	verifyInterval time.Duration
	verifyAttempts int
}

// NewCronScheduler wires the scheduler over exec.
func NewCronScheduler(exec CronExecutor) *CronScheduler {
	return &CronScheduler{
		exec:           exec,
		verifyInterval: schedulerVerifyInterval,
		verifyAttempts: schedulerVerifyAttempts,
	}
}

// Name implements the Scheduler seam.
func (s *CronScheduler) Name() string { return SchedulerCron }

// Available reports the detection inputs.
func (s *CronScheduler) Available() (bool, string) {
	if s.exec == nil {
		return false, "no crontab executor wired"
	}
	return true, ""
}

// cronLineData builds the @reboot line with the crontab-hostile path refusal
// (% = newline in crontab commands; quotes would break the sh the line runs
// under; newlines split entries).
func cronLineData(binaryPath, configPath, dataDir string) (string, error) {
	for field, p := range map[string]string{
		"BinaryPath": binaryPath,
		"DataDir":    dataDir,
	} {
		if strings.ContainsAny(p, "\"$`%\n") {
			return "", fmt.Errorf("install: %s %q contains a crontab-hostile character "+
				"(\", $, backtick, %%, or newline — %% means newline inside a crontab command, "+
				"and $ and backtick expand in the sh the line runs under); "+
				"choose a path without these characters", field, p)
		}
	}
	args := "watch"
	if configPath != "" {
		if strings.ContainsAny(configPath, "\"$`%\n") {
			return "", fmt.Errorf("install: ConfigPath %q contains a crontab-hostile character "+
				"(\", $, backtick, %%, or newline — %% means newline inside a crontab command, "+
				"and $ and backtick expand in the sh the line runs under); "+
				"choose a path without these characters", configPath)
		}
		args = `watch -c "` + configPath + `"`
	}
	return `@reboot "` + binaryPath + `" ` + args +
		` >> "` + dataDir + `/logs/watch.out.log" 2>&1 ` + CronMarker, nil
}

// cronLine renders the §3.2 line (the golden-test spelling of cronLineData).
func cronLine(binaryPath, configPath, dataDir string) (string, error) {
	return cronLineData(binaryPath, configPath, dataDir)
}

// readSpool returns the current user crontab ("" when absent — the
// "no crontab for user" error is an EMPTY spool, not a failure).
func (s *CronScheduler) readSpool() (string, error) {
	out, err := s.exec.Crontab([]string{"-l"}, "")
	if err != nil {
		if strings.Contains(err.Error(), "no crontab for") {
			return "", nil
		}
		return "", err
	}
	return out, nil
}

// writeSpool replaces the spool from stdin (the pinned `crontab -` shape).
func (s *CronScheduler) writeSpool(content string) error {
	if _, err := s.exec.Crontab([]string{"-"}, content); err != nil {
		return fmt.Errorf("install: crontab - failed: %w", err)
	}
	return nil
}

// filterMarker removes every marked line (idempotency: re-install replaces
// the old line; uninstall drops it entirely).
func filterMarker(spool string) (string, bool) {
	var kept []string
	found := false
	for line := range strings.SplitSeq(spool, "\n") {
		if strings.Contains(line, CronMarker) {
			found = true
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n"), found
}

// Install runs the §3.2 flow: copyBinary → config materialize → read the
// spool → drop any previous assay-watch line → append the new @reboot line →
// write via `crontab -` → bounded read-back verify.
func (s *CronScheduler) Install(spec SchedulerInstallSpec) (Result, error) {
	res := Result{}
	if s.exec == nil {
		return res, errors.New("install: no crontab executor wired (cron)")
	}
	binPath, err := copyBinary(spec.RunningBinary, spec.BinDir)
	if err != nil {
		return res, err
	}
	res.BinaryPath = binPath
	if err := materializeForSpec(spec, &res); err != nil {
		return res, err
	}
	dir := spec.DataDir
	if err := ensureLogsDir(dir); err != nil {
		return res, err
	}
	line, err := cronLineData(binPath, spec.ConfigPath, dir)
	if err != nil {
		return res, err
	}
	spool, err := s.readSpool()
	if err != nil {
		return res, fmt.Errorf("install: reading the user crontab failed: %w", err)
	}
	filtered, _ := filterMarker(spool)
	var sb strings.Builder
	sb.WriteString(strings.TrimSuffix(filtered, "\n"))
	if sb.Len() > 0 {
		sb.WriteString("\n")
	}
	sb.WriteString(line)
	sb.WriteString("\n")
	if err := s.writeSpool(sb.String()); err != nil {
		return res, err
	}
	// §3.3 bounded verify: read back until the marker is present.
	for range s.verifyAttempts {
		back, rerr := s.readSpool()
		if rerr == nil && strings.Contains(back, CronMarker) {
			res.ServiceActive = true
			res.UnitPaths = []string{"user crontab (@reboot assay-watch entry)"}
			return res, nil
		}
		time.Sleep(s.verifyInterval)
	}
	return res, loudProbeFailure(SchedulerCron, "crontab -l", "crontab -e", s.verifyAttempts,
		errors.New("the marked @reboot line never appeared in the spool"))
}

// Uninstall filters the marked line (§3.2): remaining lines are written
// back; an EMPTY result removes the spool entirely via `crontab -r`.
func (s *CronScheduler) Uninstall(spec SchedulerUninstallSpec) (UninstallResult, error) {
	res := UninstallResult{}
	spool, err := s.readSpool()
	if err != nil {
		// No spool at all (binary missing / unreadable): nothing to remove.
		return s.finishUninstall(spec, res)
	}
	filtered, found := filterMarker(spool)
	if !found {
		return s.finishUninstall(spec, res)
	}
	trimmed := strings.TrimSuffix(filtered, "\n")
	if strings.TrimSpace(trimmed) == "" {
		// §3.2: empty result → crontab -r (never write an empty spool).
		if _, rerr := s.exec.Crontab([]string{"-r"}, ""); rerr != nil {
			return res, fmt.Errorf("uninstall: crontab -r failed: %w\n"+
				"(run by hand: crontab -r)", rerr)
		}
		res.RemovedUnits = []string{"crontab (@reboot assay-watch)"}
		return s.finishUninstall(spec, res)
	}
	if _, werr := s.exec.Crontab([]string{"-"}, trimmed+"\n"); werr != nil {
		return res, fmt.Errorf("uninstall: crontab - failed: %w", werr)
	}
	res.RemovedUnits = []string{"crontab (@reboot assay-watch)"}
	return s.finishUninstall(spec, res)
}

// finishUninstall is the shared tail: managed-core teardown + purge.
func (s *CronScheduler) finishUninstall(spec SchedulerUninstallSpec, res UninstallResult) (UninstallResult, error) {
	coreRemoved, err := removeManagedCore(spec.DataDir)
	if err != nil {
		return res, err
	}
	res.CoreRemoved = coreRemoved
	for _, purge := range []string{spec.PurgeConfigPath, spec.PurgeDataDir} {
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

// Status reports the registration with the HONEST no-supervision posture
// (§3.2 — stated, never hidden).
func (s *CronScheduler) Status() (SchedulerStatus, error) {
	held, where := s.HeldRegistration()
	if !held {
		return SchedulerStatus{
			Active: false,
			Note:   "no @reboot assay-watch line in the user crontab (run `assay install`)",
		}, nil
	}
	return SchedulerStatus{
		Active: true,
		PID:    0,
		Note: "registered (" + where + ") — no supervision: no crash restart; " +
			"`assay watch` runs until it exits; @reboot fires when cron starts (boot), not at login",
	}, nil
}

// HeldRegistration reports the marker line's presence in the user crontab.
func (s *CronScheduler) HeldRegistration() (bool, string) {
	if s.exec == nil {
		return false, ""
	}
	spool, err := s.readSpool()
	if err != nil {
		return false, ""
	}
	if _, found := filterMarker(spool); found {
		return true, "user crontab (@reboot assay-watch)"
	}
	return false, ""
}

// crontabHoldsMarker is the scan-level helper HeldByAny uses.
func crontabHoldsMarker(exec CronExecutor) bool {
	s := NewCronScheduler(exec)
	held, _ := s.HeldRegistration()
	return held
}
