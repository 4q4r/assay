// Package xrayupdate implements `publicvpn xray-update` (W14): fetch the
// latest Xray-core release for this platform, VERIFY its published sha256
// (every release asset ships a .dgst companion), unpack, validate the NEW
// binary with `xray run -test`, and atomically replace the configured
// [activate].xray_bin target with a date-stamped backup of the old binary.
// A root-owned (unwritable) target is never half-applied: the command
// stages everything and prints the EXACT privileged commands for the owner.
package xrayupdate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Platform names for the release asset map (goconst: repeated literals).
const (
	platLinux   = "linux"
	platDarwin  = "darwin"
	platWindows = "windows"
	platFreebsd = "freebsd"
	// maxAssetBytes caps one zip entry at extraction (G110: a malicious
	// release archive must not decompress unbounded into the staging dir).
	maxAssetBytes = 512 << 20
)

// Release coordinates: the XTLS/Xray-core GitHub releases. The version is
// NEVER hardcoded — releases/latest resolves dynamically.
const (
	repoSlug        = "XTLS/Xray-core"
	defaultAPIBase  = "https://api.github.com"
	timeoutAPI      = 30 * time.Second
	timeoutDownload = 5 * time.Minute
	timeoutTest     = 30 * time.Second
)

// ErrPrivilegedTarget marks the unwritable-target outcome: the update is
// fully staged, nothing was applied, and Result.PrivilegedCommands carries
// the exact lines for the owner.
var ErrPrivilegedTarget = errors.New(
	"target directory is not writable (root-owned) — the new binary is STAGED, " +
		"the old binary is untouched; run the commands below to apply")

// ErrYesRequired marks the non-interactive refusal: without --yes a piped
// invocation must not guess the owner's intent.
var ErrYesRequired = errors.New(
	"refusing non-interactive update without --yes (pipe a y/n answer, or pass --yes)")

// Options configures one xray-update run.
type Options struct {
	CheckOnly   bool   // --check: report latest vs current, touch nothing
	BinOverride string // --bin: target path override ([activate].xray_bin otherwise)
	TargetPath  string // resolved [activate].xray_bin (expanded; CLI's concern)
	AssumeYes   bool   // --yes: skip the confirmation prompt
	// APIBase overrides the GitHub API host (test seam; empty = default).
	APIBase string
	// StagingDir is where the release is downloaded, verified, and unpacked
	// (CLI passes <data_dir>/xray-staged — survives across runs for the
	// privileged-apply path).
	StagingDir string
	// Stdin/Stdout/Stderr carry the interaction (tests inject buffers).
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Now is the clock seam (tests inject; nil = time.Now().UTC()).
	Now func() time.Time
	// TestFailsEnv is appended to the staged binary's -test environment —
	// a test seam; nil in production.
	TestFailsEnv []string
}

// Result reports what the run did (or would do).
type Result struct {
	LatestVersion  string // release tag verbatim (v26.10.21)
	CurrentVersion string // parsed `xray version`; "" = not installed
	Updated        bool   // the target binary was replaced
	BackupPath     string // date-stamped backup of the OLD binary
	StagedBinary   string // the verified, -test-passed staged binary
	// PrivilegedCommands is set ONLY on ErrPrivilegedTarget: the exact lines
	// (backup + install) the owner runs to apply the staged binary.
	PrivilegedCommands []string
}

// release is the slice of the GitHub releases/latest payload this command
// consumes.
type release struct {
	TagName string  `json:"tag_name"`
	Assets  []asset `json:"assets"`
}

type asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// Run executes the whole xray-update flow.
func Run(opts Options) (*Result, error) {
	if opts.TargetPath == "" && opts.BinOverride != "" {
		opts.TargetPath = opts.BinOverride
	}
	if opts.TargetPath == "" {
		return nil, errors.New("no target binary path (--bin or [activate].xray_bin)")
	}
	if opts.StagingDir == "" {
		return nil, errors.New("no staging directory configured")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	res := &Result{}
	current, err := currentVersion(opts.TargetPath)
	if err != nil {
		return nil, err
	}
	res.CurrentVersion = current

	rel, err := fetchRelease(opts.APIBase)
	if err != nil {
		return nil, err
	}
	res.LatestVersion = rel.TagName

	if opts.CheckOnly {
		printCheck(opts.Stdout, res)
		return res, nil
	}
	if sameVersion(current, rel.TagName) {
		_, _ = fmt.Fprintf(opts.Stdout, "xray-update: already at %s — nothing to do\n", rel.TagName)
		return res, nil
	}

	// Confirmation gates the WHOLE run (download included): the owner reads
	// the version pair first. A piped invocation without input refuses —
	// --yes is the explicit non-interactive path.
	switch proceed, err := confirm(opts, current, rel.TagName); {
	case err != nil:
		return res, err
	case !proceed:
		_, _ = fmt.Fprintf(opts.Stdout, "xray-update: declined — nothing touched\n")
		return res, nil
	}

	staged, err := stageRelease(opts, rel)
	if err != nil {
		return nil, err
	}
	res.StagedBinary = staged
	if err := applyStaged(opts, res); err != nil {
		return res, err
	}
	res.Updated = true
	_, _ = fmt.Fprintf(opts.Stdout, "xray-update: %s → %s installed at %s (old binary backed up at %s)\n",
		displayVersion(current), rel.TagName, opts.TargetPath, res.BackupPath)
	return res, nil
}

// confirm reads the owner's answer for the version pair. y/yes proceeds;
// n/no declines (a clean no-op); no input at all (EOF — the piped case)
// demands --yes instead of guessing.
func confirm(opts Options, current, tag string) (bool, error) {
	if opts.AssumeYes {
		return true, nil
	}
	if opts.Stdin == nil {
		return false, ErrYesRequired
	}
	_, _ = fmt.Fprintf(opts.Stdout, "xray-update: update %s → %s at %s? [y/N] ",
		displayVersion(current), tag, opts.TargetPath)
	answer, err := readAnswer(opts.Stdin)
	if err != nil {
		return false, ErrYesRequired // EOF/empty: the piped case
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// readAnswer reads ONE line without assuming a terminal; an empty read is
// an EOF (piped stdin), reported as an error so the caller demands --yes.
func readAnswer(r io.Reader) (string, error) {
	buf := make([]byte, 0, 16)
	small := make([]byte, 1)
	for {
		n, err := r.Read(small)
		if n > 0 {
			if small[0] == '\n' {
				return string(buf), nil
			}
			buf = append(buf, small[0])
			if len(buf) > 64 {
				return string(buf), nil
			}
		}
		if err != nil {
			if len(buf) > 0 {
				return string(buf), nil
			}
			return "", err // EOF with no input
		}
	}
}

// currentVersion runs `<bin> version` and parses the banner; a missing
// binary is a valid fresh-install state ("" version), not an error.
func currentVersion(bin string) (string, error) {
	if _, err := os.Stat(bin); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The binary path comes from the owner's config — the config IS the trust root.
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return "", fmt.Errorf("read current version (%s version): %w", bin, err)
	}
	return parseVersionBanner(string(out)), nil
}

// parseVersionBanner extracts "26.3.27" from the `xray version` first line
// ("Xray 26.3.27 (Xray, Penetrates Everything.) ...").
func parseVersionBanner(out string) string {
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && strings.EqualFold(fields[0], "xray") {
			return strings.TrimPrefix(fields[1], "v")
		}
	}
	return ""
}

func displayVersion(v string) string {
	if v == "" {
		return "(not installed)"
	}
	return "v" + v
}

func sameVersion(current, tag string) bool {
	return current != "" && strings.TrimPrefix(tag, "v") == current
}

func printCheck(w io.Writer, res *Result) {
	switch {
	case res.CurrentVersion == "":
		_, _ = fmt.Fprintf(w, "xray-update: latest %s, current (not installed)\n", res.LatestVersion)
	case sameVersion(res.CurrentVersion, res.LatestVersion):
		_, _ = fmt.Fprintf(w, "xray-update: latest %s, current v%s — up to date\n",
			res.LatestVersion, res.CurrentVersion)
	default:
		_, _ = fmt.Fprintf(w, "xray-update: latest %s, current v%s — update available (run without --check)\n",
			res.LatestVersion, res.CurrentVersion)
	}
}

// fetchRelease resolves the latest release + its asset list from the GitHub
// API. The client's Proxy is nil by L5 discipline: a binary download must
// never silently ride the owner's live VPN.
func fetchRelease(apiBase string) (*release, error) {
	if apiBase == "" {
		apiBase = defaultAPIBase
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeoutAPI)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		apiBase+"/repos/"+repoSlug+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: timeoutAPI, Transport: &http.Transport{Proxy: nil}} // L5: never the ambient proxy
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s latest release: %w", repoSlug, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("fetch %s latest release: HTTP %d %s",
			repoSlug, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release payload: %w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("release payload carries no tag")
	}
	return &rel, nil
}

// assetForPlatform maps GOOS/GOARCH(/GOARM) onto the release's asset naming
// convention via an explicit table. An unmapped platform yields "" — the
// caller errors loud, never guesses.
func assetForPlatform(goos, arch, arm string) string {
	key := goos + "/" + arch
	if goos == platLinux && arch == "arm" {
		switch arm {
		case "5", "6":
			key = platLinux + "/arm" + arm
		default: // "" or 7: v7a is the release's canonical arm32 build
			key = platLinux + "/arm7"
		}
	}
	return platformAssets[key]
}

// platformAssets is the release asset naming table (verified against the
// live Xray-core release asset list, 2026-10-29).
var platformAssets = map[string]string{
	platLinux + "/amd64":   "Xray-linux-64.zip",
	platLinux + "/386":     "Xray-linux-32.zip",
	platLinux + "/arm64":   "Xray-linux-arm64-v8a.zip",
	platLinux + "/arm5":    "Xray-linux-arm32-v5.zip",
	platLinux + "/arm6":    "Xray-linux-arm32-v6.zip",
	platLinux + "/arm7":    "Xray-linux-arm32-v7a.zip",
	platLinux + "/riscv64": "Xray-linux-riscv64.zip",
	platLinux + "/loong64": "Xray-linux-loong64.zip",
	platLinux + "/ppc64le": "Xray-linux-ppc64le.zip",
	platLinux + "/s390x":   "Xray-linux-s390x.zip",
	platDarwin + "/amd64":  "Xray-macos-64.zip",
	platDarwin + "/arm64":  "Xray-macos-arm64-v8a.zip",
	platWindows + "/amd64": "Xray-windows-64.zip",
	platWindows + "/386":   "Xray-windows-32.zip",
	platWindows + "/arm64": "Xray-windows-arm64-v8a.zip",
	platFreebsd + "/amd64": "Xray-freebsd-64.zip",
	platFreebsd + "/arm64": "Xray-freebsd-arm64-v8a.zip",
}

func findAsset(rel *release, name string) (*asset, error) {
	if name == "" {
		return nil, fmt.Errorf("platform %s/%s (arm %q) has no release asset mapping",
			runtime.GOOS, runtime.GOARCH, os.Getenv("GOARM"))
	}
	for i := range rel.Assets {
		if rel.Assets[i].Name == name {
			return &rel.Assets[i], nil
		}
	}
	return nil, fmt.Errorf("release %s ships no asset %q", rel.TagName, name)
}

// stageRelease downloads the release asset, VERIFIES its sha256 against the
// release's published .dgst companion, unpacks, and validates the staged
// binary with `xray run -test`. Any failure aborts before the target is
// touched.
func stageRelease(opts Options, rel *release) (string, error) {
	assetName := assetForPlatform(runtime.GOOS, runtime.GOARCH, os.Getenv("GOARM"))
	a, err := findAsset(rel, assetName)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(opts.StagingDir, 0o750); err != nil {
		return "", err
	}
	zipPath := filepath.Join(opts.StagingDir, assetName)
	_, _ = fmt.Fprintf(opts.Stdout, "xray-update: downloading %s (%s)…\n", a.Name, rel.TagName)
	if err := download(a.URL, zipPath); err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(zipPath) }() // the zip is scratch; the unpacked binary stays

	want, err := fetchExpectedSha256(a.URL + ".dgst")
	if err != nil {
		return "", err
	}
	got, err := fileSha256(zipPath)
	if err != nil {
		return "", err
	}
	if got != want {
		return "", fmt.Errorf(
			"sha256 verification FAILED for %s (release %s): expected %s (from the "+
				"release's published .dgst), got %s — the download is corrupt or "+
				"tampered; nothing was applied",
			a.Name, rel.TagName, want, got)
	}
	_, _ = fmt.Fprintf(opts.Stdout, "xray-update: sha256 verified (%s…)\n", got[:12])

	binName := "xray"
	if runtime.GOOS == "windows" {
		binName = "xray.exe"
	}
	staged := filepath.Join(opts.StagingDir, binName)
	if err := unzipFlat(zipPath, opts.StagingDir); err != nil {
		return "", err
	}
	if _, err := os.Stat(staged); err != nil {
		return "", fmt.Errorf("release archive carries no %s binary: %w", binName, err)
	}
	//nolint:gosec // G302: an executable BINARY stays 0755
	if err := os.Chmod(staged, 0o755); err != nil {
		return "", err
	}
	if err := runTestGate(staged, opts.TestFailsEnv); err != nil {
		return "", fmt.Errorf("staged binary failed validation (staged at %s): %w", staged, err)
	}
	_, _ = fmt.Fprintf(opts.Stdout, "xray-update: staged binary passed `xray run -test`\n")
	return staged, nil
}

// download streams url into dst (no ambient proxy — L5).
func download(url, dst string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDownload)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: timeoutDownload, Transport: &http.Transport{Proxy: nil}} // L5 // L5
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	return nil
}

// fetchExpectedSha256 parses the release's published checksum companion.
// The .dgst format (verified against live Xray-core releases):
//
//	MD5= …
//	SHA1= …
//	SHA2-256= <hex>
//	SHA2-512= …
func fetchExpectedSha256(url string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeoutAPI)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: timeoutAPI, Transport: &http.Transport{Proxy: nil}} // L5 // L5
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch checksum %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch checksum %s: HTTP %d — verification is MANDATORY, refusing to proceed",
			url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		// Tolerate the observed spellings (SHA2-256= / sha256=).
		lower := strings.ToLower(strings.TrimSpace(line))
		if rest, ok := cutPrefix(lower, "sha2-256="); ok {
			return strings.TrimSpace(rest), nil
		}
		if rest, ok := cutPrefix(lower, "sha256="); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf(
		"checksum file %s carries no SHA2-256 line — verification is MANDATORY, refusing to proceed", url)
}

func cutPrefix(s, prefix string) (string, bool) {
	return strings.CutPrefix(s, prefix)
}

func fileSha256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// unzipFlat extracts every archive entry FLAT into dir: the release layout
// is flat (xray + dat files), and flattening structurally kills zip-slip
// (any entry carrying a path separator is rejected loud).
func unzipFlat(archive, dir string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("open release archive: %w", err)
	}
	defer func() { _ = zr.Close() }()
	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.Name != filepath.Base(entry.Name) {
			return fmt.Errorf("release archive entry %q carries a path — refusing non-flat layout", entry.Name)
		}
		if entry.UncompressedSize64 > maxAssetBytes {
			return fmt.Errorf("release archive entry %q claims %d bytes — refusing (cap %d)",
				entry.Name, entry.UncompressedSize64, maxAssetBytes)
		}
		src, err := entry.Open()
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dir, filepath.Base(entry.Name))
		dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			_ = src.Close()
			return err
		}
		if _, err := io.CopyN(dst, src, int64(maxAssetBytes)); err != nil && !errors.Is(err, io.EOF) {
			_ = src.Close()
			_ = dst.Close()
			return fmt.Errorf("extract %s: %w", entry.Name, err)
		}
		_ = src.Close()
		if err := dst.Close(); err != nil {
			return err
		}
	}
	return nil
}

// runVersionCapture returns the raw stdout of `<bin> version`; the
// post-replace validation needs the banner even when it fails to parse.
func runVersionCapture(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The binary path comes from the owner's config — the config IS the trust root.
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return "", fmt.Errorf("read version (%s version): %w", bin, err)
	}
	return string(out), nil
}

// validateInstalled re-validates the binary AT the target after the atomic
// rename: `version` must parse a banner and `run -test` must accept a
// minimal config with the target's directory as the asset root — the same
// gates staging passed, now proving the INSTALLED artifact (a truncated
// copy or a broken asset root cannot hide behind the staging check).
func validateInstalled(opts Options, target string) error {
	banner, err := runVersionCapture(target)
	if err != nil {
		return fmt.Errorf("post-replace validation: %w", err)
	}
	if parseVersionBanner(banner) == "" {
		// Cap the quoted output: a hostile/odd binary may print anything.
		if len(banner) > 200 {
			banner = banner[:200]
		}
		return fmt.Errorf("post-replace validation: %s version printed no parsable banner (%q)",
			target, strings.TrimSpace(banner))
	}
	if err := runTestGate(target, opts.TestFailsEnv); err != nil {
		return fmt.Errorf("post-replace validation: %w", err)
	}
	return nil
}

// rollbackReplace undoes a failed post-replace validation: the backup is
// renamed back over the target (same directory, atomic), or a fresh
// install is removed outright. The returned error names the rollback
// loudly — and a FAILED rollback fails louder still, pointing at the
// surviving backup.
func rollbackReplace(res *Result, target string, cause error) error {
	if res.BackupPath == "" {
		if rerr := os.Remove(target); rerr != nil {
			return fmt.Errorf("%w; ROLLBACK FAILED (%w) — remove the broken %s manually", cause, rerr, target)
		}
		return fmt.Errorf("%w — ROLLED BACK: the fresh install was removed, %s is not installed", cause, target)
	}
	backup := res.BackupPath
	if rerr := os.Rename(backup, target); rerr != nil {
		return fmt.Errorf("%w; ROLLBACK FAILED (%w) — the previous binary is still at %s, restore it manually",
			cause, rerr, backup)
	}
	res.BackupPath = "" // restored in place; no separate backup file remains
	return fmt.Errorf("%w — ROLLED BACK: the previous binary was restored from the backup over %s", cause, target)
}

// runTestGate runs `xray run -test` on a minimal config against the given
// binary, with the binary's directory as the asset root — the same check
// the activate stage applies to a rendered config. extraEnv carries the
// test seam (opts.TestFailsEnv).
func runTestGate(bin string, extraEnv []string) error {
	cfg := `{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`
	cfgPath := filepath.Join(filepath.Dir(bin), "test-config.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return err
	}
	defer func() { _ = os.Remove(cfgPath) }()

	ctx, cancel := context.WithTimeout(context.Background(), timeoutTest)
	defer cancel()
	//nolint:gosec // binary we just checksum-verified
	cmd := exec.CommandContext(ctx, bin, "run", "-test", "-c", cfgPath)
	cmd.Env = append(dropProxyEnv(os.Environ()),
		"XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("`xray run -test` failed (binary at %s): %w\n%s",
			bin, err, tailBytes(out, 800))
	}
	return nil
}

// applyStaged replaces the target atomically: a date-stamped backup of the
// OLD binary first, then copy the staged binary to a temp file IN the
// target's directory (same filesystem) and rename over the target. An
// unwritable target directory is the privileged path: nothing is applied,
// the staged binary survives, and the exact sudo commands are returned for
// the owner.
func applyStaged(opts Options, res *Result) error {
	target := opts.TargetPath
	dir := filepath.Dir(target)
	stamp := opts.Now().UTC().Format("20060102-150405")

	// 1. Writability probe FIRST (temp-create/remove in the target's
	// directory): an unwritable (root-owned) target must land on the
	// stage-and-instruct path BEFORE the backup runs — the backup would hit
	// the same EACCES and die with a generic permission error and no sudo
	// lines (I-1). The target's directory may not exist yet (fresh install)
	// — create it.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create target directory %s: %w", dir, err)
	}
	probe := filepath.Join(dir, ".xray-update-probe-"+stamp)
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		_ = os.Remove(probe)
		return stageAndInstruct(opts, res, target, stamp)
	}
	_ = os.Remove(probe)

	// 2. Date-stamped backup of the OLD binary (activate-stage convention
	// .bak-<ts>), taken before anything touches the target.
	if _, err := os.Stat(target); err == nil {
		backup := target + ".bak-" + stamp
		if err := copyFile(target, backup, 0o755); err != nil {
			return fmt.Errorf("backup %s before replace: %w", target, err)
		}
		res.BackupPath = backup
	}

	// 3. Atomic replace: same-directory temp + rename. The writability
	// probe above already proved the directory accepts our files, so a
	// failure here is a genuine error (disk full, race), not the
	// permissions signal — loud, never a silent fall-through.
	temp := filepath.Join(dir, ".xray-update-"+stamp)
	if err := copyFile(res.StagedBinary, temp, 0o755); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("stage temp copy %s: %w", temp, err)
	}
	if rerr := os.Rename(temp, target); rerr != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("atomic replace %s: %w", target, rerr)
	}

	// 4. Post-replace validation (I-2): re-validate the INSTALLED binary at
	// its new position — version banner parses, `run -test` accepts a
	// config with the target's directory as the asset root. A failure rolls
	// the backup back over the target and errors loud naming the rollback:
	// a broken install must never be the resting state.
	if verr := validateInstalled(opts, target); verr != nil {
		return rollbackReplace(res, target, verr)
	}
	return nil
}

// stageAndInstruct is the unwritable-target outcome: nothing applied, the
// staged binary survives, and the exact sudo commands reach the owner.
func stageAndInstruct(opts Options, res *Result, target, stamp string) error {
	// Stage-and-instruct: the EXACT privileged commands (backup + install),
	// never a half-apply.
	backup := target + ".bak-" + stamp
	res.PrivilegedCommands = []string{
		"sudo cp -p " + target + " " + backup,
		"sudo install -m 0755 " + res.StagedBinary + " " + target,
	}
	_, _ = fmt.Fprintf(opts.Stderr, "xray-update: %s\n\n", ErrPrivilegedTarget.Error())
	_, _ = fmt.Fprintf(opts.Stderr, "  staged binary (verified, -test passed): %s\n", res.StagedBinary)
	for _, cmdLine := range res.PrivilegedCommands {
		_, _ = fmt.Fprintf(opts.Stderr, "  %s\n", cmdLine)
	}
	_, _ = fmt.Fprintf(opts.Stderr, "\n  user-level alternative: point [activate].xray_bin at ~/.local/bin/xray "+
		"and xray-update applies freely without sudo\n")
	return ErrPrivilegedTarget
}

// copyFile copies src → dst with the given permission (create/truncate).
func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// dropProxyEnv strips ambient proxy variables from a child environment
// (L5: nothing in the pipeline may silently route through the live client).
func dropProxyEnv(env []string) []string {
	out := env[:0]
	for _, e := range env {
		upper := strings.ToUpper(e)
		if strings.HasPrefix(upper, "HTTP_PROXY=") || strings.HasPrefix(upper, "HTTPS_PROXY=") ||
			strings.HasPrefix(upper, "ALL_PROXY=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

func tailBytes(b []byte, n int) string {
	s := string(b)
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
