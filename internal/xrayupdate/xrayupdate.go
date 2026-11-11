// Package xrayupdate implements `assay xray-update` (W14): fetch the
// latest Xray-core release for this platform, VERIFY its published sha256
// (every release asset ships a .dgst companion), unpack, validate the NEW
// binary with `xray run -test`, and atomically replace the target binary
// with a date-stamped backup of the old one. Since D4/S5 the update surface
// is MANAGED-ONLY: the target resolves through [core].xray_bin (the managed
// default <data>/bin/xray or the explicit override). An unwritable target
// directory is a loud misconfiguration — nothing is half-applied, and no
// privileged commands are ever printed (the managed core never needs sudo).
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

	"assay/internal/ui"
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
	repoSlug = "XTLS/Xray-core"
	// DefaultAPIBase is the canonical GitHub API host; the managed-core
	// lifecycle (internal/core) reuses the same release surface through the
	// exported helpers below.
	DefaultAPIBase  = "https://api.github.com"
	timeoutAPI      = 30 * time.Second
	timeoutDownload = 5 * time.Minute
	timeoutTest     = 30 * time.Second
)

// ErrYesRequired marks the non-interactive refusal: without --yes a piped
// invocation must not guess the owner's intent.
var ErrYesRequired = errors.New(
	"refusing non-interactive update without --yes (pipe a y/n answer, or pass --yes)")

// Options configures one xray-update run.
type Options struct {
	CheckOnly   bool   // --check: report latest vs current, touch nothing
	BinOverride string // --bin: target path override ([core].xray_bin otherwise)
	TargetPath  string // resolved [core].xray_bin (expanded; CLI's concern)
	AssumeYes   bool   // --yes: skip the confirmation prompt
	// Color chip-styles the final VERDICT lines (W18); the stage progress
	// lines stay plain — journald-friendly by construction.
	Color bool
	// Label prefixes the stage progress lines ("xray-update:" by default);
	// the managed-core lifecycle (internal/core) passes "core:" so the wave
	// journal reads one grammar.
	Label string
	// APIBase overrides the GitHub API host (test seam; empty = default).
	APIBase string
	// StagingDir is where the release is downloaded, verified, and unpacked
	// (CLI passes <data_dir>/xray-staged — the managed-core lifecycle reads
	// the staged binary out of the same dir within its own invocation).
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
		return nil, errors.New("no target binary path (--bin or [core].xray_bin)")
	}
	if opts.StagingDir == "" {
		return nil, errors.New("no staging directory configured")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	res := &Result{}
	current, err := currentVersion(context.Background(), opts.TargetPath)
	if err != nil {
		return nil, err
	}
	res.CurrentVersion = current

	rel, err := fetchRelease(context.Background(), opts.APIBase)
	if err != nil {
		return nil, err
	}
	res.LatestVersion = rel.TagName

	if opts.CheckOnly {
		printCheck(opts.Stdout, res, opts.Color)
		return res, nil
	}
	if sameVersion(current, rel.TagName) {
		printVerdict(opts.Stdout, opts.Color, ui.Green, "already at "+rel.TagName+" — nothing to do")
		return res, nil
	}

	// Confirmation gates the WHOLE run (download included): the owner reads
	// the version pair first. A piped invocation without input refuses —
	// --yes is the explicit non-interactive path.
	switch proceed, err := confirm(opts, current, rel.TagName); {
	case err != nil:
		return res, err
	case !proceed:
		printVerdict(opts.Stdout, opts.Color, "", "declined — nothing touched")
		return res, nil
	}

	staged, err := stageRelease(context.Background(), opts, rel)
	if err != nil {
		return nil, err
	}
	res.StagedBinary = staged
	if err := applyStaged(opts, res); err != nil {
		return res, err
	}
	res.Updated = true
	printVerdict(opts.Stdout, opts.Color, ui.Green,
		displayVersion(current)+" → "+rel.TagName+" installed at "+opts.TargetPath+
			" (old binary backed up at "+orEmpty(res.BackupPath)+")")
	return res, nil
}

// printVerdict renders one final outcome line as a chip: the
// "xray-update:" label dim 241, the verdict colored by its class
// (green installed/no-op, plain informational). Progress lines never use
// this — they stay plain for journald.
func printVerdict(w io.Writer, color bool, class, verdict string) {
	value := verdict
	if class != "" {
		value = ui.Colorize(class, verdict, color)
	}
	_, _ = fmt.Fprintln(w, ui.Chip("xray-update:", value, color))
}

func orEmpty(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
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
func currentVersion(ctx context.Context, bin string) (string, error) {
	if _, err := os.Stat(bin); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
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

func printCheck(w io.Writer, res *Result, color bool) {
	switch {
	case res.CurrentVersion == "":
		printVerdict(w, color, ui.Green, "latest "+res.LatestVersion+", current (not installed)")
	case sameVersion(res.CurrentVersion, res.LatestVersion):
		printVerdict(w, color, ui.Green,
			"latest "+res.LatestVersion+", current v"+res.CurrentVersion+" — up to date")
	default:
		printVerdict(w, color, ui.Amber,
			"latest "+res.LatestVersion+", current v"+res.CurrentVersion+" — update available (run without --check)")
	}
}

// fetchRelease resolves the latest release + its asset list from the GitHub
// API. The client's Proxy is nil by L5 discipline: a binary download must
// never silently ride the owner's live VPN.
func fetchRelease(ctx context.Context, apiBase string) (*release, error) {
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}
	ctx, cancel := context.WithTimeout(ctx, timeoutAPI)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		apiBase+"/repos/"+repoSlug+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// DisableKeepAlives: every client here is ONE-SHOT (a single request per
	// invocation), so idle-connection reuse buys nothing — and a kept-alive
	// transport leaves background goroutines that read process-global state
	// (time.Now → time.Local) after the caller moved on, which races any
	// later time.Local mutation in the same process (-race caught exactly
	// that across two cli tests). No lingering transport goroutines, ever.
	client := &http.Client{Timeout: timeoutAPI, Transport: &http.Transport{
		Proxy:             nil, // L5: never the ambient proxy
		DisableKeepAlives: true,
	}}
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
// logLabel is the prefix of the stage progress lines (Options.Label; the
// default stays the command's own chip label).
func (o Options) logLabel() string {
	if o.Label != "" {
		return o.Label
	}
	return "xray-update:"
}

func stageRelease(ctx context.Context, opts Options, rel *release) (string, error) {
	assetName := assetForPlatform(runtime.GOOS, runtime.GOARCH, os.Getenv("GOARM"))
	a, err := findAsset(rel, assetName)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(opts.StagingDir, 0o750); err != nil {
		return "", err
	}
	zipPath := filepath.Join(opts.StagingDir, assetName)
	_, _ = fmt.Fprintf(opts.Stdout, "%s downloading %s (%s)…\n", opts.logLabel(), a.Name, rel.TagName)
	if err := download(ctx, a.URL, zipPath); err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(zipPath) }() // the zip is scratch; the unpacked binary stays

	want, err := fetchExpectedSha256(ctx, a.URL+".dgst")
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
	_, _ = fmt.Fprintf(opts.Stdout, "%s sha256 verified (%s…)\n", opts.logLabel(), got[:12])

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
	if err := runTestGate(ctx, staged, opts.TestFailsEnv); err != nil {
		return "", fmt.Errorf("staged binary failed validation (staged at %s): %w", staged, err)
	}
	_, _ = fmt.Fprintf(opts.Stdout, "%s staged binary passed `xray run -test`\n", opts.logLabel())
	return staged, nil
}

// download streams url into dst (no ambient proxy — L5).
func download(ctx context.Context, url, dst string) error {
	ctx, cancel := context.WithTimeout(ctx, timeoutDownload)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: timeoutDownload, Transport: &http.Transport{
		Proxy:             nil,  // L5: never the ambient proxy
		DisableKeepAlives: true, // one-shot client — no lingering transport goroutines
	}}
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
func fetchExpectedSha256(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeoutAPI)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: timeoutAPI, Transport: &http.Transport{
		Proxy:             nil,  // L5: never the ambient proxy
		DisableKeepAlives: true, // one-shot client — no lingering transport goroutines
	}}
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
	if err := runTestGate(context.Background(), target, opts.TestFailsEnv); err != nil {
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
func runTestGate(ctx context.Context, bin string, extraEnv []string) error {
	cfg := `{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`
	cfgPath := filepath.Join(filepath.Dir(bin), "test-config.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return err
	}
	defer func() { _ = os.Remove(cfgPath) }()

	ctx, cancel := context.WithTimeout(ctx, timeoutTest)
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
// unwritable target directory is a LOUD misconfiguration (S5: the update
// surface is managed-only — a writable user-owned binary needs no
// privileged path): nothing is applied, the staged binary survives, and the
// error names the directory and the knob.
func applyStaged(opts Options, res *Result) error {
	target := opts.TargetPath
	dir := filepath.Dir(target)
	stamp := opts.Now().UTC().Format("20060102-150405")

	// 1. Writability probe FIRST (temp-create/remove in the target's
	// directory): an unwritable (root-owned) target refuses before the
	// backup runs — the backup would hit the same EACCES and die with a
	// generic permission error naming nothing actionable (I-1). The target's
	// directory may not exist yet (fresh install) — create it.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create target directory %s: %w", dir, err)
	}
	probe := filepath.Join(dir, ".xray-update-probe-"+stamp)
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		_ = os.Remove(probe)
		_, _ = fmt.Fprintf(opts.Stderr, "xray-update: target directory %s is not writable — "+
			"nothing applied, the staged binary survives at %s\n", dir, res.StagedBinary)
		return fmt.Errorf("target directory %s is not writable (the update surface is "+
			"managed-only per D4/S5 — point [core].xray_bin at a user-owned path and retry)", dir)
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

// CurrentVersion reads the CURRENT core version via `<bin> version` and
// parses the banner; a missing binary is a valid fresh-install state
// ("" version), not an error. Exported for the managed-core lifecycle
// (internal/core) — the same banner contract the manual path uses. ctx
// bounds the child.
func CurrentVersion(ctx context.Context, bin string) (string, error) {
	return currentVersion(ctx, bin)
}

// FetchLatestTag resolves the latest Xray-core release tag from the GitHub
// API (the check leg of the managed-core auto-update; ctx bounds the call).
// The client's Proxy is nil by L5 discipline.
func FetchLatestTag(ctx context.Context, apiBase string) (string, error) {
	rel, err := fetchRelease(ctx, apiBase)
	if err != nil {
		return "", err
	}
	return rel.TagName, nil
}

// StageVerifiedRelease runs the managed download leg: fetch the latest
// release, download the platform asset, VERIFY its sha256 against the
// release's published .dgst companion, unpack flat into stagingDir, and
// gate the staged binary with `xray run -test`. Returns the staged binary
// path and the release tag; the target is untouched (the caller installs).
// label prefixes the progress lines in the caller's journal. ctx bounds
// every leg (network + gate child).
func StageVerifiedRelease(
	ctx context.Context, apiBase, stagingDir, label string, stdout io.Writer, extraTestEnv []string,
) (string, string, error) {
	rel, err := fetchRelease(ctx, apiBase)
	if err != nil {
		return "", "", err
	}
	opts := Options{
		StagingDir:   stagingDir,
		Label:        label,
		APIBase:      apiBase,
		Stdout:       stdout,
		Stderr:       stdout,
		TestFailsEnv: extraTestEnv,
	}
	staged, err := stageRelease(ctx, opts, rel)
	if err != nil {
		return "", "", err
	}
	return staged, rel.TagName, nil
}
