// Package fetch implements the D9 dynamic source discovery + download stage:
// sources are repo ids plus a discovery method (GitHub contents API listing or
// an upstream manifest file); raw URLs are resolved fresh every wave, never
// pinned. All HTTP goes direct (no ambient proxy — landmine L5).
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"public_vpn/internal/config"
)

// ClientConfig wires the client to (test) hosts.
type ClientConfig struct {
	APIBase     string        // default https://api.github.com
	RawBase     string        // default https://raw.githubusercontent.com
	Token       string        // optional GitHub token
	Timeout     time.Duration // per request
	Retries     int           // attempts on retryable (5xx/network) failures
	Concurrency int           // parallel file downloads per source
}

// Client discovers and downloads source files.
type Client struct {
	cfg  ClientConfig
	http *http.Client
}

// FetchedFile is one downloaded source body.
type FetchedFile struct {
	Source    string    `json:"source"`
	Path      string    `json:"path"` // repo-relative path
	URL       string    `json:"url"`  // resolved raw URL
	Body      []byte    `json:"-"`
	Sha256    string    `json:"sha256"`
	Cached    bool      `json:"cached"`
	FetchedAt time.Time `json:"fetched_at"`
}

// NewClient builds a client. The transport deliberately ignores proxy
// environment variables: pipeline traffic must never tunnel through the owner's
// VPN (landmine L5 — the in-process equivalent of env -u http_proxy).
func NewClient(cfg ClientConfig) *Client {
	if cfg.APIBase == "" {
		cfg.APIBase = "https://api.github.com"
	}
	if cfg.RawBase == "" {
		cfg.RawBase = "https://raw.githubusercontent.com"
	}
	if cfg.Retries == 0 {
		cfg.Retries = 3
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 4
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
	}
}

// Source resolves and downloads every file one source contributes.
func (c *Client) Source(ctx context.Context, id string, src config.Source) ([]FetchedFile, error) {
	paths, err := c.Discover(ctx, src)
	if err != nil {
		return nil, err
	}
	return c.fetchPaths(ctx, id, src.Repo, paths)
}

// SourceCached is Source with disk caching: bodies land under
// cacheDir/<source>/<safe-path> and conditional GETs (ETag/If-None-Match)
// turn into 304 → cached-body reuse.
func (c *Client) SourceCached(
	ctx context.Context, id string, src config.Source, cacheDir string,
) ([]FetchedFile, error) {
	paths, err := c.Discover(ctx, src)
	if err != nil {
		return nil, err
	}
	type job struct {
		idx  int
		path string
		etag string
	}
	jobs := make([]job, len(paths))
	for i, p := range paths {
		jobs[i] = job{idx: i, path: p, etag: readCacheEtag(filepath.Join(cacheDir, id, SafePath(p)))}
	}
	out := make([]FetchedFile, len(paths))
	var mu sync.Mutex
	var firstErr error
	fanErr := bounded(ctx, c.cfg.Concurrency, jobs, func(j job) error {
		body, etag, err := c.fetchWithValidator(ctx, src.Repo, j.path, j.etag)
		if err != nil {
			mu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
			return nil
		}
		cachePath := filepath.Join(cacheDir, id, SafePath(j.path))
		cached, err := storeCache(cachePath, body, etag)
		if err != nil {
			mu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
			return nil
		}
		if body == nil {
			body, err = os.ReadFile(cachePath)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return nil
			}
		}
		sum := sha256.Sum256(body)
		mu.Lock()
		out[j.idx] = FetchedFile{
			Source: id, Path: j.path, URL: c.rawURL(src.Repo, j.path), Body: body,
			Sha256: hex.EncodeToString(sum[:]), Cached: cached, FetchedAt: time.Now().UTC(),
		}
		mu.Unlock()
		return nil
	})
	if firstErr != nil {
		return nil, firstErr
	}
	if fanErr != nil {
		return nil, fmt.Errorf("fetch source %s: %w", id, fanErr)
	}
	return out, nil
}

// Discover resolves the current file paths a source contributes (D9).
func (c *Client) Discover(ctx context.Context, src config.Source) ([]string, error) {
	switch src.Discovery {
	case "github-contents":
		return c.discoverContents(ctx, src)
	case "manifest":
		return c.discoverManifest(ctx, src)
	default:
		return nil, fmt.Errorf("unknown discovery method %q", src.Discovery)
	}
}

func (c *Client) discoverContents(ctx context.Context, src config.Source) ([]string, error) {
	url := fmt.Sprintf("%s/repos/%s/git/trees/HEAD?recursive=1", c.cfg.APIBase, src.Repo)
	var payload struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
		Truncated bool   `json:"truncated"`
		Message   string `json:"message"`
	}
	if err := c.getJSON(ctx, url, &payload); err != nil {
		return nil, fmt.Errorf("list tree for %s: %w", src.Repo, err)
	}
	if payload.Truncated {
		// A truncated listing is missing entries; treating it as complete
		// would silently drop source files from the wave.
		return nil, fmt.Errorf("tree listing for %s is truncated by GitHub — "+
			"narrow include patterns or paginate per-directory", src.Repo)
	}
	var paths []string
	for _, entry := range payload.Tree {
		if entry.Type != "blob" {
			continue
		}
		if matchesAnyInclude(src.Include, entry.Path) {
			paths = append(paths, entry.Path)
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("discover %s: no files matched include patterns %v (upstream layout changed?)",
			src.Repo, src.Include)
	}
	sort.Strings(paths)
	return paths, nil
}

// discoverManifest fetches the upstream manifest and collects every .txt file
// URL it references (protocol_files, categories.*.files, cascade_categories.*.
// files, or any string ending in .txt). Mirror twins of the same repo-relative
// path are deduped in favor of the raw host.
func (c *Client) discoverManifest(ctx context.Context, src config.Source) ([]string, error) {
	manifestURL := c.rawURL(src.Repo, src.Manifest)
	var manifest map[string]any
	if err := c.getJSON(ctx, manifestURL, &manifest); err != nil {
		return nil, fmt.Errorf("read manifest %s for %s: %w", src.Manifest, src.Repo, err)
	}
	cands := collectManifestCandidates(manifest)
	if len(cands) == 0 {
		return nil, fmt.Errorf("manifest %s of %s references no .txt files", src.Manifest, src.Repo)
	}
	best := preferRawTwins(cands, manifestRawBase(manifest))
	var paths []string
	for p := range best {
		if matchesAnyInclude(src.Include, p) {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("manifest %s of %s: no files matched include patterns %v", src.Manifest, src.Repo, src.Include)
	}
	sort.Strings(paths)
	return paths, nil
}

func manifestRawBase(manifest map[string]any) string {
	if rb, ok := manifest["raw_base"].(string); ok {
		return rb
	}
	return ""
}

// manifestCandidate is one .txt URL referenced by a manifest.
type manifestCandidate struct {
	path string
	url  string
}

// collectManifestCandidates walks the manifest JSON collecting every .txt file
// URL (protocol_files, categories.*.files, cascade_categories.*.files, or any
// string ending in .txt).
func collectManifestCandidates(manifest map[string]any) []manifestCandidate {
	var cands []manifestCandidate
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for _, vv := range t {
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		case string:
			if base, _, _ := strings.Cut(t, "?"); strings.HasSuffix(base, ".txt") {
				cands = append(cands, manifestCandidate{path: pathOfURL(t), url: t})
			}
		}
	}
	walk(manifest)
	return cands
}

// preferRawTwins dedupes mirror twins of the same repo-relative path in favor
// of the raw host (mirrors may lag).
func preferRawTwins(cands []manifestCandidate, rawBase string) map[string]string {
	best := make(map[string]string, len(cands))
	for _, cd := range cands {
		prev, ok := best[cd.path]
		if !ok {
			best[cd.path] = cd.url
			continue
		}
		if isRawHost(cd.url, rawBase) && !isRawHost(prev, rawBase) {
			best[cd.path] = cd.url
		}
	}
	return best
}

func isRawHost(u, rawBase string) bool {
	if rawBase == "" {
		return strings.Contains(u, "raw.githubusercontent.com")
	}
	return strings.HasPrefix(u, rawBase)
}

// pathOfURL extracts the repo-relative path portion of a raw URL:
// scheme://host/owner/repo/branch/rest → rest.
func pathOfURL(u string) string {
	trimmed, _, _ := strings.Cut(u, "?")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	trimmed = strings.TrimPrefix(trimmed, "http://")
	parts := strings.SplitN(trimmed, "/", 5)
	if len(parts) == 5 {
		return parts[4]
	}
	return trimmed
}

func (c *Client) fetchPaths(ctx context.Context, id, repo string, paths []string) ([]FetchedFile, error) {
	out := make([]FetchedFile, len(paths))
	var mu sync.Mutex
	var firstErr error
	jobs := make([]int, len(paths))
	for i := range jobs {
		jobs[i] = i
	}
	fanErr := bounded(ctx, c.cfg.Concurrency, jobs, func(i int) error {
		body, err := c.Fetch(ctx, repo, paths[i])
		if err != nil {
			mu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
			return nil
		}
		sum := sha256.Sum256(body)
		mu.Lock()
		out[i] = FetchedFile{
			Source: id, Path: paths[i], URL: c.rawURL(repo, paths[i]), Body: body,
			Sha256: hex.EncodeToString(sum[:]), FetchedAt: time.Now().UTC(),
		}
		mu.Unlock()
		return nil
	})
	if firstErr != nil {
		return nil, firstErr
	}
	if fanErr != nil {
		return nil, fmt.Errorf("fetch %s: %w", repo, fanErr)
	}
	return out, nil
}

// Fetch downloads one raw file with retries.
func (c *Client) Fetch(ctx context.Context, repo, p string) ([]byte, error) {
	body, _, err := c.fetchWithValidator(ctx, repo, p, "")
	return body, err
}

func (c *Client) fetchWithValidator(ctx context.Context, repo, p, etag string) ([]byte, string, error) {
	url := c.rawURL(repo, p)
	var lastErr error
	for attempt := 0; attempt <= c.cfg.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, "", ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
		body, newEtag, err := c.fetchAttempt(ctx, url, etag)
		if err == nil {
			return body, newEtag, nil
		}
		lastErr = err
		if !errors.Is(err, errRetryableFetch) {
			break // 404 and friends are terminal
		}
	}
	return nil, "", lastErr
}

// errRetryableFetch marks 5xx/429 responses worth another attempt.
var errRetryableFetch = errors.New("retryable fetch failure")

func (c *Client) fetchAttempt(ctx context.Context, url, etag string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "public_vpn (pipeline; contact: owner)")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if c.cfg.Token != "" && strings.Contains(url, "api.github.com") {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", errRetryableFetch
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return nil, "", errRetryableFetch
		}
		return body, resp.Header.Get("ETag"), nil
	case resp.StatusCode == http.StatusNotModified:
		return nil, resp.Header.Get("ETag"), nil
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return nil, "", fmt.Errorf("%w: GET %s: %s", errRetryableFetch, url, resp.Status)
	default:
		return nil, "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
}

func (c *Client) getJSON(ctx context.Context, url string, v any) error {
	for attempt := 0; attempt <= c.cfg.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "public_vpn (pipeline; contact: owner)")
		req.Header.Set("Accept", "application/vnd.github+json")
		if c.cfg.Token != "" && strings.Contains(url, "api.github.com") {
			req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if attempt == c.cfg.Retries {
				return err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			err = fmt.Errorf("GET %s: %s", url, resp.Status)
			if resp.StatusCode >= 500 && attempt < c.cfg.Retries {
				continue
			}
			return err
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
		_ = resp.Body.Close()
		if err != nil && attempt < c.cfg.Retries {
			continue
		}
		return err
	}
	return errors.New("unreachable")
}

func (c *Client) rawURL(repo, p string) string {
	return fmt.Sprintf("%s/%s/HEAD/%s", c.cfg.RawBase, repo, path.Clean(p))
}

// bounded runs jobs with at most n concurrent workers.
func bounded[T any](ctx context.Context, n int, jobs []T, run func(T) error) error {
	if n < 1 {
		n = 1
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for _, j := range jobs {
		wg.Add(1)
		go func(item T) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if err := run(item); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(j)
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	// Workers that skipped via ctx.Done leave their outputs untouched; report
	// the cancellation so callers never mistake the gaps for a clean wave.
	return ctx.Err()
}

// matchesAnyInclude applies include patterns to a repo-relative path:
//   - "dir/"  → path prefix
//   - "a/b"   → exact or path-suffix match
//   - "b.txt" → basename equality
func matchesAnyInclude(patterns []string, p string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pat := range patterns {
		pat = strings.TrimSuffix(pat, "*")
		if pat == "" {
			return true
		}
		if strings.HasSuffix(pat, "/") && strings.HasPrefix(p, pat) {
			return true
		}
		if p == pat || strings.HasSuffix(p, "/"+pat) {
			return true
		}
		if !strings.Contains(pat, "/") && path.Base(p) == pat {
			return true
		}
	}
	return false
}

// SafePath maps a repo-relative source path to a flat, filesystem-safe cache
// file name. Exported because parse (cli) must read back exactly the names
// fetch wrote — the mapping has exactly one definition (review finding 10).
func SafePath(p string) string {
	return strings.NewReplacer("/", "_", "..", "_").Replace(p)
}

// readCacheEtag loads the stored validator for a cache path ("" when absent).
func readCacheEtag(cachePath string) string {
	b, err := os.ReadFile(cachePath + ".meta.json")
	if err != nil {
		return ""
	}
	var meta cacheMeta
	if json.Unmarshal(b, &meta) != nil {
		return ""
	}
	return meta.ETag
}

// storeCache writes the body + etag sidecar; returns whether the body came
// from cache (304 path).
func storeCache(cachePath string, body []byte, etag string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o750); err != nil {
		return false, err
	}
	meta := cacheMeta{ETag: etag, FetchedAt: time.Now().UTC()}
	if body == nil {
		b, err := os.ReadFile(cachePath)
		if err != nil {
			return false, fmt.Errorf("cache hit but body missing for %s: %w", cachePath, err)
		}
		body = b
		meta.Cached = true
	}
	//nolint:gosec // G703: cache path derived from owner config (trust root)
	if err := os.WriteFile(cachePath, body, 0o600); err != nil {
		return false, err
	}
	metaBytes, err := json.Marshal(meta)
	if err == nil {
		// The sidecar is pipeline state on the owner's disk — 0600 like the
		// body it describes (review finding 11).
		_ = os.WriteFile(cachePath+".meta.json", metaBytes, 0o600)
	}
	return meta.Cached, nil
}

type cacheMeta struct {
	ETag      string    `json:"etag,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
	Cached    bool      `json:"cached"`
}
