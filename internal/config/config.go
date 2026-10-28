// Package config loads and validates the single source of truth for the
// pipeline: a TOML file (owner convention: everything in config, never env
// vars). Unknown keys fail loudly — no silent-ignore configuration drift.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

// Source is one upstream node feed (D9): repo id + discovery method. Raw URLs
// are never pinned; discovery resolves current paths every wave.
type Source struct {
	Repo      string   `toml:"repo"`
	Discovery string   `toml:"discovery"` // "github-contents" | "manifest"
	Manifest  string   `toml:"manifest"`  // for discovery="manifest": manifest file path in repo
	Include   []string `toml:"include"`   // path patterns the discovery must fetch
	Enabled   *bool    `toml:"enabled"`   // nil = enabled (a declared source is opted in)
}

// IsEnabled reports whether the source participates in fetch waves.
func (s Source) IsEnabled() bool {
	return s.Enabled == nil || *s.Enabled
}

// FetchConfig controls source fetching.
type FetchConfig struct {
	Timeout     Duration `toml:"timeout"`
	Retries     int      `toml:"retries"`
	Concurrency int      `toml:"concurrency"`
	GitHubToken string   `toml:"github_token"` // optional, raises api.github.com rate limits
	CacheMaxAge Duration `toml:"cache_max_age"`
}

// FilterConfig controls the ingest security filter stage.
type FilterConfig struct {
	// SourceCap limits how many nodes one source may contribute per wave.
	// 0 = unlimited. The --source-cap CLI flag overrides it when set.
	SourceCap int `toml:"source_cap"`
	// Protocols is the scheme allowlist (acceptance policy). Default
	// vless,vmess,trojan; ss is opt-in (PSK-only shadowsocks is weak — the
	// reality/tls security requirement below still applies on top).
	Protocols []string `toml:"protocols"`
	// AllowInsecure admits links carrying allowInsecure/insecure=1|true
	// instead of dropping them. Default false (denial in filter). The
	// renderer has no allowInsecure capability on core 26.3.27 — the feature
	// was removed upstream (migrated to pinnedPeerCertSha256) — so an
	// admitted link only loses the param (rendered as a loud drop-report
	// entry, never silently).
	AllowInsecure bool `toml:"allow_insecure"`
}

// ProbeConfig controls the xray-knife probe wave (out-of-band only).
type ProbeConfig struct {
	Path                string   `toml:"path"`
	Timeout             Duration `toml:"timeout"`
	Threads             int      `toml:"threads"`
	URL                 string   `toml:"url"`
	Speedtest           bool     `toml:"speedtest"`
	SpeedtestTimeout    Duration `toml:"speedtest_timeout"`
	CheckPreset         string   `toml:"check_preset"`
	URLSuccessThreshold float64  `toml:"url_success_threshold"`
	DBPath              string   `toml:"db_path"`
	MaxPassed           int      `toml:"max_passed"`
}

// GeoConfig controls ip-api.com batch enrichment (L6: free tier is HTTP-only,
// 15 batch req/min; 429 risks a 1h ban).
type GeoConfig struct {
	Endpoint  string   `toml:"endpoint"`
	BatchSize int      `toml:"batch_size"`
	PerMinute int      `toml:"per_minute"`
	TTL       Duration `toml:"ttl"`
	Timeout   Duration `toml:"timeout"`
}

// SelectConfig controls the ranking caps (D7): countries unlimited,
// per-country cap K, global soft cap N expanding to the ceiling when enough
// distinct cities are alive.
type SelectConfig struct {
	PerCountryCap       int `toml:"per_country_cap"`
	SoftCap             int `toml:"soft_cap"`
	CityExpandThreshold int `toml:"city_expand_threshold"`
	Ceiling             int `toml:"ceiling"`
}

// PoolRoute is one owner-configured routing rule that steers traffic into the
// pool (D2 trust wall: pool participates only in explicit routes). Balancer
// is the route target: a rendered `pool_*` balancer tag or a direct
// `pool-<cc>-NN` outbound tag (D5 single-node city); render refuses any other
// target loud (D6).
type PoolRoute struct {
	Balancer string   `toml:"balancer"`
	Domains  []string `toml:"domains"`
}

// RenderConfig controls xray config rendering.
type RenderConfig struct {
	Template   string      `toml:"template"`
	OutputDir  string      `toml:"output_dir"`
	StatsPort  int         `toml:"stats_port"`
	PoolRoutes []PoolRoute `toml:"pool_routes"`
}

// ActivateConfig controls the -test gate, backup, and atomic replace.
type ActivateConfig struct {
	Target    string `toml:"target"`
	XrayBin   string `toml:"xray_bin"`
	AssetDir  string `toml:"asset_dir"` // XRAY_LOCATION_ASSET for -test; default = template dir
	BackupDir string `toml:"backup_dir"`
}

// MaintainConfig controls the W4 maintenance wave (DESIGN.md §4.9).
type MaintainConfig struct {
	// PruneDeadAfter removes a geo-base record that is not alive and whose
	// last_probe is older than this window (default 48h).
	PruneDeadAfter Duration `toml:"prune_dead_after"`
	// RefreshInterval is the refresh-wave recheck period. install renders it
	// into the refresh timer as OnUnitActiveSec (default 6h, floor 5m);
	// re-running install after a config change applies the new period.
	RefreshInterval Duration `toml:"refresh_interval"`
	// SpeedtestInterval is the speedtest-wave recheck period (default 168h,
	// floor 5m) — rendered into the speedtest timer's OnUnitActiveSec.
	SpeedtestInterval Duration `toml:"speedtest_interval"`
}

// IntervalFloor is the minimum recheck period for both maintenance waves:
// faster loops would hammer the sources, the probe origin, and the live
// client for no selection benefit.
const IntervalFloor = 5 * time.Minute

// Config is the pipeline configuration root.
type Config struct {
	DataDir  string            `toml:"data_dir"`
	Sources  map[string]Source `toml:"sources"`
	Fetch    FetchConfig       `toml:"fetch"`
	Filter   FilterConfig      `toml:"filter"`
	Probe    ProbeConfig       `toml:"probe"`
	Geo      GeoConfig         `toml:"geo"`
	Select   SelectConfig      `toml:"select"`
	Render   RenderConfig      `toml:"render"`
	Activate ActivateConfig    `toml:"activate"`
	Maintain MaintainConfig    `toml:"maintain"`
}

// Duration wraps time.Duration for TOML string values like "30s", "24h".
type Duration struct {
	time.Duration
}

// UnmarshalText parses Go duration strings.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalText renders the duration back to a TOML string.
func (d *Duration) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// Load reads, strict-decodes, defaults, and validates the config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	dec := toml.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	applyDefaults(cfg)
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

func applyDefaults(c *Config) {
	applyFetchDefaults(&c.Fetch)
	applyFilterDefaults(&c.Filter)
	applyProbeDefaults(&c.Probe)
	applyGeoDefaults(&c.Geo)
	applySelectDefaults(&c.Select)
	applyRenderDefaults(&c.Render)
	applyActivateDefaults(&c.Activate)
	applyMaintainDefaults(&c.Maintain)
}

// defaultProtocols is the protocol acceptance allowlist applied when
// [filter].protocols is unset (ss is opt-in — PSK-only shadowsocks is weak).
var defaultProtocols = []string{"vless", "vmess", "trojan"}

func applyFilterDefaults(f *FilterConfig) {
	if len(f.Protocols) == 0 {
		f.Protocols = append([]string(nil), defaultProtocols...)
	}
}

func applyFetchDefaults(f *FetchConfig) {
	if f.Timeout.Duration == 0 {
		f.Timeout.Duration = 30 * time.Second
	}
	if f.Retries == 0 {
		f.Retries = 3
	}
	if f.Concurrency == 0 {
		f.Concurrency = 4
	}
	if f.CacheMaxAge.Duration == 0 {
		f.CacheMaxAge.Duration = 6 * time.Hour
	}
}

func applyProbeDefaults(p *ProbeConfig) {
	if p.Path == "" {
		p.Path = "~/.local/bin/xray-knife"
	}
	if p.Timeout.Duration == 0 {
		p.Timeout.Duration = 10 * time.Second
	}
	if p.Threads == 0 {
		p.Threads = 20
	}
	if p.URL == "" {
		p.URL = "https://cloudflare.com/cdn-cgi/trace"
	}
	if p.SpeedtestTimeout.Duration == 0 {
		p.SpeedtestTimeout.Duration = 30 * time.Second
	}
	if p.URLSuccessThreshold == 0 {
		p.URLSuccessThreshold = 1.0
	}
	if p.DBPath == "" {
		p.DBPath = "xray-knife.db"
	}
}

func applyGeoDefaults(g *GeoConfig) {
	if g.Endpoint == "" {
		g.Endpoint = "http://ip-api.com/batch"
	}
	if g.BatchSize == 0 {
		g.BatchSize = 100
	}
	if g.PerMinute == 0 {
		g.PerMinute = 15
	}
	if g.TTL.Duration == 0 {
		g.TTL.Duration = 24 * time.Hour
	}
	if g.Timeout.Duration == 0 {
		g.Timeout.Duration = 15 * time.Second
	}
}

func applySelectDefaults(s *SelectConfig) {
	if s.PerCountryCap == 0 {
		s.PerCountryCap = 3
	}
	if s.SoftCap == 0 {
		s.SoftCap = 25
	}
	if s.CityExpandThreshold == 0 {
		s.CityExpandThreshold = 25
	}
	if s.Ceiling == 0 {
		s.Ceiling = 40
	}
}

func applyRenderDefaults(r *RenderConfig) {
	if r.Template == "" {
		r.Template = "~/projects/xray-raw/config.json"
	}
	if r.OutputDir == "" {
		r.OutputDir = "rendered"
	}
	if r.StatsPort == 0 {
		r.StatsPort = 15490
	}
}

func applyActivateDefaults(a *ActivateConfig) {
	if a.Target == "" {
		a.Target = "~/projects/xray-raw/config.json"
	}
	if a.XrayBin == "" {
		a.XrayBin = "/usr/bin/xray"
	}
	if a.BackupDir == "" {
		a.BackupDir = "backups"
	}
}

func applyMaintainDefaults(m *MaintainConfig) {
	if m.PruneDeadAfter.Duration == 0 {
		m.PruneDeadAfter.Duration = 48 * time.Hour
	}
	if m.RefreshInterval.Duration == 0 {
		m.RefreshInterval.Duration = 6 * time.Hour
	}
	if m.SpeedtestInterval.Duration == 0 {
		m.SpeedtestInterval.Duration = 168 * time.Hour
	}
}

func validate(c *Config) error {
	if err := validateBasics(c); err != nil {
		return err
	}
	if err := validateSources(c); err != nil {
		return err
	}
	if err := validateSelect(c.Select); err != nil {
		return err
	}
	if err := validateFilter(c.Filter); err != nil {
		return err
	}
	if err := validateGeo(c.Geo); err != nil {
		return err
	}
	if err := validateMaintain(c.Maintain); err != nil {
		return err
	}
	return validateRender(c.Render)
}

func validateMaintain(m MaintainConfig) error {
	if m.PruneDeadAfter.Duration < 0 {
		return fmt.Errorf("maintain.prune_dead_after must be >= 0 (0 = default 48h), got %s", m.PruneDeadAfter.Duration)
	}
	for name, d := range map[string]Duration{
		"maintain.refresh_interval":   m.RefreshInterval,
		"maintain.speedtest_interval": m.SpeedtestInterval,
	} {
		if d.Duration < IntervalFloor {
			return fmt.Errorf("%s must be >= %s (too-fast rechecks hammer sources, probes, and the client), got %s",
				name, IntervalFloor, d.Duration)
		}
	}
	return nil
}

// parseableSchemes are the schemes the parser can normalize; the filter
// allowlist may only reference these.
var parseableSchemes = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "ss": true,
}

func validateFilter(f FilterConfig) error {
	if f.SourceCap < 0 {
		return fmt.Errorf("filter.source_cap must be >= 0 (0 = unlimited), got %d", f.SourceCap)
	}
	for _, p := range f.Protocols {
		if !parseableSchemes[p] {
			return fmt.Errorf("filter.protocols: scheme %q is not parseable (allowed: vless, vmess, trojan, ss)", p)
		}
	}
	return nil
}

func validateBasics(c *Config) error {
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if len(c.Sources) == 0 {
		return errors.New("at least one [sources.<id>] must be declared")
	}
	return nil
}

func validateSources(c *Config) error {
	enabled := 0
	for id, s := range c.Sources {
		if !s.IsEnabled() {
			continue
		}
		enabled++
		if s.Repo == "" {
			return fmt.Errorf("source %q: repo is required", id)
		}
		switch s.Discovery {
		case "github-contents":
		case "manifest":
			if s.Manifest == "" {
				return fmt.Errorf("source %q: discovery %q requires manifest path", id, "manifest")
			}
		default:
			return fmt.Errorf("source %q: discovery must be %q or %q, got %q", id, "github-contents", "manifest", s.Discovery)
		}
	}
	if enabled == 0 {
		return errors.New("no enabled sources")
	}
	return nil
}

func validateSelect(s SelectConfig) error {
	if s.PerCountryCap < 1 || s.PerCountryCap > 10 {
		return fmt.Errorf("select.per_country_cap must be 1..10 (design guidance K=3-5), got %d", s.PerCountryCap)
	}
	if s.SoftCap < 1 {
		return errors.New("select.soft_cap must be >= 1")
	}
	if s.Ceiling < s.SoftCap {
		return fmt.Errorf("select.ceiling (%d) must be >= soft_cap (%d)", s.Ceiling, s.SoftCap)
	}
	if s.CityExpandThreshold < 1 {
		return errors.New("select.city_expand_threshold must be >= 1")
	}
	return nil
}

func validateGeo(g GeoConfig) error {
	// L6: ip-api free tier is HTTP-only; https on the free endpoint fails.
	if !strings.HasPrefix(g.Endpoint, "http://") {
		return fmt.Errorf("geo.endpoint must use plain http (ip-api free tier is HTTP-only), got %q", g.Endpoint)
	}
	if g.BatchSize < 1 || g.BatchSize > 100 {
		return fmt.Errorf("geo.batch_size must be 1..100, got %d", g.BatchSize)
	}
	if g.PerMinute < 1 || g.PerMinute > 15 {
		return fmt.Errorf("geo.per_minute must be 1..15 (free-tier batch limit), got %d", g.PerMinute)
	}
	return nil
}

func validateRender(r RenderConfig) error {
	if r.StatsPort < 1024 || r.StatsPort > 65535 {
		return fmt.Errorf("render.stats_port must be a valid TCP port, got %d", r.StatsPort)
	}
	for i, route := range r.PoolRoutes {
		if route.Balancer == "" {
			return fmt.Errorf("render.pool_routes[%d]: balancer is required", i)
		}
		if len(route.Domains) == 0 {
			return fmt.Errorf("render.pool_routes[%d]: at least one domain is required", i)
		}
	}
	return nil
}

// ExpandHome replaces a leading ~ with the user home directory.
func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
