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

// Source is one upstream node feed descriptor (D9): repo id + discovery
// method. Since W10 this is a PROGRAMMATIC type only — the [sources.*]
// config table is gone (the ingest layer is Lua plugins; the host's
// github_files helper builds Source values from plugin arguments). Raw URLs
// are never pinned; discovery resolves current paths every wave.
type Source struct {
	Repo      string   `toml:"repo"`
	Discovery string   `toml:"discovery"` // "github-contents" | "manifest"
	Manifest  string   `toml:"manifest"`  // for discovery="manifest": manifest file path in repo
	Include   []string `toml:"include"`   // path patterns the discovery must fetch
}

// PluginsConfig points the pipeline at the Lua plugins dir (W10: the source
// ingest layer is plugin-based; sources are .lua files, not config tables).
type PluginsConfig struct {
	// Dir is the watched plugins directory. Empty = <data_dir>/plugins. The
	// embedded defaults materialize into it on FIRST RUN only; owner edits
	// and removals persist. A removed/re-named plugin = source disabled.
	Dir string `toml:"dir"`
	// RunTimeout bounds ONE plugin's entire fetch run (the Lua chunk + the
	// discover call, network included). gopher-lua has no hook/budget API, so
	// a spinning plugin (`while true do end`) cannot be interrupted from
	// inside the VM — the run timeout abandons it instead: the wave logs
	// LOUD, continues with the healthy plugins, and the abandoned goroutine
	// + Lua state leak (one per wave for a persistently hanging plugin — the
	// documented trade-off; the daemon-level WatchdogSec covers the hang
	// class honestly). Nil = unset → DefaultPluginRunTimeout (120s); an
	// explicit "0s" means UNBOUNDED (owner ruling: no artificial floor — a
	// legitimately slow plugin may take as long as it takes). Negative
	// values are structurally invalid.
	RunTimeout *Duration `toml:"run_timeout"`
}

// FetchConfig controls the fetch-stage client shared by pipeline discovery
// and the plugins' github_files helper.
type FetchConfig struct {
	Timeout     Duration `toml:"timeout"`
	Retries     int      `toml:"retries"`
	Concurrency int      `toml:"concurrency"`
	GitHubToken string   `toml:"github_token"` // optional, raises api.github.com rate limits
	// CacheMaxAge is the Gap-0 freshness window: a cached source body file
	// younger than this skips the network fetch for that file entirely
	// ("cache fresh, skipping"). Nil = unset → DefaultCacheMaxAge; an
	// explicit "0s" means always fetch. Negative values are structurally
	// invalid (sign correctness — W6 knobs carry no range bounds).
	CacheMaxAge *Duration `toml:"cache_max_age"`
	// APIBase overrides the GitHub API host (mirror support); empty = the
	// api.github.com default.
	APIBase string `toml:"api_base"`
	// RawBase overrides the raw-content host (mirror support); empty = the
	// raw.githubusercontent.com default.
	RawBase string `toml:"raw_base"`
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
	Path    string   `toml:"path"`
	Timeout Duration `toml:"timeout"`
	Threads int      `toml:"threads"`
	URL     string   `toml:"url"`
	// Speedtest opts every wave's probe into the -S throughput measurement.
	// W10 owner ruling: default TRUE (speed data on every wave; the
	// dedicated speedtest_interval wave remains for deeper runs). nil =
	// unset → true; an explicit false turns it off.
	Speedtest           *bool    `toml:"speedtest"`
	SpeedtestTimeout    Duration `toml:"speedtest_timeout"`
	CheckPreset         string   `toml:"check_preset"`
	URLSuccessThreshold float64  `toml:"url_success_threshold"`
	DBPath              string   `toml:"db_path"`
	MaxPassed           int      `toml:"max_passed"`
	// SkipFreshWithin skips re-probing nodes whose latest result is `passed`
	// and NEWER than this window (0s = probe everything, the default).
	// Negative values are structurally invalid.
	SkipFreshWithin Duration `toml:"skip_fresh_within"`
}

// IsSpeedtest resolves the speedtest default: on unless explicitly
// disabled (W10 owner ruling — the former false default flipped).
func (p ProbeConfig) IsSpeedtest() bool {
	return p.Speedtest == nil || *p.Speedtest
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
	// TieBandRTTTolerance widens/narrows the city tie-break band: a candidate
	// joins the head's band when its RTT ≤ head·tolerance. 0 → the
	// DefaultTieBandRTTTolerance; negative values are structurally invalid.
	// Deliberately unbounded (owner ruling — the analyst's 1.0–3.0 range is
	// rejected).
	TieBandRTTTolerance float64 `toml:"tie_band_rtt_tolerance"`
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
	// PoolInboundTags lists the inbound tags every pool routing rule carries.
	// Render-time validation: every listed tag must exist among the
	// template's inbound tags, or the render fails loud naming the missing
	// tag (closes the silent D2 fall-through path). Default:
	// socks-in,http-in.
	PoolInboundTags []string `toml:"pool_inbound_tags"`
	// ObservatoryInterval is the Plan-A pool observatory probeInterval — a
	// STRING PASSTHROUGH rendered verbatim (default "60s") so any duration
	// spelling the core accepts works. Deliberately unbounded (owner ruling —
	// the ≥30s recommendation is rejected); garbage values fail the xray
	// -test gate loud.
	ObservatoryInterval string `toml:"observatory_interval"`
	// TCPMaxSeg is the sockopt.tcpMaxSeg value emitted MANDATORILY on every
	// rendered streamSettings (the owner-calibrated anti-TSPU clamp — the
	// emission never becomes optional, only the value is configurable).
	// Negative values are structurally invalid; otherwise unbounded.
	TCPMaxSeg int `toml:"tcp_max_seg"`
	// TLSFingerprint is the uTLS client fingerprint on tls/reality settings
	// (default firefox). NO allowlist — a bad value fails the xray -test gate
	// loud and safe.
	TLSFingerprint string `toml:"tls_fingerprint"`
	// BalancerTolerance is the leastLoad tolerance on country AND city pool
	// balancers (default 0.2). Deliberately unbounded (owner ruling).
	BalancerTolerance float64 `toml:"balancer_tolerance"`
}

// ActivateConfig controls the -test gate, backup, and atomic replace.
type ActivateConfig struct {
	Target    string `toml:"target"`
	XrayBin   string `toml:"xray_bin"`
	AssetDir  string `toml:"asset_dir"` // XRAY_LOCATION_ASSET for -test; default = template dir
	BackupDir string `toml:"backup_dir"`
	// TestTimeout bounds the `xray run -test` child process. Nil = unset →
	// DefaultTestTimeout (30s); an explicit "0s" means NO deadline (current
	// behavior, documented). Negative values are structurally invalid.
	TestTimeout *Duration `toml:"test_timeout"`
	// ServiceName is the systemd unit named in the printed restart hint
	// (this package never restarts anything itself). Default:
	// xray-raw.service.
	ServiceName string `toml:"service_name"`
	// BackupKeep caps backup retention: after a successful new backup write,
	// only the BackupKeep newest .bak-<ts> files are kept (0 = unlimited,
	// the default). Deletion failures are loud — rollback depth is never
	// silently reduced. Negative values are structurally invalid.
	BackupKeep int `toml:"backup_keep"`
}

// MaintainConfig controls the W4 maintenance wave (DESIGN.md §4.9).
type MaintainConfig struct {
	// PruneDeadAfter removes a geo-base record that is not alive and whose
	// last_probe is older than this window (default 48h).
	PruneDeadAfter Duration `toml:"prune_dead_after"`
	// RefreshInterval is the refresh-wave recheck period (default 1h since
	// W10, floor 5m). install is unaffected — the watch daemon reads the
	// config live, so a period change needs no re-install.
	RefreshInterval Duration `toml:"refresh_interval"`
	// SpeedtestInterval is the speedtest-wave recheck period (default 168h,
	// floor 5m) — rendered into the speedtest timer's OnUnitActiveSec.
	SpeedtestInterval Duration `toml:"speedtest_interval"`
	// StatsTimeout bounds one `xray api statsquery` exec — the single knob
	// behind BOTH the pipeline's stage timeout and the stats package's inner
	// fallback guard (the old 5s/10s inconsistency is gone). Default 10s;
	// negative values are structurally invalid.
	StatsTimeout Duration `toml:"stats_timeout"`
	// PruneBackupKeep caps the geo-base .bak-<ts> retention the same way
	// activate.backup_keep caps activation backups (0 = unlimited, the
	// default; deletion failures are loud). Resolves parked item M3.
	PruneBackupKeep int `toml:"prune_backup_keep"`
}

// HTTPConfig carries settings shared by every pipeline HTTP client (fetch
// discovery/downloads and geo enrichment) — one knob per concern, so the
// User-Agent exists in exactly one place.
type HTTPConfig struct {
	// UserAgent is THE pipeline User-Agent string (all three historical
	// hardcoded sites read this one knob). Default: DefaultUserAgent —
	// today's exact string.
	UserAgent string `toml:"user_agent"`
}

// IntervalFloor is the minimum recheck period for both maintenance waves:
// faster loops would hammer the sources, the probe origin, and the live
// client for no selection benefit.
const IntervalFloor = 5 * time.Minute

// W6 knob defaults — the single literal for every default value, referenced
// by the consumers (render/fetch/geo/stats/activate fallbacks included) so
// the default can never drift between layers. Defaults preserve today's
// behavior byte-for-byte (owner binding ruling on the W6 wave).
const (
	DefaultAPIBase             = "https://api.github.com"
	DefaultRawBase             = "https://raw.githubusercontent.com"
	DefaultUserAgent           = "public_vpn (pipeline; contact: owner)"
	DefaultCacheMaxAge         = 6 * time.Hour
	DefaultTestTimeout         = 30 * time.Second
	DefaultStatsTimeout        = 10 * time.Second
	DefaultObservatoryInterval = "60s"
	DefaultTLSFingerprint      = "firefox"
	DefaultTCPMaxSeg           = 1440
	DefaultBalancerTolerance   = 0.2
	DefaultTieBandRTTTolerance = 1.2
	DefaultServiceName         = "xray-raw.service"
	// DefaultPluginRunTimeout bounds one plugin's whole fetch run (the
	// [plugins].run_timeout default): generous enough for a nested
	// multi-subscription fetch, small enough that a hung plugin wastes one
	// wave slot, not the whole schedule.
	DefaultPluginRunTimeout = 120 * time.Second
	// DefaultRefreshInterval is the W10 owner ruling: the refresh wave
	// rechecks hourly (was 6h in the timer era).
	DefaultRefreshInterval = time.Hour
)

// defaultPoolInboundTags is the render.pool_inbound_tags default (the tags
// every pool routing rule has carried since W3).
var defaultPoolInboundTags = []string{"socks-in", "http-in"}

// DefaultPoolInboundTags returns a copy of the pool_inbound_tags default.
func DefaultPoolInboundTags() []string {
	return append([]string(nil), defaultPoolInboundTags...)
}

// Config is the pipeline configuration root.
type Config struct {
	DataDir  string         `toml:"data_dir"`
	Plugins  PluginsConfig  `toml:"plugins"`
	Fetch    FetchConfig    `toml:"fetch"`
	Filter   FilterConfig   `toml:"filter"`
	Probe    ProbeConfig    `toml:"probe"`
	Geo      GeoConfig      `toml:"geo"`
	Select   SelectConfig   `toml:"select"`
	Render   RenderConfig   `toml:"render"`
	Activate ActivateConfig `toml:"activate"`
	Maintain MaintainConfig `toml:"maintain"`
	HTTP     HTTPConfig     `toml:"http"`
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

// Load reads, migration-checks, strict-decodes, defaults, and validates the
// config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := checkRemovedSections(raw); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
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

// checkRemovedSections fails LOUD on the removed [sources.*] layout, naming
// the exact migration path (W10: the ingest layer is Lua plugins — there is
// no silent fallback chain from the old section).
func checkRemovedSections(raw []byte) error {
	probe := map[string]any{}
	decodeErr := toml.NewDecoder(strings.NewReader(string(raw))).Decode(&probe)
	if decodeErr == nil {
		if _, ok := probe["sources"]; ok {
			return errors.New(
				"the [sources.*] section was removed — the source-ingest layer is now Lua plugins " +
					"(W10). Delete every [sources.<id>] table and use the [plugins] section " +
					"([plugins] dir = \"...\", default <data_dir>/plugins). The built-in plugins " +
					"(matin, epodonios, radikal, haker, stintikvpn) materialize into the plugins " +
					"dir on first run — edit or add .lua files there; a new provider is a new " +
					".lua file, no Go rebuild")
		}
	}
	return nil // a lenient-decode failure is the strict decode's problem below
}

func applyDefaults(c *Config) {
	applyPluginsDefaults(c)
	applyFetchDefaults(&c.Fetch)
	applyFilterDefaults(&c.Filter)
	applyProbeDefaults(&c.Probe)
	applyGeoDefaults(&c.Geo)
	applySelectDefaults(&c.Select)
	applyRenderDefaults(&c.Render)
	applyActivateDefaults(&c.Activate)
	applyMaintainDefaults(&c.Maintain)
	applyHTTPDefaults(&c.HTTP)
}

// applyPluginsDefaults resolves the plugins dir default: <data_dir>/plugins,
// and the run timeout default (nil = unset → DefaultPluginRunTimeout; an
// explicit "0s" stays 0 = unbounded).
func applyPluginsDefaults(c *Config) {
	if c.Plugins.Dir == "" {
		c.Plugins.Dir = filepath.Join(c.DataDir, "plugins")
	}
	if c.Plugins.RunTimeout == nil {
		c.Plugins.RunTimeout = &Duration{Duration: DefaultPluginRunTimeout}
	}
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
	if f.CacheMaxAge == nil {
		f.CacheMaxAge = &Duration{Duration: DefaultCacheMaxAge}
	}
	if f.APIBase == "" {
		f.APIBase = DefaultAPIBase
	}
	if f.RawBase == "" {
		f.RawBase = DefaultRawBase
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
	// SkipFreshWithin: no default application — 0s IS the default (probe
	// everything); an explicit 0s and an absent key are the same behavior.
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
	if s.TieBandRTTTolerance == 0 {
		s.TieBandRTTTolerance = DefaultTieBandRTTTolerance
	}
}

// dedupeStrings collapses duplicate entries preserving order — the first
// occurrence wins, later duplicates are dropped.
func dedupeStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func applyRenderDefaults(r *RenderConfig) {
	// Normalize duplicates at the load boundary (M-4): "socks-in" twice must
	// not render a duplicated inboundTag — first occurrence wins, order is
	// preserved.
	r.PoolInboundTags = dedupeStrings(r.PoolInboundTags)
	if r.Template == "" {
		r.Template = "~/projects/xray-raw/config.json"
	}
	if r.OutputDir == "" {
		r.OutputDir = "rendered"
	}
	if r.StatsPort == 0 {
		r.StatsPort = 15490
	}
	if len(r.PoolInboundTags) == 0 {
		r.PoolInboundTags = DefaultPoolInboundTags()
	}
	if r.ObservatoryInterval == "" {
		r.ObservatoryInterval = DefaultObservatoryInterval
	}
	if r.TCPMaxSeg == 0 {
		r.TCPMaxSeg = DefaultTCPMaxSeg
	}
	if r.TLSFingerprint == "" {
		r.TLSFingerprint = DefaultTLSFingerprint
	}
	if r.BalancerTolerance == 0 {
		r.BalancerTolerance = DefaultBalancerTolerance
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
	if a.TestTimeout == nil {
		a.TestTimeout = &Duration{Duration: DefaultTestTimeout}
	}
	if a.ServiceName == "" {
		a.ServiceName = DefaultServiceName
	}
	// BackupKeep: no default application — 0 IS the default (unlimited).
}

func applyMaintainDefaults(m *MaintainConfig) {
	if m.PruneDeadAfter.Duration == 0 {
		m.PruneDeadAfter.Duration = 48 * time.Hour
	}
	if m.RefreshInterval.Duration == 0 {
		m.RefreshInterval.Duration = DefaultRefreshInterval
	}
	if m.SpeedtestInterval.Duration == 0 {
		m.SpeedtestInterval.Duration = 168 * time.Hour
	}
	if m.StatsTimeout.Duration == 0 {
		m.StatsTimeout.Duration = DefaultStatsTimeout
	}
	// PruneBackupKeep: no default application — 0 IS the default (unlimited).
}

func applyHTTPDefaults(h *HTTPConfig) {
	if h.UserAgent == "" {
		h.UserAgent = DefaultUserAgent
	}
}

func validate(c *Config) error {
	if err := validateBasics(c); err != nil {
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
	if err := validateRender(c.Render); err != nil {
		return err
	}
	if err := validateActivate(c.Activate); err != nil {
		return err
	}
	if c.Fetch.CacheMaxAge != nil {
		if err := validateNonNegative("fetch.cache_max_age", c.Fetch.CacheMaxAge.Duration); err != nil {
			return err
		}
	}
	if c.Plugins.RunTimeout != nil {
		if err := validateNonNegative("plugins.run_timeout", c.Plugins.RunTimeout.Duration); err != nil {
			return err
		}
	}
	return validateNonNegative("probe.skip_fresh_within", c.Probe.SkipFreshWithin.Duration)
}

// validateNonNegative is the W6 structural check: a negative number is
// sign-invalid, period. It is NOT a range bound — every non-negative value is
// accepted, per the owner ruling that rejected all floor/ceiling validation.
func validateNonNegative(name string, v any) error {
	const reason = "negative is structurally invalid, not a range bound"
	switch n := v.(type) {
	case time.Duration:
		if n < 0 {
			return fmt.Errorf("%s must be >= 0 (%s), got %s", name, reason, n)
		}
	case int:
		if n < 0 {
			return fmt.Errorf("%s must be >= 0 (%s), got %d", name, reason, n)
		}
	case float64:
		if n < 0 {
			return fmt.Errorf("%s must be >= 0 (%s), got %g", name, reason, n)
		}
	}
	return nil
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
	// W6: sign correctness only. stats_timeout carries no floor — an owner
	// who wants a 1s stats poll gets one. The 5m IntervalFloor above applies
	// ONLY to refresh_interval/speedtest_interval (W5, owner-approved).
	if err := validateNonNegative("maintain.stats_timeout", m.StatsTimeout.Duration); err != nil {
		return err
	}
	return validateNonNegative("maintain.prune_backup_keep", m.PruneBackupKeep)
}

// parseableSchemes are the schemes the parser can normalize; the filter
// allowlist may only reference these. hysteria2 parses like ss: OPT-IN via
// [filter].protocols — the default acceptance list is unchanged.
var parseableSchemes = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "ss": true,
	"hysteria2": true,
}

func validateFilter(f FilterConfig) error {
	if f.SourceCap < 0 {
		return fmt.Errorf("filter.source_cap must be >= 0 (0 = unlimited), got %d", f.SourceCap)
	}
	for _, p := range f.Protocols {
		if !parseableSchemes[p] {
			return fmt.Errorf("filter.protocols: scheme %q is not parseable (allowed: vless, vmess, trojan, ss, hysteria2)", p)
		}
	}
	return nil
}

func validateBasics(c *Config) error {
	if c.DataDir == "" {
		return errors.New("data_dir is required")
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
	return validateNonNegative("select.tie_band_rtt_tolerance", s.TieBandRTTTolerance)
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
	if err := validateNonNegative("render.tcp_max_seg", r.TCPMaxSeg); err != nil {
		return err
	}
	if err := validateNonNegative("render.balancer_tolerance", r.BalancerTolerance); err != nil {
		return err
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

// validateActivate covers the W6 [activate] knobs: sign correctness only —
// test_timeout has no floor (0s = no deadline is a documented mode) and
// backup_keep has no ceiling.
func validateActivate(a ActivateConfig) error {
	if a.TestTimeout != nil {
		if err := validateNonNegative("activate.test_timeout", a.TestTimeout.Duration); err != nil {
			return err
		}
	}
	return validateNonNegative("activate.backup_keep", a.BackupKeep)
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
