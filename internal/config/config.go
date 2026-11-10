// Package config loads and validates the single source of truth for the
// pipeline: a TOML file (owner convention: everything in config, never env
// vars). Unknown keys fail loudly — no silent-ignore configuration drift.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	// discover call, network included). Execution is bound by context
	// cancellation via gopher-lua LState.SetContext, terminating runaway scripts.
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
	// MaxConsecutiveFailures is the plugin circuit breaker (round-7 item 6,
	// owner spec: «автоотключение неотвечающих плагинов, 5 ошибок по
	// дефолту отключают его»): N consecutive FAILURE events (a run-timeout
	// abandonment or a loud run error) auto-disable the plugin — it is
	// excluded from subsequent waves and stays disabled until a successful
	// run resets the counter or the file is edited (a watchdog reload =
	// owner touched it = fresh chance). Nil = unset →
	// DefaultMaxConsecutiveFailures (5); an explicit 0 means UNLIMITED —
	// the breaker is OFF (same owner no-floor/ceiling ruling class as
	// run_timeout "0s"). Negative values are structurally invalid.
	MaxConsecutiveFailures *int `toml:"max_consecutive_failures"`
	// MaxDuplicatePercent is the per-plugin duplicate threshold: percent of
	// nodes that have the same key as nodes from other plugins. Nil = unset
	// (disabled by default); an explicit 0 means DISABLED; a positive value
	// enables the check. Negative values are structurally invalid. No upper
	// bound (owner ruling).
	MaxDuplicatePercent *float64 `toml:"max_duplicate_percent"`
	// MinLivePercent is the per-plugin minimum live nodes threshold: percent
	// of nodes that are alive after probing. Nil = unset (disabled by
	// default); an explicit 0 means DISABLED; a positive value enables the
	// check. Negative values are structurally invalid. No upper bound (owner
	// ruling).
	MinLivePercent *float64 `toml:"min_live_percent"`
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
	// Protocols is the scheme allowlist (acceptance policy). Default: every
	// rendered protocol — vless,vmess,trojan,ss,hysteria2 (round-7 owner
	// ruling 14c). The reality/tls security requirement and the
	// allow_insecure=false default below still apply on top.
	Protocols []string `toml:"protocols"`
	// AllowInsecure admits links carrying allowInsecure/insecure=1|true
	// instead of dropping them. Default false (denial in filter). The
	// renderer has no allowInsecure capability on core 26.3.27 — the feature
	// was removed upstream (migrated to pinnedPeerCertSha256) — so an
	// admitted link only loses the param (rendered as a loud drop-report
	// entry, never silently).
	AllowInsecure bool `toml:"allow_insecure"`
}

// ProbeConfig controls the real-xray probe wave (W14): every probed node
// gets a temporary single-node xray instance (the SAME infrastructure the
// check stage uses — one factory, no drift), so liveness and speed
// measurement uniformly cover every rendered protocol, hysteria2 included.
// The xray binary is [activate].xray_bin (one knob, shared with check).
type ProbeConfig struct {
	Timeout Duration `toml:"timeout"`
	// Threads is the parallel temp-instance worker count (each worker owns
	// one node's probe; instance BOOTs are serialized by the factory's boot
	// mutex, the HTTP phase runs fully parallel). Default 12 (wave3: lowered
	// from 32 — 12 concurrent batches keep the boot ceiling saturated while
	// bounding the instantaneous process count).
	Threads int `toml:"threads"`
	// Attempts is the HTTP GET count per node per wave. Default 3 (checker
	// parity): all attempts success = `passed`, some = `semi-passed`, none =
	// `failed`. 0 = unset → the default; negative values are structurally
	// invalid.
	Attempts int    `toml:"attempts"`
	URL      string `toml:"url"`
	// Speedtest opts every wave's probe into the throughput measurement: a
	// sample download from SpeedtestURL through the node's temp instance →
	// bytes/time → speed_bps. ROUND-8 OWNER RULING (supersedes the W10
	// default-ON): the default is FALSE — refresh waves are probe-only.
	// «Только спидтест выключи». nil = unset → false; an explicit true keeps
	// speed-testing every wave; the dedicated weekly speedtest wave
	// ([maintain].speedtest_interval) carries -S semantics regardless of
	// this knob.
	Speedtest *bool `toml:"speedtest"`
	// SpeedtestURL is the sample the speedtest downloads (default: the
	// Cloudflare 25 MB down endpoint).
	SpeedtestURL     string   `toml:"speedtest_url"`
	SpeedtestTimeout Duration `toml:"speedtest_timeout"`
	// SkipFreshWithin skips re-probing nodes whose latest result is `passed`
	// and NEWER than this window (0s = probe everything, the default).
	// Negative values are structurally invalid.
	SkipFreshWithin Duration `toml:"skip_fresh_within"`
	// BatchSize is the number of nodes sharing one xray process in batch
	// probe mode (0 = unset → DefaultProbeBatchSize). Negative values are
	// structurally invalid. No upper bound (owner ruling).
	BatchSize int `toml:"batch_size"`
	// BatchConcurrency is the number of nodes probed concurrently inside
	// one batch (0 = unset → DefaultProbeBatchConcurrency). Negative values
	// are structurally invalid. No upper bound (owner ruling).
	BatchConcurrency int `toml:"batch_concurrency"`
	// CalibrationEnabled turns dynamic timeout calibration on/off (default true).
	CalibrationEnabled bool `toml:"calibration_enabled"`
	// CalibrationBase is the base timeout in seconds used when no calibration
	// state exists yet (default 10).
	CalibrationBase float64 `toml:"calibration_base"`
	// CalibrationMargin is the safety margin in seconds added to p95 (default 1).
	CalibrationMargin float64 `toml:"calibration_margin"`
	// Granularity selects the calibration key granularity: "global", "country"
	// (default), or "city". The fallback chain city -> country -> global ->
	// base protects against sparse data.
	Granularity string `toml:"granularity"`
	// TCPPrefilter gates the wave-1 TCP pre-filter stage: before any temp
	// xray boot, every unique node endpoint gets ONE plain TCP dial
	// (bounded by tcp_prefilter_timeout, DNS included); a failed dial means
	// no TCP listener — an xray TCP transport cannot connect either — so the
	// node is excluded from THIS wave with a per-reason drop report and its
	// previous probe results stay untouched. UDP-transport nodes (hysteria2,
	// kcp/mkcp/quic transports) bypass — a TCP dial says nothing about a UDP
	// transport. Default TRUE (owner-approved probe-optimization program,
	// 2026-11-06: the pool is ~95% dead and every skipped endpoint saves a
	// full xray boot); an explicit false keeps the stage off (zero dials,
	// byte-identical to the pre-stage behavior). Tri-state like
	// [geo].unlock_probes: nil (absent) materializes as true in
	// applyProbeDefaults.
	TCPPrefilter *bool `toml:"tcp_prefilter"`
	// TCPPrefilterWorkers is the pre-filter's concurrent-dial count (a plain
	// SYN handshake is cheap — no core instance). 0 = unset →
	// DefaultProbePrefilterWorkers. Negative values are structurally
	// invalid; no upper bound (owner ruling).
	TCPPrefilterWorkers int `toml:"tcp_prefilter_workers"`
	// TCPPrefilterTimeout bounds ONE pre-filter TCP dial, DNS resolution
	// included. 0 = unset → DefaultProbePrefilterTimeout. Negative values
	// are structurally invalid; no upper bound (owner ruling).
	TCPPrefilterTimeout Duration `toml:"tcp_prefilter_timeout"`
}

// TCPPrefilterEnabled resolves the tri-state knob: nil (absent) = true — the
// owner default (the TCP pre-filter runs on every wave); an explicit false
// keeps the stage off. applyProbeDefaults materializes the absent case, so
// loaded configs and hand-built configs agree.
func (p ProbeConfig) TCPPrefilterEnabled() bool {
	return p.TCPPrefilter == nil || *p.TCPPrefilter
}

// IsSpeedtest resolves the speedtest default: OFF unless explicitly enabled
// (round-8 owner ruling «Только спидтест выключи» — supersedes the former
// W10 true default). The dedicated weekly speedtest wave is unaffected: the
// scheduler passes -S explicitly for it (probeOptions ORs the wave flag).
func (p ProbeConfig) IsSpeedtest() bool {
	return p.Speedtest != nil && *p.Speedtest
}

// GeoConfig controls the exit-classification knobs (W11 self-report design;
// W16 adds the HTTPS third hop; since the classification merge the pass
// rides the probe wave): every alive node asks geo endpoints THROUGH ITS
// OWN TUNNEL, so the requests originate from thousands of distinct node IPs and
// per-source budgets never pool — the old aggregate batch clamp
// (endpoint/batch_size/per_minute, retired loud) is gone in principle. The
// failure ladder per node: (1) HTTP ip-api self-report, (2) HTTPS self-geo
// via [geo].https_url (default ipinfo.io/json), (3) the through-tunnel DoH
// view (o-o.myaddr TXT → the exit network's resolver IP → ip-api single-IP
// lookup through the same tunnel) via [geo].doh_url, (4) unknown.
type GeoConfig struct {
	// DoHURL is the DoH endpoint the fallback queries THROUGH the tunnel.
	// Must be https (DoH is a TLS protocol — structural check, not a range
	// bound). Default: DefaultDoHURL.
	DoHURL string `toml:"doh_url"`
	// HTTPSURL is the hop-2 HTTPS self-geo endpoint: a keyless URL that
	// answers "who is asking" over TLS (default ipinfo.io/json — free tier,
	// rate-limited per source IP like ip-api, and every node is its own
	// source). Structural https check only — ANY https endpoint is accepted
	// verbatim (owner ruling: a plain string knob, no allowlist). Default:
	// DefaultGeoHTTPSURL.
	HTTPSURL      string `toml:"https_url"`
	ExitIPEchoURL string `toml:"exit_ip_echo_url"`
	// TTL is the legacy geo-freshness knob of the REMOVED geo stage's
	// exit-IP cache (classification now refreshes every wave — the 24h
	// freshness gates are gone). Still live for `assay check` (GeoTTL).
	TTL Duration `toml:"ttl"`
	// MaxTTL was the rate-limit retry-sleep cap of the REMOVED geo-stage
	// batch fallback (the local-machine ip-api overlay is gone with the
	// stage). Retained for config compatibility; classification honors the
	// 429 X-Ttl by falling through to the HTTPS/DoH rungs instead.
	MaxTTL Duration `toml:"max_ttl"`
	// Timeout is the per-node FLOOR (minimum effective timeout) of ONE
	// through-tunnel classification request. The effective per-request
	// timeout is RTT-adaptive (owner order 2026-11-08):
	// clamp(adaptiveRTTMultiplier x probe RTT, Timeout,
	// adaptiveTimeoutCeiling) — see geo.classifyTimeout. A node with no
	// usable probe RTT (rttMs <= 0 or NaN) fails safe to this floor.
	Timeout Duration `toml:"timeout"`
	// SelfReportConcurrency is the maximum number of concurrent temp
	// instances during geo self-report (each is a full xray process; 0 =
	// unset → DefaultGeoSelfReportConcurrency). Negative values are
	// structurally invalid. No upper bound (owner ruling).
	SelfReportConcurrency int `toml:"self_report_concurrency"`
	// UnlockProbes gates the merged classification pass (owner order
	// 2026-11-07 «сразу на чеке»): every node the probe stage proves ALIVE
	// gets the FULL battery — the ip-api self-report ladder (country/city/
	// ISP/AS + hosting/proxy flags) plus the unlock battery v2 (cftrace
	// echo, 3-source consensus, DNS-over-TCP, media probes, hijack
	// detection, OK_FLAKY retry, STUN for hysteria2) — THROUGH THE SAME HOT
	// xray instance the probe just passed, before that instance is torn
	// down; the geo-base records refresh every wave. The separate geo and
	// unlock stages with their 24h freshness gates are REMOVED (merged into
	// the probe batch lifecycle). Default TRUE (owner ruling 2026-11-06
	// stands); an explicit false is the escape hatch = probe-only wave
	// (zero classification requests; the geo-base keeps its last state).
	// Tri-state like auto_restart: nil (absent) materializes as true in
	// applyGeoDefaults.
	UnlockProbes *bool `toml:"unlock_probes"`
}

// UnlockProbesEnabled resolves the tri-state knob: nil (absent) = true —
// the owner default-flip ruling (unlock probes run by default); an
// explicit false keeps the stage off. applyGeoDefaults materializes the
// absent case, so loaded configs and hand-built configs agree.
func (g GeoConfig) UnlockProbesEnabled() bool {
	return g.UnlockProbes == nil || *g.UnlockProbes
}

// SelectConfig controls the ranking caps (D5/D7; W19 unbounded flip):
// countries unlimited; every cap knob defaults to UNBOUNDED — absent/0 means
// ALL alive nodes go active (the owner order «259 живых, значит 259
// раскидываются по балансирам стран и городов»), the unknown-geo group
// included. An explicit positive value keeps its D7 cap semantics; the
// city-expansion threshold is moot when the selection is unbounded.
type SelectConfig struct {
	// PerCountryCap caps one country's active nodes (the old K). 0 =
	// UNLIMITED (W19 default) — every alive node of every country lands in
	// the render. Negative values are structurally invalid.
	PerCountryCap int `toml:"per_country_cap"`
	// SoftCap is the global selection cap. 0 = UNBOUNDED (W19 default): all
	// alive nodes go active. Negative values are structurally invalid.
	SoftCap int `toml:"soft_cap"`
	// CityExpandThreshold fires the D7 expansion (cap grows to cover city
	// diversity). 0 = expansion OFF (W19 default — moot when the selection
	// is unbounded anyway). Only meaningful with an explicit soft_cap.
	CityExpandThreshold int `toml:"city_expand_threshold"`
	// Ceiling bounds the D7 expansion. 0 = UNBOUNDED (W19 default — the
	// expansion is bounded only by the alive count). Only meaningful with
	// an explicit soft_cap. Negative values are structurally invalid.
	Ceiling int `toml:"ceiling"`
	// TieBandRTTTolerance widens/narrows the city tie-break band: a candidate
	// joins the head's band when its RTT ≤ head·tolerance. 0 → the
	// DefaultTieBandRTTTolerance; negative values are structurally invalid.
	// Deliberately unbounded (owner ruling — the analyst's 1.0–3.0 range is
	// rejected).
	TieBandRTTTolerance float64 `toml:"tie_band_rtt_tolerance"`
	// OnlyClean filters the candidate pool to nodes whose geo record has
	// hosting_flag=false AND proxy_flag=false (clean IPs only). Nil/unset =
	// false (no filtering); explicit true = filter. When enabled, all
	// selected nodes are clean, so render skips the redundant clean-*
	// balancers and renders only the common (all) balancers.
	OnlyClean *bool `toml:"only_clean"`
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
	// STRING PASSTHROUGH rendered verbatim when set, so any duration spelling
	// the core accepts works. ABSENT (empty, the W19 default) = ADAPTIVE: the
	// render computes the interval from the active count (max(60s,
	// ceil(N×200ms)) — probes/sec ≤ 5, code-owned budget, no new knob).
	// Deliberately unbounded (owner ruling — the ≥30s recommendation is
	// rejected); garbage values fail the xray -test gate loud.
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
	// (the manual path — auto_restart = false only; the W13 auto path is
	// byte-pinned to DefaultServiceName and refuses any other unit loud).
	// Default: xray-raw.service.
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
	// SpeedtestInterval is the speedtest-wave recheck period — a TRI-STATE
	// pointer (round-8): absent (nil) → DefaultSpeedtestInterval (168h, the
	// weekly wave exists and carries -S); an explicit "0s" → 0 = the
	// speedtest wave is DISABLED entirely (the scheduler never schedules
	// one — the owner's «выключи» made real at the schedule level); a
	// positive value below the 5m floor fails loud. Negative values are
	// structurally invalid.
	SpeedtestInterval *Duration `toml:"speedtest_interval"`
	// StatsTimeout bounds one `xray api statsquery` exec — the single knob
	// behind BOTH the pipeline's stage timeout and the stats package's inner
	// fallback guard (the old 5s/10s inconsistency is gone). Default 10s;
	// negative values are structurally invalid.
	StatsTimeout Duration `toml:"stats_timeout"`
	// PruneBackupKeep caps the geo-base .bak-<ts> retention the same way
	// activate.backup_keep caps activation backups (0 = unlimited, the
	// default; deletion failures are loud). Resolves parked item M3.
	PruneBackupKeep int `toml:"prune_backup_keep"`
	// AutoRestart restarts the live xray client through the byte-pinned
	// allowlist executor (internal/restart) after every gated activation —
	// the W13 owner ruling: hands-off, zero manual restarts ever. Nil
	// (unset) defaults to TRUE; an explicit false restores the W4-era
	// manual semantics (the printed restart hint instead of a restart).
	AutoRestart *bool `toml:"auto_restart"`
}

// AutoRestartEnabled resolves the tri-state knob: unset = true (hands-off
// is the approved premise), explicit false = manual-restart semantics.
func (m MaintainConfig) AutoRestartEnabled() bool {
	return m.AutoRestart == nil || *m.AutoRestart
}

// DefaultSpeedtestInterval is the speedtest-wave default: weekly (168h).
const DefaultSpeedtestInterval = 168 * time.Hour

// SpeedtestWavePeriod resolves the schedule-level speedtest-wave period:
// nil (unset — a hand-built struct without defaults) and an explicit "0s"
// both resolve to 0 = no speedtest wave; a loaded/configless config always
// carries the materialized DefaultSpeedtestInterval for the absent case
// (applyMaintainDefaults). Zero-alloc view over the pointer.
func (m MaintainConfig) SpeedtestWavePeriod() time.Duration {
	if m.SpeedtestInterval == nil {
		return 0
	}
	return m.SpeedtestInterval.Duration
}

// SpeedtestWaveEnabled reports whether the speedtest wave exists on the
// schedule: false for nil (unset) and explicit "0s", true for any positive
// period (a loaded config without the key materializes 168h here).
func (m MaintainConfig) SpeedtestWaveEnabled() bool {
	return m.SpeedtestWavePeriod() > 0
}

// SelfUpdateConfig controls the watch daemon's self-update detection: it
// watches its own binary on disk and, on a confirmed change, restarts via
// systemd at the next wave boundary.
type SelfUpdateConfig struct {
	// Enabled turns binary-change detection on/off. Default: true.
	Enabled bool `toml:"enabled"`
	// CheckInterval is how often the daemon stat-checks its own binary in
	// addition to fsnotify (default 30s).
	CheckInterval Duration `toml:"check_interval"`
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
	DefaultUserAgent           = "assay (pipeline; contact: owner)"
	DefaultCacheMaxAge         = 6 * time.Hour
	DefaultTestTimeout         = 30 * time.Second
	DefaultStatsTimeout        = 10 * time.Second
	DefaultTLSFingerprint      = "firefox"
	DefaultTCPMaxSeg           = 1440
	DefaultBalancerTolerance   = 0.2
	DefaultTieBandRTTTolerance = 1.2
	DefaultServiceName         = "xray-raw.service"
	// DefaultDoHURL is the [geo].doh_url default: the DoH endpoint the geo
	// fallback queries through the tunnel (the same endpoint the checker's
	// doh-via-exit view uses — one DoH host across the pipeline).
	DefaultDoHURL = "https://dns.google/resolve"
	// DefaultGeoHTTPSURL is the [geo].https_url default (the W16 hop-2
	// HTTPS self-geo): ipinfo.io/json is keyless, serves the caller's own
	// geo over TLS, and is free-tier rate-limited per source IP — the same
	// no-aggregate-limit argument as the W11 self-report (every node is its
	// own source). Field surface verified live 2026-10-29.
	DefaultGeoHTTPSURL = "https://ipinfo.io/json"
	// DefaultGeoExitIPEchoURL is the [geo].exit_ip_echo_url default: an
	// HTTPS endpoint that echoes the caller's exit IP (keyless, TLS-only).
	DefaultGeoExitIPEchoURL = "https://icanhazip.com"
	// DefaultPluginRunTimeout bounds one plugin's whole fetch run (the
	// [plugins].run_timeout default): generous enough for a nested
	// multi-subscription fetch, small enough that a hung plugin wastes one
	// wave slot, not the whole schedule.
	DefaultPluginRunTimeout = 120 * time.Second
	// DefaultMaxConsecutiveFailures is the plugin circuit breaker default
	// (round-7 item 6, owner spec): 5 consecutive failures auto-disable a
	// plugin. 0 (explicit) = unlimited — the breaker is OFF.
	DefaultMaxConsecutiveFailures = 5
	// DefaultRefreshInterval is the W10 owner ruling: the refresh wave
	// rechecks hourly (was 6h in the timer era).
	DefaultRefreshInterval = time.Hour
	// DefaultProbeThreads is the W14 probe default: parallel temp-instance
	// workers (batches in flight). 12 saturates the factory's
	// boot-serialization ceiling (~10 boots/sec) while keeping the
	// instantaneous process count bounded (12 concurrent real xray processes
	// max). The owner's explicit value in prod config (20) is untouched.
	DefaultProbeThreads = 12
	// DefaultProbeAttempts is the W14 probe default (checker parity): all
	// attempts success = `passed`, some = `semi-passed`, none = `failed`.
	DefaultProbeAttempts = 3
	// DefaultProbeSpeedtestURL is the W14 speedtest sample: the Cloudflare
	// 25 MB down endpoint, downloaded through each node's tunnel.
	DefaultProbeSpeedtestURL = "https://speed.cloudflare.com/__down?bytes=25000000"
	// DefaultProbeBatchSize is the default number of nodes sharing one xray
	// process in batch probe mode (0 in config → this default). Big-batch
	// model: one temp xray holds 1000 inbound+outbound pairs — boot ≈0.225s,
	// RSS ≈49MB (+13.3kB/pair), fds ≈ N+6 (spike-verified on the box's xray
	// 26.3.27) — so a wave boots a handful of processes instead of hundreds.
	// A batch that fails AS A BATCH retries at half its size (adaptive
	// halving, floor 20 = the pre-big-batch default, code-level constant).
	DefaultProbeBatchSize = 1000
	// DefaultProbeBatchConcurrency is the default number of nodes probed
	// concurrently inside one batch (0 in config → this default).
	DefaultProbeBatchConcurrency = 10
	// DefaultProbePrefilterWorkers is the wave-1 TCP pre-filter's concurrent
	// dial count (0 in config → this default). A plain SYN handshake is
	// cheap — no core instance (the xray-knife prescan reference runs 512).
	DefaultProbePrefilterWorkers = 256
	// DefaultProbePrefilterTimeout bounds ONE pre-filter TCP dial, DNS
	// resolution included (0 in config → this default).
	DefaultProbePrefilterTimeout = time.Second
	// DefaultGeoSelfReportConcurrency is the default number of concurrent
	// temp instances during geo self-report (0 in config → this default).
	DefaultGeoSelfReportConcurrency = 8
	// DefaultGeoMaxTTL caps the rate-limit retry sleep (the X-Ttl honor on a
	// 429 batch fallback) when [geo].max_ttl is unset.
	DefaultGeoMaxTTL = 30 * time.Second
	// DefaultMaxTTL is an alias for DefaultGeoMaxTTL.
	DefaultMaxTTL = DefaultGeoMaxTTL
)

// defaultPoolInboundTags is the render.pool_inbound_tags default (the tags
// every pool routing rule has carried since W3).
var defaultPoolInboundTags = []string{"socks-in", "http-in"}

// DefaultPoolInboundTags returns a copy of the pool_inbound_tags default.
func DefaultPoolInboundTags() []string {
	return append([]string(nil), defaultPoolInboundTags...)
}

// ResourceConfig describes the machine resource envelope the pipeline may
// spend on concurrent work (temp xray instances, geo self-report workers,
// probe threads). A zero value means "auto-detect": MaxCPUCores falls back
// to runtime.NumCPU() and MaxRAMMB to the host's total RAM. HeadroomPct
// reserves that percentage of the detected/declared RAM for the OS and other
// processes (default 10 when unset).
type ResourceConfig struct {
	// MaxCPUCores caps the CPU side of the wave budget (concurrent workers).
	// 0 = auto-detect (runtime.NumCPU()). Negative values are structurally
	// invalid.
	MaxCPUCores int `toml:"max_cpu_cores"`
	// MaxRAMMB caps the RAM side of the wave budget (MB). 0 = auto-detect
	// (host total RAM). Negative values are structurally invalid.
	MaxRAMMB int `toml:"max_ram_mb"`
	// HeadroomPct reserves this percentage of RAM for the OS/other processes
	// (default 10). 0 = default. Negative values are structurally invalid.
	HeadroomPct int `toml:"headroom_pct"`
}

// Config is the pipeline configuration root.
type Config struct {
	DataDir    string           `toml:"data_dir"`
	Resources  ResourceConfig   `toml:"resources"`
	Resource   ResourceConfig   `toml:"resource"`
	Plugins    PluginsConfig    `toml:"plugins"`
	Fetch      FetchConfig      `toml:"fetch"`
	Filter     FilterConfig     `toml:"filter"`
	Probe      ProbeConfig      `toml:"probe"`
	Geo        GeoConfig        `toml:"geo"`
	Select     SelectConfig     `toml:"select"`
	Render     RenderConfig     `toml:"render"`
	Activate   ActivateConfig   `toml:"activate"`
	Maintain   MaintainConfig   `toml:"maintain"`
	HTTP       HTTPConfig       `toml:"http"`
	SelfUpdate SelfUpdateConfig `toml:"self_update"`
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
	cfg := &Config{
		SelfUpdate: SelfUpdateConfig{Enabled: true, CheckInterval: Duration{Duration: 30 * time.Second}},
		Probe:      ProbeConfig{CalibrationEnabled: true},
	}
	dec := toml.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	syncResourceConfig(cfg)
	applyDefaults(cfg, false)
	syncResourceConfig(cfg)
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// checkRemovedSections fails LOUD on removed layouts, naming the exact
// migration path. Two removed generations live here:
//   - [sources.*] (W10): the ingest layer is Lua plugins — no silent fallback
//     chain from the old section;
//   - [geo] batch knobs (W11): the per-node self-report (since the
//     classification merge, part of the probe pass) rides each node's own
//     tunnel, so geo.endpoint / geo.batch_size / geo.per_minute are
//     dead — requests originate from thousands of distinct node IPs and the
//     aggregate limit they clamped cannot pool. The self-report is automatic
//     (no knob); the surviving knobs are ttl / timeout / doh_url.
func checkRemovedSections(raw []byte) error {
	probe := map[string]any{}
	decodeErr := toml.NewDecoder(strings.NewReader(string(raw))).Decode(&probe)
	if decodeErr == nil {
		if _, ok := probe["sources"]; ok {
			return errors.New(
				"the [sources.*] section was removed — the source-ingest layer is now Lua plugins " +
					"(W10). Delete every [sources.<id>] table and use the [plugins] section " +
					"([plugins] dir = \"...\", default <data_dir>/plugins). The built-in sample " +
					"plugin (sample.lua) materializes into the plugins " +
					"dir on first run — edit or add .lua files there; a new provider is a new " +
					".lua file, no Go rebuild")
		}
		if probeTable, ok := probe["probe"].(map[string]any); ok {
			dead := make([]string, 0, 5)
			for _, key := range []string{"path", "db_path", "check_preset", "url_success_threshold", "max_passed"} {
				if _, present := probeTable[key]; present {
					dead = append(dead, "probe."+key)
				}
			}
			if len(dead) > 0 {
				return fmt.Errorf(
					"%s: removed — the probe wave no longer shells out to xray-knife (W14): every "+
						"probed node now gets a temporary single-node xray instance (the SAME "+
						"infrastructure the check stage uses), so liveness and the speedtest "+
						"uniformly cover every rendered protocol, hysteria2 included. Migration: "+
						"delete the dead key(s); the temp instances use [activate].xray_bin (there is "+
						"no separate prober binary or database anymore); panel grading moved to the "+
						"`assay check` command (per-site verdicts through real tunnels); early "+
						"stop is gone — selection caps live at the select stage",
					strings.Join(dead, ", "))
			}
		}
		if geoTable, ok := probe["geo"].(map[string]any); ok {
			dead := make([]string, 0, 3)
			for _, key := range []string{"endpoint", "batch_size", "per_minute"} {
				if _, present := geoTable[key]; present {
					dead = append(dead, "geo."+key)
				}
			}
			if len(dead) > 0 {
				return fmt.Errorf(
					"%s: removed — the classification pass (merged into the probe wave) "+
						"self-reports per node: every alive node asks "+
						"ip-api (http://ip-api.com/json/, no ip parameter) through its own tunnel, so "+
						"requests come from thousands of distinct node IPs and the aggregate per-source "+
						"limit these batch knobs clamped can never pool (W11). The self-report is "+
						"automatic — there is no replacement knob. Delete the dead key(s) from your "+
						"[geo] table (keep ttl and timeout; the DoH fallback endpoint is [geo].doh_url, "+
						"default %s)",
					strings.Join(dead, ", "), DefaultDoHURL)
			}
		}
	}
	return nil // a lenient-decode failure is the strict decode's problem below
}

func applyDefaults(c *Config, configless bool) {
	syncResourceConfig(c)
	applyResourceDefaults(&c.Resources)
	applyResourceDefaults(&c.Resource)
	applyPluginsDefaults(c)
	applyFetchDefaults(&c.Fetch)
	applyFilterDefaults(&c.Filter)
	applyProbeDefaults(&c.Probe)
	applyGeoDefaults(&c.Geo)
	applySelectDefaults(&c.Select)
	applyRenderDefaults(&c.Render, configless)
	applyActivateDefaults(&c.Activate, configless)
	applyMaintainDefaults(&c.Maintain)
	applyHTTPDefaults(&c.HTTP)
	applySelfUpdateDefaults(&c.SelfUpdate)
}

// applyPluginsDefaults resolves the plugins dir default: <data_dir>/plugins,
// and the run timeout default (nil = unset → DefaultPluginRunTimeout; an
// explicit "0s" stays 0 = unbounded). The threshold knobs (max_duplicate_percent,
// min_live_percent) stay nil by default — disabled unless explicitly set.
func applyPluginsDefaults(c *Config) {
	if c.Plugins.Dir == "" {
		c.Plugins.Dir = filepath.Join(c.DataDir, "plugins")
	}
	if c.Plugins.RunTimeout == nil {
		c.Plugins.RunTimeout = &Duration{Duration: DefaultPluginRunTimeout}
	}
	if c.Plugins.MaxConsecutiveFailures == nil {
		def := DefaultMaxConsecutiveFailures
		c.Plugins.MaxConsecutiveFailures = &def
	}
	// MaxDuplicatePercent and MinLivePercent: nil stays nil (disabled by default).
	// An explicit 0 in the config means disabled; a positive value enables the check.
	// No default application — the owner must opt in.
}

// defaultProtocols is the protocol acceptance allowlist applied when
// [filter].protocols is unset: EVERY rendered protocol (round-7 owner
// ruling 14c — the former vless/vmess/trojan-only default disabled hysteria
// without the owner's word). The security filter (reality/tls requirement,
// allow_insecure=false default) still applies ON TOP: protocol breadth is
// not a license for insecure links.
var defaultProtocols = []string{"vless", "vmess", "trojan", "ss", "hysteria2"}

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
	if p.Timeout.Duration == 0 {
		p.Timeout.Duration = 10 * time.Second
	}
	if p.Threads == 0 {
		p.Threads = DefaultProbeThreads
	}
	if p.Attempts == 0 {
		p.Attempts = DefaultProbeAttempts
	}
	if p.URL == "" {
		p.URL = "https://cloudflare.com/cdn-cgi/trace"
	}
	if p.SpeedtestURL == "" {
		p.SpeedtestURL = DefaultProbeSpeedtestURL
	}
	if p.SpeedtestTimeout.Duration == 0 {
		p.SpeedtestTimeout.Duration = 30 * time.Second
	}
	// SkipFreshWithin: no default application — 0s IS the default (probe
	// everything); an explicit 0s and an absent key are the same behavior.
	if p.BatchSize == 0 {
		p.BatchSize = DefaultProbeBatchSize
	}
	if p.BatchConcurrency == 0 {
		p.BatchConcurrency = DefaultProbeBatchConcurrency
	}
	if p.CalibrationBase == 0 {
		p.CalibrationBase = 10
	}
	if p.CalibrationMargin == 0 {
		p.CalibrationMargin = 1
	}
	if p.Granularity == "" {
		p.Granularity = "country"
	}
	if p.TCPPrefilterWorkers == 0 {
		p.TCPPrefilterWorkers = DefaultProbePrefilterWorkers
	}
	if p.TCPPrefilterTimeout.Duration == 0 {
		p.TCPPrefilterTimeout.Duration = DefaultProbePrefilterTimeout
	}
	// TCPPrefilter: nil (absent) materializes TRUE — the owner-approved
	// probe-optimization default (the stage runs on every wave);
	// TCPPrefilterEnabled() treats a nil pointer the same way, so hand-built
	// configs agree with loaded ones. An explicit false survives defaults
	// and keeps the stage off with zero dials.
	if p.TCPPrefilter == nil {
		v := true
		p.TCPPrefilter = &v
	}
}

func applyGeoDefaults(g *GeoConfig) {
	if g.DoHURL == "" {
		g.DoHURL = DefaultDoHURL
	}
	if g.HTTPSURL == "" {
		g.HTTPSURL = DefaultGeoHTTPSURL
	}
	if g.ExitIPEchoURL == "" {
		g.ExitIPEchoURL = DefaultGeoExitIPEchoURL
	}
	if g.TTL.Duration == 0 {
		g.TTL.Duration = 24 * time.Hour
	}
	if g.Timeout.Duration == 0 {
		g.Timeout.Duration = 8 * time.Second
	}
	if g.SelfReportConcurrency == 0 {
		g.SelfReportConcurrency = DefaultGeoSelfReportConcurrency
	}
	if g.MaxTTL.Duration == 0 {
		g.MaxTTL.Duration = DefaultGeoMaxTTL
	}
	// UnlockProbes: nil (absent) materializes TRUE — the owner default-flip
	// ruling (unlock probes run by default); UnlockProbesEnabled() treats a
	// nil pointer the same way, so hand-built configs agree with loaded ones.
	// An explicit false survives defaults and keeps the stage off.
	if g.UnlockProbes == nil {
		v := true
		g.UnlockProbes = &v
	}
}

func applySelectDefaults(s *SelectConfig) {
	// W19 owner flip: NO default refills remain on the cap knobs — 0 IS the
	// default (UNBOUNDED: every alive node goes active; per-country K
	// unlimited, no ceiling, no city expansion). An explicit positive value
	// keeps the D7 cap semantics (rank.effectiveCap).
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

func applyRenderDefaults(r *RenderConfig, configless bool) {
	// Normalize duplicates at the load boundary (M-4): "socks-in" twice must
	// not render a duplicated inboundTag — first occurrence wins, order is
	// preserved.
	r.PoolInboundTags = dedupeStrings(r.PoolInboundTags)
	// The template default is a FILE-LOADED default only: a configless run
	// keeps render.template empty so the render stage fails loud at its
	// boundary instead of silently pointing at the live client's config.
	if !configless && r.Template == "" {
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
	// ObservatoryInterval: NO default application (W19) — empty = ADAPTIVE:
	// the render computes max(60s, ceil(active×200ms)) from the selection
	// size so sustained observatory probes stay ≤ 5/s regardless of pool
	// growth. An explicit value renders verbatim (xray -test gate remains
	// the loud backstop for garbage spellings).
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

func applyActivateDefaults(a *ActivateConfig, configless bool) {
	// The target default is a FILE-LOADED default only: configless mode
	// keeps activate.target empty so activation fails loud at its boundary
	// instead of silently aiming at the live client's config.
	if !configless && a.Target == "" {
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
	// SpeedtestInterval is tri-state: nil (absent) materializes the weekly
	// default; an explicit "0s" STAYS 0 = the speedtest wave is disabled
	// (round-8 owner ruling — the schedule-level «выключи»).
	if m.SpeedtestInterval == nil {
		m.SpeedtestInterval = &Duration{Duration: DefaultSpeedtestInterval}
	}
	if m.StatsTimeout.Duration == 0 {
		m.StatsTimeout.Duration = DefaultStatsTimeout
	}
	// PruneBackupKeep: no default application — 0 IS the default (unlimited).
	// AutoRestart: nil (unset) materializes as TRUE — hands-off is the W13
	// owner ruling; AutoRestartEnabled() treats a nil pointer the same way,
	// so both direct-struct (test) construction and file loading agree.
	if m.AutoRestart == nil {
		v := true
		m.AutoRestart = &v
	}
}

func applyHTTPDefaults(h *HTTPConfig) {
	if h.UserAgent == "" {
		h.UserAgent = DefaultUserAgent
	}
}

func applySelfUpdateDefaults(s *SelfUpdateConfig) {
	// Enabled default (true) is pre-set in Load/configless before decode so
	// an explicit false survives; nothing to do here.
	if s.CheckInterval.Duration == 0 {
		s.CheckInterval.Duration = 30 * time.Second
	}
}

func applyResourceDefaults(r *ResourceConfig) {
	if r.HeadroomPct == 0 {
		r.HeadroomPct = 10
	}
}

// syncResourceConfig keeps the singular and plural resource fields in sync so
// either spelling works (ResourceConfig lives under both [resources] and
// [resource] for compatibility with callers/tests).
func syncResourceConfig(c *Config) {
	rZero := c.Resources.MaxCPUCores == 0 && c.Resources.MaxRAMMB == 0 && c.Resources.HeadroomPct == 0
	sZero := c.Resource.MaxCPUCores == 0 && c.Resource.MaxRAMMB == 0 && c.Resource.HeadroomPct == 0
	if rZero && !sZero {
		c.Resources = c.Resource
	}
	if sZero && !rZero {
		c.Resource = c.Resources
	}
	if !rZero && !sZero {
		// both set: prefer resources
		c.Resource = c.Resources
	}
}

// EffectiveCPUCores resolves MaxCPUCores: 0 = auto-detect (runtime.NumCPU()).
func (r ResourceConfig) EffectiveCPUCores() int {
	if r.MaxCPUCores > 0 {
		return r.MaxCPUCores
	}
	n := runtime.NumCPU()
	return max(n, 1)
}

// EffectiveRAMMB resolves MaxRAMMB: 0 = auto-detect (host total RAM in MB).
func (r ResourceConfig) EffectiveRAMMB() int {
	if r.MaxRAMMB > 0 {
		return r.MaxRAMMB
	}
	return detectTotalRAMMB()
}

// HeadroomFraction returns the reserved fraction (HeadroomPct/100).
func (r ResourceConfig) HeadroomFraction() float64 {
	if r.HeadroomPct <= 0 {
		return 0.10
	}
	return float64(r.HeadroomPct) / 100.0
}

// UsableRAMMB returns the RAM available to the pipeline after headroom.
func (r ResourceConfig) UsableRAMMB() int {
	total := r.EffectiveRAMMB()
	usable := int(float64(total) * (1 - r.HeadroomFraction()))
	return max(usable, 1)
}

func validate(c *Config) error {
	if err := validateBasics(c); err != nil {
		return err
	}
	if err := validateResource(c.Resources); err != nil {
		return err
	}
	if err := validateResource(c.Resource); err != nil {
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
	if err := validatePlugins(c.Plugins); err != nil {
		return err
	}
	if err := validateProbe(c.Probe); err != nil {
		return err
	}
	return validateNonNegative("probe.skip_fresh_within", c.Probe.SkipFreshWithin.Duration)
}

// validateProbe carries the W14 structural checks: a negative attempt/worker
// count (including the TCP pre-filter knobs) or timeout is sign-invalid
// (0 = unset → default, the W6 convention). No range bounds (owner ruling).
func validateProbe(p ProbeConfig) error {
	if err := validateNonNegative("probe.attempts", p.Attempts); err != nil {
		return err
	}
	if err := validateNonNegative("probe.threads", p.Threads); err != nil {
		return err
	}
	if err := validateNonNegative("probe.batch_size", p.BatchSize); err != nil {
		return err
	}
	if err := validateNonNegative("probe.batch_concurrency", p.BatchConcurrency); err != nil {
		return err
	}
	if err := validateNonNegative("probe.tcp_prefilter_workers", p.TCPPrefilterWorkers); err != nil {
		return err
	}
	return validateNonNegative("probe.tcp_prefilter_timeout", p.TCPPrefilterTimeout.Duration)
}

// validatePlugins carries the structural checks for the [plugins] section:
// every tunable knob is sign-checked (negative = invalid) and otherwise
// unbounded (owner ruling). Extracted from validate to keep its cyclomatic
// complexity under the cyclop limit.
func validatePlugins(p PluginsConfig) error {
	if p.RunTimeout != nil {
		if err := validateNonNegative("plugins.run_timeout", p.RunTimeout.Duration); err != nil {
			return err
		}
	}
	if p.MaxConsecutiveFailures != nil {
		if err := validateNonNegative("plugins.max_consecutive_failures", *p.MaxConsecutiveFailures); err != nil {
			return err
		}
	}
	if p.MaxDuplicatePercent != nil {
		if err := validateNonNegative("plugins.max_duplicate_percent", *p.MaxDuplicatePercent); err != nil {
			return err
		}
	}
	if p.MinLivePercent != nil {
		if err := validateNonNegative("plugins.min_live_percent", *p.MinLivePercent); err != nil {
			return err
		}
	}
	return nil
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
	if m.RefreshInterval.Duration < IntervalFloor {
		return fmt.Errorf("maintain.refresh_interval must be >= %s (too-fast rechecks hammer sources, probes, "+
			"and the client), got %s", IntervalFloor, m.RefreshInterval.Duration)
	}
	// speedtest_interval (tri-state, round-8): 0 = the wave is DISABLED —
	// the floor does not apply to the explicit disable; any positive value
	// below the floor stays loud. Negative values are structurally invalid.
	if m.SpeedtestInterval != nil {
		if err := validateNonNegative("maintain.speedtest_interval", m.SpeedtestInterval.Duration); err != nil {
			return err
		}
		if d := m.SpeedtestInterval.Duration; d > 0 && d < IntervalFloor {
			return fmt.Errorf("maintain.speedtest_interval must be >= %s or exactly 0s (0 = no speedtest wave), got %s",
				IntervalFloor, d)
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
// allowlist may only reference these. Since W14 ALL of them are accepted by
// default (round-7 owner ruling 14c).
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

func validateResource(r ResourceConfig) error {
	if err := validateNonNegative("resources.max_cpu_cores", r.MaxCPUCores); err != nil {
		return err
	}
	if err := validateNonNegative("resources.max_ram_mb", r.MaxRAMMB); err != nil {
		return err
	}
	return validateNonNegative("resources.headroom_pct", r.HeadroomPct)
}

func validateSelect(s SelectConfig) error {
	// W19 doctrine: 0 = UNBOUNDED is legal on every cap knob; only sign
	// correctness is structural (owner no-floor/no-ceiling ruling — the
	// former per_country_cap 1..10 range is gone with the flip).
	if s.PerCountryCap < 0 {
		return fmt.Errorf("select.per_country_cap must be >= 0 (0 = unlimited), got %d", s.PerCountryCap)
	}
	if s.SoftCap < 0 {
		return fmt.Errorf("select.soft_cap must be >= 0 (0 = unbounded), got %d", s.SoftCap)
	}
	if s.Ceiling < 0 {
		return fmt.Errorf("select.ceiling must be >= 0 (0 = unbounded), got %d", s.Ceiling)
	}
	if s.CityExpandThreshold < 0 {
		return fmt.Errorf("select.city_expand_threshold must be >= 0 (0 = expansion off), got %d", s.CityExpandThreshold)
	}
	if s.Ceiling > 0 && s.SoftCap > 0 && s.Ceiling < s.SoftCap {
		return fmt.Errorf("select.ceiling (%d) must be >= soft_cap (%d)", s.Ceiling, s.SoftCap)
	}
	return validateNonNegative("select.tie_band_rtt_tolerance", s.TieBandRTTTolerance)
}

func validateGeo(g GeoConfig) error {
	// DoH is a TLS protocol: a plain-http doh_url is a config error (the
	// dns.google/resolve default and every real DoH endpoint serve TLS-only).
	// Structural scheme check, not a range bound.
	if !strings.HasPrefix(g.DoHURL, "https://") {
		return fmt.Errorf("geo.doh_url must use https (DoH is a TLS protocol), got %q", g.DoHURL)
	}
	// The W16 hop-2 endpoint rides TLS by definition (the rung's whole point
	// is an HTTPS self-geo). Structural scheme check ONLY — any https URL is
	// accepted verbatim (owner ruling: no allowlist, plain string knob).
	if !strings.HasPrefix(g.HTTPSURL, "https://") {
		return fmt.Errorf("geo.https_url must use https (the self-geo endpoint answers over TLS), got %q", g.HTTPSURL)
	}
	if g.ExitIPEchoURL != "" && !strings.HasPrefix(g.ExitIPEchoURL, "https://") {
		return fmt.Errorf("geo.exit_ip_echo_url must use https (the echo endpoint answers over TLS), got %q", g.ExitIPEchoURL)
	}
	if err := validateNonNegative("geo.self_report_concurrency", g.SelfReportConcurrency); err != nil {
		return err
	}
	return validateNonNegative("geo.max_ttl", g.MaxTTL.Duration)
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

// detectTotalRAMMB best-effort reads host total RAM in MB. Falls back to
// 4096 MB when the platform or /proc is unavailable (no new dependencies).
func detectTotalRAMMB() int {
	// Linux: /proc/meminfo MemTotal (kB).
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "MemTotal:" {
				// fields[1] is kB
				var kb int
				_, _ = fmt.Sscanf(fields[1], "%d", &kb)
				if kb > 0 {
					return kb / 1024
				}
			}
		}
	}
	return 4096
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
