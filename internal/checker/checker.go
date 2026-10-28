package checker

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"public_vpn/internal/model"
	"public_vpn/internal/render"
	"public_vpn/internal/store"
)

// Engine defaults (exported: the CLI flag defaults reference the same
// literals — one default, no layer drift). The default tested set is capped
// by a sane ceiling (--limit always raises it); concurrency bounds how many
// temp instances exist at once (throttle — each is a full xray process).
const (
	DefaultNodeCeiling = 60
	DefaultConcurrency = 4
	DefaultAttempts    = 3
	DefaultTimeout     = 15 * time.Second
)

// Options configures one check run. All paths come from the CLI (config data
// dir); no config-schema keys were added for check — flags carry the knobs.
type Options struct {
	Targets          []string
	Countries        []string // ISO codes; empty = all
	Limit            int      // >0 caps the tested set; 0 = alive count capped by the ceiling
	Attempts         int      // HTTP attempts per node per URL
	Timeout          time.Duration
	Concurrency      int  // parallel temp instances (0 = default 4)
	WithDead         bool // include nodes not alive in the last probe
	XrayBin          string
	GeoBasePath      string
	ProbeResultsPath string
	NodesPath        string
	GeoTTL           time.Duration
	WorkDir          string
	// Render carries the hardening knobs every temp outbound MUST carry —
	// tcp_max_seg (mandatory emission) and the TLS fingerprint — straight
	// from the same [render] config section the live renderer reads, so
	// hardening is uniform across the live client and throwaway instances.
	Render render.Config
	// Now is the clock seam (tests inject; nil = time.Now().UTC()).
	Now func() time.Time
	// Progress receives per-node progress lines. nil = discard.
	Progress io.Writer

	// Package-internal test seams (zero in production).
	factoryOverride InstanceFactory
	dohOverride     string
	tlsRoots        *x509.CertPool
}

// poolEntry couples the checkable node with its cold-base geo facts.
type poolEntry struct {
	node  *model.Node
	rec   *model.GeoRecord
	alive bool
}

// Run executes the whole check: pool selection → per-node temp instance +
// attempts → aggregation → geo summary.
func Run(ctx context.Context, opts Options) (*Report, error) {
	if len(opts.Targets) == 0 {
		return nil, errors.New("check: no targets given")
	}
	if opts.Attempts < 1 {
		return nil, fmt.Errorf("check: --attempts must be ≥ 1 (got %d)", opts.Attempts)
	}
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("check: --timeout must be positive (got %s)", opts.Timeout)
	}
	if opts.Concurrency < 0 {
		return nil, fmt.Errorf("check: --concurrency must be ≥ 0 (got %d)", opts.Concurrency)
	}
	if opts.factoryOverride == nil && opts.XrayBin == "" {
		return nil, errors.New("check: xray binary path is empty (activate.xray_bin)")
	}
	targets := make([]Target, 0, len(opts.Targets))
	for _, raw := range opts.Targets {
		t, err := NormalizeTarget(raw)
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	pool, skipped, newestProbe, err := loadPool(opts)
	if err != nil {
		return nil, err
	}
	if len(pool) == 0 {
		return nil, errors.New(
			"check: no checkable nodes (cold base empty or no alive nodes — " +
				"run `publicvpn probe` + `publicvpn geo` first, or pass --with-dead)")
	}

	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	factory := opts.factoryOverride
	if factory == nil {
		factory = NewXrayFactory(opts.XrayBin, opts.WorkDir, opts.Render)
	}

	perNode := runPool(ctx, opts, factory, pool, targets)
	report := buildReport(now, opts, targets, pool, perNode, skipped, newestProbe)
	return report, nil
}

// loadPool joins filtered nodes with cold-base geo records and probe
// liveness (rank's exact join semantics), filters by country and aliveness,
// orders alive-fastest-first and applies the limit.
func loadPool(opts Options) ([]poolEntry, int, time.Time, error) {
	nodes, err := store.ReadNodes(opts.NodesPath)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("read filtered nodes: %w", err)
	}
	records, err := store.ReadGeo(opts.GeoBasePath)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("read geo base: %w", err)
	}
	geoByIdentity := make(map[string]*model.GeoRecord, len(records))
	newest := time.Time{}
	for _, r := range records {
		geoByIdentity[model.GeoIdentity(r)] = r
		if t, perr := time.Parse(time.RFC3339, r.LastProbe); perr == nil && t.After(newest) {
			newest = t
		}
	}
	country := map[string]bool{}
	for _, c := range opts.Countries {
		country[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	all, skipped := selectPool(nodes, geoByIdentity, country, opts.WithDead)
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.alive != b.alive {
			return a.alive // alive first
		}
		ra, rb := sortRTT(a.rec.RTTMs), sortRTT(b.rec.RTTMs)
		if ra != rb {
			return ra < rb
		}
		return a.rec.Tag < b.rec.Tag
	})
	return capPool(all, opts.Limit, opts.WithDead), skipped, newest, nil
}

// selectPool joins filtered nodes with their geo records (rank's identity
// join) and applies the country filter and the alive-set rule.
func selectPool(
	nodes []*model.Node, geoByIdentity map[string]*model.GeoRecord, country map[string]bool, withDead bool,
) ([]poolEntry, int) {
	var all []poolEntry
	skipped := 0
	for _, n := range nodes {
		rec, ok := geoByIdentity[model.GeoIdentity(&model.GeoRecord{Scheme: n.Scheme, Host: n.Host, Port: n.Port})]
		if !ok {
			skipped++ // no geo context → nothing to rank on
			continue
		}
		if len(country) > 0 && !country[strings.ToUpper(rec.Country)] {
			continue
		}
		if !rec.Alive && !withDead {
			skipped++
			continue
		}
		all = append(all, poolEntry{node: n, rec: rec, alive: rec.Alive})
	}
	return all, skipped
}

// capPool resolves the effective tested-set size: an explicit --limit wins;
// the default is the alive count (or the whole set with --with-dead), always
// capped by the sane ceiling.
func capPool(all []poolEntry, limit int, withDead bool) []poolEntry {
	if limit <= 0 {
		limit = len(all)
		if !withDead {
			alive := 0
			for _, e := range all {
				if e.alive {
					alive++
				}
			}
			limit = alive
		}
		if limit > DefaultNodeCeiling {
			limit = DefaultNodeCeiling
		}
	}
	if limit > len(all) {
		limit = len(all)
	}
	return all[:limit]
}

func sortRTT(rtt float64) float64 {
	if rtt <= 0 {
		return 1e18 // never-probed sorts after measured
	}
	return rtt
}

// runPool checks every pool entry under the concurrency throttle, preserving
// input order in the results.
func runPool(
	ctx context.Context, opts Options, factory InstanceFactory, pool []poolEntry, targets []Target,
) [][]*NodeResult {
	concurrency := opts.Concurrency
	if concurrency == 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency < 1 {
		concurrency = 1
	}
	perNode := make([][]*NodeResult, len(pool))
	sem := make(chan struct{}, concurrency)
	done := make([]chan struct{}, len(pool))
	for i := range done {
		done[i] = make(chan struct{})
	}
	for i := range pool {
		go func(i int) {
			sem <- struct{}{}
			defer func() { <-sem }()
			perNode[i] = runNode(ctx, opts, factory, pool[i], targets)
			close(done[i])
		}(i)
	}
	for i := range done {
		<-done[i]
	}
	return perNode
}

// runNode drives one node: temp instance → attempts per target → TLS check
// → DNS view → aggregation.
func runNode(
	ctx context.Context, opts Options, factory InstanceFactory, entry poolEntry, targets []Target,
) []*NodeResult {
	out := make([]*NodeResult, len(targets))
	instanceFailed := func(err error) {
		for i := range targets {
			r := &NodeResult{
				Tag: entry.rec.Tag, Key: entry.node.Key, Host: entry.node.Host,
				Country: entry.rec.Country, City: entry.rec.City,
				ASN: entry.rec.ASN, ISP: displayISP(entry.rec),
				InstanceFailed: true, InstanceErr: err.Error(),
				Attempts: []Attempt{{N: 1, Verdict: VerdictError, Err: "instance failed to start"}},
			}
			r.Aggregate()
			out[i] = r
		}
	}
	if opts.Progress != nil {
		_, _ = fmt.Fprintf(opts.Progress, "checking %s (%s %s/%s)…\n",
			entry.rec.Tag, flagEmoji(entry.rec.Country), strings.ToUpper(entry.rec.Country), entry.node.Host)
	}
	inst, err := factory(ctx, entry.node)
	if err != nil {
		instanceFailed(err)
		return out
	}
	defer func() { _ = inst.Close() }()
	tc := newTunnelClient(inst.Addr(), opts.Timeout)
	tc.dohURL = opts.dohOverride
	tc.tlsRoots = opts.tlsRoots

	for i, tg := range targets {
		r := &NodeResult{
			Tag: entry.rec.Tag, Key: entry.node.Key, Host: entry.node.Host,
			Country: entry.rec.Country, City: entry.rec.City,
			ASN: entry.rec.ASN, ISP: displayISP(entry.rec),
		}
		for n := range opts.Attempts {
			attempt, aerr := tc.get(ctx, tg.URL)
			attempt.N = n + 1
			if aerr != nil && attempt.Verdict == "" {
				// Fallback (get normally classifies itself): the trace phase
				// read from the attempt — a measured connect means the tunnel
				// came up, so a timeout here is a stalled read, not a dial.
				attempt.Verdict = verdictFor(aerr, attempt.ConnectMS > 0)
			}
			r.Attempts = append(r.Attempts, attempt)
		}
		if tg.isHTTPS() {
			ver, terr := tc.tlsCheck(ctx, tg.hostPort(), tg.Host)
			if terr == nil {
				r.TLSVersion, r.TLSOK = ver, true
			} else {
				r.TLSErr = terr.Error()
			}
		}
		if ips, derr := tc.resolveAtExit(ctx, tg.Host); derr == nil {
			r.ResolvedIPs, r.DNSMethod = ips, dnsMethod
		}
		r.Aggregate()
		if r.Verdict == VerdictFail && r.TLSErr != "" {
			r.Verdict = VerdictTLSFail
		}
		out[i] = r
	}
	return out
}

func displayISP(r *model.GeoRecord) string {
	if strings.TrimSpace(r.ASName) != "" {
		return r.ASName
	}
	return r.ISP
}

// buildReport assembles the final report: per-target rows, geo summaries and
// the staleness hint.
func buildReport(
	now time.Time, opts Options, targets []Target, pool []poolEntry,
	perNode [][]*NodeResult, skipped int, newestProbe time.Time,
) *Report {
	rep := &Report{
		GeneratedAt: now,
		Checked:     len(pool),
		Skipped:     skipped,
		Attempts:    opts.Attempts,
		Timeout:     opts.Timeout.String(),
	}
	if opts.GeoTTL > 0 && !newestProbe.IsZero() {
		age := now.Sub(newestProbe)
		rep.GeoTTL = opts.GeoTTL.String()
		if age > opts.GeoTTL {
			rep.Stale = true
			rep.StaleAge = age.Round(time.Minute).String()
		}
	}
	for ti, tg := range targets {
		rows := make([]*NodeResult, len(pool))
		for ni := range pool {
			rows[ni] = perNode[ni][ti]
		}
		rep.Targets = append(rep.Targets, &TargetResult{
			URL:            tg.URL,
			Rows:           rows,
			Countries:      RankGroups(GroupByCountry(rows)),
			Cities:         RankGroups(GroupByCity(rows)),
			Recommendation: filterServed(RankGroups(GroupByCountry(rows))),
		})
	}
	return rep
}
