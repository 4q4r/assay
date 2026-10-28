// Package geo implements the exit-IP geo-enrichment stage: batch lookups
// against ip-api.com /batch (≤100 IPs per request, ≤15 requests/min, honoring
// X-Rl/X-Ttl; the free tier is HTTP-only and a 429 risks a 1-hour ban — so a
// 429 aborts the wave instead of retrying into the ban, landmine L6).
package geo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"public_vpn/internal/config"
	"public_vpn/internal/model"
	"public_vpn/internal/store"

	"golang.org/x/time/rate"
)

// Response is one ip-api batch entry we consume.
type Response struct {
	Query       string `json:"query"`
	Status      string `json:"status"`
	CountryCode string `json:"countryCode"`
	Country     string `json:"country"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	AS          string `json:"as"`
	ASName      string `json:"asname"`
	Proxy       bool   `json:"proxy"`
	Hosting     bool   `json:"hosting"`
}

// ASN extracts the AS-number token ("AS60781") from the composite as field.
func (r Response) ASN() string {
	f := strings.Fields(r.AS)
	if len(f) > 0 {
		return f[0]
	}
	return ""
}

// Input bundles the geo stage dependencies.
type Input struct {
	DataDir    string
	Nodes      []*model.Node
	ProbeByKey map[string]store.ProbeResult
	Cfg        config.GeoConfig
	// UserAgent is [http].user_agent — the ONE pipeline UA knob; empty falls
	// back to config.DefaultUserAgent inside the client constructor.
	UserAgent string
}

// Run enriches alive nodes' exit IPs, merges probe outcomes, and upserts the
// geo-base.jsonl cold store. Records are returned for reporting.
func Run(ctx context.Context, in Input) ([]*model.GeoRecord, error) {
	exitIPs := collectExitIPs(in.Nodes, in.ProbeByKey)
	byIP := map[string]Response{}
	if len(exitIPs.distinct) > 0 {
		resp, err := NewClient(in.Cfg, in.UserAgent).Enrich(ctx, exitIPs.distinct)
		if err != nil {
			return nil, err
		}
		for _, r := range resp {
			byIP[r.Query] = r
		}
	}
	records, err := mergeGeoRecords(in, byIP, exitIPs.byNode)
	if err != nil {
		return nil, err
	}
	if err := store.UpsertGeo(filepath.Join(in.DataDir, "geo-base.jsonl"), records); err != nil {
		return nil, err
	}
	return records, nil
}

type exitIPIndex struct {
	distinct []string
	byNode   map[string]string // node key -> exit ip
}

// collectExitIPs indexes the tunnel exit IPs of alive probes (D8): only nodes
// with a live probe carrying an exit IP enter geo enrichment.
func collectExitIPs(nodes []*model.Node, probeByKey map[string]store.ProbeResult) exitIPIndex {
	idx := exitIPIndex{byNode: map[string]string{}}
	seen := map[string]bool{}
	for _, n := range nodes {
		pr, ok := probeByKey[n.Key]
		if !ok || !pr.Alive || pr.ExitIP == "" {
			continue
		}
		idx.byNode[n.Key] = pr.ExitIP
		if !seen[pr.ExitIP] {
			seen[pr.ExitIP] = true
			idx.distinct = append(idx.distinct, pr.ExitIP)
		}
	}
	return idx
}

func mergeGeoRecords(in Input, byIP map[string]Response, ipByNode map[string]string) ([]*model.GeoRecord, error) {
	existing, err := store.ReadGeo(filepath.Join(in.DataDir, "geo-base.jsonl"))
	if err != nil {
		return nil, err
	}
	prevByKey := map[string]*model.GeoRecord{}
	for _, e := range existing {
		prevByKey[model.GeoIdentity(e)] = e
	}
	now := time.Now().UTC()
	// Same-identity records (scheme|host|port) can arrive from distinct node
	// keys (the same server advertised with different credentials/params).
	// Apply their probes in stable (identity, node key) order so the outcome
	// that survives the store's last-write merge never depends on the
	// caller's arrival order — identical inputs always yield the same winner
	// (M-b).
	nodes := make([]*model.Node, len(in.Nodes))
	copy(nodes, in.Nodes)
	sort.Slice(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		if a.Scheme != b.Scheme {
			return a.Scheme < b.Scheme
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Key < b.Key
	})
	records := make([]*model.GeoRecord, 0, len(in.ProbeByKey))
	for _, n := range nodes {
		pr, ok := in.ProbeByKey[n.Key]
		if !ok {
			// Partial probe wave: the node has no probe outcome in the map,
			// so this wave carries no new liveness truth for it. Emit nothing
			// — re-emitting the previous record would either resurrect stale
			// values or (via the store merge) zero Alive/RTT/Speed under a
			// stale last_probe. Unprobed records stay byte-identical on disk.
			continue
		}
		rec := &model.GeoRecord{
			Source: n.Source, Scheme: n.Scheme, Host: n.Host, Port: n.Port,
			FirstSeen: now.Format(time.RFC3339), LastSeen: now.Format(time.RFC3339),
		}
		if prev, ok := prevByKey[model.GeoIdentity(rec)]; ok {
			rec = prev
			rec.LastSeen = now.Format(time.RFC3339)
		}
		rec.ApplyProbe(pr.Alive, pr.RTTMs, pr.SpeedBPS, pr.CheckedAt)
		applyGeoLookup(rec, ipByNode[n.Key], byIP)
		records = append(records, rec)
	}
	return records, nil
}

func applyGeoLookup(rec *model.GeoRecord, ip string, byIP map[string]Response) {
	if ip == "" {
		return
	}
	rec.IP = ip
	if g, ok := byIP[ip]; ok && g.Status == "success" {
		rec.Country = strings.ToLower(g.CountryCode)
		rec.City = g.City
		rec.ASN = g.ASN()
		rec.ASName = g.ASName
		rec.ISP = g.ISP
		rec.ProxyFlag = g.Proxy
		rec.HostingFlag = g.Hosting
	}
}

// Client is the ip-api.com batch client.
type Client struct {
	cfg       config.GeoConfig
	userAgent string
	http      *http.Client
	limiter   *rate.Limiter
}

// batchInterval derives the production batch interval: the free-tier clamp
// min(perMinute, 15), floored at one request per minute. Unit-tested directly
// so pinning the 900→15 clamp costs no wall time.
func batchInterval(perMinute int) time.Duration {
	perMinute = min(perMinute, 15)
	perMinute = max(perMinute, 1)
	return time.Minute / time.Duration(perMinute)
}

// NewClient builds a client; the rate limiter is clamped to the free-tier
// batch ceiling of 15 requests/min regardless of configuration generosity.
// An empty userAgent falls back to config.DefaultUserAgent.
func NewClient(cfg config.GeoConfig, userAgent string) *Client {
	return NewClientWithLimiter(cfg, rate.NewLimiter(rate.Every(batchInterval(cfg.PerMinute)), 1), userAgent)
}

// NewClientWithLimiter is the construction seam: tests inject a limiter to
// assert spacing contracts without real 4-second waits. Production callers
// use NewClient.
func NewClientWithLimiter(cfg config.GeoConfig, limiter *rate.Limiter, userAgent string) *Client {
	if userAgent == "" {
		userAgent = config.DefaultUserAgent
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // L5: geo lookups must not ride the owner's VPN
	return &Client{
		cfg:       cfg,
		userAgent: userAgent,
		http: &http.Client{
			Timeout:   cfg.Timeout.Duration,
			Transport: transport,
		},
		// Burst 1: strictly spaced batches (bursting is how 429s happen).
		limiter: limiter,
	}
}

// honorRateHeaders respects X-Rl (remaining) / X-Ttl (window seconds): when
// the server-side window is exhausted we wait it out before the next batch
// instead of driving into a 429 and its 1-hour ban (L6).
func (c *Client) honorRateHeaders(ctx context.Context, h http.Header) {
	remain, ttl := h.Get("X-Rl"), h.Get("X-Ttl")
	if remain == "" || ttl == "" {
		return
	}
	var r int
	if _, err := fmt.Sscanf(remain, "%d", &r); err != nil || r > 0 {
		return
	}
	var t int
	if _, err := fmt.Sscanf(ttl, "%d", &t); err != nil {
		return
	}
	if t = min(t, 120); t <= 0 {
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Duration(t) * time.Second):
	}
}

// Enrich enriches any number of IPs, splitting into ≤100-IP batches.
func (c *Client) Enrich(ctx context.Context, ips []string) ([]Response, error) {
	var out []Response
	for start := 0; start < len(ips); start += c.cfg.BatchSize {
		end := min(start+c.cfg.BatchSize, len(ips))
		batch := ips[start:end]
		resp, err := c.enrichBatch(ctx, batch)
		if err != nil {
			return nil, err
		}
		out = append(out, resp...)
	}
	return out, nil
}

func (c *Client) enrichBatch(ctx context.Context, batch []string) ([]Response, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusTooManyRequests {
		// L6: honoring X-Rl is how you avoid this; a received 429 means the
		// ban window may already be in effect — abort loudly, never retry.
		return nil, errors.New("ip-api returned 429 (rate ban risk): aborting geo wave; " +
			"honor X-Rl/X-Ttl and wait before the next wave")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip-api batch: %s", resp.Status)
	}
	c.honorRateHeaders(ctx, resp.Header)
	var out []Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode ip-api batch response: %w", err)
	}
	kept := out[:0]
	for _, r := range out {
		if r.Status == "success" {
			kept = append(kept, r)
		}
	}
	return kept, nil
}
