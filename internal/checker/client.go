package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// maxBodyBytes caps how much of a response is read (classification + speed
// sampling): a site check never downloads unbounded bodies.
const maxBodyBytes = 20 << 20

// dohEndpoint is the supplementary DNS view queried THROUGH the tunnel
// (clearly labeled in the output with the method): dns.google/resolve shows
// how the EXIT's resolver sees the target.
const dohEndpoint = "https://dns.google/resolve"

// dnsMethod is the label rendered next to resolved IPs.
const dnsMethod = "doh-via-exit"

// checkUserAgent is a current browser UA: the tool measures what a real
// visitor from the node's location would see — a bot-flavored default Go UA
// would skew blockpage classifiers before geography ever matters.
const checkUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

// tunnelClient drives HTTP through one node's temp SOCKS5 instance.
type tunnelClient struct {
	socksAddr string
	timeout   time.Duration
	dohURL    string         // test seam; empty = dohEndpoint
	tlsRoots  *x509.CertPool // test seam; nil = system roots
}

func newTunnelClient(socksAddr string, timeout time.Duration) *tunnelClient {
	return &tunnelClient{socksAddr: socksAddr, timeout: timeout, dohURL: dohEndpoint}
}

// dialer builds the SOCKS5 dialer for the temp instance. The x/net socks
// dialer forwards HOSTNAMES to the proxy (ATYP=domain) — resolution happens
// at the EXIT (socks5h semantics), which is exactly the location signal this
// feature measures.
//
//nolint:ireturn // x/net exposes SOCKS5 dialers only as interfaces; http.Transport consumes this one
func (t *tunnelClient) dialer() (proxy.ContextDialer, error) {
	d, err := proxy.SOCKS5("tcp", t.socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks dialer: %w", err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks dialer: no context support")
	}
	return cd, nil
}

// client builds an http.Client whose ONLY transport path is the tunnel.
// Proxy nil is the L5 landmine guard pinned in code: the ambient http_proxy
// of the owner's shell must never hijack check traffic through the live
// client — every dial goes through the temp instance, resolution at the exit.
func (t *tunnelClient) client(chain *redirectChain) (*http.Client, error) {
	dialer, err := t.dialer()
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			Proxy:               nil, // L5: NEVER http.ProxyFromEnvironment here
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: t.timeout,
			DisableKeepAlives:   true, // fresh connection per request → clean per-attempt traces
		},
		CheckRedirect: chain.checkRedirect,
		Timeout:       t.timeout,
	}, nil
}

// redirectChain records every followed redirect hop.
type redirectChain struct {
	Statuses []int
	Hops     []string
}

func (c *redirectChain) checkRedirect(req *http.Request, via []*http.Request) error {
	if req.Response != nil {
		c.Statuses = append(c.Statuses, req.Response.StatusCode)
		if req.Response.Request != nil && req.Response.Request.URL != nil {
			c.Hops = append(c.Hops, req.Response.Request.URL.String())
		}
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// get performs ONE HTTP attempt through the tunnel, collecting httptrace
// timings (connect, TLS handshake, TTFB, total), the redirect chain, body
// bytes (capped) and the response verdict.
func (t *tunnelClient) get(ctx context.Context, rawURL string) (Attempt, error) {
	attempt := Attempt{}
	chain := &redirectChain{}
	client, err := t.client(chain)
	if err != nil {
		attempt.Verdict, attempt.Err = VerdictError, err.Error()
		return attempt, err
	}
	var (
		t0           = time.Now()
		connectStart time.Time
		tlsStart     time.Time
		connected    bool // the tunnel CONNECT completed (phase for verdictFor)
	)
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { connectStart = time.Now() },
		ConnectDone: func(_, _ string, err error) {
			if err == nil && !connectStart.IsZero() {
				attempt.ConnectMS = msSince(connectStart)
				connected = true
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil && !tlsStart.IsZero() {
				attempt.TLSMS = msSince(tlsStart)
			}
		},
		GotFirstResponseByte: func() { attempt.TTFBMS = msSince(t0) },
	}
	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace), http.MethodGet, rawURL, nil)
	if err != nil {
		attempt.Verdict, attempt.Err = VerdictError, err.Error()
		return attempt, err
	}
	req.Header.Set("User-Agent", checkUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		attempt.TotalMS = msSince(t0)
		attempt.Verdict = verdictFor(err, connected)
		attempt.Err = err.Error()
		return attempt, err
	}
	defer func() { _ = resp.Body.Close() }()
	body := readCapped(resp.Body)
	attempt.Bytes = int64(len(body))
	attempt.TotalMS = msSince(t0)
	if attempt.TotalMS > 0 {
		attempt.SpeedBPS = float64(attempt.Bytes) / (attempt.TotalMS / 1000)
	}
	attempt.Status = resp.StatusCode
	attempt.Statuses = append(append([]int(nil), chain.Statuses...), resp.StatusCode)
	attempt.Hops = chain.Hops
	if resp.Request != nil && resp.Request.URL != nil {
		attempt.FinalURL = resp.Request.URL.String()
	}
	cls := Classify(resp.StatusCode, body)
	attempt.Verdict = cls.Verdict
	attempt.Signature = cls.Signature
	return attempt, nil
}

// readCapped reads up to maxBodyBytes from r.
func readCapped(r io.Reader) []byte {
	buf := make([]byte, 32*1024)
	body := make([]byte, 0, 4096)
	for len(body) < maxBodyBytes {
		n, err := r.Read(buf)
		if n > 0 {
			take := n
			if len(body)+take > maxBodyBytes {
				take = maxBodyBytes - len(body)
			}
			body = append(body, buf[:take]...)
		}
		if err != nil {
			break
		}
	}
	return body
}

// resolveAtExit queries the DoH endpoint THROUGH the tunnel and returns the
// A records the exit's resolver sees (type-filtered; AAAA ignored — the
// checked connectivity is IPv4 egress).
func (t *tunnelClient) resolveAtExit(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil // literal target: no resolution question
	}
	client, err := t.client(&redirectChain{})
	if err != nil {
		return nil, err
	}
	endpoint := t.dohURL + "?name=" + url.QueryEscape(host) + "&type=A"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", checkUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var dr struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&dr); err != nil {
		return nil, fmt.Errorf("decode doh answer: %w", err)
	}
	ips := make([]string, 0, len(dr.Answer))
	for _, a := range dr.Answer {
		if a.Type == 1 && a.Data != "" {
			ips = append(ips, a.Data)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("doh answer carries no A records for %s", host)
	}
	return ips, nil
}

// tlsCheck performs an EXPLICIT TLS handshake against the target through the
// tunnel (not a side effect of GET): a node failing TLS for the target is a
// distinct failure class from HTTP-level blocks. addr is the dialable
// host:port (the CONNECT address); serverName is the SNI/verification name —
// resolution of a hostname addr happens at the exit. Returns the negotiated
// version ("1.3" style) and the verification error, if any.
func (t *tunnelClient) tlsCheck(ctx context.Context, addr, serverName string) (string, error) {
	dialer, err := t.dialer()
	if err != nil {
		return "", err
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("tunnel dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	tc := tls.Client(conn, &tls.Config{
		ServerName: serverName,
		RootCAs:    t.tlsRoots,
		MinVersion: tls.VersionTLS12,
	})
	hsCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	if err := tc.HandshakeContext(hsCtx); err != nil {
		return "", fmt.Errorf("handshake: %w", err)
	}
	return tlsVersionName(tc.ConnectionState().Version), nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}
