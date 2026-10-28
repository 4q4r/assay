package geo_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// socksServer is a minimal in-process SOCKS5 CONNECT server (no-auth only —
// exactly what the x/net proxy.SOCKS5 client offers). It lets the geo tests
// drive the PRODUCTION through-tunnel client end to end: the reporter dials
// this server as the temp instance's socks endpoint, and the server relays
// CONNECTs to the real loopback targets (httptest ip-api/DoH doubles).
type socksServer struct {
	ln      net.Listener
	mu      sync.Mutex
	closers []io.Closer
	done    sync.WaitGroup
	// Connects counts completed CONNECT relays (the piggyback counter's
	// counterpart on the wire: every tunnel request passes one).
	Connects atomic.Int32
	// LastTarget records the last CONNECT target host:port (wire evidence
	// that the hostname rode the tunnel — socks5h semantics).
	LastTarget atomic.Pointer[string]
}

func newSocksServer(t *testing.T) *socksServer {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks test server listen: %v", err)
	}
	s := &socksServer{ln: ln}
	s.done.Add(1)
	go s.serve()
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func (s *socksServer) Addr() string { return s.ln.Addr().String() }

func (s *socksServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.ln.Close()
	for _, c := range s.closers {
		_ = c.Close()
	}
	s.done.Wait()
	return err
}

func (s *socksServer) serve() {
	defer s.done.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.closers = append(s.closers, conn)
		s.mu.Unlock()
		s.done.Go(func() {
			s.handle(conn)
		})
	}
}

func (s *socksServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	// Greeting: VER, NMETHODS, METHODS — accept only the no-auth offer.
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	// Request: VER, CMD, RSV, ATYP, ADDR, PORT — CONNECT only.
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != 5 || req[1] != 1 {
		return
	}
	var target string
	switch req[3] {
	case 1: // IPv4
		raw := make([]byte, 4)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return
		}
		target = joinTarget(net.IP(raw).String(), conn)
	case 3: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return
		}
		target = joinTarget(string(name), conn)
	case 4: // IPv6
		raw := make([]byte, 16)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return
		}
		target = joinTarget(net.IP(raw).String(), conn)
	default:
		return
	}
	s.LastTarget.Store(&target)

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	up, err := dialer.DialContext(context.Background(), "tcp", target)
	if err != nil {
		// SOCKS5 general failure; the client surfaces it as a dial error.
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	s.Connects.Add(1)
	relay(conn, up)
}

// joinTarget reads the 2-byte port after the address portion was consumed
// and renders the dialable host:port.
func joinTarget(host string, conn net.Conn) string {
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))
}

// relay pumps both directions until either side closes, then tears BOTH down
// (half-close semantics: an upstream close must reach the client as EOF, not
// as a hung reverse direction).
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}
