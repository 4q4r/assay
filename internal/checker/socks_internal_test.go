package checker

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
)

// socksServer is a minimal RFC 1928 CONNECT server for integration tests:
// it accepts the greeting (no auth), records the REQUESTED address (atyp +
// host — the remote-DNS pin), forwards to the real target and pumps bytes.
type socksServer struct {
	ln              net.Listener
	routes          map[string]string // requested host:port → upstream (DoH endpoint etc.)
	defaultUpstream string            // everything else forwards here

	mu       sync.Mutex
	lastATYP byte
	lastHost string
	lastPort int
	accepted int

	domainHosts []string // every atyp=DOMAIN request (the remote-DNS pin)
}

func newSocksServerForward(t *testing.T, upstream string) *socksServer {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	s := &socksServer{ln: ln, routes: map[string]string{}, defaultUpstream: upstream}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *socksServer) addr() string { return s.ln.Addr().String() }

func (s *socksServer) domainRequests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.domainHosts...)
}

func (s *socksServer) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

func (s *socksServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.accepted++
		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *socksServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil { // ver, nmethods
		return
	}
	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return
	}
	head := make([]byte, 4) // ver, cmd, rsv, atyp
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	var host string
	switch head[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return
		}
		host = string(name)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return
	}
	portNum := int(port[0])<<8 | int(port[1])
	s.mu.Lock()
	s.lastATYP, s.lastHost, s.lastPort = head[3], host, portNum
	if head[3] == 0x03 {
		s.domainHosts = append(s.domainHosts, host)
	}
	s.mu.Unlock()

	key := net.JoinHostPort(host, strconv.Itoa(portNum))
	target := s.routes[key]
	if target == "" {
		target = s.defaultUpstream
	}
	upstream, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", target)
	if err != nil { // upstream refused/unreachable → SOCKS "connection refused"
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = upstream.Close() }()
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	go func() { _, _ = io.Copy(upstream, conn) }()
	_, _ = io.Copy(conn, upstream)
}
