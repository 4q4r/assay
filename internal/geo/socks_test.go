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
	// Request: VER, CMD, RSV, ATYP, ADDR, PORT — CONNECT or UDP ASSOCIATE.
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != 5 {
		return
	}
	if req[1] == 3 {
		s.handleUDPAssociate(conn)
		return
	}
	if req[1] != 1 {
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

// udpAssociateState tracks one ASSOCIATE exchange (the STUN e2e evidence:
// the requests counter proves the battery's Binding rode the relay).
type udpAssociateState struct {
	client   *net.UDPAddr
	relay    *net.UDPConn
	requests atomic.Int32
}

// relayLoop is the UDP ASSOCIATE datagram pump (split out so the control
// connection watcher and the shared closers can both end it).
func (s *socksServer) relayLoop(uc *net.UDPConn, state *udpAssociateState) {
	buf := make([]byte, 1500)
	var clientAddr *net.UDPAddr
	for {
		n, from, rerr := uc.ReadFromUDP(buf)
		if rerr != nil {
			return
		}
		if clientAddr == nil {
			if n >= 10 && buf[0] == 0 && buf[1] == 0 && (buf[3] == 1 || buf[3] == 4) {
				clientAddr = &net.UDPAddr{IP: from.IP, Port: from.Port}
				state.client = clientAddr
			} else {
				continue
			}
		}
		if from.Port == clientAddr.Port {
			atyp := buf[3]
			var daddr string
			var hdrLen int
			switch atyp {
			case 1:
				daddr = net.IP(buf[4:8]).String()
				hdrLen = 10
			case 4:
				daddr = net.IP(buf[4:20]).String()
				hdrLen = 22
			default:
				continue
			}
			port := int(binary.BigEndian.Uint16(buf[hdrLen-2 : hdrLen]))
			dst, derr := net.ResolveUDPAddr("udp", net.JoinHostPort(daddr, strconv.Itoa(port)))
			if derr != nil {
				continue
			}
			state.requests.Add(1)
			if _, werr := uc.WriteToUDP(buf[hdrLen:n], dst); werr != nil {
				return
			}
			continue
		}
		// Upstream → client: SOCKS-encapsulate with the source address.
		hdr := []byte{0, 0, 0}
		if v4 := from.IP.To4(); v4 != nil {
			hdr = append(hdr, 1)
			hdr = append(hdr, v4...)
		} else {
			hdr = append(hdr, 4)
			hdr = append(hdr, from.IP.To16()...)
		}
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(from.Port))
		if _, werr := uc.WriteToUDP(append(hdr, buf[:n]...), clientAddr); werr != nil {
			return
		}
	}
}

var udpAssocs sync.Map // listener addr string → *udpAssociateState

// handleUDPAssociate serves SOCKS5 CMD=3 (the STUN channel's transport):
// the reply carries the fixture's own UDP relay port, and datagrams are
// routed by direction — encapsulated client datagrams are stripped and
// forwarded to the embedded destination, raw upstream answers are
// encapsulated back to the client.
func (s *socksServer) handleUDPAssociate(conn net.Conn) {
	tail := make([]byte, 6) // DST.ADDR/PORT (wildcard) — ignored
	if _, err := io.ReadFull(conn, tail); err != nil {
		return
	}
	var lc net.ListenConfig
	relay, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	uc := relay.(*net.UDPConn)
	lport := uc.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1}
	reply = binary.BigEndian.AppendUint16(reply, uint16(lport))
	if _, err := conn.Write(reply); err != nil {
		_ = uc.Close()
		return
	}
	state := &udpAssociateState{relay: uc}
	udpAssocs.Store(s.Addr(), state)
	// Register the UDP relay in the shared closers: socksServer.Close must
	// be able to unblock the ReadFromUDP loop below (and the s.done
	// WaitGroup must cover it, or Close hangs forever).
	s.mu.Lock()
	s.closers = append(s.closers, uc)
	s.mu.Unlock()
	var udpDone sync.WaitGroup
	udpDone.Go(func() {
		s.relayLoop(uc, state)
	})
	// The control connection's death also ends the relay (the client hung
	// up — the exchange is over either way).
	_, _ = io.Copy(io.Discard, conn)
	_ = uc.Close()
	udpDone.Wait()
	udpAssocs.Delete(s.Addr())
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
