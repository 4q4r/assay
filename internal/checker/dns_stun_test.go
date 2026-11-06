package checker

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// dnsFixture is a framed DNS-over-TCP test server: it verifies the 2-byte
// big-endian length prefix on the inbound query (the framing contract the
// research landmines pin), then writes the scripted answer frame.
type dnsFixture struct {
	ln      net.Listener
	mu      sync.Mutex
	queries [][]byte // every framed query body received
	answer  []byte   // the FULL 2-byte-prefixed answer frame to send
}

func newDNSFixture(t *testing.T, answer []byte) *dnsFixture {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns fixture listen: %v", err)
	}
	fx := &dnsFixture{ln: ln, answer: answer}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				prefix := make([]byte, 2)
				if _, err := io.ReadFull(c, prefix); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(prefix))
				msg := make([]byte, n)
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				fx.mu.Lock()
				fx.queries = append(fx.queries, msg)
				fx.mu.Unlock()
				_, _ = c.Write(fx.answer)
			}(conn)
		}
	}()
	return fx
}

func (fx *dnsFixture) addr() string { return fx.ln.Addr().String() }

func (fx *dnsFixture) queryCount() int {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return len(fx.queries)
}

// buildTXTAnswer frames a DNS response: rcode, optional single TXT answer
// whose character-string embeds the given text (the
// o-o.myaddr.l.google.com "IP.# evidence" shape).
func buildTXTAnswer(rcode int, txt string, withAnswer bool) []byte {
	owner := "o-o.myaddr.l.google"
	qname := append([]byte{byte(len(owner))}, owner...)
	qname = append(qname, byte(3))
	qname = append(qname, "com"...)
	qname = append(qname, 0)

	msg := []byte{0x00, 0x00, 0x80, byte(rcode & 0x0F), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	msg = append(msg, qname...)
	msg = binary.BigEndian.AppendUint16(msg, 16) // qtype TXT
	msg = binary.BigEndian.AppendUint16(msg, 1)  // IN
	if withAnswer {
		rdata := append([]byte{byte(len(txt))}, txt...)
		msg[6], msg[7] = 0x00, 0x01 // ancount
		msg = append(msg, 0xC0, 0x0C)
		msg = binary.BigEndian.AppendUint16(msg, 16)
		msg = binary.BigEndian.AppendUint16(msg, 1)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
		msg = append(msg, rdata...)
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
	return append(frame, msg...)
}

// dnsQueryBone is a well-formed query body for the TXT question (what
// buildDNSQuery produces for the test owner name) — used to assert the
// fixture actually received the framed query.
const dnsOwner = "o-o.myaddr.l.google.com"

func TestDNSOverTCPRcode0TXT(t *testing.T) {
	fx := newDNSFixture(t, buildTXTAnswer(0, "198.51.100.53.# evidence", true))
	socks := newSocksServerForward(t, fx.addr())
	tc := NewTunnelClient(socks.addr(), 2*time.Second)

	txts, err := tc.DNSOverTCP(context.Background(), fx.addr(), dnsOwner, 16)
	if err != nil {
		t.Fatalf("DNSOverTCP: %v", err)
	}
	if txts != "198.51.100.53.# evidence" {
		t.Fatalf("TXT rdata = %q", txts)
	}
	if fx.queryCount() != 1 {
		t.Fatalf("queries = %d, want 1", fx.queryCount())
	}
	fx.mu.Lock()
	q := fx.queries[0]
	fx.mu.Unlock()
	// The framed query carried the TXT question (name + qtype 16).
	if len(q) < 18 || q[2] != 0x00 || q[3] != 0x00 {
		t.Fatalf("query flags malformed: % x", q[:min(4, len(q))])
	}
	qtype := binary.BigEndian.Uint16(q[len(q)-4:])
	if qtype != 16 {
		t.Fatalf("qtype = %d, want TXT(16)", qtype)
	}
	// DNS wire format splits the name into length-prefixed LABELS — assert
	// the label fragments rode the frame.
	for _, frag := range []string{"o-o", "myaddr", "google", "com"} {
		if !bytes.Contains(q, []byte(frag)) {
			t.Fatalf("query lost the label %q: % x", frag, q)
		}
	}
}

func TestDNSOverTCPRcode4WithAnswersAccepted(t *testing.T) {
	// The systemd-resolved quirk (research landmine): NOTIMP WITH answers
	// is still an answer.
	fx := newDNSFixture(t, buildTXTAnswer(4, "198.51.100.53", true))
	socks := newSocksServerForward(t, fx.addr())
	tc := NewTunnelClient(socks.addr(), 2*time.Second)

	txts, err := tc.DNSOverTCP(context.Background(), fx.addr(), dnsOwner, 16)
	if err != nil {
		t.Fatalf("rcode-4-with-answers must be accepted: %v", err)
	}
	if txts != "198.51.100.53" {
		t.Fatalf("TXT rdata = %q", txts)
	}
}

func TestDNSOverTCPRcode4WithoutAnswersRejected(t *testing.T) {
	fx := newDNSFixture(t, buildTXTAnswer(4, "", false))
	socks := newSocksServerForward(t, fx.addr())
	tc := NewTunnelClient(socks.addr(), 2*time.Second)

	if _, err := tc.DNSOverTCP(context.Background(), fx.addr(), dnsOwner, 16); err == nil {
		t.Fatal("NOTIMP without answers carries no echo evidence — must error")
	}
}

func TestDNSOverTCPRcode3Rejected(t *testing.T) {
	fx := newDNSFixture(t, buildTXTAnswer(3, "nx", true))
	socks := newSocksServerForward(t, fx.addr())
	tc := NewTunnelClient(socks.addr(), 2*time.Second)

	if _, err := tc.DNSOverTCP(context.Background(), fx.addr(), dnsOwner, 16); err == nil {
		t.Fatal("NXDOMAIN must error")
	}
}

// TestDNSOverTCPGarbageFramesRejected pins the framing landmine: a
// garbage prefix, a zero-length declaration, and a TRUNCATED body are all
// malformed messages, never partial answers.
func TestDNSOverTCPGarbageFramesRejected(t *testing.T) {
	cases := map[string][]byte{
		"declared-zero":  {0x00, 0x00, 0x01, 0x02},
		"declared-huge":  {0xFF, 0xFF, 0x01, 0x02},
		"truncated-body": {0x00, 0x20, 0x01, 0x02, 0x03}, // says 32, sends 3
		"short-prefix":   {0x00},
		"garbage-message": func() []byte {
			frame := binary.BigEndian.AppendUint16(nil, 4)
			return append(frame, 0xDE, 0xAD, 0xBE, 0xEF)
		}(),
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newDNSFixture(t, answer)
			socks := newSocksServerForward(t, fx.addr())
			tc := NewTunnelClient(socks.addr(), 2*time.Second)
			if _, err := tc.DNSOverTCP(context.Background(), fx.addr(), dnsOwner, 16); err == nil {
				t.Fatalf("%s must reject the frame", name)
			}
		})
	}
}

// stunFixture is a UDP "STUN" server: it captures the Binding request,
// verifies the magic cookie, and replies with the scripted bytes.
type stunFixture struct {
	pc       *net.UDPConn
	mu       sync.Mutex
	request  []byte
	replyFor func(req []byte) []byte // the reply scripted off the captured request
}

func newSTUNFixture(t *testing.T, replyFor func(req []byte) []byte) *stunFixture {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("stun fixture listen: %v", err)
	}
	fx := &stunFixture{pc: pc, replyFor: replyFor}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			fx.mu.Lock()
			fx.request = append([]byte(nil), buf[:n]...)
			build := fx.replyFor
			fx.mu.Unlock()
			if build != nil {
				if reply := build(fx.request); reply != nil {
					_, _ = pc.WriteToUDP(reply, raddr)
				}
			}
		}
	}()
	return fx
}

func (fx *stunFixture) addr() string { return fx.pc.LocalAddr().String() }

func (fx *stunFixture) gotRequest() []byte {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return fx.request
}

// buildXORReply builds a Binding success response carrying
// XOR-MAPPED-ADDRESS for the given IPv4/port (the XOR mask is the magic
// cookie) against the given transaction id.
func buildXORReply(txid [12]byte, ip [4]byte, port uint16) []byte {
	msg := make([]byte, 0, 20+12)
	msg = append(msg, 0x01, 0x01)                // Binding success
	msg = binary.BigEndian.AppendUint16(msg, 12) // attribute length
	msg = binary.BigEndian.AppendUint32(msg, stunMagicCookie)
	msg = append(msg, txid[:]...)
	msg = binary.BigEndian.AppendUint16(msg, attrXORMappedAddress)
	msg = binary.BigEndian.AppendUint16(msg, 8)
	msg = append(msg, 0x00, stunFamilyIPv4)
	xport := port ^ 0x2112
	msg = binary.BigEndian.AppendUint16(msg, xport)
	for i, b := range ip {
		cookie := []byte{0x21, 0x12, 0xA4, 0x42}
		msg = append(msg, b^cookie[i])
	}
	return msg
}

// udpAssocSocks is a minimal SOCKS5 server speaking UDP ASSOCIATE (CMD=3):
// it answers ASSOCIATE with its own UDP relay socket, then routes
// datagrams — encapsulated client datagrams are stripped and forwarded to
// the embedded destination; raw datagrams arriving from anywhere else are
// SOCKS-encapsulated and sent back to the client's UDP address.
type udpAssocSocks struct {
	ln    net.Listener
	relay *net.UDPConn
}

func newUDPAssocSocks(t *testing.T) *udpAssocSocks {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("assoc listen: %v", err)
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	u := &udpAssocSocks{ln: ln, relay: relay}
	t.Cleanup(func() { _ = ln.Close(); _ = relay.Close() })
	go u.serve()
	return u
}

func (u *udpAssocSocks) addr() string { return u.ln.Addr().String() }

func (u *udpAssocSocks) serve() {
	for {
		conn, err := u.ln.Accept()
		if err != nil {
			return
		}
		go u.handle(conn)
	}
}

func (u *udpAssocSocks) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	if !u.associate(conn) {
		return
	}
	u.pumpDatagrams()
}

// associate runs the ASSOCIATE handshake on the control connection;
// false = the connection was not a valid UDP ASSOCIATE request.
func (u *udpAssocSocks) associate(conn net.Conn) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return false
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return false
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return false
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[1] != 0x03 {
		return false // this fixture only serves UDP ASSOCIATE
	}
	tail := make([]byte, 6) // DST.ADDR/PORT (ATYP=1: 4+2) — ignored wildcard
	if _, err := io.ReadFull(conn, tail); err != nil {
		return false
	}
	laddr := u.relay.LocalAddr().(*net.UDPAddr)
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1}
	reply = binary.BigEndian.AppendUint16(reply, uint16(laddr.Port))
	if _, err := conn.Write(reply); err != nil {
		return false
	}
	return true
}

// pumpDatagrams routes datagrams by direction until the relay dies.
func (u *udpAssocSocks) pumpDatagrams() {
	// ONE reader on the relay socket: client datagrams are encapsulated
	// (10/22-byte header), upstream answers are raw — route by direction.
	var clientAddr *net.UDPAddr
	buf := make([]byte, 1500)
	for {
		n, from, err := u.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if clientAddr == nil {
			// The first datagram is the client's (a SOCKS-encapsulated
			// datagram starts with two zero RSV bytes + ATYP).
			if n >= 10 && buf[0] == 0 && buf[1] == 0 && (buf[3] == 1 || buf[3] == 4) {
				clientAddr = &net.UDPAddr{IP: from.IP, Port: from.Port}
			} else {
				continue
			}
		}
		isClient := from.Port == clientAddr.Port
		if isClient && n >= 10 {
			// Client → destination: strip the SOCKS header, forward.
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
			if _, werr := u.relay.WriteToUDP(buf[hdrLen:n], dst); werr != nil {
				return
			}
			continue
		}
		if !isClient {
			if clientAddr == nil {
				continue // nothing to answer to yet
			}
			// Upstream → client: SOCKS-encapsulate with the source addr.
			hdr := []byte{0, 0, 0}
			switch {
			case from.IP.To4() != nil:
				hdr = append(hdr, 1)
				hdr = append(hdr, from.IP.To4()...)
			default:
				hdr = append(hdr, 4)
				hdr = append(hdr, from.IP.To16()...)
			}
			hdr = binary.BigEndian.AppendUint16(hdr, uint16(from.Port))
			if _, werr := u.relay.WriteToUDP(append(hdr, buf[:n]...), clientAddr); werr != nil {
				return
			}
		}
	}
}

func TestSTUNBindingXORMapped(t *testing.T) {
	const wantIP = "198.51.100.99"
	// The reply must echo the REQUEST's own transaction id — STUNBinding
	// generates a fresh one internally, so the fixture reads it from the
	// captured Binding request.
	replyFor := func(req []byte) []byte {
		if len(req) < 20 {
			return nil
		}
		var txid [12]byte
		copy(txid[:], req[8:20])
		return buildXORReply(txid, [4]byte{198, 51, 100, 99}, 3478)
	}
	fx := newSTUNFixture(t, replyFor)
	socks := newUDPAssocSocks(t)
	tc := NewTunnelClient(socks.addr(), 3*time.Second)

	ip, err := tc.STUNBinding(context.Background(), fx.addr())
	if err != nil {
		t.Fatalf("STUNBinding: %v", err)
	}
	if ip != wantIP {
		t.Fatalf("XOR-MAPPED-ADDRESS decoded %q, want %q", ip, wantIP)
	}
	req := fx.gotRequest()
	if len(req) != 20 {
		t.Fatalf("binding request = %d bytes, want 20", len(req))
	}
	if req[0] != 0x00 || req[1] != 0x01 {
		t.Fatalf("binding type = % x", req[0:2])
	}
	if binary.BigEndian.Uint32(req[4:8]) != stunMagicCookie {
		t.Fatalf("magic cookie missing: % x", req[4:8])
	}
	if binary.BigEndian.Uint16(req[2:4]) != 0 {
		t.Fatalf("message length = %d, want 0", binary.BigEndian.Uint16(req[2:4]))
	}
}

func TestSTUNMalformedReplyIsError(t *testing.T) {
	fx := newSTUNFixture(t, func([]byte) []byte {
		return []byte{0x01, 0x01, 0x00, 0x00} // header only, no txid/attributes
	})
	socks := newUDPAssocSocks(t)
	tc := NewTunnelClient(socks.addr(), 2*time.Second)

	if _, err := tc.STUNBinding(context.Background(), fx.addr()); err == nil {
		t.Fatal("a malformed binding reply must error (recorded non-fatal upstream)")
	}
}

func TestSTUNUnreachableServerIsError(t *testing.T) {
	socks := newUDPAssocSocks(t)
	tc := NewTunnelClient(socks.addr(), 2*time.Second)
	// A routed-but-silent port (loopback 1: nothing listens, datagrams die
	// quietly) — the exchange must time out into an error, not hang.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := tc.STUNBinding(ctx, "127.0.0.1:9"); err == nil {
		t.Fatal("a silent STUN server must error")
	}
}

func TestBuildSTUNBindingShape(t *testing.T) {
	req, txid, err := buildSTUNBinding()
	if err != nil {
		t.Fatalf("buildSTUNBinding: %v", err)
	}
	if len(req) != 20 {
		t.Fatalf("request = %d bytes, want 20", len(req))
	}
	if req[0] != 0x00 || req[1] != 0x01 {
		t.Fatalf("type = % x, want Binding", req[0:2])
	}
	if binary.BigEndian.Uint16(req[2:4]) != 0 {
		t.Fatal("message length must be 0")
	}
	if binary.BigEndian.Uint32(req[4:8]) != stunMagicCookie {
		t.Fatal("magic cookie mismatch")
	}
	if bytes.Equal(req[8:20], make([]byte, 12)) {
		t.Fatal("transaction id must be random, not zero")
	}
	if req[8:20] != nil && !bytes.Equal(req[8:20], txid[:]) {
		t.Fatal("txid mismatch between return values")
	}
}

// TestSocksUDPEnabledPerProtocol pins the temp-instance UDP contract: the
// socks inbound enables the UDP relay ONLY for hysteria outbounds (the
// STUN channel's transport); vless/vmess/trojan/ss stay udp:false.
func TestSocksUDPEnabledPerProtocol(t *testing.T) {
	for proto, want := range map[string]bool{
		"hysteria":    true, // core's protocol name for hysteria2 = v2
		"vless":       false,
		"vmess":       false,
		"trojan":      false,
		"shadowsocks": false,
		"":            false,
	} {
		if got := socksUDPEnabled(map[string]any{"protocol": proto}); got != want {
			t.Fatalf("protocol %q: udp=%v, want %v", proto, got, want)
		}
	}
	if socksUDPEnabled(map[string]any{}) {
		t.Fatal("no protocol field: udp must stay false")
	}
}
