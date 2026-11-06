package checker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Tunnel-client helpers for the unlock battery's independent exit-IP
// channels (2026-11-07 exit-truth research): a hand-rolled DNS-over-TCP
// client and a minimal RFC 5389 STUN Binding client. Both ride the SAME
// temp-instance SOCKS5 endpoint as every other tunnel request — no new
// runtime dependencies, stdlib framing only.
//
// DNS: the exit's own authoritative answer to "who is asking" comes from
// TXT o-o.myaddr.l.google.com at ns1.google.com (216.239.32.10:53) queried
// over TCP THROUGH the tunnel (the socks CONNECT inbound carries TCP to any
// port). Framing landmines verified live in the research: a 2-byte
// big-endian length prefix in BOTH directions, a fresh connection per
// query, and both rcode 0 and rcode 4 (NOTIMP) WITH answers are accepted —
// the systemd-resolved-quirk shape the research captured.
//
// STUN: hysteria2 nodes expose a socks inbound with UDP relay enabled, so a
// Binding request to stun.l.google.com:19302 through the socks UDP path
// returns XOR-MAPPED-ADDRESS — the transport-level exit IP, independent of
// every HTTPS echo.

const (
	// dnsTCPTimeout bounds one framed DNS exchange (connect + write + read).
	dnsTCPTimeout = 4 * time.Second
	// dnsTCPMaxMessage caps the decoded DNS message (a response larger than
	// this is garbage regardless of its declared prefix length).
	dnsTCPMaxMessage = 64 << 10
	// stunTimeout bounds one Binding exchange.
	stunTimeout = 4 * time.Second
	// stunMagicCookie is the RFC 5389 fixed magic (§6).
	stunMagicCookie = 0x2112A442
	// stunHeaderLen is the fixed 20-byte STUN header.
	stunHeaderLen = 20
	// attrXORMappedAddress / attrMappedAddress (RFC 5389 §18.2).
	attrXORMappedAddress = 0x0020
	// familyIPv4 in the XOR-MAPPED-ADDRESS attribute.
	stunFamilyIPv4 = 0x01
)

// errDNSMessage is the shared failure shape for malformed framed DNS
// traffic (truncated prefixes, garbage frames, oversized declarations).
var errDNSMessage = errors.New("dns-over-tcp: malformed message")

// DNSOverTCP queries qname/qtype via DNS-over-TCP through the tunnel to
// server (host:port), returning the concatenated TXT character-strings of
// the first TXT answer ("" when the answer carries no TXT records). A fresh
// TCP connection is used per query (the research's framing contract). Both
// rcode 0 and rcode 4 (NOTIMP) WITH answers are accepted; every other
// rcode, a truncated or garbage frame, or a transport failure is an error —
// the caller records the outcome as evidence, non-fatally.
func (t *TunnelClient) DNSOverTCP(ctx context.Context, server, qname string, qtype uint16) (string, error) {
	query := buildDNSQuery(qname, qtype)
	frame := make([]byte, 2+len(query))
	//nolint:gosec // G115: a framed DNS query is capped far below 64KiB by qname length
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)

	dialer, err := t.dialer()
	if err != nil {
		return "", fmt.Errorf("socks dialer: %w", err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, dnsTCPTimeout)
	defer cancel()
	conn, err := dialer.DialContext(dialCtx, "tcp", server)
	if err != nil {
		return "", fmt.Errorf("tunnel dial %s: %w", server, err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(frame); err != nil {
		return "", fmt.Errorf("write query frame: %w", err)
	}
	msg, err := readFramedDNS(conn)
	if err != nil {
		return "", err
	}
	txts, rcode, answers, perr := parseDNSResponse(msg)
	if perr != nil {
		return "", perr
	}
	// rcode 0 = NOERROR; rcode 4 = NOTIMP with answers is the
	// systemd-resolved quirk the research verified live — an answer is an
	// answer. Anything else (NXDOMAIN, SERVFAIL, NOTIMP without answers)
	// carries no echo evidence.
	if rcode != 0 && (rcode != 4 || answers == 0) {
		return "", fmt.Errorf("dns-over-tcp: rcode %d with %d answers", rcode, answers)
	}
	return strings.Join(txts, ""), nil
}

// buildDNSQuery hand-rolls one DNS query message: header (id 0 — the
// framed exchange is stateless per connection, no matching needed),
// one question, RD=0 (we ask an authoritative server, not a stub).
func buildDNSQuery(qname string, qtype uint16) []byte {
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	// 12-byte header + 1 initial length byte + qname + 4 (qtype/qclass)
	// + 1 root terminator.
	buf := make([]byte, 0, 12+1+len(qname)+1+4)
	buf = append(buf,
		0x00, 0x00, // ID: 0 — fresh conn per query, no in-flight matching
		0x00, 0x00, // flags: standard query, RD=0
		0x00, 0x01, // QDCOUNT 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/ARCOUNT 0
	)
	for _, l := range labels {
		buf = append(buf, byte(len(l))) //nolint:gosec // G115: DNS labels are ≤63 bytes
		buf = append(buf, l...)
	}
	buf = append(buf, 0x00) // root
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, 1) // IN
	return buf
}

// readFramedDNS reads exactly one 2-byte-prefixed DNS message: the prefix
// must be present, within the message cap, and the declared number of bytes
// must actually arrive (truncated frames are garbage, not partial answers).
func readFramedDNS(conn net.Conn) ([]byte, error) {
	prefix := make([]byte, 2)
	if _, err := io.ReadFull(conn, prefix); err != nil {
		return nil, fmt.Errorf("%w: short length prefix: %w", errDNSMessage, err)
	}
	n := binary.BigEndian.Uint16(prefix)
	if n == 0 || int(n) > dnsTCPMaxMessage {
		return nil, fmt.Errorf("%w: declared length %d", errDNSMessage, n)
	}
	msg := make([]byte, int(n))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, fmt.Errorf("%w: truncated body: %w", errDNSMessage, err)
	}
	return msg, nil
}

// parseDNSResponse walks a DNS response message: header sanity, the
// question section skipped by label-walking, then answer records scanned
// for TXT rdata (type 16). Returns the TXT character-strings, the response
// rcode, and the answer count.
func parseDNSResponse(msg []byte) ([]string, int, int, error) {
	if len(msg) < 12 {
		return nil, 0, 0, fmt.Errorf("%w: response shorter than the header", errDNSMessage)
	}
	rcode := int(msg[3] & 0x0F)
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	var txts []string
	for range qd {
		next, serr := skipDNSName(msg, off)
		if serr != nil {
			return nil, rcode, an, serr
		}
		off = next
		if off+4 > len(msg) {
			return nil, rcode, an, fmt.Errorf("%w: question section truncated", errDNSMessage)
		}
		off += 4 // qtype + qclass
	}
	for range an {
		next, nerr := skipDNSName(msg, off)
		if nerr != nil {
			return txts, rcode, an, nerr
		}
		off = next
		if off+10 > len(msg) {
			return txts, rcode, an, fmt.Errorf("%w: answer record truncated", errDNSMessage)
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return txts, rcode, an, fmt.Errorf("%w: rdata exceeds the message", errDNSMessage)
		}
		if typ == 16 { // TXT
			txts = append(txts, parseTXTStrings(msg[off:off+rdlen])...)
		}
		off += rdlen
	}
	return txts, rcode, an, nil
}

// skipDNSName walks a (possibly compression-pointer) domain name at off,
// returning the offset just past it. Skipping needs no pointer chasing: a
// compression pointer (0xC0-prefixed) TERMINATES the encoded name — the
// remaining record fields follow the 2-byte pointer.
func skipDNSName(msg []byte, off int) (int, error) {
	pos := off
	for {
		if pos >= len(msg) {
			return 0, fmt.Errorf("%w: name runs past the message", errDNSMessage)
		}
		l := int(msg[pos])
		switch {
		case l == 0:
			return pos + 1, nil
		case l&0xC0 == 0xC0: // compression pointer: name ends here
			if pos+2 > len(msg) {
				return 0, fmt.Errorf("%w: truncated compression pointer", errDNSMessage)
			}
			return pos + 2, nil
		default:
			if pos+1+l > len(msg) {
				return 0, fmt.Errorf("%w: label exceeds the message", errDNSMessage)
			}
			pos += 1 + l
		}
	}
}

// parseTXTStrings splits TXT rdata into its character-strings (each a
// 1-byte length + that many bytes; RFC 1035 §3.3.14).
func parseTXTStrings(rdata []byte) []string {
	var out []string
	for i := 0; i < len(rdata); {
		l := int(rdata[i])
		if i+1+l > len(rdata) {
			break // trailing garbage is not a string
		}
		out = append(out, string(rdata[i+1:i+1+l]))
		i += 1 + l
	}
	return out
}

// STUNBinding performs ONE RFC 5389 Binding transaction to server
// (host:port) through the tunnel's UDP path (the socks UDP ASSOCIATE the
// hysteria2 probe instances carry) and returns the XOR-MAPPED-ADDRESS IP.
// A malformed or absent XOR-MAPPED-ADDRESS is an error — the caller records
// the failure as evidence, non-fatally.
func (t *TunnelClient) STUNBinding(ctx context.Context, server string) (string, error) {
	req, txid, err := buildSTUNBinding()
	if err != nil {
		return "", err
	}
	udpConn, closeSock, err := t.dialUDP(ctx, server)
	if err != nil {
		return "", err
	}
	defer closeSock()
	exCtx, cancel := context.WithTimeout(ctx, stunTimeout)
	defer cancel()
	deadline, ok := exCtx.Deadline()
	if !ok {
		return "", errors.New("stun: no deadline on the exchange context")
	}
	if err := udpConn.SetDeadline(deadline); err != nil {
		return "", fmt.Errorf("stun: set deadline: %w", err)
	}
	dgram, err := stunDatagram(server, req)
	if err != nil {
		return "", err
	}
	if _, werr := udpConn.Write(dgram); werr != nil {
		return "", fmt.Errorf("stun: send binding: %w", werr)
	}
	return readSTUNReply(udpConn, txid)
}

// stunDatagram wraps one Binding request in the SOCKS5 UDP datagram
// encapsulation (RFC 1928 §7): every datagram client→relay carries
// RSV/FRAG/ATYP/DST.ADDR/DST.PORT ahead of the payload; the relay strips
// it and forwards to that destination.
func stunDatagram(server string, req []byte) ([]byte, error) {
	host, portStr, serr := net.SplitHostPort(server)
	if serr != nil {
		return nil, fmt.Errorf("stun: server address %q: %w", server, serr)
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("stun: server port in %q: %w", server, perr)
	}
	raddrIP := net.ParseIP(host)
	if raddrIP == nil {
		return nil, fmt.Errorf("stun: server address %q: unparseable IP", server)
	}
	hdr := []byte{0x00, 0x00, 0x00}
	if v4 := raddrIP.To4(); v4 != nil {
		hdr = append(hdr, 0x01)
		hdr = append(hdr, v4...)
	} else {
		hdr = append(hdr, 0x04)
		hdr = append(hdr, raddrIP.To16()...)
	}
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(port))
	return append(hdr, req...), nil
}

// readSTUNReply reads datagrams until a Binding success carrying this
// transaction's XOR-MAPPED-ADDRESS arrives (or the deadline fires).
func readSTUNReply(udpConn *net.UDPConn, txid [12]byte) (string, error) {
	buf := make([]byte, 1500)
	for {
		n, rerr := udpConn.Read(buf)
		if rerr != nil {
			return "", fmt.Errorf("stun: read binding reply: %w", rerr)
		}
		// The reply rides the same encapsulation (header from the relay):
		// strip it, then match the STUN message.
		payload, perr := stripUDPHeader(buf[:n])
		if perr != nil {
			continue // not a parseable encapsulated datagram — keep reading
		}
		ip, ok := stunXORMappedIP(payload, txid)
		if ok {
			return ip, nil
		}
		// Not a Binding success reply (malformed/other attribute layout):
		// keep reading until the deadline — a chatty relay must not be
		// mistaken for an answer.
	}
}

// stripUDPHeader removes the SOCKS5 datagram encapsulation header
// (RFC 1928 §7) and returns the payload; a truncated or unknown-ATYP
// datagram is an error.
func stripUDPHeader(d []byte) ([]byte, error) {
	if len(d) < 4 {
		return nil, errors.New("stun: datagram shorter than the socks header")
	}
	switch d[3] {
	case 0x01:
		if len(d) < 10 {
			return nil, errors.New("stun: truncated socks header (v4)")
		}
		return d[10:], nil
	case 0x04:
		if len(d) < 22 {
			return nil, errors.New("stun: truncated socks header (v6)")
		}
		return d[22:], nil
	default:
		return nil, errors.New("stun: socks header atyp")
	}
}

// dialUDP opens the socks UDP relay path: the ASSOCIATE CONTROL connection
// is a DIRECT TCP connection to the socks inbound (the temp instance
// listens on the same loopback as the probe — the client↔proxy control
// channel never routes through the proxy itself), and the returned UDP
// socket speaks the datagram encapsulation toward the relay address the
// server answers with. The returned closer tears the control connection
// down.
func (t *TunnelClient) dialUDP(ctx context.Context, _ string) (*net.UDPConn, func(), error) {
	var d net.Dialer
	tcpConn, terr := d.DialContext(ctx, "tcp", t.socksAddr)
	if terr != nil {
		return nil, nil, fmt.Errorf("socks associate dial: %w", terr)
	}
	relayAddr, err := socksUDPAssociate(tcpConn)
	if err != nil {
		_ = tcpConn.Close()
		return nil, nil, err
	}
	udpConn, uerr := net.DialUDP("udp", nil, relayAddr)
	if uerr != nil {
		_ = tcpConn.Close()
		return nil, nil, fmt.Errorf("stun relay socket: %w", uerr)
	}
	return udpConn, func() { _ = udpConn.Close(); _ = tcpConn.Close() }, nil
}

// socksUDPAssociate runs the SOCKS5 UDP ASSOCIATE handshake over conn
// (greeting → CMD=3 request → relay address reply). The client's UDP
// endpoint is unspecified (wildcard request); xray answers with the relay
// port on its own listen address — a wildcard BND.ADDR means "this host".
func socksUDPAssociate(conn net.Conn) (*net.UDPAddr, error) {
	// Greeting: VER=5, NMETHODS=1, NO-AUTH.
	if _, werr := conn.Write([]byte{0x05, 0x01, 0x00}); werr != nil {
		return nil, fmt.Errorf("socks associate greeting: %w", werr)
	}
	head := make([]byte, 2)
	if _, rerr := io.ReadFull(conn, head); rerr != nil || head[0] != 0x05 || head[1] != 0x00 {
		return nil, fmt.Errorf("socks associate greeting reply: ver=%d rep=%d", head[0], head[1])
	}
	// Request: VER=5 CMD=3 (UDP ASSOCIATE) RSV=0 ATYP=1 DST.ADDR=0.0.0.0
	// DST.PORT=0.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, werr := conn.Write(req); werr != nil {
		return nil, fmt.Errorf("socks associate request: %w", werr)
	}
	resp := make([]byte, 4)
	if _, rerr := io.ReadFull(conn, resp); rerr != nil || resp[0] != 0x05 || resp[1] != 0x00 {
		return nil, fmt.Errorf("socks associate reply: ver=%d rep=%d", resp[0], resp[1])
	}
	addrLen := 4
	if resp[3] == 0x04 {
		addrLen = 16
	} else if resp[3] != 0x01 {
		return nil, fmt.Errorf("socks associate relay atyp=%d", resp[3])
	}
	raw := make([]byte, addrLen+2)
	if _, rerr := io.ReadFull(conn, raw); rerr != nil {
		return nil, fmt.Errorf("socks associate relay addr: %w", rerr)
	}
	relayIP := net.IP(raw[:addrLen])
	relayPort := int(binary.BigEndian.Uint16(raw[addrLen:]))
	relayHost := relayIP.String()
	if relayIP.IsUnspecified() {
		relayHost = "127.0.0.1"
	}
	return &net.UDPAddr{IP: net.ParseIP(relayHost), Port: relayPort}, nil
}

// buildSTUNBinding builds the 20-byte Binding request: type 0x0001, length
// 0, the fixed magic cookie, and a fresh 96-bit transaction id.
func buildSTUNBinding() ([]byte, [12]byte, error) {
	var txid [12]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return nil, txid, fmt.Errorf("stun: transaction id: %w", err)
	}
	req := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(req[0:2], 0x0001) // Binding
	binary.BigEndian.PutUint16(req[2:4], 0)      // message length (no attributes)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	copy(req[8:20], txid[:])
	return req, txid, nil
}

// stunXORMappedIP scans one STUN message for XOR-MAPPED-ADDRESS of THIS
// transaction and decodes the IPv4 address (the XOR mask is the magic
// cookie, §12.2). ok=false when the message is not a Binding success for
// txid carrying the attribute (malformed relays are not answers).
func stunXORMappedIP(msg []byte, txid [12]byte) (string, bool) {
	if len(msg) < stunHeaderLen {
		return "", false
	}
	if binary.BigEndian.Uint16(msg[0:2]) != 0x0101 { // Binding success
		return "", false
	}
	if binary.BigEndian.Uint32(msg[4:8]) != stunMagicCookie {
		return "", false
	}
	if !bytes.Equal(msg[8:20], txid[:]) {
		return "", false // another transaction's answer is not this answer
	}
	mlen := int(binary.BigEndian.Uint16(msg[2:4]))
	if mlen > len(msg)-stunHeaderLen {
		return "", false
	}
	off := stunHeaderLen
	end := stunHeaderLen + mlen
	for off+4 <= end {
		atype := binary.BigEndian.Uint16(msg[off : off+2])
		alen := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
		if off+4+alen > end {
			return "", false
		}
		if atype == attrXORMappedAddress && alen >= 8 && msg[off+5] == stunFamilyIPv4 {
			// Attribute: 2-byte type, 2-byte length, 1 byte reserved
			// (zero), 1 byte family, 2-byte XOR'd port, 4-byte XOR'd IP.
			x := msg[off+8 : off+12]
			// The XOR mask is the 4 magic-cookie bytes in network order
			// (RFC 5389 §12.2).
			cookie := []byte{0x21, 0x12, 0xA4, 0x42}
			ip := make(net.IP, 4)
			for i := range 4 {
				ip[i] = x[i] ^ cookie[i]
			}
			return ip.String(), true
		}
		off += 4 + alen
	}
	return "", false
}
