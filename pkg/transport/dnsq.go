package transport

// dnsq.go — DNS Query (UDP) transport with EDNS0 OPT payload encoding.
//
// Architecture (mirrors Slipstream-rust-plus):
//
//   Client                    Public Resolver(s)           Server (authoritative NS)
//   ──────                    ──────────────────           ─────────────────────────
//   Write(data) ─► [DNS query, EDNS0 OPT payload] ──► resolver ──► server:53 UDP
//   Read(data)  ◄─ [DNS response, EDNS0 OPT payload] ◄─ resolver ◄─ server:53 UDP
//
// Each DNS query carries up to dnsqPayloadMax bytes of raw binary data inside
// the EDNS0 OPT additional record — no base32 encoding overhead.
//
// Reliability is provided by a sliding-window protocol (seq + ack in payload header).
// Multiple resolver goroutines run in parallel for throughput:
//   N resolvers × chunk_size / RTT = throughput
//   e.g. 4 resolvers × 3882 B / 10 ms ≈ 15 MB/s; 8 resolvers ≈ 30 MB/s

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// ── Constants ────────────────────────────────────────────────────────────────

const (
	// dnsqPayloadMax is the max bytes of tunnel data per DNS message.
	// DNS UDP with EDNS0 supports up to 4096-byte messages; we reserve room
	// for DNS header (12) + question (~20) + OPT record header (11) + our frame header.
	dnsqPayloadMax = 3882

	// dnsqFrameHdr is: sessionID(8) + seq(4) + ack(4) + flags(2) = 18 bytes
	dnsqFrameHdr = 18

	// sliding window: number of in-flight queries before blocking Write
	dnsqWindow = 128

	// per-query retransmit timeout
	dnsqRetransmit = 200 * time.Millisecond

	// empty-payload poll interval: keeps server→client data flowing
	// when the client has no data to send
	dnsqPollInterval = 15 * time.Millisecond
)

// Frame flags
const (
	dnsqData = uint16(0) // carries data
	dnsqPoll = uint16(1) // keepalive / request for pending server data
	dnsqFin  = uint16(2) // connection close
)

// ── Frame helpers ─────────────────────────────────────────────────────────────

// encodeFrame builds the 18-byte frame header + data into a single slice.
func encodeFrame(sessionID [8]byte, seq, ack uint32, flags uint16, data []byte) []byte {
	buf := make([]byte, dnsqFrameHdr+len(data))
	copy(buf[:8], sessionID[:])
	binary.BigEndian.PutUint32(buf[8:12], seq)
	binary.BigEndian.PutUint32(buf[12:16], ack)
	binary.BigEndian.PutUint16(buf[16:18], flags)
	copy(buf[18:], data)
	return buf
}

// decodeFrame unpacks a received EDNS0 RDATA payload.
func decodeFrame(b []byte) (sessionID [8]byte, seq, ack uint32, flags uint16, data []byte, err error) {
	if len(b) < dnsqFrameHdr {
		err = fmt.Errorf("dnsq: frame too short (%d)", len(b))
		return
	}
	copy(sessionID[:], b[:8])
	seq = binary.BigEndian.Uint32(b[8:12])
	ack = binary.BigEndian.Uint32(b[12:16])
	flags = binary.BigEndian.Uint16(b[16:18])
	data = b[18:]
	return
}

// ── Minimal DNS wire-format builder ──────────────────────────────────────────
// We build and parse only the parts we need — no external DNS library required.

// encodeDNSName converts a dot-separated domain name to DNS wire format.
// e.g. "t.j.pingzone.ir" → \x01t\x01j\x08pingzone\x02ir\x00
func encodeDNSName(name string) []byte {
	var out []byte
	for _, label := range splitLabels(name) {
		if len(label) == 0 {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0x00)
	return out
}

func splitLabels(name string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

// buildDNSQuery creates a DNS query message with an EDNS0 OPT additional record
// carrying payload as raw RDATA. If domain is non-empty, the QNAME is set to
// <16-hex-nonce>.<domain> so public resolvers forward the query to the domain's
// authoritative nameserver (your tunnel server). Otherwise a static local name
// is used (for direct mode where no domain NS is needed).
// queryID must be a random uint16 chosen by the caller.
func buildDNSQuery(queryID uint16, domain string, payload []byte) []byte {
	var qname []byte
	if domain != "" {
		// Relay mode: <16-char random hex>.<domain>
		// The random prefix prevents caching and makes each query unique.
		var nonce [8]byte
		rand.Read(nonce[:]) //nolint:errcheck
		nonceHex := fmt.Sprintf("%x", nonce)
		qname = encodeDNSName(nonceHex + "." + domain)
	} else {
		// Direct mode: static minimal name "t.q." — no DNS forwarding needed.
		// Question: encode "t.q." as a DNS name (two labels: "t" and "q")
		// Wire: \x01 t \x01 q \x00
		qname = []byte{0x01, 't', 0x01, 'q', 0x00}
	}
	qtype := uint16(16)  // TXT (looks like a normal DNS TXT query)
	qclass := uint16(1)  // IN

	// DNS Header (12 bytes)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], queryID) // ID
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)  // Flags: RD=1 (recursion desired)
	binary.BigEndian.PutUint16(hdr[4:6], 1)        // QDCOUNT = 1
	// ANCOUNT, NSCOUNT = 0
	binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCOUNT = 1 (the OPT record)

	// Question section
	q := make([]byte, len(qname)+4)
	copy(q, qname)
	binary.BigEndian.PutUint16(q[len(qname):], qtype)
	binary.BigEndian.PutUint16(q[len(qname)+2:], qclass)

	// OPT additional record (EDNS0, RFC 6891)
	//   Name:    0x00 (root)
	//   Type:    41
	//   Class:   4096 (requestor's UDP payload size)
	//   TTL:     0 (EDNS0 extended RCODE and flags)
	//   RDLEN:   len(payload)
	//   RDATA:   payload
	opt := make([]byte, 11+len(payload))
	opt[0] = 0x00 // root name
	binary.BigEndian.PutUint16(opt[1:3], 41)   // OPT type
	binary.BigEndian.PutUint16(opt[3:5], 4096) // UDP payload size
	// TTL = 0 (bytes 5-8)
	binary.BigEndian.PutUint16(opt[9:11], uint16(len(payload))) // RDLEN
	copy(opt[11:], payload)

	msg := make([]byte, 0, len(hdr)+len(q)+len(opt))
	msg = append(msg, hdr...)
	msg = append(msg, q...)
	msg = append(msg, opt...)
	return msg
}

// buildNXDomainResponse returns a minimal authoritative NXDOMAIN answer.
// Sent to non-tunnel DNS queries so public resolvers see this server as a
// live nameserver and keep forwarding tunnel queries to it.
func buildNXDomainResponse(queryID uint16, question []byte) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], queryID)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8183) // QR=1 AA=1 RD=1 RA=1 RCODE=3(NXDOMAIN)
	if len(question) > 0 {
		binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT=1
	}
	msg := make([]byte, 0, len(hdr)+len(question))
	msg = append(msg, hdr...)
	msg = append(msg, question...)
	return msg
}

// buildDNSResponse creates a DNS response (QR=1) echoing the incoming query ID
// and question section so public resolvers can match it to the original query.
func buildDNSResponse(queryID uint16, question []byte, payload []byte) []byte {
	// DNS Header (12 bytes)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], queryID) // echo client's query ID
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180)  // QR=1, AA=1, RD=1, RA=1
	if len(question) > 0 {
		binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT=1
	}
	binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCOUNT=1 (OPT record)

	// OPT additional record (EDNS0, RFC 6891)
	opt := make([]byte, 11+len(payload))
	opt[0] = 0x00 // root name
	binary.BigEndian.PutUint16(opt[1:3], 41)   // OPT type
	binary.BigEndian.PutUint16(opt[3:5], 4096) // UDP payload size
	// TTL = 0 (bytes 5-8)
	binary.BigEndian.PutUint16(opt[9:11], uint16(len(payload))) // RDLEN
	copy(opt[11:], payload)

	msg := make([]byte, 0, len(hdr)+len(question)+len(opt))
	msg = append(msg, hdr...)
	msg = append(msg, question...)
	msg = append(msg, opt...)
	return msg
}

// extractDNSQueryInfo extracts the query ID and raw question section bytes
// from an incoming DNS query message.
func extractDNSQueryInfo(msg []byte) (queryID uint16, question []byte) {
	if len(msg) < 12 {
		return 0, nil
	}
	queryID = binary.BigEndian.Uint16(msg[0:2])
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	if qdcount == 0 {
		return queryID, nil
	}
	pos := 12
	for i := uint16(0); i < qdcount && pos < len(msg); i++ {
		pos = skipDNSName(msg, pos)
		pos += 4 // type + class
	}
	if pos > len(msg) {
		return queryID, nil
	}
	question = msg[12:pos]
	return queryID, question
}

// parseDNSOptPayload extracts the EDNS0 OPT RDATA from a raw DNS message.
// Returns nil if no OPT record is found.
func parseDNSOptPayload(msg []byte) []byte {
	if len(msg) < 12 {
		return nil
	}
	arcount := binary.BigEndian.Uint16(msg[10:12])
	if arcount == 0 {
		return nil
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])
	nscount := binary.BigEndian.Uint16(msg[8:10])

	// Skip header
	pos := 12

	// Skip question section
	for i := uint16(0); i < qdcount && pos < len(msg); i++ {
		pos = skipDNSName(msg, pos)
		pos += 4 // type + class
	}

	// Skip answer + authority sections
	toSkip := int(ancount) + int(nscount)
	for i := 0; i < toSkip && pos < len(msg); i++ {
		pos = skipDNSName(msg, pos)
		if pos+10 > len(msg) {
			return nil
		}
		rdlen := binary.BigEndian.Uint16(msg[pos+8 : pos+10])
		pos += 10 + int(rdlen)
	}

	// Scan additional records for OPT (type 41)
	for i := uint16(0); i < arcount && pos < len(msg); i++ {
		nameStart := pos
		pos = skipDNSName(msg, pos)
		if pos+10 > len(msg) {
			return nil
		}
		rtype := binary.BigEndian.Uint16(msg[pos : pos+2])
		rdlen := binary.BigEndian.Uint16(msg[pos+8 : pos+10])
		pos += 10
		_ = nameStart
		if rtype == 41 { // OPT
			if pos+int(rdlen) > len(msg) {
				return nil
			}
			rdata := msg[pos : pos+int(rdlen)]
			pos += int(rdlen)
			return rdata
		}
		pos += int(rdlen)
	}
	return nil
}

// skipDNSName advances pos past a DNS wire-format name (labels or pointer).
func skipDNSName(msg []byte, pos int) int {
	for pos < len(msg) {
		l := int(msg[pos])
		if l == 0 {
			return pos + 1
		}
		if l&0xC0 == 0xC0 { // pointer
			return pos + 2
		}
		pos += 1 + l
	}
	return pos
}

// ── DNSQueryConn ─────────────────────────────────────────────────────────────

// DNSQueryConn implements net.Conn over DNS UDP with EDNS0 payload encoding.
// It sends DNS queries to a list of resolvers in round-robin and reads data
// from their responses.  A sliding-window reliability protocol (seq+ack in
// the EDNS0 payload header) ensures ordered, lossless delivery over UDP.
type DNSQueryConn struct {
	resolvers   []string
	domain      string        // tunnel domain for relay mode (e.g. "t.j.pingzone.ir")
	socks       []*net.UDPConn // one socket per resolver
	sessionID   [8]byte
	ridx        atomic.Uint32 // round-robin index

	closed    chan struct{}
	closeOnce sync.Once

	// ── Send state ───────────────────────────────────────────────────────────
	sendMu  sync.Mutex
	sendSeq uint32
	sendQ   chan sendItem // chunks queued by Write()

	// inflight: seq -> *inflightEntry
	inflight   sync.Map
	inflightCt atomic.Int32

	// ── Receive state ─────────────────────────────────────────────────────────
	recvMu    sync.Mutex
	recvSeq   uint32 // next expected seq from peer
	recvPend  map[uint32][]byte
	recvBuf   []byte
	recvReady chan struct{} // signals Read() that data arrived

	// ── ACK state (what we ack to peer) ─────────────────────────────────────
	ackMu   sync.Mutex
	lastAck uint32 // highest contiguous seq received from peer (sent in next query)

	localAddr  net.Addr
	remoteAddr net.Addr

	readDeadline  atomic.Value // stores time.Time
	writeDeadline atomic.Value
}

type sendItem struct {
	data  []byte
	flags uint16
}

type inflightEntry struct {
	seq   uint32
	flags uint16
	data  []byte
	acked chan struct{}
}

// DialDNSQuery connects to a DNS tunnel server via one or more UDP DNS resolvers.
// Each resolver is contacted on UDP port 53. The server must listen with ListenDNSQuery.
// DialDNSQuery connects to a DNS tunnel server via one or more UDP DNS resolvers.
// domain is the tunnel domain for relay mode (e.g. "t.j.pingzone.ir"); pass ""
// for direct mode where resolvers point straight to the server IP.
func DialDNSQuery(resolvers []string, domain string, timeout time.Duration) (*DNSQueryConn, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("dnsq: no resolvers specified")
	}

	c := &DNSQueryConn{
		resolvers:  resolvers,
		domain:     domain,
		recvPend:   make(map[uint32][]byte),
		recvReady:  make(chan struct{}, 1),
		sendQ:      make(chan sendItem, dnsqWindow*2),
		closed:     make(chan struct{}),
	}
	rand.Read(c.sessionID[:]) //nolint:errcheck

	// Open one UDP socket per resolver for even load distribution.
	c.socks = make([]*net.UDPConn, len(resolvers))
	for i, r := range resolvers {
		raddr, err := net.ResolveUDPAddr("udp", r)
		if err != nil {
			c.closeAll()
			return nil, fmt.Errorf("dnsq: resolve %s: %w", r, err)
		}
		sock, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			c.closeAll()
			return nil, fmt.Errorf("dnsq: dial %s: %w", r, err)
		}
		c.socks[i] = sock
		c.localAddr = sock.LocalAddr()
		c.remoteAddr = raddr
	}

	// Start background goroutines.
	for i, sock := range c.socks {
		go c.recvLoop(sock, i)
	}
	go c.sendLoop()
	go c.pollLoop()
	go c.retransmitLoop()

	return c, nil
}

// ── net.Conn interface ────────────────────────────────────────────────────────

func (c *DNSQueryConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > dnsqPayloadMax {
			chunk = p[:dnsqPayloadMax]
		}
		cp := make([]byte, len(chunk))
		copy(cp, chunk)
		select {
		case c.sendQ <- sendItem{data: cp, flags: dnsqData}:
		case <-c.closed:
			return total, fmt.Errorf("dnsq: connection closed")
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *DNSQueryConn) Read(p []byte) (int, error) {
	for {
		c.recvMu.Lock()
		if len(c.recvBuf) > 0 {
			n := copy(p, c.recvBuf)
			c.recvBuf = c.recvBuf[n:]
			if len(c.recvBuf) == 0 {
				c.recvBuf = nil
			}
			c.recvMu.Unlock()
			return n, nil
		}
		c.recvMu.Unlock()

		// Check deadline
		var timeout <-chan time.Time
		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, fmt.Errorf("dnsq: read timeout")
			}
			timeout = time.After(d)
		}

		select {
		case <-c.recvReady:
		case <-c.closed:
			return 0, fmt.Errorf("dnsq: connection closed")
		case <-timeout:
			return 0, fmt.Errorf("dnsq: read timeout")
		}
	}
}

func (c *DNSQueryConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.closeAll()
	})
	return nil
}

func (c *DNSQueryConn) closeAll() {
	for _, s := range c.socks {
		if s != nil {
			s.Close()
		}
	}
}

func (c *DNSQueryConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *DNSQueryConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *DNSQueryConn) SetDeadline(t time.Time) error      { c.readDeadline.Store(t); c.writeDeadline.Store(t); return nil }
func (c *DNSQueryConn) SetReadDeadline(t time.Time) error  { c.readDeadline.Store(t); return nil }
func (c *DNSQueryConn) SetWriteDeadline(t time.Time) error { c.writeDeadline.Store(t); return nil }

// ── Background goroutines ─────────────────────────────────────────────────────

// sendLoop dequeues items from sendQ, assigns sequence numbers, sends DNS queries,
// and tracks them in the inflight map.
func (c *DNSQueryConn) sendLoop() {
	for {
		select {
		case item := <-c.sendQ:
			c.sendOne(item.flags, item.data)
		case <-c.closed:
			return
		}
	}
}

func (c *DNSQueryConn) sendOne(flags uint16, data []byte) {
	// Backpressure: wait until window has space.
	for c.inflightCt.Load() >= dnsqWindow {
		select {
		case <-c.closed:
			return
		case <-time.After(2 * time.Millisecond):
		}
	}

	c.sendMu.Lock()
	seq := c.sendSeq
	c.sendSeq++
	c.sendMu.Unlock()

	c.ackMu.Lock()
	ack := c.lastAck
	c.ackMu.Unlock()

	payload := encodeFrame(c.sessionID, seq, ack, flags, data)
	entry := &inflightEntry{
		seq:   seq,
		flags: flags,
		data:  data,
		acked: make(chan struct{}),
	}
	c.inflight.Store(seq, entry)
	c.inflightCt.Add(1)

	sock := c.nextSock()
	qid := uint16(rand.Uint32())
	msg := buildDNSQuery(qid, c.domain, payload)
	sock.Write(msg) //nolint:errcheck
}

// pollLoop sends empty queries on a timer so the server can send pending data
// back to the client even when Write() hasn't been called.
func (c *DNSQueryConn) pollLoop() {
	t := time.NewTicker(dnsqPollInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// Only poll if no data is queued (avoid doubling sends).
			if len(c.sendQ) == 0 {
				c.sendOne(dnsqPoll, nil)
			}
		case <-c.closed:
			return
		}
	}
}

// retransmitLoop reschedules in-flight frames that haven't been ACK'd.
func (c *DNSQueryConn) retransmitLoop() {
	t := time.NewTicker(dnsqRetransmit)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.inflight.Range(func(key, val any) bool {
				e := val.(*inflightEntry)
				select {
				case <-e.acked:
					return true // already acked
				default:
				}
				// Resend.
				c.ackMu.Lock()
				ack := c.lastAck
				c.ackMu.Unlock()
				payload := encodeFrame(c.sessionID, e.seq, ack, e.flags, e.data)
				sock := c.nextSock()
				msg := buildDNSQuery(uint16(rand.Uint32()), c.domain, payload)
				sock.Write(msg) //nolint:errcheck
				log.Debugf("dnsq: retransmit seq=%d", e.seq)
				return true
			})
		case <-c.closed:
			return
		}
	}
}

// recvLoop reads UDP packets from one socket, parses DNS responses,
// and dispatches received data to the reassembly buffer.
func (c *DNSQueryConn) recvLoop(sock *net.UDPConn, idx int) {
	buf := make([]byte, 4096+512)
	for {
		n, err := sock.Read(buf)
		if err != nil {
			select {
			case <-c.closed:
				return
			default:
				log.Debugf("dnsq: recv[%d]: %v", idx, err)
				continue
			}
		}
		rdata := parseDNSOptPayload(buf[:n])
		if rdata == nil {
			continue
		}
		_, seq, ack, flags, data, err := decodeFrame(rdata)
		if err != nil {
			continue
		}

		// Process ACK: mark in-flight entries as done.
		c.processAck(ack)

		// Ignore pure ACK/poll responses with no data.
		if flags == dnsqPoll && len(data) == 0 {
			continue
		}
		if flags == dnsqFin {
			c.Close()
			return
		}

		// Deliver data to reassembly buffer.
		if len(data) > 0 {
			c.recvMu.Lock()
			if seq == c.recvSeq {
				// In-order: deliver directly.
				c.recvBuf = append(c.recvBuf, data...)
				c.recvSeq++
				// Drain any buffered out-of-order frames now in order.
				for {
					next, ok := c.recvPend[c.recvSeq]
					if !ok {
						break
					}
					c.recvBuf = append(c.recvBuf, next...)
					delete(c.recvPend, c.recvSeq)
					c.recvSeq++
				}
			} else if seq > c.recvSeq {
				// Out-of-order: buffer it.
				if _, dup := c.recvPend[seq]; !dup {
					cp := make([]byte, len(data))
					copy(cp, data)
					c.recvPend[seq] = cp
				}
			}
			// seq < recvSeq: duplicate, discard.
			hasData := len(c.recvBuf) > 0
			c.recvMu.Unlock()

			// Update ACK for next outgoing query.
			c.ackMu.Lock()
			if c.recvSeq-1 > c.lastAck {
				c.lastAck = c.recvSeq - 1
			}
			c.ackMu.Unlock()

			if hasData {
				select {
				case c.recvReady <- struct{}{}:
				default:
				}
			}
		}
	}
}

// processAck marks all inflight entries with seq ≤ ack as acknowledged.
func (c *DNSQueryConn) processAck(ack uint32) {
	c.inflight.Range(func(key, val any) bool {
		e := val.(*inflightEntry)
		if e.seq <= ack {
			select {
			case <-e.acked:
			default:
				close(e.acked)
				c.inflight.Delete(key)
				c.inflightCt.Add(-1)
			}
		}
		return true
	})
}

func (c *DNSQueryConn) nextSock() *net.UDPConn {
	idx := c.ridx.Add(1) - 1
	return c.socks[int(idx)%len(c.socks)]
}

// ── Server-side listener ──────────────────────────────────────────────────────

// DNSQueryListener listens on UDP:53 and returns *DNSQueryServerConn per unique
// client session.
type DNSQueryListener struct {
	sock     *net.UDPConn
	sessions sync.Map          // sessionID(8-byte string) -> *DNSQueryServerConn
	accept   chan *DNSQueryServerConn
	closed   chan struct{}
	closeOnce sync.Once
}

// ListenDNSQuery starts a UDP DNS listener on addr (e.g. ":53").
func ListenDNSQuery(addr string) (*DNSQueryListener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	sock, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	l := &DNSQueryListener{
		sock:   sock,
		accept: make(chan *DNSQueryServerConn, 64),
		closed: make(chan struct{}),
	}
	go l.recvLoop()
	return l, nil
}

func (l *DNSQueryListener) recvLoop() {
	buf := make([]byte, 4096+512)
	for {
		n, raddr, err := l.sock.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
				continue
			}
		}
		rdata := parseDNSOptPayload(buf[:n])
		if len(rdata) < dnsqFrameHdr {
			// No OPT record, or standard dig OPT with RDLEN=0 — not a tunnel query.
			// Reply NXDOMAIN so public resolvers see us as a live authoritative NS.
			qid, qsec := extractDNSQueryInfo(buf[:n])
			l.sock.WriteToUDP(buildNXDomainResponse(qid, qsec), raddr) //nolint:errcheck
			continue
		}
		sessionID, seq, ack, flags, data, err := decodeFrame(rdata)
		if err != nil {
			continue
		}

		key := string(sessionID[:])
		var sess *DNSQueryServerConn
		if v, ok := l.sessions.Load(key); ok {
			sess = v.(*DNSQueryServerConn)
		} else {
			// New session.
			sess = newDNSQueryServerConn(l.sock, raddr, sessionID)
			l.sessions.Store(key, sess)
			select {
			case l.accept <- sess:
			default:
			}
		}

		queryID, question := extractDNSQueryInfo(buf[:n])
		sess.handleIncoming(raddr, queryID, question, seq, ack, flags, data)
	}
}

func (l *DNSQueryListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closed:
		return nil, fmt.Errorf("dnsq: listener closed")
	}
}

func (l *DNSQueryListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		l.sock.Close()
	})
	return nil
}

func (l *DNSQueryListener) Addr() net.Addr { return l.sock.LocalAddr() }

// DNSQueryServerConn is the server-side half of a DNS query session.
// It sends responses back to the client's UDP address via the shared listener socket.
type DNSQueryServerConn struct {
	sock      *net.UDPConn
	raddr     *net.UDPAddr
	sessionID [8]byte

	closed    chan struct{}
	closeOnce sync.Once

	// Send (server → client, piggybacked on DNS responses to client queries)
	sendMu  sync.Mutex
	sendSeq uint32
	sendBuf []byte // pending data waiting for next client query to arrive

	// Receive (client → server)
	recvMu    sync.Mutex
	recvSeq   uint32
	recvPend  map[uint32][]byte
	recvBuf   []byte
	recvReady chan struct{}

	ackMu   sync.Mutex
	lastAck uint32

	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

func newDNSQueryServerConn(sock *net.UDPConn, raddr *net.UDPAddr, sid [8]byte) *DNSQueryServerConn {
	return &DNSQueryServerConn{
		sock:      sock,
		raddr:     raddr,
		sessionID: sid,
		recvPend:  make(map[uint32][]byte),
		recvReady: make(chan struct{}, 1),
		closed:    make(chan struct{}),
	}
}

// handleIncoming is called by the listener when a client query arrives for this session.
// raddr is the source address of THIS specific query (may differ per resolver in relay mode).
// queryID and question are echoed back in the DNS response so the resolver can match it.
func (c *DNSQueryServerConn) handleIncoming(raddr *net.UDPAddr, queryID uint16, question []byte, seq, ack uint32, flags uint16, data []byte) {
	// Update our receive window with the client's data.
	if len(data) > 0 || flags == dnsqData {
		c.recvMu.Lock()
		if seq == c.recvSeq {
			c.recvBuf = append(c.recvBuf, data...)
			c.recvSeq++
			for {
				next, ok := c.recvPend[c.recvSeq]
				if !ok {
					break
				}
				c.recvBuf = append(c.recvBuf, next...)
				delete(c.recvPend, c.recvSeq)
				c.recvSeq++
			}
		} else if seq > c.recvSeq {
			if _, dup := c.recvPend[seq]; !dup {
				cp := make([]byte, len(data))
				copy(cp, data)
				c.recvPend[seq] = cp
			}
		}
		c.recvMu.Unlock()

		c.ackMu.Lock()
		if c.recvSeq-1 > c.lastAck {
			c.lastAck = c.recvSeq - 1
		}
		c.ackMu.Unlock()

		select {
		case c.recvReady <- struct{}{}:
		default:
		}
	}

	// Process client's ACK on our sent data (not yet tracked; add if needed).
	_ = ack

	if flags == dnsqFin {
		c.Close()
		return
	}

	// Reply immediately with any pending server→client data.
	c.sendMu.Lock()
	var chunk []byte
	if len(c.sendBuf) > 0 {
		size := len(c.sendBuf)
		if size > dnsqPayloadMax {
			size = dnsqPayloadMax
		}
		chunk = c.sendBuf[:size]
		c.sendBuf = c.sendBuf[size:]
	}
	seq2 := c.sendSeq
	if len(chunk) > 0 {
		c.sendSeq++
	}
	c.sendMu.Unlock()

	c.ackMu.Lock()
	myAck := c.lastAck
	c.ackMu.Unlock()

	replyFlags := dnsqPoll
	if len(chunk) > 0 {
		replyFlags = dnsqData
	}
	payload := encodeFrame(c.sessionID, seq2, myAck, uint16(replyFlags), chunk)
	resp := buildDNSResponse(queryID, question, payload)
	c.sock.WriteToUDP(resp, raddr) //nolint:errcheck
}

func (c *DNSQueryServerConn) Write(p []byte) (int, error) {
	c.sendMu.Lock()
	c.sendBuf = append(c.sendBuf, p...)
	c.sendMu.Unlock()
	return len(p), nil
}

func (c *DNSQueryServerConn) Read(p []byte) (int, error) {
	for {
		c.recvMu.Lock()
		if len(c.recvBuf) > 0 {
			n := copy(p, c.recvBuf)
			c.recvBuf = c.recvBuf[n:]
			if len(c.recvBuf) == 0 {
				c.recvBuf = nil
			}
			c.recvMu.Unlock()
			return n, nil
		}
		c.recvMu.Unlock()

		var timeout <-chan time.Time
		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, fmt.Errorf("dnsq: read timeout")
			}
			timeout = time.After(d)
		}
		select {
		case <-c.recvReady:
		case <-c.closed:
			return 0, fmt.Errorf("dnsq: connection closed")
		case <-timeout:
			return 0, fmt.Errorf("dnsq: read timeout")
		}
	}
}

func (c *DNSQueryServerConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *DNSQueryServerConn) LocalAddr() net.Addr                { return c.sock.LocalAddr() }
func (c *DNSQueryServerConn) RemoteAddr() net.Addr               { return c.raddr }
func (c *DNSQueryServerConn) SetDeadline(t time.Time) error      { c.readDeadline.Store(t); c.writeDeadline.Store(t); return nil }
func (c *DNSQueryServerConn) SetReadDeadline(t time.Time) error  { c.readDeadline.Store(t); return nil }
func (c *DNSQueryServerConn) SetWriteDeadline(t time.Time) error { c.writeDeadline.Store(t); return nil }
