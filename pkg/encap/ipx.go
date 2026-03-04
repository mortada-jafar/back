package encap

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Protocol numbers for different IPX profiles.
const (
	ProtoICMP = 1
	ProtoIPIP = 4
	ProtoTCP  = 6
	ProtoUDP  = 17
	ProtoGRE  = 47
	ProtoBIP  = 253 // experimental
)

const bipHeaderSize = 6

const (
	FlagEncrypted uint16 = 0x0001
	FlagHeartbeat uint16 = 0x0002
)

// fragKey identifies a reassembly stream: the sender's IP + their random fragment ID.
type fragKey struct {
	srcIP  [4]byte
	fragID uint16
}

// fragEntry holds the pieces of an in-progress reassembly.
type fragEntry struct {
	total    int
	pieces   map[int][]byte // fragIndex -> data
	deadline time.Time
}

// fragHeaderSize is the extra header added to every BIP fragment payload.
// Layout: fragID(2) | fragTotal(2) | fragIndex(2) | dataLen(2)  = 8 bytes
const fragHeaderSize = 8

// IPXSocket wraps a raw socket for all IPX profiles.
type IPXSocket struct {
	fd       int
	localIP  net.IP
	remoteIP net.IP
	iface    string
	profile  string
	proto    int
	icmpType int
	icmpCode int
	closed   atomic.Bool

	// Reassembly table (only used when fragment_size > 0)
	reassemblyMu sync.Mutex
	reassembly   map[fragKey]*fragEntry
}

// NewIPXSocket creates the raw socket for the given profile.
func NewIPXSocket(listenIP, dstIP, iface, profile string, icmpType, icmpCode int) (*IPXSocket, error) {
	lip := net.ParseIP(listenIP)
	if lip == nil {
		return nil, fmt.Errorf("invalid listen_ip: %s", listenIP)
	}
	rip := net.ParseIP(dstIP)
	if rip == nil {
		return nil, fmt.Errorf("invalid dst_ip: %s", dstIP)
	}

	proto := profileToProto(profile)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, proto)
	if err != nil {
		return nil, fmt.Errorf("raw socket (proto %d): %w", proto, err)
	}

	sa := &unix.SockaddrInet4{}
	copy(sa.Addr[:], lip.To4())
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", listenIP, err)
	}

	// For non-ICMP/non-IPIP, we don't include our own IP header
	if profile != "icmp" && profile != "ipip" {
		unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 0)
	}

	if iface != "" {
		if err := unix.BindToDevice(fd, iface); err != nil {
			log.Warnf("SO_BINDTODEVICE %s: %v (need CAP_NET_RAW)", iface, err)
		}
	}

	sock := &IPXSocket{
		fd:         fd,
		localIP:    lip,
		remoteIP:   rip,
		iface:      iface,
		profile:    profile,
		proto:      proto,
		icmpType:   icmpType,
		icmpCode:   icmpCode,
		reassembly: make(map[fragKey]*fragEntry),
	}

	log.WithFields(log.Fields{
		"profile": profile, "proto": proto,
		"local": listenIP, "remote": dstIP, "iface": iface,
	}).Info("IPX socket created")

	return sock, nil
}

func profileToProto(profile string) int {
	switch profile {
	case "icmp":
		return ProtoICMP
	case "ipip":
		return ProtoIPIP
	case "udp":
		return ProtoUDP
	case "tcp":
		return ProtoTCP
	case "gre":
		return ProtoGRE
	case "bip":
		return ProtoBIP
	default:
		return ProtoBIP
	}
}

// Send sends a payload via the raw socket with BIP framing (for bip profile)
// or raw for other profiles.
func (s *IPXSocket) Send(payload []byte, encrypted bool) error {
	var data []byte

	switch s.profile {
	case "bip":
		data = make([]byte, bipHeaderSize+len(payload))
		binary.BigEndian.PutUint32(data[0:4], uint32(len(payload)))
		var flags uint16
		if encrypted {
			flags |= FlagEncrypted
		}
		binary.BigEndian.PutUint16(data[4:6], flags)
		copy(data[bipHeaderSize:], payload)

	case "icmp":
		// ICMP header: type(1) + code(1) + checksum(2) + id(2) + seq(2) = 8 bytes
		hdr := make([]byte, 8+len(payload))
		hdr[0] = byte(s.icmpType)
		hdr[1] = byte(s.icmpCode)
		copy(hdr[8:], payload)
		// Compute checksum
		cs := icmpChecksum(hdr)
		hdr[2] = byte(cs >> 8)
		hdr[3] = byte(cs)
		data = hdr

	case "gre":
		// Minimal GRE header: flags(2) + protocol(2) = 4 bytes
		hdr := make([]byte, 4+len(payload))
		hdr[0] = 0x00
		hdr[1] = 0x00
		binary.BigEndian.PutUint16(hdr[2:4], 0x0800) // IPv4 payload
		copy(hdr[4:], payload)
		data = hdr

	default: // tcp, udp, ipip, raw
		data = payload
	}

	sa := &unix.SockaddrInet4{}
	copy(sa.Addr[:], s.remoteIP.To4())
	return unix.Sendto(s.fd, data, 0, sa)
}

// SendHeartbeat sends a zero-length BIP heartbeat frame.
func (s *IPXSocket) SendHeartbeat() error {
	if s.profile != "bip" {
		return nil
	}
	data := make([]byte, bipHeaderSize)
	binary.BigEndian.PutUint16(data[4:6], FlagHeartbeat)
	sa := &unix.SockaddrInet4{}
	copy(sa.Addr[:], s.remoteIP.To4())
	return unix.Sendto(s.fd, data, 0, sa)
}

// Recv receives a payload. Returns (payload, isHeartbeat, error).
func (s *IPXSocket) Recv(buf []byte) ([]byte, bool, error) {
	return s.recvRaw(buf)
}

// SendFragmented splits payload into chunks of maxFragPayload bytes and sends
// each as an individual BIP frame with an 8-byte fragment header prepended.
// Fragment header layout (inside BIP payload):
//
//	[fragID: 2B][fragTotal: 2B][fragIndex: 2B][dataLen: 2B]
//
// When maxFragPayload <= 0, the packet is sent as-is (same as Send).
func (s *IPXSocket) SendFragmented(payload []byte, encrypted bool, maxFragPayload int) error {
	if maxFragPayload <= 0 || len(payload) <= maxFragPayload {
		return s.Send(payload, encrypted)
	}

	// Compute fragment count
	chunkSize := maxFragPayload
	total := (len(payload) + chunkSize - 1) / chunkSize
	if total > 0xFFFF {
		return fmt.Errorf("too many fragments: %d", total)
	}

	// Random 16-bit ID to group fragments belonging to this original packet
	fragID := uint16(rand.Uint32())

	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[start:end]

		// Build fragmented payload: 8-byte header + chunk data
		fragPayload := make([]byte, fragHeaderSize+len(chunk))
		binary.BigEndian.PutUint16(fragPayload[0:2], fragID)
		binary.BigEndian.PutUint16(fragPayload[2:4], uint16(total))
		binary.BigEndian.PutUint16(fragPayload[4:6], uint16(i))
		binary.BigEndian.PutUint16(fragPayload[6:8], uint16(len(chunk)))
		copy(fragPayload[fragHeaderSize:], chunk)

		if err := s.Send(fragPayload, encrypted); err != nil {
			return fmt.Errorf("fragment %d/%d send: %w", i+1, total, err)
		}
	}
	return nil
}

// RecvReassemble reads one raw packet and attempts fragment reassembly.
// Returns:
//   - payload: the fully reassembled original payload (nil while pending)
//   - isHB: true if the packet was a heartbeat
//   - pending: true if more fragments are still expected (caller should loop)
//   - err
func (s *IPXSocket) RecvReassemble(buf []byte) (payload []byte, isHB bool, pending bool, err error) {
	raw, hb, err := s.recvRaw(buf)
	if err != nil {
		return nil, false, false, err
	}
	if hb {
		return nil, true, false, nil
	}

	// Must have at least a frag header
	if len(raw) < fragHeaderSize {
		// Not a fragmented packet — return as-is
		return raw, false, false, nil
	}

	fragID := binary.BigEndian.Uint16(raw[0:2])
	fragTotal := int(binary.BigEndian.Uint16(raw[2:4]))
	fragIndex := int(binary.BigEndian.Uint16(raw[4:6]))
	dataLen := int(binary.BigEndian.Uint16(raw[6:8]))

	// Sanity checks — if they fail, treat as an unfragmented legacy packet
	if fragTotal == 0 || fragIndex >= fragTotal || dataLen > len(raw)-fragHeaderSize {
		return raw, false, false, nil
	}

	chunk := raw[fragHeaderSize : fragHeaderSize+dataLen]

	// Derive srcIP from the outer IP header stored in buf (bytes 12–16)
	var srcIP [4]byte
	copy(srcIP[:], buf[12:16])
	key := fragKey{srcIP: srcIP, fragID: fragID}

	s.reassemblyMu.Lock()
	s.pruneExpired()
	e2 := s.reassembly[key]
	if e2 == nil {
		e2 = &fragEntry{
			total:    fragTotal,
			pieces:   make(map[int][]byte),
			deadline: time.Now().Add(5 * time.Second),
		}
		s.reassembly[key] = e2
	}
	piece := make([]byte, len(chunk))
	copy(piece, chunk)
	e2.pieces[fragIndex] = piece
	gotAll := len(e2.pieces) == e2.total
	var assembled []byte
	if gotAll {
		// Reassemble in order
		totalLen := 0
		for _, p := range e2.pieces {
			totalLen += len(p)
		}
		assembled = make([]byte, 0, totalLen)
		for i := 0; i < e2.total; i++ {
			assembled = append(assembled, e2.pieces[i]...)
		}
		delete(s.reassembly, key)
	}
	s.reassemblyMu.Unlock()

	if gotAll {
		return assembled, false, false, nil
	}
	return nil, false, true, nil
}

// recvRaw is the shared receive path used by both Recv and RecvReassemble.
// It reads from the socket, strips the outer IP header and profile-specific
// header, and returns the raw BIP payload (or signals a heartbeat).
func (s *IPXSocket) recvRaw(buf []byte) ([]byte, bool, error) {
	n, _, err := unix.Recvfrom(s.fd, buf, 0)
	if err != nil {
		return nil, false, err
	}
	if n < 20 {
		return nil, false, fmt.Errorf("packet too small: %d", n)
	}

	// Strip outer IP header
	ihl := int(buf[0]&0x0F) * 4
	if n < ihl {
		return nil, false, fmt.Errorf("n < IHL")
	}
	raw := buf[ihl:n]

	switch s.profile {
	case "bip":
		if len(raw) < bipHeaderSize {
			return nil, false, fmt.Errorf("BIP frame too small")
		}
		length := binary.BigEndian.Uint32(raw[0:4])
		flags := binary.BigEndian.Uint16(raw[4:6])
		if flags&FlagHeartbeat != 0 {
			return nil, true, nil
		}
		payload := raw[bipHeaderSize:]
		if int(length) > len(payload) {
			return nil, false, fmt.Errorf("BIP length mismatch")
		}
		return payload[:length], false, nil

	case "icmp":
		if len(raw) < 8 {
			return nil, false, fmt.Errorf("ICMP too short")
		}
		return raw[8:], false, nil

	case "gre":
		if len(raw) < 4 {
			return nil, false, fmt.Errorf("GRE too short")
		}
		return raw[4:], false, nil

	default:
		return raw, false, nil
	}
}

// pruneExpired removes timed-out reassembly entries. Must be called with re‌assembleMu held.
func (s *IPXSocket) pruneExpired() {
	now := time.Now()
	for k, e := range s.reassembly {
		if now.After(e.deadline) {
			delete(s.reassembly, k)
		}
	}
}

func (s *IPXSocket) SetSendBuffer(size int) error {
	return unix.SetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size)
}
func (s *IPXSocket) SetRecvBuffer(size int) error {
	return unix.SetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size)
}
func (s *IPXSocket) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		log.Info("Closing IPX raw socket")
		return unix.Close(s.fd)
	}
	return nil
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}
