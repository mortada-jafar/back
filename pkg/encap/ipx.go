package encap

import (
	"encoding/binary"
	"fmt"
	"net"

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

// IPXSocket wraps a raw socket for all IPX profiles.
type IPXSocket struct {
	fd        int
	localIP   net.IP
	remoteIP  net.IP
	iface     string
	profile   string
	proto     int
	icmpType  int
	icmpCode  int
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
		fd: fd, localIP: lip, remoteIP: rip,
		iface: iface, profile: profile, proto: proto,
		icmpType: icmpType, icmpCode: icmpCode,
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

func (s *IPXSocket) SetSendBuffer(size int) error {
	return unix.SetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size)
}
func (s *IPXSocket) SetRecvBuffer(size int) error {
	return unix.SetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size)
}
func (s *IPXSocket) Close() error { return unix.Close(s.fd) }

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
