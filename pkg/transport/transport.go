package transport

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/tunpixbip/backhaul-core/pkg/config"
)

// dnsMaxMsg is the largest payload per DNS-over-TCP message (just under the 65535 limit).
const dnsMaxMsg = 65500

// DNSConn wraps a TCP connection with DNS-over-TCP wire framing (RFC 1035 §4.2.2).
// Each Write is sent as one or more DNS messages prefixed by a 2-byte big-endian length.
// This makes traffic on port 53 appear as legitimate DNS-over-TCP to packet inspectors,
// while delivering full TCP throughput (30 MB/s+) when the firewall allows port 53 through.
type DNSConn struct {
	net.Conn
	r       *bufio.Reader
	readBuf []byte
	wmu     sync.Mutex
}

func NewDNSConn(c net.Conn) *DNSConn {
	return &DNSConn{Conn: c, r: bufio.NewReaderSize(c, 65536)}
}

func (c *DNSConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > dnsMaxMsg {
			chunk = p[:dnsMaxMsg]
		}
		hdr := [2]byte{byte(len(chunk) >> 8), byte(len(chunk))}
		bufs := net.Buffers{hdr[:], chunk}
		if _, err := bufs.WriteTo(c.Conn); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *DNSConn) Read(p []byte) (int, error) {
	// Drain leftover bytes from a previous oversized message first.
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		if len(c.readBuf) == 0 {
			c.readBuf = nil
		}
		return n, nil
	}
	// Read 2-byte DNS-over-TCP length prefix.
	var hdr [2]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return 0, err
	}
	msgLen := int(binary.BigEndian.Uint16(hdr[:]))
	if msgLen == 0 {
		return 0, nil
	}
	// Read the full DNS message payload.
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(c.r, msg); err != nil {
		return 0, err
	}
	n := copy(p, msg)
	if n < msgLen {
		c.readBuf = msg[n:]
	}
	return n, nil
}

// dnsListener wraps a net.Listener so every Accept returns a *DNSConn.
type dnsListener struct{ net.Listener }

func (l *dnsListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewDNSConn(c), nil
}

// Dial connects to the remote endpoint based on transport type.
func Dial(cfg *config.Config) (net.Conn, error) {
	d := cfg.Dialer
	timeout := time.Duration(d.DialTimeout) * time.Second
	addr := d.RemoteAddr

	switch cfg.Transport.Type {
	case "tcp", "tcpmux", "xtcpmux":
		return net.DialTimeout("tcp", addr, timeout)

	case "tls", "anytls":
		sni := ""
		if cfg.TLS != nil {
			sni = cfg.TLS.SNI
		}
		return tls.DialWithDialer(
			&net.Dialer{Timeout: timeout}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, ServerName: sni, MinVersion: tls.VersionTLS12},
		)

	case "ws", "wsmux", "xwsmux":
		target := addr
		if d.EdgeIP != "" {
			target = d.EdgeIP
		}
		conn, _, err := websocket.DefaultDialer.Dial("ws://"+target+"/tunnel", nil)
		if err != nil {
			return nil, err
		}
		return NewWSConn(conn), nil

	case "wss", "wssmux":
		target := addr
		if d.EdgeIP != "" {
			target = d.EdgeIP
		}
		dialer := websocket.Dialer{
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
			HandshakeTimeout: timeout,
		}
		conn, _, err := dialer.Dial("wss://"+target+"/tunnel", nil)
		if err != nil {
			return nil, err
		}
		return NewWSConn(conn), nil

	case "dns", "dnsmux":
		if cfg.DNS != nil && len(cfg.DNS.Resolvers) > 1 {
			return dialDNSRoundRobin(cfg, timeout)
		}
		// Single resolver: use remote_addr or the only entry in resolvers.
		if cfg.DNS != nil && len(cfg.DNS.Resolvers) == 1 {
			addr = cfg.DNS.Resolvers[0]
		}
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return nil, err
		}
		return NewDNSConn(conn), nil

	case "dnsq", "dnsqmux":
		resolvers := []string{addr}
		domain := ""
		if cfg.DNS != nil {
			if len(cfg.DNS.Resolvers) > 0 {
				resolvers = cfg.DNS.Resolvers
			}
			domain = cfg.DNS.Domain
		}
		return DialDNSQuery(resolvers, domain, timeout)

	default:
		return nil, fmt.Errorf("unsupported dial transport: %s", cfg.Transport.Type)
	}
}

// dialDNSRoundRobin tries resolvers in round-robin order, falling back to the
// next one on connection failure. Returns an error only if all resolvers fail.
func dialDNSRoundRobin(cfg *config.Config, timeout time.Duration) (net.Conn, error) {
	resolvers := cfg.DNS.Resolvers
	n := len(resolvers)
	// NextAddr atomically advances the counter and returns the chosen address.
	start := cfg.DNS.NextAddr()
	for i := 0; i < n; i++ {
		var addr string
		if i == 0 {
			addr = start
		} else {
			addr = cfg.DNS.NextAddr()
		}
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			log.Debugf("DNS resolver %s unreachable: %v", addr, err)
			continue
		}
		log.Debugf("DNS resolver %s connected", addr)
		return NewDNSConn(conn), nil
	}
	return nil, fmt.Errorf("all DNS resolvers unreachable: %v", resolvers)
}

// Listen creates a listener based on transport type.
func Listen(cfg *config.Config) (net.Listener, error) {
	addr := cfg.Listener.BindAddr

	switch cfg.Transport.Type {
	case "tcp", "tcpmux", "xtcpmux":
		return net.Listen("tcp", addr)

	case "anytls", "wss", "wssmux":
		cert, err := tls.LoadX509KeyPair(cfg.TLS.TLSCert, cfg.TLS.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load TLS cert: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		return tls.Listen("tcp", addr, tlsCfg)

	case "ws", "wsmux", "xwsmux":
		return net.Listen("tcp", addr)

	case "dns", "dnsmux":
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		return &dnsListener{ln}, nil

	case "dnsq", "dnsqmux":
		return ListenDNSQuery(addr)

	default:
		return nil, fmt.Errorf("unsupported listen transport: %s", cfg.Transport.Type)
	}
}

// ServeWebSocket upgrades HTTP connections to WebSocket and sends them to a channel.
func ServeWebSocket(ln net.Listener) <-chan net.Conn {
	ch := make(chan net.Conn, 64)
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Errorf("WS upgrade: %v", err)
			return
		}
		ch <- NewWSConn(ws)
	})

	go http.Serve(ln, mux)
	return ch
}

// --- WSConn: websocket.Conn -> net.Conn adapter ---

type WSConn struct {
	ws     *websocket.Conn
	reader io.Reader
	mu     sync.Mutex
}

func NewWSConn(ws *websocket.Conn) *WSConn { return &WSConn{ws: ws} }

func (c *WSConn) Read(p []byte) (int, error) {
	for {
		if c.reader == nil {
			_, r, err := c.ws.NextReader()
			if err != nil {
				return 0, err
			}
			c.reader = r
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *WSConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *WSConn) Close() error                       { return c.ws.Close() }
func (c *WSConn) LocalAddr() net.Addr                { return c.ws.LocalAddr() }
func (c *WSConn) RemoteAddr() net.Addr               { return c.ws.RemoteAddr() }
func (c *WSConn) SetDeadline(t time.Time) error      { return c.ws.UnderlyingConn().SetDeadline(t) }
func (c *WSConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *WSConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }
