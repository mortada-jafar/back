package transport

import (
	"crypto/tls"
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

	default:
		return nil, fmt.Errorf("unsupported dial transport: %s", cfg.Transport.Type)
	}
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
