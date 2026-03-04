package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/tunpixbip/backhaul-core/pkg/config"
	"github.com/tunpixbip/backhaul-core/pkg/encap"
	"github.com/tunpixbip/backhaul-core/pkg/forward"
	"github.com/tunpixbip/backhaul-core/pkg/health"
	pmux "github.com/tunpixbip/backhaul-core/pkg/mux"
	"github.com/tunpixbip/backhaul-core/pkg/security"
	"github.com/tunpixbip/backhaul-core/pkg/transport"
	"github.com/tunpixbip/backhaul-core/pkg/tuning"
)

type Engine struct {
	cfg     *config.Config
	tun     *TunDevice
	ipx     *encap.IPXSocket
	cipher  *security.Cipher
	auth    *security.TokenAuth
	profile tuning.Profile
	stats   *health.Stats
	tunCh   chan []byte
	netCh   chan []byte
	done    chan struct{}
}

func NewEngine(cfg *config.Config) (*Engine, error) {
	profile := tuning.Resolve(cfg.Tuning)
	stats := &health.Stats{StartTime: time.Now()}

	e := &Engine{
		cfg:     cfg,
		profile: profile,
		stats:   stats,
		tunCh:   make(chan []byte, profile.ChannelSize),
		netCh:   make(chan []byte, profile.ChannelSize),
		done:    make(chan struct{}),
	}

	// Setup encryption (IPX mode)
	if cfg.IsIPX() && cfg.Security.EnableEncryption != nil && *cfg.Security.EnableEncryption {
		c, err := security.NewCipher(cfg.Security.Algorithm, cfg.Security.PSK, cfg.Security.KDFIterations)
		if err != nil {
			return nil, fmt.Errorf("cipher init: %w", err)
		}
		e.cipher = c
		log.WithFields(log.Fields{
			"algorithm": cfg.Security.Algorithm, "kdf_iter": cfg.Security.KDFIterations,
			"overhead": c.Overhead(),
		}).Info("Encryption enabled")
	}

	// Token auth (non-IPX mode)
	if !cfg.IsIPX() && cfg.Security.Token != "" {
		e.auth = security.NewTokenAuth(cfg.Security.Token)
	}

	return e, nil
}

func (e *Engine) Run() error {
	if e.cfg.IsTun() {
		return e.runTunMode()
	}
	return e.runProxyMode()
}

// ---------- TUN MODE (transport=tun) ----------

func (e *Engine) runTunMode() error {
	cfg := e.cfg

	// Create TUN device
	tun, err := NewTunDevice(cfg.Tun.Name, cfg.Tun.LocalAddr, cfg.Tun.RemoteAddr, cfg.Tun.MTU)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	e.tun = tun

	// Health check
	go health.Serve(cfg.Tun.HealthPort, e.stats)

	if cfg.IsIPX() {
		return e.runIPXTransport()
	}
	return e.runTCPTunTransport()
}

func (e *Engine) runIPXTransport() error {
	cfg := e.cfg
	icmpType, icmpCode := 0, 0
	if cfg.IPX.ICMPType != nil {
		icmpType = *cfg.IPX.ICMPType
	}
	if cfg.IPX.ICMPCode != nil {
		icmpCode = *cfg.IPX.ICMPCode
	}

	ipx, err := encap.NewIPXSocket(
		cfg.IPX.ListenIP, cfg.IPX.DstIP, cfg.IPX.Interface,
		cfg.IPX.Profile, icmpType, icmpCode,
	)
	if err != nil {
		return fmt.Errorf("IPX socket: %w", err)
	}
	e.ipx = ipx

	if e.profile.SoSndbuf > 0 {
		ipx.SetSendBuffer(e.profile.SoSndbuf)
	}

	e.stats.Connected.Store(true)

	// Port forwarding (server only)
	if cfg.Mode() == "server" && cfg.Ports != nil {
		e.startPortForwarding()
	}

	var wg sync.WaitGroup

	// TUN read workers
	for i := 0; i < e.profile.Workers; i++ {
		wg.Add(1)
		go func(id int) { defer wg.Done(); e.tunReadWorker(id) }(i)
	}
	// TUN write workers
	for i := 0; i < e.profile.Workers; i++ {
		wg.Add(1)
		go func(id int) { defer wg.Done(); e.tunWriteWorker(id) }(i)
	}
	// IPX send
	wg.Add(1)
	go func() { defer wg.Done(); e.ipxSendWorker() }()
	// IPX recv
	wg.Add(1)
	go func() { defer wg.Done(); e.ipxRecvWorker() }()
	// Heartbeat
	wg.Add(1)
	go func() { defer wg.Done(); e.heartbeatWorker() }()

	log.WithFields(log.Fields{
		"mode": cfg.IPX.Mode, "profile": cfg.IPX.Profile,
		"local": cfg.Tun.LocalAddr, "remote": cfg.Tun.RemoteAddr,
		"listen": cfg.IPX.ListenIP, "dst": cfg.IPX.DstIP,
	}).Info("IPX tunnel running")

	wg.Wait()
	return nil
}

func (e *Engine) runTCPTunTransport() error {
	cfg := e.cfg
	var wg sync.WaitGroup

	// TUN workers
	for i := 0; i < e.profile.Workers; i++ {
		wg.Add(1)
		go func(id int) { defer wg.Done(); e.tunReadWorker(id) }(i)
	}
	for i := 0; i < e.profile.Workers; i++ {
		wg.Add(1)
		go func(id int) { defer wg.Done(); e.tunWriteWorker(id) }(i)
	}

	if cfg.Mode() == "server" {
		wg.Add(1)
		go func() { defer wg.Done(); e.tcpTunServer() }()
	} else {
		wg.Add(1)
		go func() { defer wg.Done(); e.tcpTunClient() }()
	}

	// Port forwarding (server)
	if cfg.Mode() == "server" && cfg.Ports != nil {
		e.startPortForwarding()
	}

	wg.Wait()
	return nil
}

func (e *Engine) tcpTunServer() {
	ln, err := transport.Listen(e.cfg)
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	log.Infof("TUN-TCP server listening on %s", e.cfg.Listener.BindAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Errorf("Accept: %v", err)
			continue
		}
		go e.handleTunTCPConn(conn)
	}
}

func (e *Engine) tcpTunClient() {
	for {
		conn, err := transport.Dial(e.cfg)
		if err != nil {
			log.Errorf("Dial: %v", err)
			time.Sleep(time.Duration(e.cfg.Dialer.RetryInterval) * time.Second)
			continue
		}
		e.handleTunTCPConn(conn)
		log.Warn("Connection lost, reconnecting...")
		time.Sleep(time.Duration(e.cfg.Dialer.RetryInterval) * time.Second)
	}
}

func (e *Engine) handleTunTCPConn(conn net.Conn) {
	defer conn.Close()
	tuning.ApplySocketOptions(conn, e.cfg, e.profile)
	e.stats.Connected.Store(true)
	defer e.stats.Connected.Store(false)

	// Bidirectional: TUN packets over length-prefixed TCP
	var wg sync.WaitGroup
	done := make(chan struct{})

	// tunCh -> conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case pkt := <-e.tunCh:
				payload := pkt
				if e.cipher != nil {
					enc, err := e.cipher.Encrypt(pkt)
					if err != nil {
						continue
					}
					payload = enc
				}
				if err := writeFrame(conn, payload); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	// conn -> netCh
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for {
			data, err := readFrame(conn)
			if err != nil {
				return
			}
			payload := data
			if e.cipher != nil {
				dec, err := e.cipher.Decrypt(data)
				if err != nil {
					continue
				}
				payload = dec
			}
			pkt := make([]byte, len(payload))
			copy(pkt, payload)
			select {
			case e.netCh <- pkt:
				e.stats.PacketsRx.Add(1)
			default:
				e.stats.Drops.Add(1)
			}
		}
	}()

	wg.Wait()
}

// ---------- PROXY MODE (tcp/ws/wss/mux transports, non-TUN) ----------

func (e *Engine) runProxyMode() error {
	cfg := e.cfg

	if cfg.Mode() == "server" {
		return e.proxyServer()
	}
	return e.proxyClient()
}

func (e *Engine) proxyServer() error {
	cfg := e.cfg

	isWS := cfg.Transport.Type == "ws" || cfg.Transport.Type == "wss" ||
		cfg.Transport.Type == "wsmux" || cfg.Transport.Type == "wssmux" ||
		cfg.Transport.Type == "xwsmux"

	ln, err := transport.Listen(cfg)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	log.Infof("Proxy server on %s (%s)", cfg.Listener.BindAddr, cfg.Transport.Type)

	var connCh <-chan net.Conn
	if isWS {
		connCh = transport.ServeWebSocket(ln)
	}

	// Port forwarding
	if cfg.Ports != nil {
		e.startPortForwarding()
	}

	for {
		var conn net.Conn
		if connCh != nil {
			conn = <-connCh
		} else {
			c, err := ln.Accept()
			if err != nil {
				log.Errorf("Accept: %v", err)
				continue
			}
			conn = c
		}
		tuning.ApplySocketOptions(conn, cfg, e.profile)

		if cfg.IsMux() {
			go e.handleMuxServerConn(conn)
		} else {
			go e.handleProxyConn(conn)
		}
	}
}

func (e *Engine) proxyClient() error {
	cfg := e.cfg
	poolSize := 1
	if cfg.Transport.ConnectionPool != nil && *cfg.Transport.ConnectionPool > 0 {
		poolSize = *cfg.Transport.ConnectionPool
	}

	for i := 0; i < poolSize; i++ {
		go e.proxyClientWorker(i)
	}

	select {} // block forever
}

func (e *Engine) proxyClientWorker(id int) {
	cfg := e.cfg
	for {
		conn, err := transport.Dial(cfg)
		if err != nil {
			log.Errorf("Worker %d dial: %v", id, err)
			time.Sleep(time.Duration(cfg.Dialer.RetryInterval) * time.Second)
			continue
		}
		tuning.ApplySocketOptions(conn, cfg, e.profile)

		if cfg.IsMux() {
			e.handleMuxClientConn(conn)
		} else {
			e.handleProxyConn(conn)
		}
		time.Sleep(time.Duration(cfg.Dialer.RetryInterval) * time.Second)
	}
}

func (e *Engine) handleMuxServerConn(conn net.Conn) {
	defer conn.Close()
	sess, err := pmux.NewServerSession(conn, e.cfg.Mux)
	if err != nil {
		log.Errorf("Mux server session: %v", err)
		return
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go e.handleProxyConn(stream)
	}
}

func (e *Engine) handleMuxClientConn(conn net.Conn) {
	defer conn.Close()
	sess, err := pmux.NewClientSession(conn, e.cfg.Mux)
	if err != nil {
		log.Errorf("Mux client session: %v", err)
		return
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go e.handleProxyConn(stream)
	}
}

func (e *Engine) handleProxyConn(conn net.Conn) {
	defer conn.Close()
	// Placeholder: in a full implementation, this would read the destination
	// from the stream header and forward to local port.
	// For now, just copy bidirectionally.
	log.Debugf("Proxy connection from %s", conn.RemoteAddr())
}

// ---------- Shared workers ----------

func (e *Engine) tunReadWorker(id int) {
	buf := make([]byte, e.profile.ReadBufSize)
	for {
		select {
		case <-e.done:
			return
		default:
		}
		n, err := e.tun.Read(buf)
		if err != nil {
			log.Debugf("TUN read %d: %v", id, err)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case e.tunCh <- pkt:
			e.stats.PacketsTx.Add(1)
			e.stats.BytesTx.Add(uint64(n))
		default:
			e.stats.Drops.Add(1)
		}
	}
}

func (e *Engine) tunWriteWorker(id int) {
	for {
		select {
		case <-e.done:
			return
		case pkt := <-e.netCh:
			e.tun.Write(pkt)
		}
	}
}

func (e *Engine) ipxSendWorker() {
	fragSize := 0
	if e.cfg.IPX != nil {
		fragSize = e.cfg.IPX.FragmentSize
	}
	for {
		select {
		case <-e.done:
			return
		case pkt := <-e.tunCh:
			payload, encrypted := pkt, false
			if e.cipher != nil {
				enc, err := e.cipher.Encrypt(pkt)
				if err != nil {
					continue
				}
				payload, encrypted = enc, true
			}
			var err error
			if fragSize > 0 {
				err = e.ipx.SendFragmented(payload, encrypted, fragSize)
			} else {
				err = e.ipx.Send(payload, encrypted)
			}
			if err != nil {
				log.Debugf("IPX send: %v", err)
			}
		}
	}
}

func (e *Engine) ipxRecvWorker() {
	buf := make([]byte, e.profile.ReadBufSize)
	fragSize := 0
	if e.cfg.IPX != nil {
		fragSize = e.cfg.IPX.FragmentSize
	}
	for {
		select {
		case <-e.done:
			return
		default:
		}

		var (
			payload []byte
			isHB    bool
			err     error
		)

		if fragSize > 0 {
			var pending bool
			payload, isHB, pending, err = e.ipx.RecvReassemble(buf)
			if err != nil {
				log.Debugf("IPX RecvReassemble error: %v", err)
				continue
			}
			if isHB {
				e.stats.Heartbeats.Add(1)
				continue
			}
			if pending {
				// Fragment received but packet not yet complete; read next fragment
				continue
			}
		} else {
			payload, isHB, err = e.ipx.Recv(buf)
			if err != nil {
				log.Debugf("IPX Recv error: %v", err)
				continue
			}
			if isHB {
				e.stats.Heartbeats.Add(1)
				continue
			}
		}

		data := payload
		if e.cipher != nil {
			dec, err := e.cipher.Decrypt(payload)
			if err != nil {
				log.Debugf("IPX Decrypt error: %v", err)
				continue
			}
			data = dec
		}
		pkt := make([]byte, len(data))
		copy(pkt, data)
		e.stats.PacketsRx.Add(1)
		e.stats.BytesRx.Add(uint64(len(data)))
		select {
		case e.netCh <- pkt:
		default:
			e.stats.Drops.Add(1)
		}
	}
}

func (e *Engine) heartbeatWorker() {
	interval := time.Duration(e.cfg.Transport.HeartbeatInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-ticker.C:
			if e.ipx != nil {
				e.ipx.SendHeartbeat()
			}
		}
	}
}

func (e *Engine) startPortForwarding() {
	cfg := e.cfg
	if cfg.Ports == nil || len(cfg.Ports.Mapping) == 0 {
		return
	}

	// Determine the remote TUN IP for forwarding
	remoteIP := ""
	if cfg.Tun != nil {
		ip, _, _ := net.ParseCIDR(cfg.Tun.RemoteAddr)
		if ip != nil {
			remoteIP = ip.String()
		}
	}

	mappings, err := forward.ParseMappings(cfg.Ports.Mapping)
	if err != nil {
		log.Errorf("Parse port mappings: %v", err)
		return
	}

	forwarder := "backhaul"
	if cfg.Ports.Forwarder != "" {
		forwarder = cfg.Ports.Forwarder
	}

	for _, m := range mappings {
		switch forwarder {
		case "iptables":
			if err := forward.IPTablesForwarder(m.ListenStart, remoteIP, m.ForwardPort); err != nil {
				log.Errorf("iptables forward :%d: %v", m.ListenStart, err)
			}
		default: // "backhaul" — TCP-only forwarder
			go forward.TCPForwarder(m.ListenStart, remoteIP, m.ForwardPort, e.done)
		}
	}
}

// Shutdown gracefully stops the engine.
func (e *Engine) Shutdown() {
	e.stats.Connected.Store(false)
	close(e.done)

	// Close file descriptors to unblock goroutines stuck on Read/Recvfrom syscalls
	if e.tun != nil {
		e.tun.Close()
	}
	if e.ipx != nil {
		e.ipx.Close()
	}
}

// --- Frame helpers (4-byte length prefix) ---

func writeFrame(w io.Writer, data []byte) error {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(data)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr)
	if length > 65536 {
		return nil, fmt.Errorf("frame too large: %d", length)
	}
	data := make([]byte, length)
	_, err := io.ReadFull(r, data)
	return data, err
}
