package udprelay

import (
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/tunpixbip/backhaul-core/pkg/config"
)

// Peer tracks a connected UDP client.
type Peer struct {
	Addr     *net.UDPAddr
	LastSeen time.Time
}

// Relay implements the [accept_udp] functionality: UDP packets
// arriving on a port are relayed over the tunnel, and responses
// are sent back to the original sender.
type Relay struct {
	cfg       *config.AcceptUDPConfig
	conn      *net.UDPConn
	peers     map[string]*Peer
	mu        sync.RWMutex
	writeCh   chan []byte
	done      chan struct{}
}

// New creates a UDP relay bound to the given address.
func New(listenAddr string, cfg *config.AcceptUDPConfig) (*Relay, error) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	// Set read buffer based on ring_size * frame_size
	bufSize := cfg.RingSize * cfg.FrameSize
	conn.SetReadBuffer(bufSize)

	r := &Relay{
		cfg:     cfg,
		conn:    conn,
		peers:   make(map[string]*Peer),
		writeCh: make(chan []byte, cfg.RingSize),
		done:    make(chan struct{}),
	}

	log.Infof("UDP relay listening on %s (ring=%d, frame=%d)", listenAddr, cfg.RingSize, cfg.FrameSize)
	return r, nil
}

// ReadLoop reads UDP packets and sends them to the returned channel.
func (r *Relay) ReadLoop() <-chan []byte {
	ch := make(chan []byte, r.cfg.RingSize)
	go func() {
		buf := make([]byte, r.cfg.FrameSize)
		for {
			select {
			case <-r.done:
				return
			default:
			}
			n, addr, err := r.conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			r.mu.Lock()
			r.peers[addr.String()] = &Peer{Addr: addr, LastSeen: time.Now()}
			r.mu.Unlock()

			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			ch <- pkt
		}
	}()

	// Peer cleanup goroutine
	go func() {
		ticker := time.NewTicker(time.Duration(r.cfg.PeerIdleTimeoutS) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-r.done:
				return
			case <-ticker.C:
				r.mu.Lock()
				cutoff := time.Now().Add(-time.Duration(r.cfg.PeerIdleTimeoutS) * time.Second)
				for k, p := range r.peers {
					if p.LastSeen.Before(cutoff) {
						delete(r.peers, k)
					}
				}
				r.mu.Unlock()
			}
		}
	}()

	return ch
}

// WriteTo sends data back to a peer by address key.
func (r *Relay) WriteTo(data []byte, peerKey string) error {
	r.mu.RLock()
	peer, ok := r.peers[peerKey]
	r.mu.RUnlock()
	if !ok {
		return nil
	}
	r.conn.SetWriteDeadline(time.Now().Add(time.Duration(r.cfg.WriteTimeoutMs) * time.Millisecond))
	_, err := r.conn.WriteToUDP(data, peer.Addr)
	return err
}

func (r *Relay) Close() error {
	close(r.done)
	return r.conn.Close()
}
