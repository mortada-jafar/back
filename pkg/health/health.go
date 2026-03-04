package health

import (
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

type Stats struct {
	PacketsTx  atomic.Uint64
	PacketsRx  atomic.Uint64
	BytesTx    atomic.Uint64
	BytesRx    atomic.Uint64
	Drops      atomic.Uint64
	Heartbeats atomic.Uint64
	Connected  atomic.Bool
	StartTime  time.Time
}

type Snapshot struct {
	PacketsTx  uint64 `json:"packets_tx"`
	PacketsRx  uint64 `json:"packets_rx"`
	BytesTx    uint64 `json:"bytes_tx"`
	BytesRx    uint64 `json:"bytes_rx"`
	Drops      uint64 `json:"drops"`
	Heartbeats uint64 `json:"heartbeats"`
	Connected  bool   `json:"connected"`
	UptimeSec  int64  `json:"uptime_sec"`
}

func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		PacketsTx: s.PacketsTx.Load(), PacketsRx: s.PacketsRx.Load(),
		BytesTx: s.BytesTx.Load(), BytesRx: s.BytesRx.Load(),
		Drops: s.Drops.Load(), Heartbeats: s.Heartbeats.Load(),
		Connected: s.Connected.Load(),
		UptimeSec: int64(time.Since(s.StartTime).Seconds()),
	}
}

func Serve(port int, stats *Stats) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("Health listen %s: %v", addr, err)
		return
	}
	log.Infof("Health check on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			json.NewEncoder(c).Encode(stats.Snapshot())
		}(conn)
	}
}
