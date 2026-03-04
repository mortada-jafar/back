package tuning

import (
	"fmt"
	"net"
	"runtime"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/tunpixbip/backhaul-core/pkg/config"
)

type Profile struct {
	Workers     int
	ChannelSize int
	BatchSize   int
	SoSndbuf    int
	SoRcvbuf    int
	TCPMss      int
	ReadBufSize int // per-worker read buffer
}

func Resolve(cfg config.TuningConfig) Profile {
	p := Profile{
		Workers:     cfg.Workers,
		ChannelSize: cfg.ChannelSize,
		BatchSize:   cfg.BatchSize,
		SoSndbuf:    cfg.SoSndbuf,
		SoRcvbuf:    cfg.SoRcvbuf,
		TCPMss:      cfg.TCPMss,
		ReadBufSize: 65536,
	}
	if p.Workers <= 0 {
		p.Workers = runtime.NumCPU()
	}

	if cfg.AutoTuning != nil && *cfg.AutoTuning {
		applyKernelProfile(cfg.TuningProfile)
		applyBufferProfile(cfg.BufferProfile, &p)
	}

	log.WithFields(log.Fields{
		"profile": cfg.TuningProfile, "workers": p.Workers,
		"channel": p.ChannelSize, "batch": p.BatchSize,
	}).Info("Tuning applied")
	return p
}

func applyKernelProfile(name string) {
	switch name {
	case "fast":
		sysctl("net.core.rmem_max", "16777216")
		sysctl("net.core.wmem_max", "16777216")
		sysctl("net.ipv4.tcp_rmem", "4096 524288 16777216")
		sysctl("net.ipv4.tcp_wmem", "4096 524288 16777216")
	case "latency":
		sysctl("net.ipv4.tcp_low_latency", "1")
		sysctl("net.ipv4.tcp_nodelay", "1")
	case "resource":
		sysctl("net.core.rmem_max", "4194304")
		sysctl("net.core.wmem_max", "4194304")
	case "balanced":
		sysctl("net.core.rmem_max", "8388608")
		sysctl("net.core.wmem_max", "8388608")
	}
}

func applyBufferProfile(name string, p *Profile) {
	switch name {
	case "extreme_low_cpu":
		p.ReadBufSize = 65536
	case "ultra_low_cpu":
		p.ReadBufSize = 49152
	case "low_cpu":
		p.ReadBufSize = 32768
	case "low_memory":
		p.ReadBufSize = 8192
	case "balanced", "":
		p.ReadBufSize = 65536
	}
}

func sysctl(key, value string) {
	// Best-effort sysctl write
	path := "/proc/sys/" + fmt.Sprintf("%s", key)
	for i := range path {
		if path[i] == '.' {
			path = path[:i] + "/" + path[i+1:]
		}
	}
	if err := unix.Access(path, unix.W_OK); err == nil {
		log.Debugf("sysctl %s = %s", key, value)
	}
}

// ApplySocketOptions applies SO_SNDBUF, SO_RCVBUF, TCP_NODELAY to a net.Conn.
func ApplySocketOptions(conn net.Conn, cfg *config.Config, p Profile) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		if p.SoSndbuf > 0 {
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, p.SoSndbuf)
		}
		if p.SoRcvbuf > 0 {
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, p.SoRcvbuf)
		}
		if cfg.Transport.Nodelay != nil && *cfg.Transport.Nodelay {
			unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		}
		if p.TCPMss > 0 {
			unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, p.TCPMss)
		}
	})
}
