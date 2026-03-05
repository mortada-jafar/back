package config

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration, matching every section the bash script generates.
type Config struct {
	Listener  *ListenerConfig  `toml:"listener"`
	Dialer    *DialerConfig    `toml:"dialer"`
	Transport TransportConfig  `toml:"transport"`
	Tun       *TunConfig       `toml:"tun"`
	IPX       *IPXConfig       `toml:"ipx"`
	Mux       *MuxConfig       `toml:"mux"`
	Security  SecurityConfig   `toml:"security"`
	TLS       *TLSConfig       `toml:"tls"`
	Tuning    TuningConfig     `toml:"tuning"`
	AcceptUDP *AcceptUDPConfig `toml:"accept_udp"`
	Logging   LoggingConfig    `toml:"logging"`
	Ports     *PortsConfig     `toml:"ports"`
	DNS       *DNSConfig       `toml:"dns"`
}

// ---------- [listener] (server mode, non-IPX) ----------

type ListenerConfig struct {
	BindAddr string `toml:"bind_addr"` // e.g. ":8443"
}

// ---------- [dialer] (client mode, non-IPX) ----------

type DialerConfig struct {
	RemoteAddr    string `toml:"remote_addr"`    // IP:Port or Domain:Port
	EdgeIP        string `toml:"edge_ip"`        // optional CDN edge IP
	DialTimeout   int    `toml:"dial_timeout"`   // seconds
	RetryInterval int    `toml:"retry_interval"` // seconds
}

// ---------- [transport] ----------

type TransportConfig struct {
	Type              string `toml:"type"`               // tcp|tcpmux|xtcpmux|ws|wss|wsmux|wssmux|xwsmux|anytls|tun
	Nodelay           *bool  `toml:"nodelay"`            // TCP_NODELAY
	KeepalivePeriod   *int   `toml:"keepalive_period"`   // seconds
	AcceptUDP         *bool  `toml:"accept_udp"`         // server: accept UDP over TCP
	ProxyProtocol     *bool  `toml:"proxy_protocol"`     // server: PROXY protocol
	ConnectionPool    *int   `toml:"connection_pool"`    // client: connection pool size
	HeartbeatInterval int    `toml:"heartbeat_interval"` // seconds
	HeartbeatTimeout  int    `toml:"heartbeat_timeout"`  // seconds
}

// ---------- [tun] ----------

type TunConfig struct {
	Encapsulation string `toml:"encapsulation"` // "tcp" or "ipx"
	Name          string `toml:"name"`          // interface name e.g. "backhaul"
	LocalAddr     string `toml:"local_addr"`    // CIDR e.g. "10.10.10.1/24"
	RemoteAddr    string `toml:"remote_addr"`   // CIDR e.g. "10.10.10.2/24"
	HealthPort    int    `toml:"health_port"`   // TCP health check port
	MTU           int    `toml:"mtu"`           // e.g. 1320 (ipx) or 1500 (tcp)
}

// ---------- [ipx] ----------

type IPXConfig struct {
	Mode         string `toml:"mode"`          // "client" or "server"
	Profile      string `toml:"profile"`       // icmp|ipip|udp|tcp|gre|bip
	ListenIP     string `toml:"listen_ip"`     // local public IP
	DstIP        string `toml:"dst_ip"`        // remote endpoint IP
	Interface    string `toml:"interface"`     // physical NIC e.g. "eth0"
	ICMPType     *int   `toml:"icmp_type"`     // only for icmp profile
	ICMPCode     *int   `toml:"icmp_code"`     // only for icmp profile
	FragmentSize int    `toml:"fragment_size"` // 0=disabled; 300-1400 bytes recommended for GFW bypass
}

// ---------- [mux] (only when transport ends with "mux") ----------

type MuxConfig struct {
	MuxVersion       int `toml:"mux_version"`       // 1 or 2
	MuxFramesize     int `toml:"mux_framesize"`     // default 32768
	MuxRecieveBuffer int `toml:"mux_recievebuffer"` // default 4194304 (sic: matches script typo)
	MuxStreamBuffer  int `toml:"mux_streambuffer"`  // default 2097152
	MuxConcurrency   int `toml:"mux_concurrency"`   // default 8
}

// ---------- [security] ----------

type SecurityConfig struct {
	// Token-based (non-IPX transports)
	Token string `toml:"token"`

	// Encryption-based (IPX transports)
	EnableEncryption *bool  `toml:"enable_encryption"`
	Algorithm        string `toml:"algorithm"`      // aes-256-gcm|chacha20-poly1305|aes-128-gcm
	PSK              string `toml:"psk"`            // base64 pre-shared key
	KDFIterations    int    `toml:"kdf_iterations"` // PBKDF2 iterations
}

// ---------- [tls] ----------

type TLSConfig struct {
	SNI     string `toml:"sni"`      // for anytls
	TLSCert string `toml:"tls_cert"` // server cert path
	TLSKey  string `toml:"tls_key"`  // server key path
}

// ---------- [tuning] ----------

type TuningConfig struct {
	AutoTuning    *bool  `toml:"auto_tuning"`
	TuningProfile string `toml:"tuning_profile"` // balanced|fast|latency|resource
	Workers       int    `toml:"workers"`        // 0 = auto (NumCPU)
	ChannelSize   int    `toml:"channel_size"`   // inter-worker channel buffer
	TCPMss        int    `toml:"tcp_mss"`        // 0 = auto
	SoRcvbuf      int    `toml:"so_rcvbuf"`      // 0 = OS default
	SoSndbuf      int    `toml:"so_sndbuf"`      // 0 = OS default
	BufferProfile string `toml:"buffer_profile"` // extreme_low_cpu|ultra_low_cpu|low_cpu|balanced|low_memory
	BatchSize     int    `toml:"batch_size"`     // IPX batch size
	ReadTimeout   int    `toml:"read_timeout"`   // seconds
}

// ---------- [accept_udp] ----------

type AcceptUDPConfig struct {
	RingSize         int `toml:"ring_size"`
	FrameSize        int `toml:"frame_size"`
	PeerIdleTimeoutS int `toml:"peer_idle_timeout_s"`
	WriteTimeoutMs   int `toml:"write_timeout_ms"`
}

// ---------- [logging] ----------

type LoggingConfig struct {
	LogLevel string `toml:"log_level"` // panic|fatal|error|warn|info|debug|trace
}

// ---------- [dns] ----------

// DNSConfig holds DNS-transport-specific settings.
// Must not be copied after first use (contains atomic state).
type DNSConfig struct {
	// Resolvers is the list of DNS resolver addresses to use (round-robin).
	// For dnsq/dnsqmux direct mode: put your server IPs here (e.g. "1.2.3.4:53").
	// For dnsq/dnsqmux relay mode (through public resolvers): put "1.1.1.1:53",
	// "8.8.8.8:53", etc. — requires Domain to be set.
	Resolvers []string `toml:"resolvers"`

	// Domain is the tunnel domain for dnsq relay mode.
	// Public resolvers forward queries for *.Domain to your authoritative server.
	// DNS setup required on your registrar:
	//   NS  <domain>       ->  ns1.<domain>
	//   A   ns1.<domain>   ->  <your server IP>
	// Example: domain = "t.j.pingzone.ir"
	Domain string `toml:"domain"`

	resolverIdx uint64 // atomic round-robin counter; not in TOML
}

// NextAddr returns the next resolver address in round-robin order.
// Safe to call concurrently from multiple goroutines.
func (d *DNSConfig) NextAddr() string {
	idx := atomic.AddUint64(&d.resolverIdx, 1) - 1
	return d.Resolvers[int(idx)%len(d.Resolvers)]
}

// ---------- [ports] ----------

type PortsConfig struct {
	Forwarder string   `toml:"forwarder"` // "backhaul" or "iptables"
	Mapping   []string `toml:"mapping"`   // e.g. ["443", "443=5000", "443-600"]
}

// ---------- Helpers ----------

// Mode returns "server" or "client" based on config sections present.
func (c *Config) Mode() string {
	if c.Listener != nil {
		return "server"
	}
	if c.Dialer != nil {
		return "client"
	}
	// IPX mode: determined by ipx.mode field
	if c.IPX != nil {
		return c.IPX.Mode
	}
	return "unknown"
}

// IsIPX returns true if this is a TUN+IPX configuration.
func (c *Config) IsIPX() bool {
	return c.Tun != nil && c.Tun.Encapsulation == "ipx"
}

// IsTun returns true if transport type is "tun".
func (c *Config) IsTun() bool {
	return c.Transport.Type == "tun"
}

// IsMux returns true if transport type ends with "mux".
func (c *Config) IsMux() bool {
	return strings.HasSuffix(c.Transport.Type, "mux")
}

// IsDNS returns true if the transport uses any DNS-based framing (TCP or UDP query).
func (c *Config) IsDNS() bool {
	switch c.Transport.Type {
	case "dns", "dnsmux", "dnsq", "dnsqmux":
		return true
	}
	return false
}

// NeedsTLS returns true if the transport requires TLS.
func (c *Config) NeedsTLS() bool {
	switch c.Transport.Type {
	case "anytls", "wss", "wssmux":
		return true
	}
	return false
}

// Load reads and validates a TOML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Transport.HeartbeatInterval == 0 {
		cfg.Transport.HeartbeatInterval = 10
	}
	if cfg.Transport.HeartbeatTimeout == 0 {
		cfg.Transport.HeartbeatTimeout = 25
	}
	if cfg.Tun != nil {
		if cfg.Tun.Name == "" {
			cfg.Tun.Name = "backhaul"
		}
		if cfg.Tun.MTU == 0 {
			if cfg.IsIPX() {
				cfg.Tun.MTU = 1320
			} else {
				cfg.Tun.MTU = 1500
			}
		}
		if cfg.Tun.HealthPort == 0 {
			cfg.Tun.HealthPort = 1234
		}
	}
	if cfg.IPX != nil {
		if cfg.IPX.Profile == "" {
			cfg.IPX.Profile = "tcp"
		}
	}
	if cfg.Mux != nil {
		if cfg.Mux.MuxVersion == 0 {
			cfg.Mux.MuxVersion = 2
		}
		if cfg.Mux.MuxFramesize == 0 {
			cfg.Mux.MuxFramesize = 32768
		}
		if cfg.Mux.MuxRecieveBuffer == 0 {
			cfg.Mux.MuxRecieveBuffer = 4194304
		}
		if cfg.Mux.MuxStreamBuffer == 0 {
			cfg.Mux.MuxStreamBuffer = 2097152
		}
		if cfg.Mux.MuxConcurrency == 0 {
			cfg.Mux.MuxConcurrency = 8
		}
	}
	if cfg.Security.KDFIterations == 0 && cfg.IsIPX() {
		cfg.Security.KDFIterations = 100000
	}
	if cfg.Security.Algorithm == "" && cfg.IsIPX() {
		cfg.Security.Algorithm = "aes-256-gcm"
	}
	if cfg.Tuning.Workers == 0 {
		cfg.Tuning.Workers = runtime.NumCPU()
	}
	if cfg.Tuning.ChannelSize == 0 {
		if cfg.IsTun() {
			cfg.Tuning.ChannelSize = 10000
		} else {
			cfg.Tuning.ChannelSize = 4096
		}
	}
	if cfg.Tuning.TuningProfile == "" {
		cfg.Tuning.TuningProfile = "balanced"
	}
	if cfg.Tuning.BufferProfile == "" && !cfg.IsTun() && !cfg.IsIPX() {
		cfg.Tuning.BufferProfile = "balanced"
	}
	if cfg.AcceptUDP != nil {
		if cfg.AcceptUDP.RingSize == 0 {
			cfg.AcceptUDP.RingSize = 64
		}
		if cfg.AcceptUDP.FrameSize == 0 {
			cfg.AcceptUDP.FrameSize = 2048
		}
		if cfg.AcceptUDP.PeerIdleTimeoutS == 0 {
			cfg.AcceptUDP.PeerIdleTimeoutS = 120
		}
		if cfg.AcceptUDP.WriteTimeoutMs == 0 {
			cfg.AcceptUDP.WriteTimeoutMs = 3
		}
	}
	if cfg.Dialer != nil {
		if cfg.Dialer.DialTimeout == 0 {
			cfg.Dialer.DialTimeout = 10
		}
		if cfg.Dialer.RetryInterval == 0 {
			cfg.Dialer.RetryInterval = 3
		}
	}
	if cfg.Logging.LogLevel == "" {
		cfg.Logging.LogLevel = "info"
	}
}

func validate(cfg *Config) error {
	validTransports := map[string]bool{
		"tcp": true, "tcpmux": true, "xtcpmux": true,
		"ws": true, "wss": true, "wsmux": true, "wssmux": true, "xwsmux": true,
		"anytls": true, "tun": true,
		"dns": true, "dnsmux": true,
		"dnsq": true, "dnsqmux": true,
	}
	if !validTransports[cfg.Transport.Type] {
		return fmt.Errorf("invalid transport type: %q", cfg.Transport.Type)
	}

	if cfg.IsTun() && cfg.Tun == nil {
		return fmt.Errorf("transport=tun requires [tun] section")
	}

	if cfg.Tun != nil {
		if cfg.Tun.LocalAddr == "" {
			return fmt.Errorf("tun.local_addr is required")
		}
		if cfg.Tun.RemoteAddr == "" {
			return fmt.Errorf("tun.remote_addr is required")
		}
		if _, _, err := net.ParseCIDR(cfg.Tun.LocalAddr); err != nil {
			return fmt.Errorf("invalid tun.local_addr: %w", err)
		}
		if _, _, err := net.ParseCIDR(cfg.Tun.RemoteAddr); err != nil {
			return fmt.Errorf("invalid tun.remote_addr: %w", err)
		}
		validEncap := map[string]bool{"tcp": true, "ipx": true}
		if !validEncap[cfg.Tun.Encapsulation] {
			return fmt.Errorf("invalid tun.encapsulation: %q (tcp or ipx)", cfg.Tun.Encapsulation)
		}
	}

	if cfg.IsIPX() {
		if cfg.IPX == nil {
			return fmt.Errorf("tun encapsulation=ipx requires [ipx] section")
		}
		validProfiles := map[string]bool{
			"icmp": true, "ipip": true, "udp": true,
			"tcp": true, "gre": true, "bip": true,
		}
		if !validProfiles[cfg.IPX.Profile] {
			return fmt.Errorf("invalid ipx.profile: %q", cfg.IPX.Profile)
		}
		if cfg.IPX.ListenIP == "" {
			return fmt.Errorf("ipx.listen_ip is required")
		}
		if cfg.IPX.DstIP == "" {
			return fmt.Errorf("ipx.dst_ip is required")
		}
		if cfg.IPX.Mode != "client" && cfg.IPX.Mode != "server" {
			return fmt.Errorf("ipx.mode must be 'client' or 'server'")
		}
	}

	if cfg.IsIPX() && cfg.Security.EnableEncryption != nil && *cfg.Security.EnableEncryption {
		validAlgs := map[string]bool{
			"aes-256-gcm": true, "chacha20-poly1305": true, "aes-128-gcm": true,
		}
		if !validAlgs[cfg.Security.Algorithm] {
			return fmt.Errorf("invalid security.algorithm: %q", cfg.Security.Algorithm)
		}
		if cfg.Security.PSK == "" {
			return fmt.Errorf("security.psk required when encryption enabled")
		}
	}

	if cfg.IsMux() && cfg.Mux == nil {
		return fmt.Errorf("mux transport requires [mux] section")
	}

	if cfg.IsDNS() && cfg.DNS != nil && len(cfg.DNS.Resolvers) == 0 {
		return fmt.Errorf("[dns] resolvers list is empty; provide at least one address or remove the section")
	}

	if cfg.NeedsTLS() && cfg.Mode() == "server" {
		if cfg.TLS == nil {
			return fmt.Errorf("transport %s requires [tls] section on server", cfg.Transport.Type)
		}
	}

	return nil
}
