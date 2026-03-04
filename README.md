# backhaul-core

Open-source Go implementation of a high-performance reverse tunnel supporting all transport types, IPX encapsulation profiles, multiplexing, encryption, port forwarding, and UDP relay.

## Features (matching the bash script 1:1)

| Feature | Status | Config Section |
|---------|--------|---------------|
| **Transports**: tcp, tcpmux, xtcpmux, ws, wss, wsmux, wssmux, xwsmux, anytls, tun | ✅ | `[transport]` |
| **TUN encapsulation**: tcp, ipx | ✅ | `[tun]` |
| **IPX profiles**: icmp, ipip, udp, tcp, gre, bip | ✅ | `[ipx]` |
| **Encryption**: aes-256-gcm, aes-128-gcm, chacha20-poly1305 | ✅ | `[security]` |
| **Token auth** (non-IPX) | ✅ | `[security]` |
| **Mux**: yamux (v2) + smux (v1) | ✅ | `[mux]` |
| **TLS/SNI** (anytls, wss, wssmux) | ✅ | `[tls]` |
| **Port forwarding**: backhaul TCP + iptables DNAT | ✅ | `[ports]` |
| **UDP relay** (accept_udp) | ✅ | `[accept_udp]` |
| **Health check** TCP endpoint | ✅ | `[tun] health_port` |
| **Tuning profiles**: balanced, fast, latency, resource | ✅ | `[tuning]` |
| **Buffer profiles**: extreme_low_cpu, ultra_low_cpu, low_cpu, balanced, low_memory | ✅ | `[tuning]` |
| **Connection pool** (client) | ✅ | `[transport]` |
| **Edge IP / CDN** (WS/WSS client) | ✅ | `[dialer]` |
| **PROXY protocol** (server) | ✅ | `[transport]` |
| **TCP_NODELAY, keepalive, SO_SNDBUF/RCVBUF, TCP_MSS** | ✅ | `[transport]` + `[tuning]` |
| **Heartbeat** interval + timeout | ✅ | `[transport]` |

## Project Structure

```
backhaul-core/
├── cmd/tunpix/main.go              # CLI: -c config.toml / -v / -genkey
├── pkg/
│   ├── config/config.go            # ALL config sections parsed + validated
│   ├── tunnel/
│   │   ├── tun_linux.go            # /dev/net/tun ioctl
│   │   └── engine.go               # Core: TUN mode + proxy mode + workers
│   ├── encap/ipx.go                # Raw socket + 6 profiles (icmp/ipip/udp/tcp/gre/bip)
│   ├── transport/transport.go      # Dial/Listen for tcp/tls/ws/wss/anytls + WSConn
│   ├── mux/mux.go                  # yamux (v2) + smux (v1) dual support
│   ├── security/cipher.go          # AES-128/256-GCM + ChaCha20 + PBKDF2 + token HMAC
│   ├── forward/forward.go          # Port forwarding (TCP backhaul + iptables DNAT)
│   ├── udprelay/relay.go           # [accept_udp] ring buffer UDP relay
│   ├── health/health.go            # TCP health check JSON endpoint
│   └── tuning/tuning.go            # Kernel sysctl + buffer + socket option profiles
├── internal/logger/logger.go       # Log level setup (panic→trace)
├── examples/
│   ├── ipx-client.toml             # Your exact config
│   ├── ipx-server-icmp.toml        # IPX server with ICMP profile
│   ├── tcp-server-mux.toml         # TCP mux server with UDP accept
│   ├── wss-client-mux.toml         # WSS mux client with edge IP + SNI
│   └── tun-tcp-server.toml         # TUN over TCP server
└── go.mod
```

## Config Format (complete reference)

```toml
# ── Server mode (non-IPX) ──
[listener]
bind_addr = ":8443"

# ── Client mode (non-IPX) ──
[dialer]
remote_addr = "1.2.3.4:8443"
edge_ip = ""                    # optional CDN edge
dial_timeout = 10
retry_interval = 3

# ── Transport ──
[transport]
type = "tun"                    # tcp|tcpmux|xtcpmux|ws|wss|wsmux|wssmux|xwsmux|anytls|tun
nodelay = true
keepalive_period = 40
accept_udp = false              # server only
proxy_protocol = false          # server only
connection_pool = 8             # client only
heartbeat_interval = 10
heartbeat_timeout = 25

# ── TUN (when type = "tun") ──
[tun]
encapsulation = "ipx"           # tcp | ipx
name = "backhaul"
local_addr = "10.10.10.2/24"
remote_addr = "10.10.10.1/24"
health_port = 1234
mtu = 1320

# ── IPX (when encapsulation = "ipx") ──
[ipx]
mode = "client"                 # client | server
profile = "bip"                 # icmp|ipip|udp|tcp|gre|bip
listen_ip = "91.99.190.159"
dst_ip = "185.142.158.220"
interface = "eth0"
icmp_type = 0                   # only for icmp profile
icmp_code = 0

# ── Mux (when transport ends with "mux") ──
[mux]
mux_version = 2                 # 1=smux, 2=yamux
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 2097152
mux_concurrency = 8

# ── Security ──
[security]
# Token mode (non-IPX):
token = "your_token"
# Encryption mode (IPX):
enable_encryption = true
algorithm = "aes-256-gcm"       # aes-256-gcm|chacha20-poly1305|aes-128-gcm
psk = "base64key..."
kdf_iterations = 100000

# ── TLS (anytls/wss/wssmux) ──
[tls]
sni = "www.digikala.com"
tls_cert = "/path/to/cert.crt"  # server only
tls_key = "/path/to/cert.key"

# ── Tuning ──
[tuning]
auto_tuning = true
tuning_profile = "balanced"     # balanced|fast|latency|resource
workers = 0                     # 0 = NumCPU
channel_size = 10_000
batch_size = 2048               # IPX only
so_sndbuf = 0
so_rcvbuf = 0
tcp_mss = 0
buffer_profile = "balanced"     # extreme_low_cpu|ultra_low_cpu|low_cpu|balanced|low_memory
read_timeout = 120

# ── UDP over TCP (server, accept_udp=true) ──
[accept_udp]
ring_size = 64
frame_size = 2048
peer_idle_timeout_s = 120
write_timeout_ms = 3

# ── Logging ──
[logging]
log_level = "info"              # panic|fatal|error|warn|info|debug|trace

# ── Port Forwarding (server) ──
[ports]
forwarder = "backhaul"          # backhaul (TCP only) | iptables (TCP+UDP)
mapping = [
    "443",                      # listen 443 → forward 443
    "443=5000",                 # listen 443 → forward 5000
    "443-600",                  # range 443-600 → same ports
    "443-600:5201",             # range → starting at 5201
]
```

## Build

```bash
go build -o backhaul_core ./cmd/tunpix

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o backhaul_core_amd64 ./cmd/tunpix
GOOS=linux GOARCH=arm64 go build -o backhaul_core_arm64 ./cmd/tunpix
```

## Usage

```bash
# Generate PSK
./backhaul_core -genkey

# Run with config
sudo ./backhaul_core -c examples/ipx-client.toml

# Check version
./backhaul_core -v
```

## Systemd Service

```ini
[Unit]
Description=Backhaul Core
After=network.target

[Service]
Type=simple
ExecStart=/root/backhaul-core/backhaul_core -c /root/backhaul-core/config.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

## Requirements

- Linux (uses /dev/net/tun + raw sockets)
- Root or CAP_NET_ADMIN + CAP_NET_RAW
- Go 1.22+

## License

MIT
