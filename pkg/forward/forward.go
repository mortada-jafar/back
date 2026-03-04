package forward

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// PortMapping represents a parsed port mapping entry.
type PortMapping struct {
	ListenStart int
	ListenEnd   int
	ForwardPort int // -1 means same as listen
}

// ParseMappings parses all mapping formats from the script:
//
//	"443"           -> listen 443, forward 443
//	"443=5000"      -> listen 443, forward 5000
//	"443-600"       -> listen range 443-600, forward same
//	"443-600:5201"  -> listen range 443-600, forward starting at 5201
func ParseMappings(entries []string) ([]PortMapping, error) {
	var mappings []PortMapping
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Format: range:forward  e.g. "443-600:5201"
		if strings.Contains(entry, ":") && strings.Contains(entry, "-") {
			parts := strings.SplitN(entry, ":", 2)
			rng := strings.SplitN(parts[0], "-", 2)
			start, _ := strconv.Atoi(rng[0])
			end, _ := strconv.Atoi(rng[1])
			fwd, _ := strconv.Atoi(parts[1])
			for i := start; i <= end; i++ {
				mappings = append(mappings, PortMapping{
					ListenStart: i, ListenEnd: i,
					ForwardPort: fwd + (i - start),
				})
			}
			continue
		}

		// Format: range  e.g. "443-600"
		if strings.Contains(entry, "-") && !strings.Contains(entry, "=") {
			parts := strings.SplitN(entry, "-", 2)
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			for i := start; i <= end; i++ {
				mappings = append(mappings, PortMapping{ListenStart: i, ListenEnd: i, ForwardPort: i})
			}
			continue
		}

		// Format: listen=forward  e.g. "443=5000"
		if strings.Contains(entry, "=") {
			parts := strings.SplitN(entry, "=", 2)
			listen, _ := strconv.Atoi(parts[0])
			fwd, _ := strconv.Atoi(parts[1])
			mappings = append(mappings, PortMapping{ListenStart: listen, ListenEnd: listen, ForwardPort: fwd})
			continue
		}

		// Format: single port  e.g. "443"
		port, err := strconv.Atoi(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid port mapping: %q", entry)
		}
		mappings = append(mappings, PortMapping{ListenStart: port, ListenEnd: port, ForwardPort: port})
	}
	return mappings, nil
}

// TCPForwarder runs a TCP port forwarder (the "backhaul" forwarder type).
// It listens on listenPort and forwards to remoteIP:forwardPort.
func TCPForwarder(listenPort int, remoteIP string, forwardPort int, done <-chan struct{}) {
	addr := fmt.Sprintf(":%d", listenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("Forward listen %s: %v", addr, err)
		return
	}
	defer ln.Close()

	target := fmt.Sprintf("%s:%d", remoteIP, forwardPort)
	log.Infof("Port forward: %s -> %s (TCP)", addr, target)

	go func() {
		<-done
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				log.Debugf("Forward accept: %v", err)
				continue
			}
		}
		go handleForward(conn, target)
	}
}

func handleForward(src net.Conn, target string) {
	defer src.Close()
	dst, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Debugf("Forward dial %s: %v", target, err)
		return
	}
	defer dst.Close()

	done := make(chan struct{})
	go func() {
		io.Copy(dst, src)
		close(done)
	}()
	io.Copy(src, dst)
	<-done
}

// IPTablesForwarder sets up iptables DNAT rules for TCP+UDP forwarding.
func IPTablesForwarder(listenPort int, remoteIP string, forwardPort int) error {
	// DNAT rule for TCP
	if err := iptablesRule("tcp", listenPort, remoteIP, forwardPort); err != nil {
		return err
	}
	// DNAT rule for UDP
	if err := iptablesRule("udp", listenPort, remoteIP, forwardPort); err != nil {
		return err
	}

	// MASQUERADE so that reply packets from the TUN remote are properly
	// returned to the local process (required for the OUTPUT-chain DNAT path).
	_ = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-d", remoteIP, "-j", "MASQUERADE",
	).Run()

	log.Infof("iptables DNAT: :%d -> %s:%d (TCP+UDP)", listenPort, remoteIP, forwardPort)
	return nil
}

func iptablesRule(proto string, listenPort int, remoteIP string, fwdPort int) error {
	dest := fmt.Sprintf("%s:%d", remoteIP, fwdPort)
	dport := strconv.Itoa(listenPort)

	// PREROUTING: redirect external traffic arriving on this host
	if err := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-p", proto, "--dport", dport,
		"-j", "DNAT", "--to-destination", dest,
	).Run(); err != nil {
		return err
	}

	// OUTPUT: redirect locally-originated traffic (e.g. ssh 127.0.0.1 -p <port>)
	if err := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", proto, "--dport", dport,
		"-j", "DNAT", "--to-destination", dest,
	).Run(); err != nil {
		return err
	}

	return nil
}

// CleanupIPTables removes DNAT rules (best-effort on shutdown).
func CleanupIPTables(listenPort int, remoteIP string, fwdPort int) {
	dest := fmt.Sprintf("%s:%d", remoteIP, fwdPort)
	dport := strconv.Itoa(listenPort)
	for _, proto := range []string{"tcp", "udp"} {
		exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
			"-p", proto, "--dport", dport,
			"-j", "DNAT", "--to-destination", dest,
		).Run()
		exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
			"-p", proto, "--dport", dport,
			"-j", "DNAT", "--to-destination", dest,
		).Run()
	}
}
