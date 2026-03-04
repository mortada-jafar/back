package tunnel

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	tunCloneDevice = "/dev/net/tun"
	ifNameSize     = 16
	iffTun         = 0x0001
	iffNoPi        = 0x1000
	tunSetIff      = 0x400454ca
)

type ifreq struct {
	Name  [ifNameSize]byte
	Flags uint16
	_     [22]byte
}

type TunDevice struct {
	name      string
	file      *os.File
	mtu       int
	closeOnce sync.Once
}

func NewTunDevice(name, localCIDR, remoteCIDR string, mtu int) (*TunDevice, error) {
	// Clean up stale device if it exists from a previous crash
	if deviceExists(name) {
		log.Warnf("TUN device %q already exists, removing stale device...", name)
		if err := runCmd("ip", "link", "delete", name); err != nil {
			log.Warnf("Failed to delete stale device %q: %v", name, err)
		}
		// Brief pause for kernel to release
		unix.Nanosleep(&unix.Timespec{Nsec: 200_000_000}, nil) // 200ms
	}

	fd, err := unix.Open(tunCloneDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunCloneDevice, err)
	}

	var req ifreq
	req.Flags = iffTun | iffNoPi
	copy(req.Name[:], name)

	if err := ioctl(fd, tunSetIff, uintptr(unsafe.Pointer(&req))); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF: %w", err)
	}

	ifName := string(req.Name[:clen(req.Name[:])])
	file := os.NewFile(uintptr(fd), tunCloneDevice)

	dev := &TunDevice{name: ifName, file: file, mtu: mtu}

	if err := dev.configure(localCIDR, remoteCIDR); err != nil {
		file.Close()
		return nil, err
	}

	log.WithFields(log.Fields{
		"name": ifName, "local": localCIDR, "remote": remoteCIDR, "mtu": mtu,
	}).Info("TUN device created")

	return dev, nil
}

func (d *TunDevice) configure(localCIDR, remoteCIDR string) error {
	localIP, _, _ := net.ParseCIDR(localCIDR)
	remoteIP, _, _ := net.ParseCIDR(remoteCIDR)
	parts := strings.SplitN(localCIDR, "/", 2)
	prefix := "24"
	if len(parts) == 2 {
		prefix = parts[1]
	}

	cmds := [][]string{
		{"ip", "addr", "add", localIP.String() + "/" + prefix, "dev", d.name},
		{"ip", "link", "set", d.name, "mtu", fmt.Sprint(d.mtu)},
		{"ip", "link", "set", d.name, "up"},
		{"ip", "route", "add", remoteIP.String(), "dev", d.name},
	}
	for _, args := range cmds {
		if err := runCmd(args[0], args[1:]...); err != nil {
			if args[1] == "route" {
				log.Debugf("route cmd (may exist): %v", err)
				continue
			}
			return fmt.Errorf("cmd %v: %w", args, err)
		}
	}
	return nil
}

func (d *TunDevice) Read(buf []byte) (int, error)  { return d.file.Read(buf) }
func (d *TunDevice) Write(buf []byte) (int, error) { return d.file.Write(buf) }
func (d *TunDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		log.Infof("Closing TUN device %q", d.name)
		err = d.file.Close()
		// Also delete the interface to prevent "device busy" on restart
		runCmd("ip", "link", "delete", d.name)
	})
	return err
}
func (d *TunDevice) Name() string { return d.name }
func (d *TunDevice) MTU() int     { return d.mtu }

func ioctl(fd int, req, arg uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, arg)
	if errno != 0 {
		return errno
	}
	return nil
}

func deviceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func clen(b []byte) int {
	for i := range b {
		if b[i] == 0 {
			return i
		}
	}
	return len(b)
}

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s: %w", name, args, strings.TrimSpace(string(out)), err)
	}
	return nil
}
