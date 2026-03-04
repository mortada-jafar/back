package mux

import (
	"fmt"
	"io"
	"net"

	"github.com/hashicorp/yamux"
	"github.com/xtaci/smux"

	"github.com/tunpixbip/backhaul-core/pkg/config"
)

// Session wraps either yamux or smux sessions.
type Session interface {
	AcceptStream() (net.Conn, error)
	OpenStream() (net.Conn, error)
	Close() error
	IsClosed() bool
	NumStreams() int
}

// NewServerSession creates a server-side mux session.
func NewServerSession(conn net.Conn, cfg *config.MuxConfig) (Session, error) {
	if cfg == nil {
		cfg = &config.MuxConfig{MuxVersion: 2}
	}
	switch cfg.MuxVersion {
	case 1:
		return newSmuxServer(conn, cfg)
	default:
		return newYamuxServer(conn, cfg)
	}
}

// NewClientSession creates a client-side mux session.
func NewClientSession(conn net.Conn, cfg *config.MuxConfig) (Session, error) {
	if cfg == nil {
		cfg = &config.MuxConfig{MuxVersion: 2}
	}
	switch cfg.MuxVersion {
	case 1:
		return newSmuxClient(conn, cfg)
	default:
		return newYamuxClient(conn, cfg)
	}
}

// --- yamux wrapper ---

type yamuxSession struct{ s *yamux.Session }

func (y *yamuxSession) AcceptStream() (net.Conn, error) { return y.s.AcceptStream() }
func (y *yamuxSession) OpenStream() (net.Conn, error)   { return y.s.OpenStream() }
func (y *yamuxSession) Close() error                    { return y.s.Close() }
func (y *yamuxSession) IsClosed() bool                  { return y.s.IsClosed() }
func (y *yamuxSession) NumStreams() int                  { return y.s.NumStreams() }

func yamuxConfig(cfg *config.MuxConfig) *yamux.Config {
	c := yamux.DefaultConfig()
	if cfg.MuxRecieveBuffer > 0 {
		c.MaxStreamWindowSize = uint32(cfg.MuxRecieveBuffer)
	}
	c.EnableKeepAlive = true
	c.LogOutput = io.Discard
	return c
}

func newYamuxServer(conn net.Conn, cfg *config.MuxConfig) (Session, error) {
	s, err := yamux.Server(conn, yamuxConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("yamux server: %w", err)
	}
	return &yamuxSession{s}, nil
}

func newYamuxClient(conn net.Conn, cfg *config.MuxConfig) (Session, error) {
	s, err := yamux.Client(conn, yamuxConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("yamux client: %w", err)
	}
	return &yamuxSession{s}, nil
}

// --- smux wrapper (mux_version=1) ---

type smuxSession struct{ s *smux.Session }

func (s *smuxSession) AcceptStream() (net.Conn, error) { return s.s.AcceptStream() }
func (s *smuxSession) OpenStream() (net.Conn, error)   { return s.s.OpenStream() }
func (s *smuxSession) Close() error                    { return s.s.Close() }
func (s *smuxSession) IsClosed() bool                  { return s.s.IsClosed() }
func (s *smuxSession) NumStreams() int                  { return s.s.NumStreams() }

func smuxConfig(cfg *config.MuxConfig) *smux.Config {
	c := smux.DefaultConfig()
	if cfg.MuxFramesize > 0 {
		c.MaxFrameSize = cfg.MuxFramesize
	}
	if cfg.MuxRecieveBuffer > 0 {
		c.MaxReceiveBuffer = cfg.MuxRecieveBuffer
	}
	if cfg.MuxStreamBuffer > 0 {
		c.MaxStreamBuffer = cfg.MuxStreamBuffer
	}
	return c
}

func newSmuxServer(conn net.Conn, cfg *config.MuxConfig) (Session, error) {
	s, err := smux.Server(conn, smuxConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("smux server: %w", err)
	}
	return &smuxSession{s}, nil
}

func newSmuxClient(conn net.Conn, cfg *config.MuxConfig) (Session, error) {
	s, err := smux.Client(conn, smuxConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("smux client: %w", err)
	}
	return &smuxSession{s}, nil
}
