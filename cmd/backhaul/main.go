package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/tunpixbip/backhaul-core/internal/logger"
	"github.com/tunpixbip/backhaul-core/pkg/config"
	"github.com/tunpixbip/backhaul-core/pkg/security"
	"github.com/tunpixbip/backhaul-core/pkg/tunnel"
)

var version = "1.0.0"

func main() {
	configPath := flag.String("c", "", "Path to TOML config file")
	showVersion := flag.Bool("v", false, "Show version")
	genKey := flag.Bool("genkey", false, "Generate a random PSK")
	flag.Parse()

	if *showVersion {
		fmt.Printf("backhaul-core v%s\n", version)
		os.Exit(0)
	}

	if *genKey {
		psk, err := security.GeneratePSK()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PSK: %s\n", psk)
		os.Exit(0)
	}

	if *configPath == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -c <config.toml>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s -v\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s -genkey\n", os.Args[0])
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	logger.Setup(cfg.Logging.LogLevel)

	log.WithFields(log.Fields{
		"version":   version,
		"mode":      cfg.Mode(),
		"transport": cfg.Transport.Type,
	}).Info("backhaul-core starting")

	if cfg.IsTun() {
		log.WithFields(log.Fields{
			"encap": cfg.Tun.Encapsulation,
			"tun":   cfg.Tun.Name,
			"local": cfg.Tun.LocalAddr,
			"mtu":   cfg.Tun.MTU,
		}).Info("TUN mode")
	}
	if cfg.IsIPX() {
		log.WithFields(log.Fields{
			"profile":  cfg.IPX.Profile,
			"listen":   cfg.IPX.ListenIP,
			"dst":      cfg.IPX.DstIP,
			"iface":    cfg.IPX.Interface,
		}).Info("IPX encapsulation")
	}

	engine, err := tunnel.NewEngine(cfg)
	if err != nil {
		log.Fatalf("Engine init: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Infof("Received %v, shutting down...", sig)
		engine.Shutdown()

		// Second Ctrl+C = force exit
		sig = <-sigCh
		log.Warnf("Received %v again, forcing exit", sig)
		os.Exit(1)
	}()

	if err := engine.Run(); err != nil {
		log.Fatalf("Engine: %v", err)
	}
}