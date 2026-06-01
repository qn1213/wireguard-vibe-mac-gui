package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"

	"wireguardc/internal/client"
	"wireguardc/internal/config"
)

const defaultConfig = "config/wireguardc.conf"

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	confPath := fs.String("config", defaultConfig, "WireGuard-style config path")
	timeout := fs.Duration("timeout", 5*time.Second, "network timeout")
	handshakeTimeout := fs.Duration("handshake-timeout", 45*time.Second, "run-mode initial handshake timeout")
	handshakeCount := fs.Int("count", 5, "benchmark handshake count")
	statsFile := fs.String("stats-file", "", "write tunnel status/stats JSON to this path")
	pidFile := fs.String("pid-file", "", "write the tunnel process PID to this path")
	routeStateFile := fs.String("route-state-file", "", "persist route cleanup commands to this path")
	ownerPID := fs.Int("owner-pid", 0, "stop and clean up when this owner process exits")
	_ = fs.Parse(os.Args[2:])

	if cmd == "cleanup-routes" {
		if *routeStateFile == "" {
			log.Fatal("cleanup-routes requires -route-state-file")
		}
		if err := client.CleanupRouteState(*routeStateFile); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg, err := config.Load(*confPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	switch cmd {
	case "doctor":
		err = doctor(cfg)
	case "probe", "test":
		err = probe(cfg, *timeout, cmd == "test")
	case "bench":
		err = bench(cfg, *timeout, *handshakeCount)
	case "run":
		err = run(cfg, *statsFile, *pidFile, *routeStateFile, *ownerPID, *handshakeTimeout)
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown command: %s", cmd)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Println(`wireguardc - from-scratch macOS WireGuard client

Usage:
  wireguardc doctor [-config config/wireguardc.conf]
  wireguardc probe  [-config config/wireguardc.conf] [-timeout 5s]
  wireguardc test   [-config config/wireguardc.conf] [-timeout 5s]
  wireguardc bench  [-config config/wireguardc.conf] [-count 5]
  sudo wireguardc run [-config config/wireguardc.conf] [-stats-file state.json] [-pid-file tunnel.pid] [-route-state-file routes.json] [-owner-pid PID] [-handshake-timeout 45s]
  sudo wireguardc cleanup-routes -route-state-file routes.json

This binary does not call wg, wg-quick, wireguard-go, or WireGuard libraries.`)
}

func doctor(cfg config.Config) error {
	fmt.Printf("OS: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS != "darwin" {
		return errors.New("run mode is macOS-only")
	}
	fmt.Printf("config: %s\n", cfg.Path)
	fmt.Printf("address: %s\n", cfg.Address)
	fmt.Printf("dns: %s\n", cfg.DNS)
	fmt.Printf("endpoint: %s\n", cfg.Endpoint)
	fmt.Printf("allowed_ips: %s\n", cfg.AllowedIPs)
	fmt.Printf("mtu: %d\n", cfg.MTU)
	fmt.Printf("client_public_key_from_private: %s\n", cfg.ClientPublicKeyBase64())
	if cfg.DeclaredPublicKey != nil && *cfg.DeclaredPublicKey != cfg.ClientPublicKey() {
		fmt.Println("warning: configured Interface PublicKey does not match the public key derived from PrivateKey")
		fmt.Println("warning: this usually means PrivateKey is actually a public key, so the server will drop handshakes")
	}
	fmt.Println("note: the server must have client_public_key_from_private registered for this client")

	udpAddr, err := net.ResolveUDPAddr("udp4", cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("endpoint resolve: %w", err)
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("udp dial: %w", err)
	}
	_ = conn.Close()
	fmt.Println("udp: endpoint address is dialable")
	return nil
}

func probe(cfg config.Config, timeout time.Duration, includeDNS bool) error {
	hs, err := client.Probe(cfg, timeout)
	if err != nil {
		return err
	}
	fmt.Printf("handshake: ok rtt=%s remote_index=%d\n", hs.RTT.Round(time.Millisecond), hs.RemoteIndex)
	if includeDNS {
		return dnsProbe(cfg.DNS, timeout)
	}
	return nil
}

func dnsProbe(server string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
	addrs, err := resolver.LookupHost(ctx, "example.com")
	if err != nil {
		return fmt.Errorf("dns probe via %s: %w", server, err)
	}
	sort.Strings(addrs)
	fmt.Printf("dns: ok server=%s answer=%s\n", server, addrs[0])
	return nil
}

func bench(cfg config.Config, timeout time.Duration, count int) error {
	if count < 1 {
		count = 1
	}
	if err := os.MkdirAll("logs", 0o755); err != nil {
		return err
	}

	var samples []time.Duration
	var lastErr error
	for i := 0; i < count; i++ {
		hs, err := client.Probe(cfg, timeout)
		if err != nil {
			lastErr = err
			fmt.Printf("sample %d: error: %v\n", i+1, err)
			continue
		}
		samples = append(samples, hs.RTT)
		fmt.Printf("sample %d: %s\n", i+1, hs.RTT.Round(time.Millisecond))
		time.Sleep(750 * time.Millisecond)
	}
	if len(samples) == 0 {
		return fmt.Errorf("all benchmark samples failed: %w", lastErr)
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	var total time.Duration
	for _, sample := range samples {
		total += sample
	}
	avg := total / time.Duration(len(samples))
	profile := filepath.Join("logs", fmt.Sprintf("profile-%s.txt", time.Now().Format("20060102-150405")))
	body := fmt.Sprintf("samples=%d min=%s median=%s max=%s avg=%s\n",
		len(samples),
		samples[0].Round(time.Millisecond),
		samples[len(samples)/2].Round(time.Millisecond),
		samples[len(samples)-1].Round(time.Millisecond),
		avg.Round(time.Millisecond),
	)
	if err := os.WriteFile(profile, []byte(body), 0o644); err != nil {
		return err
	}
	fmt.Print(body)
	fmt.Printf("profile: %s\n", profile)
	return nil
}

func run(cfg config.Config, statsFile, pidFile, routeStateFile string, ownerPID int, handshakeTimeout time.Duration) error {
	if os.Geteuid() != 0 {
		return errors.New("run requires root: use sudo ./wireguardc run")
	}
	if pidFile != "" {
		if err := os.MkdirAll(filepath.Dir(pidFile), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
			return err
		}
		defer os.Remove(pidFile)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	opts := client.RunOptions{
		StatsFile:        statsFile,
		HandshakeTimeout: handshakeTimeout,
		RouteStateFile:   routeStateFile,
		OwnerPID:         ownerPID,
	}
	err := client.RunTunnel(ctx, cfg, opts)
	if err != nil && statsFile != "" {
		_ = client.WriteStatsFile(statsFile, client.TunnelStats{
			State:     "error",
			Connected: false,
			Endpoint:  cfg.Endpoint,
			Error:     err.Error(),
			UpdatedAt: time.Now(),
		})
	}
	return err
}
