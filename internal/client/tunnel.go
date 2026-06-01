package client

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"wireguardc/internal/config"
)

const (
	sysProtoControl = 2
	utunOptIfName   = 2
)

type tunDevice struct {
	fd   int
	file *os.File
	name string
}

type RunOptions struct {
	StatsFile        string
	HandshakeTimeout time.Duration
	RouteStateFile   string
	OwnerPID         int
}

type TunnelStats struct {
	State     string    `json:"state"`
	Connected bool      `json:"connected"`
	Interface string    `json:"interface,omitempty"`
	Endpoint  string    `json:"endpoint"`
	TxBytes   uint64    `json:"txBytes"`
	RxBytes   uint64    `json:"rxBytes"`
	TxRateBps uint64    `json:"txRateBps"`
	RxRateBps uint64    `json:"rxRateBps"`
	StartedAt time.Time `json:"startedAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
	Error     string    `json:"error,omitempty"`
}

type tunnelCounters struct {
	txBytes atomic.Uint64
	rxBytes atomic.Uint64
}

func WriteStatsFile(path string, stats TunnelStats) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func RunTunnel(ctx context.Context, cfg config.Config, opts RunOptions) error {
	ctx, cancel := withOwnerWatchdog(ctx, opts.OwnerPID)
	defer cancel()

	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = 45 * time.Second
	}
	if opts.RouteStateFile != "" {
		_ = CleanupRouteState(opts.RouteStateFile)
	}
	if opts.StatsFile != "" {
		_ = WriteStatsFile(opts.StatsFile, TunnelStats{
			State:     "connecting",
			Connected: false,
			Endpoint:  cfg.Endpoint,
			UpdatedAt: time.Now(),
		})
	}

	udpAddr, err := net.ResolveUDPAddr("udp4", cfg.Endpoint)
	if err != nil {
		return err
	}
	routes := &routeManager{stateFile: opts.RouteStateFile}
	defer routes.Cleanup()
	if err := pinEndpointRoute(udpAddr.IP.String(), routes); err != nil {
		return err
	}

	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	session := NewSession(cfg)
	if err := session.Handshake(conn, opts.HandshakeTimeout); err != nil {
		return err
	}
	if _, err := conn.Write(session.EncryptKeepalive()); err != nil {
		return err
	}

	tun, err := openTun()
	if err != nil {
		return err
	}
	defer tun.Close()

	if err := configureTun(tun.name, cfg, routes); err != nil {
		_ = routes.Cleanup()
		return err
	}
	defer routes.Cleanup()

	counters := &tunnelCounters{}
	statsCtx, stopStats := context.WithCancel(ctx)
	defer stopStats()
	if opts.StatsFile != "" {
		go writeStatsLoop(statsCtx, opts.StatsFile, cfg.Endpoint, tun.name, counters)
	}

	log.Printf("tunnel up: interface=%s endpoint=%s address=%s", tun.name, cfg.Endpoint, cfg.Address)
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- tunToUDP(ctx, tun, conn, session, counters)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- udpToTun(ctx, tun, conn, session, counters)
	}()

	keepalive := time.NewTicker(time.Duration(cfg.PersistentKeepalive) * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = tun.Close()
			_ = conn.Close()
			wg.Wait()
			return nil
		case <-keepalive.C:
			_, _ = conn.Write(session.EncryptKeepalive())
		case err := <-errCh:
			if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
				continue
			}
			_ = tun.Close()
			_ = conn.Close()
			wg.Wait()
			return err
		}
	}
}

func withOwnerWatchdog(ctx context.Context, ownerPID int) (context.Context, context.CancelFunc) {
	watchedCtx, cancel := context.WithCancel(ctx)
	if ownerPID <= 0 {
		return watchedCtx, cancel
	}

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watchedCtx.Done():
				return
			case <-ticker.C:
				if !processExists(ownerPID) {
					log.Printf("owner process exited: pid=%d; stopping tunnel", ownerPID)
					cancel()
					return
				}
			}
		}
	}()

	return watchedCtx, cancel
}

func processExists(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || err == unix.EPERM
}

func tunToUDP(ctx context.Context, tun *tunDevice, conn *net.UDPConn, session *Session, counters *tunnelCounters) error {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := tun.ReadPacket(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		counters.txBytes.Add(uint64(n))
		packet := session.EncryptPacket(buf[:n])
		if _, err := conn.Write(packet); err != nil {
			return err
		}
	}
}

func udpToTun(ctx context.Context, tun *tunDevice, conn *net.UDPConn, session *Session, counters *tunnelCounters) error {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		if n < 4 || binary.LittleEndian.Uint32(buf[:4]) != messageTransport {
			continue
		}
		packet, err := session.DecryptTransport(buf[:n])
		if err != nil {
			continue
		}
		if len(packet) == 0 {
			continue
		}
		counters.rxBytes.Add(uint64(len(packet)))
		if err := tun.WritePacket(packet); err != nil {
			return err
		}
	}
}

func writeStatsLoop(ctx context.Context, path, endpoint, iface string, counters *tunnelCounters) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	started := time.Now()
	var prevTx, prevRx uint64
	write := func(state string) {
		tx := counters.txBytes.Load()
		rx := counters.rxBytes.Load()
		now := time.Now()
		stats := TunnelStats{
			State:     state,
			Connected: state == "connected",
			Interface: iface,
			Endpoint:  endpoint,
			TxBytes:   tx,
			RxBytes:   rx,
			TxRateBps: tx - prevTx,
			RxRateBps: rx - prevRx,
			StartedAt: started,
			UpdatedAt: now,
		}
		prevTx = tx
		prevRx = rx
		_ = WriteStatsFile(path, stats)
	}

	write("connected")
	for {
		select {
		case <-ctx.Done():
			write("disconnected")
			return
		case <-ticker.C:
			write("connected")
		}
	}
}

func openTun() (*tunDevice, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysProtoControl)
	if err != nil {
		return nil, fmt.Errorf("utun socket: %w", err)
	}
	var info unix.CtlInfo
	copy(info.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, &info); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("utun ioctl: %w", err)
	}
	addr := &unix.SockaddrCtl{
		ID:   info.Id,
		Unit: 0,
	}
	if err := unix.Connect(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("utun connect: %w", err)
	}
	name, err := unix.GetsockoptString(fd, sysProtoControl, utunOptIfName)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("utun ifname: %w", err)
	}
	return &tunDevice{fd: fd, file: os.NewFile(uintptr(fd), name), name: strings.TrimRight(name, "\x00")}, nil
}

func (t *tunDevice) Close() error {
	if t.file != nil {
		return t.file.Close()
	}
	return unix.Close(t.fd)
}

func (t *tunDevice) ReadPacket(buf []byte) (int, error) {
	frame := make([]byte, len(buf)+4)
	n, err := t.file.Read(frame)
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil
	}
	copy(buf, frame[4:n])
	return n - 4, nil
}

func (t *tunDevice) WritePacket(packet []byte) error {
	frame := make([]byte, len(packet)+4)
	if len(packet) > 0 && packet[0]>>4 == 6 {
		binary.BigEndian.PutUint32(frame[:4], unix.AF_INET6)
	} else {
		binary.BigEndian.PutUint32(frame[:4], unix.AF_INET)
	}
	copy(frame[4:], packet)
	_, err := t.file.Write(frame)
	return err
}

type routeManager struct {
	cleanup   [][]string
	stateFile string
}

func (r *routeManager) AddCleanup(args ...string) {
	cp := append([]string(nil), args...)
	r.cleanup = append(r.cleanup, cp)
	_ = r.persist()
}

func (r *routeManager) Cleanup() error {
	for i := len(r.cleanup) - 1; i >= 0; i-- {
		_ = runCommand(r.cleanup[i][0], r.cleanup[i][1:]...)
	}
	if r.stateFile != "" {
		_ = os.Remove(r.stateFile)
	}
	return nil
}

func (r *routeManager) persist() error {
	if r.stateFile == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.stateFile), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(r.cleanup, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.stateFile + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.stateFile)
}

func CleanupRouteState(path string) error {
	if path == "" {
		return nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var cleanup [][]string
	if err := json.Unmarshal(body, &cleanup); err != nil {
		return err
	}
	for i := len(cleanup) - 1; i >= 0; i-- {
		if len(cleanup[i]) == 0 {
			continue
		}
		_ = runCommand(cleanup[i][0], cleanup[i][1:]...)
	}
	return os.Remove(path)
}

func configureTun(name string, cfg config.Config, routes *routeManager) error {
	ip, ipNet, err := net.ParseCIDR(cfg.Address)
	if err != nil {
		return err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return errors.New("only IPv4 Address is supported")
	}
	mask := net.IP(ipNet.Mask).String()
	peer := firstHost(ipNet)
	if peer == nil {
		return fmt.Errorf("cannot derive peer address from %s", cfg.Address)
	}

	if err := runCommand("ifconfig", name, "inet", ip4.String(), peer.String(), "netmask", mask, "mtu", strconv.Itoa(cfg.MTU), "up"); err != nil {
		return err
	}
	routes.AddCleanup("ifconfig", name, "down")

	if cfg.AllowedIPs == "0.0.0.0/0" {
		for _, netRoute := range fullTunnelIPv4Routes() {
			if err := runCommand("route", "-n", "add", "-net", netRoute, "-interface", name); err != nil {
				return err
			}
			routes.AddCleanup("route", "-n", "delete", "-net", netRoute, "-interface", name)
		}
	} else {
		for _, allowed := range strings.Split(cfg.AllowedIPs, ",") {
			allowed = strings.TrimSpace(allowed)
			if allowed == "" {
				continue
			}
			if err := runCommand("route", "-n", "add", "-net", allowed, "-interface", name); err != nil {
				return err
			}
			routes.AddCleanup("route", "-n", "delete", "-net", allowed, "-interface", name)
		}
	}

	return nil
}

func fullTunnelIPv4Routes() []string {
	return []string{
		"0.0.0.0/4",
		"16.0.0.0/4",
		"32.0.0.0/4",
		"48.0.0.0/4",
		"64.0.0.0/4",
		"80.0.0.0/4",
		"96.0.0.0/4",
		"112.0.0.0/4",
		"128.0.0.0/4",
		"144.0.0.0/4",
		"160.0.0.0/4",
		"176.0.0.0/4",
		"192.0.0.0/4",
		"208.0.0.0/4",
	}
}

func firstHost(ipNet *net.IPNet) net.IP {
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	out[3]++
	return out
}

func pinEndpointRoute(host string, routes *routeManager) error {
	gateway := physicalDefaultGateway()
	if gateway == "" {
		gateway = currentGateway(host)
	}
	if gateway == "" {
		return fmt.Errorf("cannot find a physical gateway for endpoint %s", host)
	}

	if err := runCommand("route", "-n", "add", "-host", host, gateway); err != nil {
		if changeErr := runCommand("route", "-n", "change", "-host", host, gateway); changeErr != nil {
			_ = runCommand("route", "-n", "delete", "-host", host)
			if addErr := runCommand("route", "-n", "add", "-host", host, gateway); addErr != nil {
				return fmt.Errorf("pin endpoint route: add failed: %v; change failed: %v; replace failed: %w", err, changeErr, addErr)
			}
		}
	}
	routes.AddCleanup("route", "-n", "delete", "-host", host, gateway)
	log.Printf("endpoint route pinned: %s via %s", host, gateway)
	return nil
}

func physicalDefaultGateway() string {
	out, err := exec.Command("netstat", "-rn", "-f", "inet").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" {
			continue
		}
		gateway := fields[1]
		if strings.HasPrefix(gateway, "link#") {
			continue
		}
		iface := fields[len(fields)-1]
		if strings.HasPrefix(iface, "utun") {
			continue
		}
		if net.ParseIP(gateway) != nil {
			return gateway
		}
	}
	return ""
}

func currentGateway(host string) string {
	out, err := exec.Command("route", "-n", "get", host).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}
	return ""
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
