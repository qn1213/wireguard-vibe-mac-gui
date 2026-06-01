package config

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

type Config struct {
	Path                string
	PrivateKey          [32]byte
	DeclaredPublicKey   *[32]byte
	PeerPublicKey       [32]byte
	PresharedKey        [32]byte
	Address             string
	DNS                 string
	Endpoint            string
	AllowedIPs          string
	PersistentKeepalive int
	MTU                 int
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	values := map[string]map[string]string{}
	section := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if values[section] == nil {
				values[section] = map[string]string{}
			}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || section == "" {
			return Config{}, fmt.Errorf("invalid config line: %q", line)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		values[section][key] = value
	}
	if err := scanner.Err(); err != nil {
		return Config{}, err
	}

	cfg := Config{
		Path:                path,
		Address:             getValue(values, "Interface", "Address"),
		DNS:                 getValue(values, "Interface", "DNS"),
		Endpoint:            getValue(values, "Peer", "Endpoint"),
		AllowedIPs:          getValue(values, "Peer", "AllowedIPs"),
		PersistentKeepalive: 25,
		MTU:                 1420,
	}

	priv, err := parseKey(getValue(values, "Interface", "PrivateKey"))
	if err != nil {
		return Config{}, fmt.Errorf("Interface PrivateKey: %w", err)
	}
	peer, err := parseKey(getValue(values, "Peer", "PublicKey"))
	if err != nil {
		return Config{}, fmt.Errorf("Peer PublicKey: %w", err)
	}
	cfg.PrivateKey = priv
	cfg.PeerPublicKey = peer

	if declared := getValue(values, "Interface", "PublicKey"); declared != "" {
		key, err := parseKey(declared)
		if err != nil {
			return Config{}, fmt.Errorf("Interface PublicKey: %w", err)
		}
		cfg.DeclaredPublicKey = &key
	}

	if v := getValue(values, "Peer", "PresharedKey"); v != "" {
		psk, err := parseKey(v)
		if err != nil {
			return Config{}, fmt.Errorf("Peer PresharedKey: %w", err)
		}
		cfg.PresharedKey = psk
	}

	if v := getValue(values, "Peer", "PersistentKeepalive"); v != "" {
		keepalive, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("PersistentKeepalive: %w", err)
		}
		cfg.PersistentKeepalive = keepalive
	}
	if v := getValue(values, "Interface", "MTU"); v != "" {
		mtu, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("MTU: %w", err)
		}
		cfg.MTU = mtu
	}

	if cfg.Address == "" {
		return Config{}, fmt.Errorf("Interface Address is required")
	}
	if _, _, err := net.ParseCIDR(cfg.Address); err != nil {
		return Config{}, fmt.Errorf("Interface Address: %w", err)
	}
	if cfg.DNS == "" || net.ParseIP(cfg.DNS) == nil {
		return Config{}, fmt.Errorf("Interface DNS must be an IP address")
	}
	if _, err := net.ResolveUDPAddr("udp4", cfg.Endpoint); err != nil {
		return Config{}, fmt.Errorf("Peer Endpoint: %w", err)
	}
	if cfg.AllowedIPs == "" {
		return Config{}, fmt.Errorf("Peer AllowedIPs is required")
	}
	if cfg.MTU < 576 || cfg.MTU > 9000 {
		return Config{}, fmt.Errorf("MTU out of range: %d", cfg.MTU)
	}

	return cfg, nil
}

func getValue(values map[string]map[string]string, section, key string) string {
	for sectionName, sectionValues := range values {
		if !strings.EqualFold(sectionName, section) {
			continue
		}
		for name, value := range sectionValues {
			if strings.EqualFold(name, key) {
				return value
			}
		}
	}
	return ""
}

func parseKey(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("decoded key is %d bytes, want 32", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func (c Config) ClientPublicKey() [32]byte {
	pub, err := curve25519.X25519(c.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	var out [32]byte
	copy(out[:], pub)
	return out
}

func (c Config) ClientPublicKeyBase64() string {
	pub := c.ClientPublicKey()
	return base64.StdEncoding.EncodeToString(pub[:])
}
