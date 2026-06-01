package config

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestLoadParsesPresharedKeyAndCaseInsensitiveKeys(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x01", 32)))
	psk := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x02", 32)))
	path := t.TempDir() + "/wg.conf"
	body := `[Interface]
PrivateKey = ` + key + `
Address = 10.0.17.3/24
DNS = 168.126.63.1

[Peer]
PublicKey = ` + key + `
AllowedIps = 0.0.0.0/0
Endpoint = 127.0.0.1:61234
PresharedKey = ` + psk + `
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowedIPs != "0.0.0.0/0" {
		t.Fatalf("AllowedIPs = %q", cfg.AllowedIPs)
	}
	if got := base64.StdEncoding.EncodeToString(cfg.PresharedKey[:]); got != psk {
		t.Fatalf("PresharedKey = %q, want %q", got, psk)
	}
}
