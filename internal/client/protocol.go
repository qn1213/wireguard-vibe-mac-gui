package client

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"wireguardc/internal/config"
)

const (
	messageInitiation = 1
	messageResponse   = 2
	messageCookie     = 3
	messageTransport  = 4

	initiationSize = 148
	responseSize   = 92
	handshakeRetry = time.Second

	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wireGuardID       = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	labelMAC1         = "mac1----"
)

type ProbeResult struct {
	RTT         time.Duration
	RemoteIndex uint32
}

type Session struct {
	cfg       config.Config
	staticPub [32]byte

	mu            sync.Mutex
	localIndex    uint32
	remoteIndex   uint32
	ephemeralPriv [32]byte
	chainingKey   [32]byte
	handshakeHash [32]byte
	sendKey       [32]byte
	recvKey       [32]byte
	sendAEAD      cipher.AEAD
	recvAEAD      cipher.AEAD
	sendCounter   uint64
	replay        replayWindow
	establishedAt time.Time
}

func NewSession(cfg config.Config) *Session {
	return &Session{cfg: cfg, staticPub: cfg.ClientPublicKey()}
}

func Probe(cfg config.Config, timeout time.Duration) (ProbeResult, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", cfg.Endpoint)
	if err != nil {
		return ProbeResult{}, err
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return ProbeResult{}, err
	}
	defer conn.Close()

	session := NewSession(cfg)
	start := time.Now()
	if err := session.Handshake(conn, timeout); err != nil {
		return ProbeResult{}, err
	}
	if _, err := conn.Write(session.EncryptKeepalive()); err != nil {
		return ProbeResult{}, fmt.Errorf("keepalive write: %w", err)
	}
	return ProbeResult{RTT: time.Since(start), RemoteIndex: session.remoteIndex}, nil
}

func (s *Session) Handshake(conn *net.UDPConn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	var lastErr error

	for time.Now().Before(deadline) {
		initiation, err := s.CreateInitiation()
		if err != nil {
			return err
		}
		if _, err := conn.Write(initiation); err != nil {
			return fmt.Errorf("handshake initiation write: %w", err)
		}

		readDeadline := time.Now().Add(handshakeRetry)
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		if err := conn.SetReadDeadline(readDeadline); err != nil {
			return err
		}

		for {
			n, err := conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					lastErr = err
					break
				}
				return fmt.Errorf("handshake response read: %w", err)
			}
			if n < 4 {
				continue
			}
			switch binary.LittleEndian.Uint32(buf[:4]) {
			case messageResponse:
				if err := s.ConsumeResponse(buf[:n]); err != nil {
					lastErr = err
					continue
				}
				_ = conn.SetReadDeadline(time.Time{})
				return nil
			case messageCookie:
				return errors.New("server requested a cookie reply; cookie mode is not implemented in this build")
			default:
				continue
			}
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if lastErr != nil {
		return fmt.Errorf("handshake response read: %w", lastErr)
	}
	return errors.New("handshake response timeout")
}

func (s *Session) CreateInitiation() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ck := hashBytes([]byte(noiseConstruction))
	h := hashBytes(ck[:], []byte(wireGuardID))
	h = hashBytes(h[:], s.cfg.PeerPublicKey[:])

	if _, err := rand.Read(s.ephemeralPriv[:]); err != nil {
		return nil, err
	}
	ephemeralPub, err := curve25519.X25519(s.ephemeralPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	localIndex, err := randomUint32()
	if err != nil {
		return nil, err
	}
	s.localIndex = localIndex

	msg := make([]byte, initiationSize)
	binary.LittleEndian.PutUint32(msg[0:4], messageInitiation)
	binary.LittleEndian.PutUint32(msg[4:8], localIndex)
	copy(msg[8:40], ephemeralPub)

	ck = kdf1(ck[:], ephemeralPub)
	h = hashBytes(h[:], ephemeralPub)

	es, err := curve25519.X25519(s.ephemeralPriv[:], s.cfg.PeerPublicKey[:])
	if err != nil {
		return nil, fmt.Errorf("ephemeral-static dh: %w", err)
	}
	ck2, key := kdf2(ck[:], es)
	ck = ck2
	encryptedStatic, err := aeadSeal(key, 0, s.staticPub[:], h[:])
	if err != nil {
		return nil, err
	}
	copy(msg[40:88], encryptedStatic)
	h = hashBytes(h[:], encryptedStatic)

	ss, err := curve25519.X25519(s.cfg.PrivateKey[:], s.cfg.PeerPublicKey[:])
	if err != nil {
		return nil, fmt.Errorf("static-static dh: %w", err)
	}
	ck, key = kdf2(ck[:], ss)
	encryptedTimestamp, err := aeadSeal(key, 0, tai64n(), h[:])
	if err != nil {
		return nil, err
	}
	copy(msg[88:116], encryptedTimestamp)
	h = hashBytes(h[:], encryptedTimestamp)

	macKey := hashBytes([]byte(labelMAC1), s.cfg.PeerPublicKey[:])
	mac := keyedBlake2s128(macKey[:], msg[:116])
	copy(msg[116:132], mac[:])

	s.chainingKey = ck
	s.handshakeHash = h
	return msg, nil
}

func (s *Session) ConsumeResponse(msg []byte) error {
	if len(msg) != responseSize {
		return fmt.Errorf("bad response size: %d", len(msg))
	}
	if binary.LittleEndian.Uint32(msg[0:4]) != messageResponse {
		return errors.New("not a response message")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	receiver := binary.LittleEndian.Uint32(msg[8:12])
	if receiver != s.localIndex {
		return fmt.Errorf("response receiver index mismatch: got %d want %d", receiver, s.localIndex)
	}

	s.remoteIndex = binary.LittleEndian.Uint32(msg[4:8])
	respEphemeral := msg[12:44]
	encryptedEmpty := msg[44:60]

	h := hashBytes(s.handshakeHash[:], respEphemeral)
	ck := kdf1(s.chainingKey[:], respEphemeral)

	ee, err := curve25519.X25519(s.ephemeralPriv[:], respEphemeral)
	if err != nil {
		return fmt.Errorf("ephemeral-ephemeral dh: %w", err)
	}
	ck, _ = kdf2(ck[:], ee)

	se, err := curve25519.X25519(s.cfg.PrivateKey[:], respEphemeral)
	if err != nil {
		return fmt.Errorf("static-ephemeral dh: %w", err)
	}
	ck, _ = kdf2(ck[:], se)

	var zeroPSK [32]byte
	ck, tau, key := kdf3(ck[:], zeroPSK[:])
	h = hashBytes(h[:], tau[:])
	if _, err := aeadOpen(key, 0, encryptedEmpty, h[:]); err != nil {
		return fmt.Errorf("response authentication failed: %w", err)
	}
	h = hashBytes(h[:], encryptedEmpty)

	send, recv := kdf2(ck[:], nil)
	sendAEAD, err := chacha20poly1305.New(send[:])
	if err != nil {
		return err
	}
	recvAEAD, err := chacha20poly1305.New(recv[:])
	if err != nil {
		return err
	}
	s.sendKey = send
	s.recvKey = recv
	s.sendAEAD = sendAEAD
	s.recvAEAD = recvAEAD
	s.sendCounter = 0
	s.replay = replayWindow{}
	s.establishedAt = time.Now()
	return nil
}

func (s *Session) EncryptKeepalive() []byte {
	return s.EncryptPacket(nil)
}

func (s *Session) EncryptPacket(packet []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	counter := s.sendCounter
	s.sendCounter++

	msg := make([]byte, 16, 16+len(packet)+chacha20poly1305.Overhead)
	binary.LittleEndian.PutUint32(msg[0:4], messageTransport)
	binary.LittleEndian.PutUint32(msg[4:8], s.remoteIndex)
	binary.LittleEndian.PutUint64(msg[8:16], counter)
	if s.sendAEAD == nil {
		panic("transport AEAD is not established")
	}
	sealed := s.sendAEAD.Seal(nil, nonce(counter), padTransportPacket(packet), nil)
	return append(msg, sealed...)
}

func (s *Session) DecryptTransport(msg []byte) ([]byte, error) {
	if len(msg) < 32 {
		return nil, fmt.Errorf("transport packet too short: %d", len(msg))
	}
	if binary.LittleEndian.Uint32(msg[0:4]) != messageTransport {
		return nil, errors.New("not a transport message")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	receiver := binary.LittleEndian.Uint32(msg[4:8])
	if receiver != s.localIndex {
		return nil, fmt.Errorf("transport receiver mismatch: got %d want %d", receiver, s.localIndex)
	}
	counter := binary.LittleEndian.Uint64(msg[8:16])
	if !s.replay.Accept(counter) {
		return nil, errors.New("replayed transport packet")
	}
	if s.recvAEAD == nil {
		return nil, errors.New("transport AEAD is not established")
	}
	plain, err := s.recvAEAD.Open(nil, nonce(counter), msg[16:], nil)
	if err != nil {
		return nil, err
	}
	return trimIPPacket(plain), nil
}

func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func hashBytes(parts ...[]byte) [32]byte {
	h, _ := blake2s.New256(nil)
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func keyedBlake2s128(key, data []byte) [16]byte {
	h, _ := blake2s.New128(key)
	_, _ = h.Write(data)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func kdf1(key, input []byte) [32]byte {
	return kdf(key, input, 1)[0]
}

func kdf2(key, input []byte) ([32]byte, [32]byte) {
	out := kdf(key, input, 2)
	return out[0], out[1]
}

func kdf3(key, input []byte) ([32]byte, [32]byte, [32]byte) {
	out := kdf(key, input, 3)
	return out[0], out[1], out[2]
}

func kdf(key, input []byte, count int) [][32]byte {
	newHash := func() hash.Hash { h, _ := blake2s.New256(nil); return h }
	mac := hmac.New(newHash, key)
	_, _ = mac.Write(input)
	prk := mac.Sum(nil)

	out := make([][32]byte, count)
	var previous []byte
	for i := 0; i < count; i++ {
		mac = hmac.New(newHash, prk)
		_, _ = mac.Write(previous)
		_, _ = mac.Write([]byte{byte(i + 1)})
		sum := mac.Sum(nil)
		copy(out[i][:], sum)
		previous = sum
	}
	return out
}

func aeadSeal(key [32]byte, counter uint64, plaintext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce(counter), plaintext, ad), nil
}

func aeadOpen(key [32]byte, counter uint64, ciphertext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce(counter), ciphertext, ad)
}

func nonce(counter uint64) []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	return nonce[:]
}

func tai64n() []byte {
	now := time.Now()
	out := make([]byte, 12)
	binary.BigEndian.PutUint64(out[0:8], uint64(now.Unix())+0x400000000000000a)
	binary.BigEndian.PutUint32(out[8:12], uint32(now.Nanosecond()))
	return out
}

func trimIPPacket(packet []byte) []byte {
	if len(packet) == 0 {
		return packet
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) >= 20 {
			total := int(binary.BigEndian.Uint16(packet[2:4]))
			if total > 0 && total <= len(packet) {
				return packet[:total]
			}
		}
	case 6:
		if len(packet) >= 40 {
			total := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
			if total <= len(packet) {
				return packet[:total]
			}
		}
	}
	return packet
}

func padTransportPacket(packet []byte) []byte {
	if len(packet) == 0 {
		return packet
	}
	pad := (16 - (len(packet) % 16)) % 16
	if pad == 0 {
		return packet
	}
	padded := make([]byte, len(packet)+pad)
	copy(padded, packet)
	return padded
}

type replayWindow struct {
	max  uint64
	seen map[uint64]struct{}
}

func (w *replayWindow) Accept(counter uint64) bool {
	if w.seen == nil {
		w.seen = map[uint64]struct{}{}
	}
	if counter+2048 < w.max {
		return false
	}
	if _, ok := w.seen[counter]; ok {
		return false
	}
	w.seen[counter] = struct{}{}
	if counter > w.max {
		w.max = counter
		cutoff := w.max - 2048
		for value := range w.seen {
			if value < cutoff {
				delete(w.seen, value)
			}
		}
	}
	return true
}
