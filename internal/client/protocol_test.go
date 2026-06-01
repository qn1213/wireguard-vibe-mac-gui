package client

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/curve25519"

	"wireguardc/internal/config"
)

func TestInitiatorConsumesSyntheticResponse(t *testing.T) {
	clientPriv := mustPrivate(t)
	serverPriv := mustPrivate(t)
	serverPub := mustPublic(t, serverPriv)

	cfg := config.Config{
		PrivateKey:          clientPriv,
		PeerPublicKey:       serverPub,
		PresharedKey:        mustPrivate(t),
		Address:             "10.66.66.2/24",
		DNS:                 "1.1.1.1",
		Endpoint:            "127.0.0.1:51820",
		AllowedIPs:          "0.0.0.0/0",
		PersistentKeepalive: 25,
		MTU:                 1420,
	}

	initiator := NewSession(cfg)
	initiation, err := initiator.CreateInitiation()
	if err != nil {
		t.Fatal(err)
	}

	response, responderSend, responderRecv := syntheticResponse(t, serverPriv, cfg.PresharedKey, initiation)
	if err := initiator.ConsumeResponse(response); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 66, 66, 2, 1, 1, 1, 1}
	encrypted := initiator.EncryptPacket(plaintext)

	receiver := binary.LittleEndian.Uint32(encrypted[4:8])
	if receiver != binary.LittleEndian.Uint32(response[4:8]) {
		t.Fatalf("receiver index = %d, want responder index", receiver)
	}
	counter := binary.LittleEndian.Uint64(encrypted[8:16])
	decrypted, err := aeadOpen(responderRecv, counter, encrypted[16:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted)%16 != 0 {
		t.Fatalf("transport plaintext is not padded to 16 bytes: %d", len(decrypted))
	}
	if !bytes.Equal(trimIPPacket(decrypted), plaintext) {
		t.Fatalf("transport decrypt mismatch")
	}

	reply := make([]byte, 16)
	binary.LittleEndian.PutUint32(reply[0:4], messageTransport)
	binary.LittleEndian.PutUint32(reply[4:8], initiator.localIndex)
	binary.LittleEndian.PutUint64(reply[8:16], 0)
	sealed, err := aeadSeal(responderSend, 0, plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	reply = append(reply, sealed...)
	got, err := initiator.DecryptTransport(reply)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("reply decrypt mismatch")
	}
}

func BenchmarkHandshakeSynthetic(b *testing.B) {
	clientPriv := mustPrivate(b)
	serverPriv := mustPrivate(b)
	serverPub := mustPublic(b, serverPriv)
	cfg := config.Config{
		PrivateKey:          clientPriv,
		PeerPublicKey:       serverPub,
		Address:             "10.66.66.2/24",
		DNS:                 "1.1.1.1",
		Endpoint:            "127.0.0.1:51820",
		AllowedIPs:          "0.0.0.0/0",
		PersistentKeepalive: 25,
		MTU:                 1420,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		initiator := NewSession(cfg)
		initiation, err := initiator.CreateInitiation()
		if err != nil {
			b.Fatal(err)
		}
		response, _, _ := syntheticResponse(b, serverPriv, cfg.PresharedKey, initiation)
		if err := initiator.ConsumeResponse(response); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTransportEncrypt1280(b *testing.B) {
	clientPriv := mustPrivate(b)
	serverPriv := mustPrivate(b)
	serverPub := mustPublic(b, serverPriv)
	cfg := config.Config{
		PrivateKey:          clientPriv,
		PeerPublicKey:       serverPub,
		Address:             "10.66.66.2/24",
		DNS:                 "1.1.1.1",
		Endpoint:            "127.0.0.1:51820",
		AllowedIPs:          "0.0.0.0/0",
		PersistentKeepalive: 25,
		MTU:                 1420,
	}
	initiator := NewSession(cfg)
	initiation, err := initiator.CreateInitiation()
	if err != nil {
		b.Fatal(err)
	}
	response, _, _ := syntheticResponse(b, serverPriv, cfg.PresharedKey, initiation)
	if err := initiator.ConsumeResponse(response); err != nil {
		b.Fatal(err)
	}

	packet := make([]byte, 1280)
	packet[0] = 0x45
	packet[2] = 0x05
	packet[3] = 0x00

	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = initiator.EncryptPacket(packet)
	}
}

func syntheticResponse(t testing.TB, serverPriv [32]byte, psk [32]byte, msg []byte) ([]byte, [32]byte, [32]byte) {
	t.Helper()
	if len(msg) != initiationSize {
		t.Fatalf("bad initiation size: %d", len(msg))
	}

	serverPub := mustPublic(t, serverPriv)
	ck := hashBytes([]byte(noiseConstruction))
	h := hashBytes(ck[:], []byte(wireGuardID))
	h = hashBytes(h[:], serverPub[:])

	initiatorIndex := binary.LittleEndian.Uint32(msg[4:8])
	initiatorEphemeral := msg[8:40]
	encryptedStatic := msg[40:88]
	encryptedTimestamp := msg[88:116]

	ck = kdf1(ck[:], initiatorEphemeral)
	h = hashBytes(h[:], initiatorEphemeral)

	es, err := curve25519.X25519(serverPriv[:], initiatorEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	ck, key = kdf2(ck[:], es)
	initiatorPubBytes, err := aeadOpen(key, 0, encryptedStatic, h[:])
	if err != nil {
		t.Fatal(err)
	}
	var initiatorPub [32]byte
	copy(initiatorPub[:], initiatorPubBytes)
	h = hashBytes(h[:], encryptedStatic)

	ss, err := curve25519.X25519(serverPriv[:], initiatorPub[:])
	if err != nil {
		t.Fatal(err)
	}
	ck, key = kdf2(ck[:], ss)
	if _, err := aeadOpen(key, 0, encryptedTimestamp, h[:]); err != nil {
		t.Fatal(err)
	}
	h = hashBytes(h[:], encryptedTimestamp)

	var responderEphemeralPriv [32]byte
	if _, err := rand.Read(responderEphemeralPriv[:]); err != nil {
		t.Fatal(err)
	}
	responderEphemeral, err := curve25519.X25519(responderEphemeralPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}

	response := make([]byte, responseSize)
	binary.LittleEndian.PutUint32(response[0:4], messageResponse)
	binary.LittleEndian.PutUint32(response[4:8], 777)
	binary.LittleEndian.PutUint32(response[8:12], initiatorIndex)
	copy(response[12:44], responderEphemeral)

	ck = kdf1(ck[:], responderEphemeral)
	h = hashBytes(h[:], responderEphemeral)

	ee, err := curve25519.X25519(responderEphemeralPriv[:], initiatorEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	ck, _ = kdf2(ck[:], ee)

	se, err := curve25519.X25519(responderEphemeralPriv[:], initiatorPub[:])
	if err != nil {
		t.Fatal(err)
	}
	ck, _ = kdf2(ck[:], se)

	ck, tau, key := kdf3(ck[:], psk[:])
	h = hashBytes(h[:], tau[:])
	empty, err := aeadSeal(key, 0, nil, h[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(response[44:60], empty)
	h = hashBytes(h[:], empty)

	macKey := hashBytes([]byte(labelMAC1), initiatorPub[:])
	mac := keyedBlake2s128(macKey[:], response[:60])
	copy(response[60:76], mac[:])

	responderRecv, responderSend := kdf2(ck[:], nil)
	return response, responderSend, responderRecv
}

func mustPrivate(t testing.TB) [32]byte {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return key
}

func mustPublic(t testing.TB, private [32]byte) [32]byte {
	t.Helper()
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], pub)
	return out
}
