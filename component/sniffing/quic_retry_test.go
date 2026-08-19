/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/hkdf"
)

func TestQuicSnifferDecryptsLaterInitialWithOriginalDCID(t *testing.T) {
	clientHello := testClientHello("example.com")
	firstDCID := []byte("firstcid")
	secondDCID := []byte("secondid")
	first := buildTestInitial(t, quicutils.Version_V1, firstDCID, firstDCID, nil, 0, 0, clientHello[:32])
	second := buildTestInitial(t, quicutils.Version_V1, secondDCID, firstDCID, nil, 1, 32, clientHello[32:])

	sniffer := NewQuicSniffer()
	t.Cleanup(func() { _ = sniffer.Close() })
	if result := sniffer.Feed(first); result.State != QuicSniffNeedMore {
		t.Fatalf("first state = %v: %v", result.State, result.Err)
	}
	if result := sniffer.Feed([]byte{0x40, 0, 0, 0, 0, 0}); result.State != QuicSniffNeedMore {
		t.Fatalf("interleaved non-Initial state = %v: %v", result.State, result.Err)
	}
	result := sniffer.Feed(second)
	if result.State != QuicSniffFound || result.Domain != "example.com" {
		t.Fatalf("second result = %+v", result)
	}
}

func TestQuicSnifferResetsKeysAfterRetry(t *testing.T) {
	clientHello := testClientHello("example.com")
	firstDCID := []byte("firstcid")
	retryDCID := []byte("retrycid")
	first := buildTestInitial(t, quicutils.Version_V1, firstDCID, firstDCID, nil, 0, 0, clientHello[:32])
	// A token-bearing Initial after Retry derives new Initial keys from the
	// server-selected DCID and retransmits the ClientHello from offset zero.
	second := buildTestInitial(t, quicutils.Version_V1, retryDCID, retryDCID, []byte{1}, 0, 0, clientHello)

	sniffer := NewQuicSniffer()
	t.Cleanup(func() { _ = sniffer.Close() })
	if result := sniffer.Feed(first); result.State != QuicSniffNeedMore {
		t.Fatalf("first state = %v: %v", result.State, result.Err)
	}
	result := sniffer.Feed(second)
	if result.State != QuicSniffFound || result.Domain != "example.com" {
		t.Fatalf("retry result = %+v", result)
	}
	if got := string(sniffer.originalDCID); got != string(retryDCID) {
		t.Fatalf("original DCID after Retry = %q, want %q", got, retryDCID)
	}
}

func testClientHello(domain string) []byte {
	return testClientHelloWithPadding(domain, 0)
}

func testClientHelloWithPadding(domain string, padding int) []byte {
	serverName := []byte(domain)
	serverNameListLength := 1 + 2 + len(serverName)
	serverNameExtensionLength := 2 + serverNameListLength
	extensionsLength := 0
	if domain != "" {
		extensionsLength = 4 + serverNameExtensionLength
	}
	if padding > 0 {
		extensionsLength += 4 + padding
	}
	bodyLength := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensionsLength

	hello := make([]byte, 4+bodyLength)
	hello[0] = HandShakeType_Hello
	hello[1] = byte(bodyLength >> 16)
	hello[2] = byte(bodyLength >> 8)
	hello[3] = byte(bodyLength)
	offset := 4
	copy(hello[offset:], []byte{0x03, 0x03})
	offset += 2 + 32
	hello[offset] = 0 // Session ID length.
	offset++
	binary.BigEndian.PutUint16(hello[offset:], 2)
	offset += 2
	copy(hello[offset:], []byte{0x13, 0x01})
	offset += 2
	hello[offset] = 1
	hello[offset+1] = 0
	offset += 2
	binary.BigEndian.PutUint16(hello[offset:], uint16(extensionsLength))
	offset += 2
	if domain != "" {
		binary.BigEndian.PutUint16(hello[offset:], TlsExtension_ServerName)
		binary.BigEndian.PutUint16(hello[offset+2:], uint16(serverNameExtensionLength))
		offset += 4
		binary.BigEndian.PutUint16(hello[offset:], uint16(serverNameListLength))
		offset += 2
		hello[offset] = TlsExtension_ServerNameType_HostName
		binary.BigEndian.PutUint16(hello[offset+1:], uint16(len(serverName)))
		copy(hello[offset+3:], serverName)
		offset += 3 + len(serverName)
	}
	if padding > 0 {
		binary.BigEndian.PutUint16(hello[offset:], 21) // padding extension
		binary.BigEndian.PutUint16(hello[offset+2:], uint16(padding))
	}
	return hello
}

func buildTestInitial(t testing.TB, version quicutils.Version, headerDCID, keyDCID, token []byte, packetNumber byte, cryptoOffset uint64, cryptoData []byte) []byte {
	t.Helper()
	wireVersion := quicutils.VersionNumberV1
	if version == quicutils.Version_V2 {
		wireVersion = quicutils.VersionNumberV2
	}

	plaintext := []byte{quicutils.FrameTypeCrypto}
	plaintext = appendQuicVarint(plaintext, cryptoOffset)
	plaintext = appendQuicVarint(plaintext, uint64(len(cryptoData)))
	plaintext = append(plaintext, cryptoData...)

	firstByte := byte(0xc0 | version.InitialPacketType()<<4)
	header := []byte{firstByte, 0, 0, 0, 0, byte(len(headerDCID))}
	binary.BigEndian.PutUint32(header[1:5], wireVersion)
	header = append(header, headerDCID...)
	header = append(header, 0) // Source Connection ID length.
	header = appendQuicVarint(header, uint64(len(token)))
	header = append(header, token...)
	length := 1 + len(plaintext) + 16 // Packet number plus AEAD tag.
	header = appendQuicVarint(header, uint64(length))
	packetNumberOffset := len(header)
	header = append(header, packetNumber)

	key, iv, hp := testInitialKeys(t, version, keyDCID)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := append([]byte(nil), iv...)
	nonce[len(nonce)-1] ^= packetNumber
	packet := append([]byte(nil), header...)
	packet = aead.Seal(packet, nonce, plaintext, header)

	sampleStart := packetNumberOffset + quicutils.MaxPacketNumberLength
	var mask [aes.BlockSize]byte
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	hpBlock.Encrypt(mask[:], packet[sampleStart:sampleStart+quicutils.SampleSize])
	packet[0] ^= mask[0] & 0x0f
	packet[packetNumberOffset] ^= mask[1]
	return packet
}

func testInitialKeys(t testing.TB, version quicutils.Version, dcid []byte) (key, iv, hp []byte) {
	t.Helper()
	initialSecret := hkdf.Extract(sha256.New, dcid, version.InitialSalt())
	clientSecret, err := quicutils.HkdfExpandLabelFromPool(sha256.New, initialSecret, []byte("client in"), nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Put(clientSecret)
	key, err = quicutils.HkdfExpandLabelFromPool(sha256.New, clientSecret, version.KeyLabel(), nil, 16)
	if err != nil {
		t.Fatal(err)
	}
	iv, err = quicutils.HkdfExpandLabelFromPool(sha256.New, clientSecret, version.IvLabel(), nil, 12)
	if err != nil {
		pool.Put(key)
		t.Fatal(err)
	}
	hp, err = quicutils.HkdfExpandLabelFromPool(sha256.New, clientSecret, version.HpLabel(), nil, 16)
	if err != nil {
		pool.Put(key)
		pool.Put(iv)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Put(key)
		pool.Put(iv)
		pool.Put(hp)
	})
	return key, iv, hp
}

func appendQuicVarint(dst []byte, value uint64) []byte {
	if value < 1<<6 {
		return append(dst, byte(value))
	}
	if value < 1<<14 {
		return append(dst, byte(value>>8)|0x40, byte(value))
	}
	panic("test QUIC varint is too large")
}
