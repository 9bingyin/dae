/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/hkdf"
)

const (
	MaxVarintLen64 = 8

	MaxPacketNumberLength = 4
	SampleSize            = 16
	maxPacketNumber       = uint64(1)<<62 - 1
)

var InitialClientLabel = []byte("client in")

type Keys struct {
	version             Version
	clientInitialSecret []byte
	key                 []byte
	iv                  []byte
	headerProtectionKey []byte
	newAead             func(key []byte) (cipher.AEAD, error)
}

func (k *Keys) Close() error {
	if k == nil {
		return nil
	}
	pool.Put(k.clientInitialSecret)
	pool.Put(k.headerProtectionKey)
	pool.Put(k.iv)
	pool.Put(k.key)
	k.clientInitialSecret = nil
	k.headerProtectionKey = nil
	k.iv = nil
	k.key = nil
	return nil
}

func NewKeys(clientDstConnectionID []byte, version Version, newAead func(key []byte) (cipher.AEAD, error)) (*Keys, error) {
	// RFC 9001 Section 5.2 derives Initial secrets from the Destination
	// Connection ID in the client's first Initial packet.
	initialSecret := hkdf.Extract(sha256.New, clientDstConnectionID, version.InitialSalt())
	clientInitialSecret, err := HkdfExpandLabelFromPool(sha256.New, initialSecret, InitialClientLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("expand client initial secret: %w", err)
	}

	keys := &Keys{
		clientInitialSecret: clientInitialSecret,
		version:             version,
		newAead:             newAead,
	}
	if err := keys.deriveKeys(); err != nil {
		_ = keys.Close()
		return nil, err
	}
	return keys, nil
}

func (k *Keys) deriveKeys() error {
	var err error
	k.key, err = HkdfExpandLabelFromPool(sha256.New, k.clientInitialSecret, k.version.KeyLabel(), nil, 16)
	if err != nil {
		return fmt.Errorf("expand packet protection key: %w", err)
	}
	k.iv, err = HkdfExpandLabelFromPool(sha256.New, k.clientInitialSecret, k.version.IvLabel(), nil, 12)
	if err != nil {
		return fmt.Errorf("expand packet protection iv: %w", err)
	}
	k.headerProtectionKey, err = HkdfExpandLabelFromPool(sha256.New, k.clientInitialSecret, k.version.HpLabel(), nil, 16)
	if err != nil {
		return fmt.Errorf("expand header protection key: %w", err)
	}
	return nil
}

// HeaderProtection_ removes QUIC header protection in place. It is kept as a
// small primitive for RFC test vectors; production parsing uses DecryptInitial.
func (k *Keys) HeaderProtection_(sample []byte, longHeader bool, firstByte *byte, potentialPacketNumber []byte) ([]byte, error) {
	if len(sample) < SampleSize || len(potentialPacketNumber) < MaxPacketNumberLength {
		return nil, io.ErrUnexpectedEOF
	}
	block, err := aes.NewCipher(k.headerProtectionKey)
	if err != nil {
		return nil, fmt.Errorf("create header protection cipher: %w", err)
	}
	var mask [aes.BlockSize]byte
	block.Encrypt(mask[:], sample[:SampleSize])
	if longHeader {
		*firstByte ^= mask[0] & 0x0f
	} else {
		*firstByte ^= mask[0] & 0x1f
	}
	packetNumberLength := int(*firstByte&0b11) + 1
	packetNumber := potentialPacketNumber[:packetNumberLength]
	for i := range packetNumber {
		packetNumber[i] ^= mask[1+i]
	}
	return packetNumber, nil
}

// PayloadDecrypt decrypts a payload for RFC test vectors. packetNumber must
// contain the full packet number in network byte order.
func (k *Keys) PayloadDecrypt(ciphertext, packetNumber, header []byte) ([]byte, error) {
	aead, err := k.newAead(k.key)
	if err != nil {
		return nil, fmt.Errorf("create packet protection cipher: %w", err)
	}
	if len(ciphertext) < aead.Overhead() || len(packetNumber) > 8 {
		return nil, io.ErrUnexpectedEOF
	}
	var number uint64
	for _, b := range packetNumber {
		number = number<<8 | uint64(b)
	}
	nonce := make([]byte, len(k.iv))
	copy(nonce, k.iv)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], number)
	for i := range encoded {
		nonce[len(nonce)-len(encoded)+i] ^= encoded[i]
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plaintext, nil
}

// DecryptInitial decrypts one client Initial packet. packetNumberOffset points
// to the first protected packet-number byte, and packetEnd is the end selected
// by the QUIC Length field. RFC 9001 Sections 5.3 and 5.4 define the nonce and
// header-protection operations.
func (k *Keys) DecryptInitial(packet []byte, packetNumberOffset, packetEnd int, largestPacketNumber uint64, hasLargest bool) ([]byte, uint64, error) {
	if packetNumberOffset < 0 || packetEnd > len(packet) || packetNumberOffset >= packetEnd {
		return nil, 0, io.ErrUnexpectedEOF
	}

	sampleStart := packetNumberOffset + MaxPacketNumberLength
	if sampleStart > packetEnd || packetEnd-sampleStart < SampleSize {
		return nil, 0, io.ErrUnexpectedEOF
	}

	block, err := aes.NewCipher(k.headerProtectionKey)
	if err != nil {
		return nil, 0, fmt.Errorf("create header protection cipher: %w", err)
	}
	var mask [aes.BlockSize]byte
	block.Encrypt(mask[:], packet[sampleStart:sampleStart+SampleSize])

	firstByte := packet[0] ^ mask[0]&0x0f
	packetNumberLength := int(firstByte&0b11) + 1
	if packetNumberOffset+packetNumberLength > packetEnd {
		return nil, 0, io.ErrUnexpectedEOF
	}

	var truncatedPacketNumber uint64
	for i := 0; i < packetNumberLength; i++ {
		truncatedPacketNumber = truncatedPacketNumber<<8 | uint64(packet[packetNumberOffset+i]^mask[1+i])
	}
	packetNumber := decodePacketNumber(largestPacketNumber, hasLargest, truncatedPacketNumber, packetNumberLength)

	headerLength := packetNumberOffset + packetNumberLength
	header := make([]byte, headerLength)
	copy(header, packet[:headerLength])
	header[0] = firstByte
	for i := 0; i < packetNumberLength; i++ {
		shift := 8 * (packetNumberLength - 1 - i)
		header[packetNumberOffset+i] = byte(packetNumber >> shift)
	}

	aead, err := k.newAead(k.key)
	if err != nil {
		return nil, 0, fmt.Errorf("create packet protection cipher: %w", err)
	}
	ciphertext := packet[headerLength:packetEnd]
	if len(ciphertext) < aead.Overhead() {
		return nil, 0, io.ErrUnexpectedEOF
	}

	nonce := make([]byte, len(k.iv))
	copy(nonce, k.iv)
	var encodedPacketNumber [8]byte
	binary.BigEndian.PutUint64(encodedPacketNumber[:], packetNumber)
	for i := range encodedPacketNumber {
		nonce[len(nonce)-len(encodedPacketNumber)+i] ^= encodedPacketNumber[i]
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, 0, fmt.Errorf("decrypt initial payload: %w", err)
	}
	return plaintext, packetNumber, nil
}

// decodePacketNumber implements RFC 9000 Appendix A.3.
func decodePacketNumber(largest uint64, hasLargest bool, truncated uint64, packetNumberLength int) uint64 {
	var expected uint64
	if hasLargest {
		expected = largest + 1
	}

	packetNumberBits := uint(packetNumberLength * 8)
	packetNumberWindow := uint64(1) << packetNumberBits
	packetNumberHalfWindow := packetNumberWindow / 2
	packetNumberMask := packetNumberWindow - 1
	candidate := expected&^packetNumberMask | truncated

	if candidate <= maxPacketNumber-packetNumberWindow && candidate+packetNumberHalfWindow <= expected {
		return candidate + packetNumberWindow
	}
	if candidate > expected+packetNumberHalfWindow && candidate >= packetNumberWindow {
		return candidate - packetNumberWindow
	}
	return candidate
}
