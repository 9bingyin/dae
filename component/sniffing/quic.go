/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
)

const (
	quicFlagLongPacketType = 4
	quicFlagHeaderForm     = 7

	quicFlagHeaderFormLongHeader = 1

	maxQuicCryptoBytes = 16 << 10
	maxQuicFragments   = 64
	maxQuicCIDLength   = 20
)

type QuicSniffState uint8

const (
	QuicSniffNotApplicable QuicSniffState = iota
	QuicSniffNeedMore
	QuicSniffFound
	QuicSniffNoSNI
	QuicSniffUnsupportedVersion
	QuicSniffMalformed
	QuicSniffAmbiguousOverlap
	QuicSniffResourceLimit
)

func (s QuicSniffState) String() string {
	switch s {
	case QuicSniffNotApplicable:
		return "not_applicable"
	case QuicSniffNeedMore:
		return "need_more"
	case QuicSniffFound:
		return "found"
	case QuicSniffNoSNI:
		return "no_sni"
	case QuicSniffUnsupportedVersion:
		return "unsupported_version"
	case QuicSniffMalformed:
		return "malformed"
	case QuicSniffAmbiguousOverlap:
		return "ambiguous_overlap"
	case QuicSniffResourceLimit:
		return "resource_limit"
	default:
		return fmt.Sprintf("unknown_%d", s)
	}
}

type QuicSniffResult struct {
	State  QuicSniffState
	Domain string
	Err    error
}

type QuicSniffer struct {
	versionNumber uint32
	originalDCID  []byte
	keys          *quicutils.Keys
	reassembler   *quicutils.CryptoReassembler
	largestPN     uint64
	hasLargestPN  bool
}

func NewQuicSniffer() *QuicSniffer {
	return &QuicSniffer{
		reassembler: quicutils.NewCryptoReassembler(maxQuicCryptoBytes, maxQuicFragments),
	}
}

func (s *QuicSniffer) Close() error {
	if s == nil {
		return nil
	}
	if s.keys != nil {
		if err := s.keys.Close(); err != nil {
			return fmt.Errorf("close quic initial keys: %w", err)
		}
		s.keys = nil
	}
	s.versionNumber = 0
	s.originalDCID = nil
	s.largestPN = 0
	s.hasLargestPN = false
	s.reassembler.Reset()
	return nil
}

// Feed inspects one UDP datagram. It keeps only decrypted CRYPTO stream state;
// ownership of the datagram remains with the caller.
func (s *QuicSniffer) Feed(datagram []byte) QuicSniffResult {
	processed := false
	for offset := 0; offset < len(datagram); {
		header, err := parseInitialHeader(datagram[offset:])
		if err != nil {
			if errors.Is(err, errNotInitial) {
				if processed {
					break // A coalesced non-Initial packet follows the Initial packet.
				}
				if s.keys != nil {
					// 0-RTT and Handshake packets can arrive between fragmented
					// Initial packets. Keep the existing CRYPTO state until a later
					// Initial completes it or the hold deadline expires.
					return s.clientHelloResult()
				}
			}
			return resultForHeaderError(err)
		}

		packet := datagram[offset : offset+header.packetEnd]
		if err := s.ensureKeys(header); err != nil {
			return QuicSniffResult{State: QuicSniffMalformed, Err: err}
		}

		plaintext, packetNumber, err := s.keys.DecryptInitial(packet, header.packetNumberOffset, header.packetEnd, s.largestPN, s.hasLargestPN)
		if err != nil && header.tokenLength > 0 && !bytes.Equal(header.dcid, s.originalDCID) {
			plaintext, packetNumber, err = s.retryDecrypt(packet, header)
		}
		if err != nil {
			return QuicSniffResult{State: QuicSniffMalformed, Err: err}
		}
		if !s.hasLargestPN || packetNumber > s.largestPN {
			s.largestPN = packetNumber
			s.hasLargestPN = true
		}

		frames, err := quicutils.ExtractCryptoFrames(plaintext)
		if err != nil {
			if errors.Is(err, quicutils.ErrConnectionClose) {
				return QuicSniffResult{State: QuicSniffNoSNI, Err: err}
			}
			return QuicSniffResult{State: QuicSniffMalformed, Err: err}
		}
		for _, frame := range frames {
			if err := s.reassembler.Add(frame.Offset, frame.Data); err != nil {
				switch {
				case errors.Is(err, quicutils.ErrAmbiguousCrypto):
					return QuicSniffResult{State: QuicSniffAmbiguousOverlap, Err: err}
				case errors.Is(err, quicutils.ErrCryptoLimit):
					return QuicSniffResult{State: QuicSniffResourceLimit, Err: err}
				default:
					return QuicSniffResult{State: QuicSniffMalformed, Err: err}
				}
			}
		}

		processed = true
		offset += header.packetEnd
	}

	if !processed {
		return QuicSniffResult{State: QuicSniffNotApplicable}
	}
	return s.clientHelloResult()
}

func (s *QuicSniffer) ensureKeys(header initialHeader) error {
	if s.keys != nil {
		if header.versionNumber != s.versionNumber {
			return fmt.Errorf("quic version changed from 0x%08x to 0x%08x", s.versionNumber, header.versionNumber)
		}
		return nil
	}

	keys, err := quicutils.NewKeys(header.dcid, header.version, common.NewGcm)
	if err != nil {
		return fmt.Errorf("derive quic initial keys: %w", err)
	}
	s.keys = keys
	s.versionNumber = header.versionNumber
	s.originalDCID = slices.Clone(header.dcid)
	return nil
}

func (s *QuicSniffer) retryDecrypt(packet []byte, header initialHeader) ([]byte, uint64, error) {
	keys, err := quicutils.NewKeys(header.dcid, header.version, common.NewGcm)
	if err != nil {
		return nil, 0, fmt.Errorf("derive retry initial keys: %w", err)
	}
	plaintext, packetNumber, err := keys.DecryptInitial(packet, header.packetNumberOffset, header.packetEnd, 0, false)
	if err != nil {
		_ = keys.Close()
		return nil, 0, err
	}

	_ = s.keys.Close()
	s.keys = keys
	s.originalDCID = slices.Clone(header.dcid)
	s.reassembler.Reset()
	s.largestPN = 0
	s.hasLargestPN = false
	return plaintext, packetNumber, nil
}

func (s *QuicSniffer) clientHelloResult() QuicSniffResult {
	result := QuicSniffResult{State: QuicSniffNeedMore}
	clientHello := s.reassembler.ContiguousBytes()
	if len(clientHello) < 4 {
		return result
	}
	if clientHello[0] != HandShakeType_Hello {
		result.State = QuicSniffMalformed
		result.Err = ErrNotApplicable
		return result
	}

	handshakeLength := int(clientHello[1])<<16 | int(clientHello[2])<<8 | int(clientHello[3])
	expectedLength := 4 + handshakeLength
	if expectedLength > maxQuicCryptoBytes {
		result.State = QuicSniffResourceLimit
		result.Err = quicutils.ErrCryptoLimit
		return result
	}
	if len(clientHello) < expectedLength {
		return result
	}

	domain, err := extractSniFromTls(quicutils.BuiltinBytesLocator(clientHello[:expectedLength]))
	if err != nil {
		result.Err = err
		if errors.Is(err, ErrNotFound) {
			result.State = QuicSniffNoSNI
		} else {
			result.State = QuicSniffMalformed
		}
		return result
	}
	result.State = QuicSniffFound
	result.Domain = NormalizeDomain(domain)
	return result
}

var (
	errNotInitial         = errors.New("not a quic initial packet")
	errUnsupportedVersion = errors.New("unsupported quic version")
)

type initialHeader struct {
	versionNumber      uint32
	version            quicutils.Version
	dcid               []byte
	tokenLength        uint64
	packetNumberOffset int
	packetEnd          int
}

func IsLikelyQuicInitial(datagram []byte) bool {
	_, err := parseInitialHeader(datagram)
	return err == nil
}

func parseInitialHeader(packet []byte) (initialHeader, error) {
	const destinationConnectionIDPosition = 6
	if len(packet) < destinationConnectionIDPosition {
		return initialHeader{}, errNotInitial
	}
	firstByte := packet[0]
	if firstByte>>quicFlagHeaderForm&0b1 != quicFlagHeaderFormLongHeader {
		return initialHeader{}, errNotInitial
	}

	versionNumber := binary.BigEndian.Uint32(packet[1:5])
	version, err := quicutils.ParseVersion(versionNumber)
	if err != nil {
		return initialHeader{}, fmt.Errorf("%w: %v", errUnsupportedVersion, err)
	}
	if firstByte>>quicFlagLongPacketType&0b11 != version.InitialPacketType() {
		return initialHeader{}, errNotInitial
	}

	offset := destinationConnectionIDPosition
	dcidLength := int(packet[offset-1])
	if dcidLength > maxQuicCIDLength || dcidLength > len(packet)-offset {
		return initialHeader{}, io.ErrUnexpectedEOF
	}
	dcid := packet[offset : offset+dcidLength]
	offset += dcidLength
	if offset >= len(packet) {
		return initialHeader{}, io.ErrUnexpectedEOF
	}

	scidLength := int(packet[offset])
	offset++
	if scidLength > maxQuicCIDLength || scidLength > len(packet)-offset {
		return initialHeader{}, io.ErrUnexpectedEOF
	}
	offset += scidLength

	tokenLength, n, err := quicutils.BigEndianUvarint(packet[offset:])
	if err != nil {
		return initialHeader{}, fmt.Errorf("read initial token length: %w", err)
	}
	offset += n
	if tokenLength > uint64(len(packet)-offset) {
		return initialHeader{}, io.ErrUnexpectedEOF
	}
	offset += int(tokenLength)

	length, n, err := quicutils.BigEndianUvarint(packet[offset:])
	if err != nil {
		return initialHeader{}, fmt.Errorf("read initial packet length: %w", err)
	}
	offset += n
	if length > uint64(len(packet)-offset) {
		return initialHeader{}, io.ErrUnexpectedEOF
	}
	packetEnd := offset + int(length)
	if length < 1 || offset+quicutils.MaxPacketNumberLength+quicutils.SampleSize > packetEnd {
		return initialHeader{}, io.ErrUnexpectedEOF
	}

	return initialHeader{
		versionNumber:      versionNumber,
		version:            version,
		dcid:               dcid,
		tokenLength:        tokenLength,
		packetNumberOffset: offset,
		packetEnd:          packetEnd,
	}, nil
}

func resultForHeaderError(err error) QuicSniffResult {
	switch {
	case errors.Is(err, errNotInitial):
		return QuicSniffResult{State: QuicSniffNotApplicable, Err: err}
	case errors.Is(err, errUnsupportedVersion):
		return QuicSniffResult{State: QuicSniffUnsupportedVersion, Err: err}
	default:
		return QuicSniffResult{State: QuicSniffMalformed, Err: err}
	}
}
