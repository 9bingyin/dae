/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package quicutils

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
)

var (
	ErrAmbiguousCrypto  = errors.New("conflicting crypto data")
	ErrCryptoLimit      = errors.New("crypto reassembly limit exceeded")
	ErrConnectionClose  = errors.New("quic connection closed")
	ErrUnknownFrameType = errors.New("unknown frame type")
)

const (
	FrameTypePadding          = 0x00
	FrameTypePing             = 0x01
	FrameTypeAck              = 0x02
	FrameTypeAckECN           = 0x03
	FrameTypeCrypto           = 0x06
	FrameTypeConnectionClose  = 0x1c
	FrameTypeApplicationClose = 0x1d
)

type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

// ExtractCryptoFrames parses frames allowed in Initial packets. RFC 9000
// Section 12.4 permits PADDING, PING, ACK, CRYPTO, and CONNECTION_CLOSE at the
// Initial encryption level.
func ExtractCryptoFrames(payload []byte) ([]CryptoFrame, error) {
	frames := make([]CryptoFrame, 0, 2)
	for len(payload) > 0 {
		frameType, n, err := BigEndianUvarint(payload)
		if err != nil {
			return nil, fmt.Errorf("read frame type: %w", err)
		}
		payload = payload[n:]

		switch frameType {
		case FrameTypePadding, FrameTypePing:
			continue
		case FrameTypeAck, FrameTypeAckECN:
			var err error
			payload, err = skipAckFrame(payload, frameType == FrameTypeAckECN)
			if err != nil {
				return nil, err
			}
		case FrameTypeCrypto:
			offset, n, err := BigEndianUvarint(payload)
			if err != nil {
				return nil, fmt.Errorf("read crypto offset: %w", err)
			}
			payload = payload[n:]

			length, n, err := BigEndianUvarint(payload)
			if err != nil {
				return nil, fmt.Errorf("read crypto length: %w", err)
			}
			payload = payload[n:]
			if length > uint64(len(payload)) {
				return nil, fmt.Errorf("crypto data: %w", io.ErrUnexpectedEOF)
			}
			frames = append(frames, CryptoFrame{Offset: offset, Data: payload[:int(length)]})
			payload = payload[int(length):]
		case FrameTypeConnectionClose:
			var err error
			payload, err = skipVarints(payload, 2)
			if err != nil {
				return nil, fmt.Errorf("read transport close: %w", err)
			}
			payload, err = skipLengthPrefixed(payload)
			if err != nil {
				return nil, fmt.Errorf("read transport close reason: %w", err)
			}
			return nil, ErrConnectionClose
		case FrameTypeApplicationClose:
			var err error
			payload, err = skipVarints(payload, 1)
			if err != nil {
				return nil, fmt.Errorf("read application close: %w", err)
			}
			payload, err = skipLengthPrefixed(payload)
			if err != nil {
				return nil, fmt.Errorf("read application close reason: %w", err)
			}
			return nil, ErrConnectionClose
		default:
			return nil, fmt.Errorf("%w: 0x%x", ErrUnknownFrameType, frameType)
		}
	}
	return frames, nil
}

func skipAckFrame(payload []byte, ecn bool) ([]byte, error) {
	var err error
	var rangeCount uint64

	payload, err = skipVarints(payload, 2) // Largest Acknowledged, ACK Delay.
	if err != nil {
		return nil, fmt.Errorf("read ack header: %w", err)
	}
	rangeCount, payload, err = consumeVarint(payload)
	if err != nil {
		return nil, fmt.Errorf("read ack range count: %w", err)
	}
	payload, err = skipVarints(payload, 1) // First ACK Range.
	if err != nil {
		return nil, fmt.Errorf("read first ack range: %w", err)
	}
	if rangeCount > uint64(len(payload))/2 {
		return nil, fmt.Errorf("ack ranges: %w", io.ErrUnexpectedEOF)
	}
	payload, err = skipVarints(payload, int(rangeCount)*2) // Gap and ACK Range.
	if err != nil {
		return nil, fmt.Errorf("read ack ranges: %w", err)
	}
	if ecn {
		payload, err = skipVarints(payload, 3)
		if err != nil {
			return nil, fmt.Errorf("read ack ecn counts: %w", err)
		}
	}
	return payload, nil
}

func consumeVarint(payload []byte) (uint64, []byte, error) {
	value, n, err := BigEndianUvarint(payload)
	if err != nil {
		return 0, nil, err
	}
	return value, payload[n:], nil
}

func skipVarints(payload []byte, count int) ([]byte, error) {
	for range count {
		_, rest, err := consumeVarint(payload)
		if err != nil {
			return nil, err
		}
		payload = rest
	}
	return payload, nil
}

func skipLengthPrefixed(payload []byte) ([]byte, error) {
	length, rest, err := consumeVarint(payload)
	if err != nil {
		return nil, err
	}
	if length > uint64(len(rest)) {
		return nil, io.ErrUnexpectedEOF
	}
	return rest[int(length):], nil
}

type cryptoSegment struct {
	offset uint64
	data   []byte
}

type CryptoReassembler struct {
	segments     []cryptoSegment
	maxBytes     int
	maxFragments int
	fragments    int
}

func NewCryptoReassembler(maxBytes, maxFragments int) *CryptoReassembler {
	return &CryptoReassembler{maxBytes: maxBytes, maxFragments: maxFragments}
}

func (r *CryptoReassembler) Reset() {
	r.segments = nil
	r.fragments = 0
}

func (r *CryptoReassembler) Add(offset uint64, data []byte) error {
	r.fragments++
	if r.fragments > r.maxFragments {
		return ErrCryptoLimit
	}
	if len(data) == 0 {
		return nil
	}
	if offset > uint64(r.maxBytes) || uint64(len(data)) > uint64(r.maxBytes)-offset {
		return ErrCryptoLimit
	}
	for _, segment := range r.segments {
		if segment.offset == offset && bytes.Equal(segment.data, data) {
			return nil
		}
	}

	merged := cryptoSegment{offset: offset, data: slices.Clone(data)}
	out := make([]cryptoSegment, 0, len(r.segments)+1)
	inserted := false

	for _, current := range r.segments {
		if segmentEnd(current) < merged.offset {
			out = append(out, current)
			continue
		}
		if segmentEnd(merged) < current.offset {
			if !inserted {
				out = append(out, merged)
				inserted = true
			}
			out = append(out, current)
			continue
		}

		var err error
		merged, err = mergeCryptoSegments(current, merged)
		if err != nil {
			return err
		}
	}
	if !inserted {
		out = append(out, merged)
	}

	total := 0
	for _, segment := range out {
		total += len(segment.data)
	}
	if total > r.maxBytes {
		return ErrCryptoLimit
	}
	r.segments = out
	return nil
}

func (r *CryptoReassembler) ContiguousBytes() []byte {
	if len(r.segments) == 0 || r.segments[0].offset != 0 {
		return nil
	}
	return r.segments[0].data
}

func segmentEnd(segment cryptoSegment) uint64 {
	return segment.offset + uint64(len(segment.data))
}

func mergeCryptoSegments(a, b cryptoSegment) (cryptoSegment, error) {
	start := min(a.offset, b.offset)
	end := max(segmentEnd(a), segmentEnd(b))
	data := make([]byte, int(end-start))
	copy(data[a.offset-start:], a.data)

	overlapStart := max(a.offset, b.offset)
	overlapEnd := min(segmentEnd(a), segmentEnd(b))
	if overlapStart < overlapEnd {
		aStart := overlapStart - a.offset
		bStart := overlapStart - b.offset
		length := overlapEnd - overlapStart
		if !bytes.Equal(a.data[aStart:aStart+length], b.data[bStart:bStart+length]) {
			return cryptoSegment{}, ErrAmbiguousCrypto
		}
	}
	copy(data[b.offset-start:], b.data)
	return cryptoSegment{offset: start, data: data}, nil
}
