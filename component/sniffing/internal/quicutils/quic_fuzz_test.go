/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package quicutils

import "testing"

func FuzzBigEndianUvarint(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{0x40, 0x25})
	f.Add([]byte{0xc0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = BigEndianUvarint(data)
	})
}

func FuzzExtractCryptoFrames(f *testing.F) {
	f.Add([]byte{FrameTypeCrypto, 0, 3, 'a', 'b', 'c'})
	f.Add([]byte{FrameTypeAck, 0, 0, 0, 0})
	f.Add([]byte{FrameTypeCrypto, 0, 4, 'a'})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ExtractCryptoFrames(payload)
	})
}

func FuzzCryptoReassembler(f *testing.F) {
	f.Add(uint64(0), []byte("client hello"))
	f.Add(uint64(3), []byte("fragment"))
	f.Fuzz(func(t *testing.T, offset uint64, data []byte) {
		reassembler := NewCryptoReassembler(256, 8)
		_ = reassembler.Add(offset, data)
		_ = reassembler.ContiguousBytes()
	})
}
