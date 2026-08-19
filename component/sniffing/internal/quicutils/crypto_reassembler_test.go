/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package quicutils

import (
	"errors"
	"testing"
)

func TestCryptoReassembler(t *testing.T) {
	tests := []struct {
		name    string
		frames  []CryptoFrame
		want    string
		wantErr error
	}{
		{
			name: "ordered adjacent",
			frames: []CryptoFrame{
				{Offset: 0, Data: []byte("abc")},
				{Offset: 3, Data: []byte("def")},
			},
			want: "abcdef",
		},
		{
			name: "out of order",
			frames: []CryptoFrame{
				{Offset: 3, Data: []byte("def")},
				{Offset: 0, Data: []byte("abc")},
			},
			want: "abcdef",
		},
		{
			name: "duplicate",
			frames: []CryptoFrame{
				{Offset: 0, Data: []byte("abc")},
				{Offset: 0, Data: []byte("abc")},
			},
			want: "abc",
		},
		{
			name: "consistent overlap",
			frames: []CryptoFrame{
				{Offset: 0, Data: []byte("abcd")},
				{Offset: 2, Data: []byte("cdef")},
			},
			want: "abcdef",
		},
		{
			name: "gap",
			frames: []CryptoFrame{
				{Offset: 0, Data: []byte("abc")},
				{Offset: 4, Data: []byte("ef")},
			},
			want: "abc",
		},
		{
			name: "conflicting overlap",
			frames: []CryptoFrame{
				{Offset: 0, Data: []byte("abcd")},
				{Offset: 2, Data: []byte("XX")},
			},
			wantErr: ErrAmbiguousCrypto,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reassembler := NewCryptoReassembler(64, 8)
			for _, frame := range test.frames {
				err := reassembler.Add(frame.Offset, frame.Data)
				if err != nil {
					if errors.Is(err, test.wantErr) {
						return
					}
					t.Fatalf("error = %v, want %v", err, test.wantErr)
				}
			}
			if test.wantErr != nil {
				t.Fatalf("error = nil, want %v", test.wantErr)
			}
			if got := string(reassembler.ContiguousBytes()); got != test.want {
				t.Fatalf("contiguous bytes = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCryptoReassemblerLimits(t *testing.T) {
	reassembler := NewCryptoReassembler(4, 2)
	if err := reassembler.Add(0, []byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if err := reassembler.Add(4, []byte("e")); !errors.Is(err, ErrCryptoLimit) {
		t.Fatalf("byte limit error = %v", err)
	}

	reassembler.Reset()
	if err := reassembler.Add(0, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := reassembler.Add(1, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if err := reassembler.Add(2, []byte("c")); !errors.Is(err, ErrCryptoLimit) {
		t.Fatalf("fragment limit error = %v", err)
	}
}

func TestExtractCryptoFrames(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		wantErr error
	}{
		{
			name: "ack and crypto",
			payload: []byte{
				FrameTypePadding,
				FrameTypePing,
				FrameTypeAck,
				0, 0, 0, 0, // Largest, delay, range count, first range.
				FrameTypeCrypto,
				0, 3, 'a', 'b', 'c', // Offset, length, data.
			},
		},
		{
			name: "ack ecn and crypto",
			payload: []byte{
				FrameTypeAckECN,
				0, 0, 0, 0, // ACK fields.
				0, 0, 0, // ECT(0), ECT(1), CE counts.
				FrameTypeCrypto,
				0, 3, 'a', 'b', 'c',
			},
		},
		{name: "transport close", payload: []byte{FrameTypeConnectionClose, 0, 0, 0}, wantErr: ErrConnectionClose},
		{name: "application close", payload: []byte{FrameTypeApplicationClose, 0, 0}, wantErr: ErrConnectionClose},
		{name: "unknown frame", payload: []byte{0x04}, wantErr: ErrUnknownFrameType},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frames, err := ExtractCryptoFrames(test.payload)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && (len(frames) != 1 || frames[0].Offset != 0 || string(frames[0].Data) != "abc") {
				t.Fatalf("frames = %+v", frames)
			}
		})
	}
}

func TestExtractCryptoFramesRejectsTruncatedData(t *testing.T) {
	_, err := ExtractCryptoFrames([]byte{FrameTypeCrypto, 0, 4, 'a'})
	if err == nil {
		t.Fatal("expected truncated crypto error")
	}
}
