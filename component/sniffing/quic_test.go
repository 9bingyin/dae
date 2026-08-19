/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"testing"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
)

func TestQuicSnifferSinglePacket(t *testing.T) {
	sniffer := NewQuicSniffer()
	t.Cleanup(func() { _ = sniffer.Close() })

	result := sniffer.Feed(quicStream)
	if result.State != QuicSniffFound || result.Domain != "a.nel.cloudflare.com" {
		t.Fatalf("result = %+v", result)
	}
}

func TestIsLikelyQuicInitialUsesVersionPacketType(t *testing.T) {
	packet := buildTestInitial(t, quicutils.Version_V2, []byte("v2-dcid"), []byte("v2-dcid"), nil, 0, 0, testClientHello("example.com"))
	if !IsLikelyQuicInitial(packet) {
		t.Fatal("valid QUIC v2 Initial header was rejected")
	}
	packet[0] &^= 0x30
	if IsLikelyQuicInitial(packet) {
		t.Fatal("QUIC v2 packet with v1 Initial type was accepted")
	}
}

func TestQuicSnifferNoSNI(t *testing.T) {
	dcid := []byte("no-sni-id")
	packet := buildTestInitial(t, quicutils.Version_V1, dcid, dcid, nil, 0, 0, testClientHello(""))
	sniffer := NewQuicSniffer()
	t.Cleanup(func() { _ = sniffer.Close() })

	result := sniffer.Feed(packet)
	if result.State != QuicSniffNoSNI {
		t.Fatalf("result = %+v", result)
	}
}

func TestQuicSnifferCloseResetsState(t *testing.T) {
	dcid := []byte("firstcid")
	clientHello := testClientHello("example.com")
	first := buildTestInitial(t, quicutils.Version_V1, dcid, dcid, nil, 200, 0, clientHello[:32])

	sniffer := NewQuicSniffer()
	if result := sniffer.Feed(first); result.State != QuicSniffNeedMore {
		t.Fatalf("first result = %+v", result)
	}
	if err := sniffer.Close(); err != nil {
		t.Fatal(err)
	}

	secondDCID := []byte("secondid")
	second := buildTestInitial(t, quicutils.Version_V1, secondDCID, secondDCID, nil, 0, 0, clientHello)
	result := sniffer.Feed(second)
	if result.State != QuicSniffFound || result.Domain != "example.com" {
		t.Fatalf("result after close = %+v", result)
	}
	if err := sniffer.Close(); err != nil {
		t.Fatal(err)
	}
}
