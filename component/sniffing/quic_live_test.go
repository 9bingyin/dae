/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package sniffing

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	quic "github.com/daeuniverse/quic-go"
)

func TestQuicSnifferVersions(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a local UDP integration test")
	}

	tests := []struct {
		name    string
		version quic.Version
	}{
		{name: "v1", version: quic.Version1},
		{name: "v2", version: quic.Version2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			t.Cleanup(cancel)
			dialDone := make(chan struct{})
			go func() {
				defer close(dialDone)
				connection, _ := quic.DialAddr(ctx, listener.LocalAddr().String(), &tls.Config{
					ServerName: "example.com",
					NextProtos: []string{"h3"},
				}, &quic.Config{
					Versions:             []quic.Version{test.version},
					HandshakeIdleTimeout: 500 * time.Millisecond,
				})
				if connection != nil {
					_ = connection.CloseWithError(0, "test complete")
				}
			}()

			sniffer := NewQuicSniffer()
			t.Cleanup(func() { _ = sniffer.Close() })
			for packetNumber := 0; packetNumber < 4; packetNumber++ {
				if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				packet := make([]byte, 4096)
				length, _, err := listener.ReadFromUDP(packet)
				if err != nil {
					t.Fatal(err)
				}
				result := sniffer.Feed(packet[:length])
				switch result.State {
				case QuicSniffNeedMore:
					continue
				case QuicSniffFound:
					if result.Domain != "example.com" {
						t.Fatalf("domain = %q, want %q", result.Domain, "example.com")
					}
					cancel()
					select {
					case <-dialDone:
					case <-time.After(time.Second):
						t.Fatal("quic dial did not stop")
					}
					return
				default:
					t.Fatalf("state = %v: %v", result.State, result.Err)
				}
			}
			t.Fatal("domain not found within four Initial packets")
		})
	}
}
