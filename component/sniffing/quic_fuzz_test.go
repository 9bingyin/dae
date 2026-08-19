/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import "testing"

func FuzzQuicSnifferFeed(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0, 0, 0, 1})
	f.Add(quicStream)
	f.Fuzz(func(t *testing.T, datagram []byte) {
		sniffer := NewQuicSniffer()
		result := sniffer.Feed(datagram)
		if result.State == QuicSniffFound && result.Domain == "" {
			t.Fatal("found result has an empty domain")
		}
		if result.State == QuicSniffNeedMore && result.Err != nil {
			t.Fatalf("need-more result has an error: %v", result.Err)
		}
		if err := sniffer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := sniffer.Close(); err != nil {
			t.Fatal(err)
		}
	})
}
