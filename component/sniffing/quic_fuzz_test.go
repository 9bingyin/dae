/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import "testing"

func FuzzQuicSnifferFeed(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0, 0, 0, 1})
	f.Add(QuicStream3)
	f.Fuzz(func(t *testing.T, datagram []byte) {
		sniffer := NewQuicSniffer()
		_ = sniffer.Feed(datagram)
		_ = sniffer.Close()
	})
}
