/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import "testing"

func TestParseVersion(t *testing.T) {
	tests := []struct {
		wire uint32
		want Version
		ok   bool
	}{
		{wire: VersionNumberV1, want: Version_V1, ok: true},
		{wire: VersionNumberV2, want: Version_V2, ok: true},
		{wire: 0xff00001d, want: Version_Draft, ok: true},
		{wire: 0x12345678},
	}
	for _, test := range tests {
		got, err := ParseVersion(test.wire)
		if (err == nil) != test.ok || got != test.want {
			t.Fatalf("ParseVersion(%#x) = %v, %v; want %v, ok=%v", test.wire, got, err, test.want, test.ok)
		}
	}
}

func TestInitialPacketType(t *testing.T) {
	if got := Version_V1.InitialPacketType(); got != 0b00 {
		t.Fatalf("QUIC v1 Initial type = %02b, want 00", got)
	}
	if got := Version_V2.InitialPacketType(); got != 0b01 {
		t.Fatalf("QUIC v2 Initial type = %02b, want 01", got)
	}
}
