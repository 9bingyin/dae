/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import "testing"

func TestInitialPacketType(t *testing.T) {
	if got := Version_V1.InitialPacketType(); got != 0b00 {
		t.Fatalf("QUIC v1 Initial type = %02b, want 00", got)
	}
	if got := Version_V2.InitialPacketType(); got != 0b01 {
		t.Fatalf("QUIC v2 Initial type = %02b, want 01", got)
	}
}
