/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package routing

import (
	"net/netip"
	"testing"
)

func TestParsePrefixes(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  string
	}{
		{"192.0.2.1", "192.0.2.1/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"::ffff:192.0.2.1", "::ffff:192.0.2.1/128"},
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"2001:db8::/32", "2001:db8::/32"},
	} {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parsePrefixes([]string{tt.input})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0] != netip.MustParsePrefix(tt.want) {
				t.Fatalf("parsePrefixes(%q) = %v, want %s", tt.input, got, tt.want)
			}
		})
	}
	for _, input := range []string{"", "invalid", "192.0.2.1/33", "2001:db8::/129"} {
		if _, err := parsePrefixes([]string{input}); err == nil {
			t.Errorf("invalid prefix %q was accepted", input)
		}
	}
}
