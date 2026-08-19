/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package ipmatcher

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/pkg/trie"
)

func TestPrefixSetContains(t *testing.T) {
	set := NewPrefixSet([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	for _, tt := range []struct {
		addr string
		want bool
	}{
		{addr: "10.1.2.3", want: true},
		{addr: "::ffff:10.1.2.3", want: true},
		{addr: "8.8.8.8", want: false},
		{addr: "2001:db8::1", want: true},
		{addr: "2001:4860:4860::8888", want: false},
	} {
		t.Run(tt.addr, func(t *testing.T) {
			if got := set.Contains(netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Fatalf("Contains(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestPrefixSetProjectsMappedIPv4Prefixes(t *testing.T) {
	for _, tt := range []struct {
		name   string
		prefix netip.Prefix
		hit    string
		miss   string
	}{
		{
			name:   "mapped IPv4 subnet",
			prefix: netip.MustParsePrefix("::ffff:192.0.2.0/120"),
			hit:    "192.0.2.1",
			miss:   "192.0.3.1",
		},
		{
			name:   "mapped IPv4 half",
			prefix: netip.MustParsePrefix("::ffff:128.0.0.0/97"),
			hit:    "192.0.2.1",
			miss:   "10.0.0.1",
		},
		{
			name:   "IPv6 prefix covering mapped space",
			prefix: netip.MustParsePrefix("::/80"),
			hit:    "203.0.113.1",
			miss:   "2001:db8::1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			set := NewPrefixSet([]netip.Prefix{tt.prefix})
			if !set.Contains(netip.MustParseAddr(tt.hit)) {
				t.Fatalf("expected %s to match %s", tt.hit, tt.prefix)
			}
			if set.Contains(netip.MustParseAddr(tt.miss)) {
				t.Fatalf("expected %s not to match %s", tt.miss, tt.prefix)
			}
		})
	}
}

func TestPrefixSetMatchesLegacyIPTrie(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("::ffff:192.0.2.0/120"),
		netip.MustParsePrefix("::/80"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	set := NewPrefixSet(prefixes)
	legacy, err := trie.NewTrieFromPrefixes(prefixes)
	if err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewPCG(1, 0))
	for range 10000 {
		var addr netip.Addr
		if rng.Uint32()&1 == 0 {
			addr = netip.AddrFrom4([4]byte{byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32())})
		} else {
			var raw [16]byte
			for i := range raw {
				raw[i] = byte(rng.Uint32())
			}
			addr = netip.AddrFrom16(raw)
		}
		got := set.Contains(addr)
		legacyAddr := netip.AddrFrom16(addr.As16())
		want := legacy.HasPrefix(trie.Prefix2bin128(netip.PrefixFrom(legacyAddr, 128)))
		if got != want {
			t.Fatalf("addr=%s PrefixSet=%v legacy=%v", addr, got, want)
		}
	}
}

func TestPrefixSetContainsRawMappedValue(t *testing.T) {
	raw := netip.MustParseAddr("::ffff:192.0.2.1")
	set := NewPrefixSet([]netip.Prefix{netip.PrefixFrom(raw, 128)})
	if !set.ContainsRaw(raw) {
		t.Fatal("raw mapped value did not match its 128-bit prefix")
	}
}
