/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/ipmatcher"
)

type recordingDomainMatcher struct {
	hits  map[int]bool
	calls []int
	seen  []*routing.PreparedDomain
}

func (*recordingDomainMatcher) AddSet(int, []string, consts.RoutingDomainKey) {}
func (*recordingDomainMatcher) Build() error                                  { return nil }
func (*recordingDomainMatcher) MatchDomainBitmap(string) []uint32 {
	panic("ordered routing must not build a full domain bitmap")
}
func (m *recordingDomainMatcher) MatchPreparedDomain(domain *routing.PreparedDomain, bitIndex int) bool {
	m.calls = append(m.calls, bitIndex)
	m.seen = append(m.seen, domain)
	return m.hits[bitIndex]
}

func TestRoutingMatcherMatchesDomainsInRuleOrder(t *testing.T) {
	tests := []struct {
		name      string
		hits      map[int]bool
		wantCalls []int
		wantOut   consts.OutboundIndex
	}{
		{name: "first rule", hits: map[int]bool{0: true}, wantCalls: []int{0}, wantOut: 1},
		{name: "second rule", hits: map[int]bool{1: true}, wantCalls: []int{0, 1}, wantOut: 2},
		{name: "fallback", hits: map[int]bool{}, wantCalls: []int{0, 1}, wantOut: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domains := &recordingDomainMatcher{hits: tt.hits}
			matcher := &RoutingMatcher{
				domainMatcher: domains,
				matches: []bpfMatchSet{
					{Type: uint8(consts.MatchType_DomainSet), Outbound: 1},
					{Type: uint8(consts.MatchType_DomainSet), Outbound: 2},
					{Type: uint8(consts.MatchType_Fallback), Outbound: 3},
				},
			}
			addr := netip.MustParseAddr("2001:db8::1").As16()
			outbound, _, _, err := matcher.Match(addr[:], addr[:], 1, 443, consts.IpVersion_6, consts.L4ProtoType_TCP, "Example.COM.", [16]uint8{}, 0, make([]byte, 16))
			if err != nil {
				t.Fatal(err)
			}
			if outbound != tt.wantOut {
				t.Fatalf("outbound = %d, want %d", outbound, tt.wantOut)
			}
			if !slices.Equal(domains.calls, tt.wantCalls) {
				t.Fatalf("domain calls = %v, want %v", domains.calls, tt.wantCalls)
			}
			for _, prepared := range domains.seen {
				if prepared != domains.seen[0] {
					t.Fatal("domain was prepared more than once")
				}
				if prepared.Normalized() != "example.com" {
					t.Fatalf("normalized domain = %q", prepared.Normalized())
				}
			}
		})
	}
}

func TestRoutingMatcherIPSets(t *testing.T) {
	ipSet := ipmatcher.NewPrefixSet([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	})

	ipRule := bpfMatchSet{Type: uint8(consts.MatchType_IpSet), Outbound: 1}
	binary.LittleEndian.PutUint16(ipRule.Value[:], 0)
	matcher := &RoutingMatcher{
		prefixSets: []*ipmatcher.PrefixSet{ipSet},
		matches: []bpfMatchSet{
			ipRule,
			{Type: uint8(consts.MatchType_Fallback), Outbound: 2},
		},
	}

	for _, tt := range []struct {
		addr    string
		wantOut consts.OutboundIndex
	}{
		{addr: "10.1.2.3", wantOut: 1},
		{addr: "2001:db8::1", wantOut: 1},
		{addr: "8.8.8.8", wantOut: 2},
		{addr: "2001:4860:4860::8888", wantOut: 2},
	} {
		t.Run(tt.addr, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr).As16()
			outbound, _, _, err := matcher.Match(addr[:], addr[:], 1, 443, consts.IpVersion_X, consts.L4ProtoType_TCP, "", [16]uint8{}, 0, make([]byte, 16))
			if err != nil {
				t.Fatal(err)
			}
			if outbound != tt.wantOut {
				t.Fatalf("outbound = %d, want %d", outbound, tt.wantOut)
			}
		})
	}
}

func TestRoutingMatcherPreservesMappedMAC(t *testing.T) {
	mac := [16]byte{10: 0xff, 11: 0xff, 12: 1, 13: 2, 14: 3, 15: 4}
	macSet := ipmatcher.NewPrefixSet([]netip.Prefix{
		netip.PrefixFrom(netip.AddrFrom16(mac), 128),
	})

	macRule := bpfMatchSet{Type: uint8(consts.MatchType_Mac), Outbound: 1}
	binary.LittleEndian.PutUint16(macRule.Value[:], 0)
	matcher := &RoutingMatcher{
		prefixSets: []*ipmatcher.PrefixSet{macSet},
		matches: []bpfMatchSet{
			macRule,
			{Type: uint8(consts.MatchType_Fallback), Outbound: 2},
		},
	}
	addr := netip.MustParseAddr("2001:db8::1").As16()
	outbound, _, _, err := matcher.Match(addr[:], addr[:], 1, 443, consts.IpVersion_6, consts.L4ProtoType_TCP, "", [16]uint8{}, 0, mac[:])
	if err != nil {
		t.Fatal(err)
	}
	if outbound != 1 {
		t.Fatalf("outbound = %d, want 1", outbound)
	}
}
