/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/ipmatcher"
)

type recordingDNSDomainMatcher struct {
	hits  map[int]bool
	calls []int
	seen  []*routing.PreparedDomain
}

func (*recordingDNSDomainMatcher) AddSet(int, []string, consts.RoutingDomainKey) {}
func (*recordingDNSDomainMatcher) Build() error                                  { return nil }
func (*recordingDNSDomainMatcher) MatchDomainBitmap(string) []uint32 {
	panic("ordered DNS routing must not build a full domain bitmap")
}
func (m *recordingDNSDomainMatcher) MatchPreparedDomain(domain *routing.PreparedDomain, bitIndex int) bool {
	m.calls = append(m.calls, bitIndex)
	m.seen = append(m.seen, domain)
	return m.hits[bitIndex]
}

func TestRequestMatcherMatchesDomainsInRuleOrder(t *testing.T) {
	domains := &recordingDNSDomainMatcher{hits: map[int]bool{1: true}}
	matcher := &RequestMatcher{
		domainMatcher: domains,
		matches: []requestMatchSet{
			{Type: consts.MatchType_DomainSet, Upstream: 1},
			{Type: consts.MatchType_DomainSet, Upstream: 2},
			{Type: consts.MatchType_Fallback, Upstream: 3},
		},
	}
	upstream, err := matcher.Match("Example.COM.", 1)
	if err != nil {
		t.Fatal(err)
	}
	if upstream != 2 {
		t.Fatalf("upstream = %d, want 2", upstream)
	}
	if !slices.Equal(domains.calls, []int{0, 1}) {
		t.Fatalf("domain calls = %v", domains.calls)
	}
	if domains.seen[0] != domains.seen[1] {
		t.Fatal("domain was prepared more than once")
	}
	if domains.seen[0].Normalized() != "example.com" {
		t.Fatalf("normalized domain = %q", domains.seen[0].Normalized())
	}
}

func TestResponseMatcherMatchesDomainsInRuleOrder(t *testing.T) {
	domains := &recordingDNSDomainMatcher{hits: map[int]bool{0: true}}
	matcher := &ResponseMatcher{
		domainMatcher: domains,
		matches: []responseMatchSet{
			{Type: consts.MatchType_DomainSet, Upstream: 1},
			{Type: consts.MatchType_DomainSet, Upstream: 2},
			{Type: consts.MatchType_Fallback, Upstream: 3},
		},
	}
	upstream, err := matcher.Match("Example.COM.", 1, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if upstream != 1 {
		t.Fatalf("upstream = %d, want 1", upstream)
	}
	if !slices.Equal(domains.calls, []int{0}) {
		t.Fatalf("domain calls = %v", domains.calls)
	}
}

func TestResponseMatcherBARTIPSets(t *testing.T) {
	ipSet := ipmatcher.NewPrefixSet([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	matcher := &ResponseMatcher{
		ipSet: []*ipmatcher.PrefixSet{ipSet},
		matches: []responseMatchSet{
			{Type: consts.MatchType_IpSet, Value: 0, Upstream: 1},
			{Type: consts.MatchType_Fallback, Upstream: 2},
		},
	}

	for _, tt := range []struct {
		name    string
		ips     []netip.Addr
		wantOut consts.DnsResponseOutboundIndex
	}{
		{name: "IPv4 hit", ips: []netip.Addr{netip.MustParseAddr("10.1.2.3")}, wantOut: 1},
		{name: "IPv6 hit", ips: []netip.Addr{netip.MustParseAddr("2001:db8::1")}, wantOut: 1},
		{name: "any answer hits", ips: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.2.3.4")}, wantOut: 1},
		{name: "miss", ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, wantOut: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			upstream, err := matcher.Match("example.com", 1, tt.ips, 0)
			if err != nil {
				t.Fatal(err)
			}
			if upstream != tt.wantOut {
				t.Fatalf("upstream = %d, want %d", upstream, tt.wantOut)
			}
		})
	}
}
