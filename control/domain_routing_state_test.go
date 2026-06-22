/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

func TestDomainRoutingStateRestoresIntersectionAfterRemove(t *testing.T) {
	core := newTestControlPlaneCore()
	ip := "192.0.2.1"
	matching := testDnsCache("match", testDomainBitmap(0), ip)
	conflicting := testDnsCache("conflict", testDomainBitmap(), ip)

	replaceDomainState(t, core, nil, matching)
	replaceDomainState(t, core, nil, conflicting)

	maps, ok, err := core.domainRoutingMapsForIPLocked(netip.MustParseAddr(ip))
	if err != nil {
		t.Fatalf("get domain maps: %v", err)
	}
	if !ok {
		t.Fatal("domain maps should exist")
	}
	assertDomainBit(t, maps.bump, 0, true)
	assertDomainBit(t, maps.routing, 0, false)

	replaceDomainState(t, core, conflicting, nil)

	maps, ok, err = core.domainRoutingMapsForIPLocked(netip.MustParseAddr(ip))
	if err != nil {
		t.Fatalf("get domain maps after remove: %v", err)
	}
	if !ok {
		t.Fatal("domain maps should still exist")
	}
	assertDomainBit(t, maps.bump, 0, true)
	assertDomainBit(t, maps.routing, 0, true)
}

func TestDomainRoutingStateMovesAnswerIP(t *testing.T) {
	core := newTestControlPlaneCore()
	oldCache := testDnsCache("example", testDomainBitmap(0), "192.0.2.1")
	newCache := testDnsCache("example", testDomainBitmap(0), "192.0.2.2")

	replaceDomainState(t, core, nil, oldCache)
	replaceDomainState(t, core, oldCache, newCache)

	if _, ok, err := core.domainRoutingMapsForIPLocked(netip.MustParseAddr("192.0.2.1")); err != nil {
		t.Fatalf("get old ip maps: %v", err)
	} else if ok {
		t.Fatal("old ip domain maps should be removed")
	}

	maps, ok, err := core.domainRoutingMapsForIPLocked(netip.MustParseAddr("192.0.2.2"))
	if err != nil {
		t.Fatalf("get new ip maps: %v", err)
	}
	if !ok {
		t.Fatal("new ip domain maps should exist")
	}
	assertDomainBit(t, maps.bump, 0, true)
	assertDomainBit(t, maps.routing, 0, true)
}

func TestDomainRoutingStateRemoveIsIdempotent(t *testing.T) {
	core := newTestControlPlaneCore()
	cache := testDnsCache("example", testDomainBitmap(0), "192.0.2.1")
	ip := netip.MustParseAddr("192.0.2.1")

	replaceDomainState(t, core, nil, cache)
	replaceDomainState(t, core, cache, nil)
	replaceDomainState(t, core, cache, nil)

	if _, ok, err := core.domainRoutingMapsForIPLocked(ip); err != nil {
		t.Fatalf("get domain maps: %v", err)
	} else if ok {
		t.Fatal("domain maps should be removed")
	}
}

func newTestControlPlaneCore() *controlPlaneCore {
	return &controlPlaneCore{domainRefs: make(map[netip.Addr]map[string][]uint32)}
}

func replaceDomainState(t *testing.T, core *controlPlaneCore, oldCache, newCache *DnsCache) {
	t.Helper()
	if _, err := core.replaceDomainStateLocked(oldCache, newCache); err != nil {
		t.Fatalf("replace domain state: %v", err)
	}
}

func testDomainBitmap(bits ...int) []uint32 {
	bitmap := make([]uint32, consts.MaxMatchSetLen/32)
	for _, bit := range bits {
		bitmap[bit/32] |= 1 << (bit % 32)
	}
	return bitmap
}

func testDnsCache(cacheKey string, bitmap []uint32, ips ...string) *DnsCache {
	answers := make([]dnsmessage.RR, 0, len(ips))
	for _, rawIP := range ips {
		ip := net.ParseIP(rawIP)
		if ip4 := ip.To4(); ip4 != nil {
			answers = append(answers, &dnsmessage.A{A: ip4})
			continue
		}
		answers = append(answers, &dnsmessage.AAAA{AAAA: ip.To16()})
	}
	return &DnsCache{
		CacheKey:     cacheKey,
		DomainBitmap: bitmap,
		Answer:       answers,
	}
}

func assertDomainBit(t *testing.T, routing bpfDomainRouting, bit int, want bool) {
	t.Helper()
	got := routing.Bitmap[bit/32]&(1<<(bit%32)) != 0
	if got != want {
		t.Fatalf("domain bit %d: got %v, want %v", bit, got, want)
	}
}

func testAddr(raw string) netip.Addr {
	return netip.MustParseAddr(raw)
}
