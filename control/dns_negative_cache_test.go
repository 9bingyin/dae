/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestNormalizeAndCacheNxdomain(t *testing.T) {
	controller := newNegativeCacheController(t)
	msg := newDNSMsg("missing.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeNameError
	msg.Ns = []dnsmessage.RR{
		&dnsmessage.SOA{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.",
				Rrtype: dnsmessage.TypeSOA,
				Class:  dnsmessage.ClassINET,
				Ttl:    600,
			},
			Ns:      "ns.example.",
			Mbox:    "hostmaster.example.",
			Serial:  1,
			Refresh: 1,
			Retry:   1,
			Expire:  1,
			Minttl:  120,
		},
	}

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}

	cacheKey := controller.cacheKey("missing.example.", dnsmessage.TypeA)
	cache := controller.LookupDnsRespCache(cacheKey, false)
	if cache == nil {
		t.Fatal("NXDOMAIN should be cached")
	}
	if cache.Rcode != dnsmessage.RcodeNameError {
		t.Fatalf("rcode: got %d, want NXDOMAIN", cache.Rcode)
	}
	if cache.IncludeAnyIp() {
		t.Fatal("NXDOMAIN cache must not carry IPs")
	}
	// TTL = min(SOA.TTL=600, SOA.MINIMUM=120) = 120
	remain := time.Until(cache.Deadline)
	if remain < 100*time.Second || remain > 120*time.Second {
		t.Fatalf("unexpected remaining TTL: %v", remain)
	}

	out := newDNSMsg("missing.example.", dnsmessage.TypeA)
	cache.FillInto(out)
	if out.Rcode != dnsmessage.RcodeNameError {
		t.Fatalf("FillInto rcode: got %d, want NXDOMAIN", out.Rcode)
	}
	if len(out.Answer) != 0 {
		t.Fatalf("FillInto answer should be empty, got %d", len(out.Answer))
	}
}

func TestNormalizeAndCacheNodataDefaultTTL(t *testing.T) {
	controller := newNegativeCacheController(t)
	msg := newDNSMsg("empty.example.", dnsmessage.TypeAAAA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeSuccess
	// Empty answer + empty authority → cacheable NODATA with default TTL.

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}

	cacheKey := controller.cacheKey("empty.example.", dnsmessage.TypeAAAA)
	cache := controller.LookupDnsRespCache(cacheKey, false)
	if cache == nil {
		t.Fatal("NODATA should be cached")
	}
	if cache.Rcode != dnsmessage.RcodeSuccess {
		t.Fatalf("rcode: got %d, want NOERROR", cache.Rcode)
	}
	if !cache.IsNegative() {
		t.Fatal("expected negative cache entry")
	}
	remain := time.Until(cache.Deadline)
	if remain < 280*time.Second || remain > 300*time.Second {
		t.Fatalf("expected default negative TTL ~300s, got %v", remain)
	}
}

func TestNormalizeAndCacheSkipsReferral(t *testing.T) {
	controller := newNegativeCacheController(t)
	msg := newDNSMsg("ref.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Ns = []dnsmessage.RR{
		&dnsmessage.NS{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.",
				Rrtype: dnsmessage.TypeNS,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			Ns: "ns.example.",
		},
	}

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	cacheKey := controller.cacheKey("ref.example.", dnsmessage.TypeA)
	if cache := controller.LookupDnsRespCache(cacheKey, false); cache != nil {
		t.Fatal("referral must not be cached as NODATA")
	}
}

func TestNormalizeAndCacheSkipsServfail(t *testing.T) {
	controller := newNegativeCacheController(t)
	msg := newDNSMsg("fail.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeServerFailure

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	cacheKey := controller.cacheKey("fail.example.", dnsmessage.TypeA)
	if cache := controller.LookupDnsRespCache(cacheKey, false); cache != nil {
		t.Fatal("SERVFAIL must not be cached")
	}
}

func TestNegativeCacheReplacesPositiveAndClearsDomainIPs(t *testing.T) {
	var lastOld, lastNew *DnsCache
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				DomainBitmap:     testDomainBitmap(0),
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		CacheUpdateCallback: func(oldCache, newCache *DnsCache) error {
			lastOld = cloneDnsCache(oldCache)
			lastNew = cloneDnsCache(newCache)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewDnsController: %v", err)
	}

	// Seed positive A answer.
	pos := newDNSMsg("host.example.", dnsmessage.TypeA)
	pos.Response = true
	pos.Rcode = dnsmessage.RcodeSuccess
	pos.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "host.example.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("192.0.2.10").To4(),
		},
	}
	if err := controller.NormalizeAndCacheDnsResp_(pos); err != nil {
		t.Fatalf("positive normalize: %v", err)
	}
	if lastNew == nil || !lastNew.IncludeIp(testAddr("192.0.2.10")) {
		t.Fatal("positive update should include IP")
	}

	// Replace with NXDOMAIN.
	neg := newDNSMsg("host.example.", dnsmessage.TypeA)
	neg.Response = true
	neg.Rcode = dnsmessage.RcodeNameError
	if err := controller.NormalizeAndCacheDnsResp_(neg); err != nil {
		t.Fatalf("negative normalize: %v", err)
	}
	if lastOld == nil || !lastOld.IncludeIp(testAddr("192.0.2.10")) {
		t.Fatal("callback old cache should be previous positive answer")
	}
	if lastNew == nil || lastNew.IncludeAnyIp() {
		t.Fatal("callback new cache must not include IPs")
	}
	if lastNew.Rcode != dnsmessage.RcodeNameError {
		t.Fatalf("new rcode: got %d", lastNew.Rcode)
	}

	// domainCacheIPs on negative must be empty so ReplaceDomain only removes.
	if ips := domainCacheIPs(lastNew); len(ips) != 0 {
		t.Fatalf("domainCacheIPs(negative)=%v, want empty", ips)
	}
}

func TestNegativeCacheTTLCapped(t *testing.T) {
	msg := newDNSMsg("long.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeNameError
	msg.Ns = []dnsmessage.RR{
		&dnsmessage.SOA{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.",
				Rrtype: dnsmessage.TypeSOA,
				Class:  dnsmessage.ClassINET,
				Ttl:    86400,
			},
			Minttl: 86400,
		},
	}
	if got := negativeCacheTTL(msg); got != maxNegativeCacheTtl {
		t.Fatalf("ttl: got %d, want cap %d", got, maxNegativeCacheTtl)
	}
}

func newNegativeCacheController(t *testing.T) *DnsController {
	t.Helper()
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				DomainBitmap:     testDomainBitmap(0),
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		CacheUpdateCallback: func(oldCache, newCache *DnsCache) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewDnsController: %v", err)
	}
	return controller
}

func newDNSMsg(name string, qtype uint16) *dnsmessage.Msg {
	return &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{RecursionDesired: true},
		Question: []dnsmessage.Question{{
			Name:   name,
			Qtype:  qtype,
			Qclass: dnsmessage.ClassINET,
		}},
	}
}
