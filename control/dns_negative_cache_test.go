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

func TestNormalizeAndCacheNxdomainWithSOA(t *testing.T) {
	controller := newNegativeCacheController(t)
	msg := newDNSMsg("missing.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeNameError
	msg.Ns = []dnsmessage.RR{testSOA(600, 120)}

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}

	cacheKey := controller.cacheKey("missing.example.", dnsmessage.TypeA)
	cache := controller.LookupDnsRespCache(cacheKey, false)
	if cache == nil {
		t.Fatal("NXDOMAIN with SOA should be cached")
	}
	if cache.Rcode != dnsmessage.RcodeNameError {
		t.Fatalf("rcode: got %d, want NXDOMAIN", cache.Rcode)
	}
	if cache.IncludeAnyIp() || len(cache.Answer) != 0 {
		t.Fatal("NXDOMAIN cache must not carry answers/IPs")
	}
	// TTL = min(600, 120) = 120
	remain := time.Until(cache.Deadline)
	if remain < 100*time.Second || remain > 120*time.Second {
		t.Fatalf("unexpected remaining TTL: %v", remain)
	}

	out := newDNSMsg("missing.example.", dnsmessage.TypeA)
	cache.FillInto(out)
	if out.Rcode != dnsmessage.RcodeNameError {
		t.Fatalf("FillInto rcode: got %d, want NXDOMAIN", out.Rcode)
	}
}

func TestNormalizeAndCacheNxdomainWithoutSOA(t *testing.T) {
	controller := newNegativeCacheController(t)
	msg := newDNSMsg("missing.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeNameError

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	cacheKey := controller.cacheKey("missing.example.", dnsmessage.TypeA)
	if cache := controller.LookupDnsRespCache(cacheKey, false); cache != nil {
		t.Fatal("NXDOMAIN without SOA must not be cached")
	}
}

func TestNormalizeAndCacheNodataWithSOA(t *testing.T) {
	controller := newNegativeCacheController(t)
	msg := newDNSMsg("empty.example.", dnsmessage.TypeAAAA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Ns = []dnsmessage.RR{testSOA(300, 180)}

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}

	cacheKey := controller.cacheKey("empty.example.", dnsmessage.TypeAAAA)
	cache := controller.LookupDnsRespCache(cacheKey, false)
	if cache == nil {
		t.Fatal("NODATA with SOA should be cached")
	}
	if cache.Rcode != dnsmessage.RcodeSuccess {
		t.Fatalf("rcode: got %d, want NOERROR", cache.Rcode)
	}
	if !cache.IsNegative() {
		t.Fatal("expected negative cache entry")
	}
	// TTL = min(300, 180) = 180
	remain := time.Until(cache.Deadline)
	if remain < 160*time.Second || remain > 180*time.Second {
		t.Fatalf("unexpected remaining TTL: %v", remain)
	}
}

func TestNormalizeAndCacheNodataWithoutSOA(t *testing.T) {
	controller := newNegativeCacheController(t)
	msg := newDNSMsg("empty.example.", dnsmessage.TypeAAAA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeSuccess

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	cacheKey := controller.cacheKey("empty.example.", dnsmessage.TypeAAAA)
	if cache := controller.LookupDnsRespCache(cacheKey, false); cache != nil {
		t.Fatal("NODATA without SOA must not be cached")
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
	msg.Ns = []dnsmessage.RR{testSOA(300, 300)}

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	cacheKey := controller.cacheKey("fail.example.", dnsmessage.TypeA)
	if cache := controller.LookupDnsRespCache(cacheKey, false); cache != nil {
		t.Fatal("SERVFAIL must not be cached")
	}
}

func TestNormalizeAndCacheSkipsTruncated(t *testing.T) {
	controller := newNegativeCacheController(t)
	msg := newDNSMsg("tc.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Truncated = true
	msg.Rcode = dnsmessage.RcodeNameError
	msg.Ns = []dnsmessage.RR{testSOA(300, 300)}

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	cacheKey := controller.cacheKey("tc.example.", dnsmessage.TypeA)
	if cache := controller.LookupDnsRespCache(cacheKey, false); cache != nil {
		t.Fatal("truncated response must not be cached")
	}
}

func TestNormalizeAndCacheNxdomainStripsDirtyAnswer(t *testing.T) {
	var lastNew *DnsCache
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
			lastNew = cloneDnsCache(newCache)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewDnsController: %v", err)
	}

	msg := newDNSMsg("dirty.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeNameError
	msg.Ns = []dnsmessage.RR{testSOA(300, 300)}
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "dirty.example.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("192.0.2.99").To4(),
		},
	}
	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if lastNew == nil {
		t.Fatal("expected cache update")
	}
	if lastNew.IncludeAnyIp() || len(domainCacheIPs(lastNew)) != 0 {
		t.Fatal("NXDOMAIN must not install A/AAAA into domain maps")
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

	neg := newDNSMsg("host.example.", dnsmessage.TypeA)
	neg.Response = true
	neg.Rcode = dnsmessage.RcodeNameError
	neg.Ns = []dnsmessage.RR{testSOA(300, 300)}
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
	if ips := domainCacheIPs(lastNew); len(ips) != 0 {
		t.Fatalf("domainCacheIPs(negative)=%v, want empty", ips)
	}
}

func TestNegativeCacheTTLCapped(t *testing.T) {
	msg := newDNSMsg("long.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeNameError
	msg.Ns = []dnsmessage.RR{testSOA(86400, 86400)}
	ttl, ok := negativeCacheTTL(msg)
	if !ok {
		t.Fatal("expected cacheable")
	}
	if ttl != maxNegativeCacheTtl {
		t.Fatalf("ttl: got %d, want cap %d", ttl, maxNegativeCacheTtl)
	}
}

func TestNegativeCacheIgnoresFixedDomainTtlExtension(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		FixedDomainTtl: map[string]int{
			"fixed.example": 86400,
		},
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

	msg := newDNSMsg("fixed.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeNameError
	msg.Ns = []dnsmessage.RR{testSOA(300, 120)}
	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}

	cache := controller.LookupDnsRespCache(controller.cacheKey("fixed.example.", dnsmessage.TypeA), false)
	if cache == nil {
		t.Fatal("expected cached NXDOMAIN")
	}
	remain := time.Until(cache.Deadline)
	// Must follow SOA TTL 120, not fixed 86400.
	if remain < 100*time.Second || remain > 120*time.Second {
		t.Fatalf("fixed_domain_ttl must not extend negative cache, remain=%v", remain)
	}
}

func TestNegativeCacheFixedZeroSkips(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		FixedDomainTtl: map[string]int{
			"nocache.example": 0,
		},
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

	msg := newDNSMsg("nocache.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeNameError
	msg.Ns = []dnsmessage.RR{testSOA(300, 300)}
	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if cache := controller.LookupDnsRespCache(controller.cacheKey("nocache.example.", dnsmessage.TypeA), false); cache != nil {
		t.Fatal("fixed_domain_ttl=0 must skip negative cache")
	}
}

func TestImportDnsCachePreservesNxdomainRcode(t *testing.T) {
	controller := newNegativeCacheController(t)
	cacheKey := controller.cacheKey("import.example.", dnsmessage.TypeA)
	deadline := time.Now().Add(2 * time.Minute)
	imported, err := controller.ImportDnsCache(map[string]*DnsCache{
		cacheKey: {
			CacheKey:         cacheKey,
			DomainBitmap:     testDomainBitmap(0),
			Rcode:            dnsmessage.RcodeNameError,
			Deadline:         deadline,
			OriginalDeadline: deadline,
		},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("imported count: %d", len(imported))
	}
	cache := controller.LookupDnsRespCache(cacheKey, false)
	if cache == nil || cache.Rcode != dnsmessage.RcodeNameError {
		t.Fatalf("imported NXDOMAIN rcode not preserved: %+v", cache)
	}
}

func TestCnameOnlyIsNotNodata(t *testing.T) {
	controller := newNegativeCacheController(t)
	msg := newDNSMsg("cname.example.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.CNAME{
			Hdr: dnsmessage.RR_Header{
				Name:   "cname.example.",
				Rrtype: dnsmessage.TypeCNAME,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			Target: "target.example.",
		},
	}
	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	cache := controller.LookupDnsRespCache(controller.cacheKey("cname.example.", dnsmessage.TypeA), false)
	if cache == nil {
		t.Fatal("CNAME-only success should be cached as positive-path entry")
	}
	if cache.IsNegative() {
		t.Fatal("CNAME-only must not be classified as negative")
	}
	if len(cache.Answer) != 1 {
		t.Fatalf("expected CNAME preserved, got %d answers", len(cache.Answer))
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

func testSOA(ttl, minttl uint32) *dnsmessage.SOA {
	return &dnsmessage.SOA{
		Hdr: dnsmessage.RR_Header{
			Name:   "example.",
			Rrtype: dnsmessage.TypeSOA,
			Class:  dnsmessage.ClassINET,
			Ttl:    ttl,
		},
		Ns:     "ns.example.",
		Mbox:   "hostmaster.example.",
		Minttl: minttl,
	}
}

func TestPreferJoinPreservesQueriedNxdomain(t *testing.T) {
	// Client queries AAAA (non-prefer); prefer A has addresses; AAAA is NXDOMAIN.
	queried := &DnsCache{Rcode: dnsmessage.RcodeNameError}
	other := &DnsCache{
		Rcode: dnsmessage.RcodeSuccess,
		Answer: []dnsmessage.RR{
			&dnsmessage.A{A: net.ParseIP("192.0.2.50").To4()},
		},
	}
	if !preferJoinReturnQueried(dnsmessage.TypeA, dnsmessage.TypeAAAA, queried, other) {
		t.Fatal("queried NXDOMAIN must be returned even when prefer family has IPs")
	}
}

func TestPreferJoinRejectsNonPreferWhenPreferHasIp(t *testing.T) {
	queried := &DnsCache{
		Rcode: dnsmessage.RcodeSuccess,
		Answer: []dnsmessage.RR{
			&dnsmessage.AAAA{AAAA: net.ParseIP("2001:db8::1")},
		},
	}
	other := &DnsCache{
		Rcode: dnsmessage.RcodeSuccess,
		Answer: []dnsmessage.RR{
			&dnsmessage.A{A: net.ParseIP("192.0.2.50").To4()},
		},
	}
	if preferJoinReturnQueried(dnsmessage.TypeA, dnsmessage.TypeAAAA, queried, other) {
		t.Fatal("non-prefer positive answer should be suppressed when prefer has IPs")
	}
}

func TestPreferJoinReturnsPreferType(t *testing.T) {
	queried := &DnsCache{
		Rcode: dnsmessage.RcodeSuccess,
		Answer: []dnsmessage.RR{
			&dnsmessage.A{A: net.ParseIP("192.0.2.50").To4()},
		},
	}
	other := &DnsCache{
		Rcode: dnsmessage.RcodeSuccess,
		Answer: []dnsmessage.RR{
			&dnsmessage.AAAA{AAAA: net.ParseIP("2001:db8::1")},
		},
	}
	if !preferJoinReturnQueried(dnsmessage.TypeA, dnsmessage.TypeA, queried, other) {
		t.Fatal("prefer-type query should return its cache")
	}
}

func TestPreferJoinReturnsWhenOtherIsNodata(t *testing.T) {
	queried := &DnsCache{
		Rcode: dnsmessage.RcodeSuccess,
		Answer: []dnsmessage.RR{
			&dnsmessage.AAAA{AAAA: net.ParseIP("2001:db8::1")},
		},
	}
	other := &DnsCache{Rcode: dnsmessage.RcodeSuccess} // NODATA
	if !preferJoinReturnQueried(dnsmessage.TypeA, dnsmessage.TypeAAAA, queried, other) {
		t.Fatal("non-prefer answer should be returned when prefer side has no IP")
	}
}

func TestIsNegativeConsistentWithDnsCacheIsNegative(t *testing.T) {
	if !(&DnsCache{Rcode: dnsmessage.RcodeNameError, Answer: []dnsmessage.RR{
		&dnsmessage.A{A: net.ParseIP("192.0.2.1").To4()},
	}}).IsNegative() {
		// NXDOMAIN is negative by rcode even if dirty answers remain in a hand-built entry.
		t.Fatal("NXDOMAIN should be negative")
	}
	if !(&DnsCache{Rcode: dnsmessage.RcodeSuccess}).IsNegative() {
		t.Fatal("empty NOERROR should be negative (NODATA)")
	}
	if (&DnsCache{
		Rcode: dnsmessage.RcodeSuccess,
		Answer: []dnsmessage.RR{
			&dnsmessage.CNAME{Target: "x.example."},
		},
	}).IsNegative() {
		t.Fatal("CNAME-only must not be negative")
	}
}
