/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package control

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// TestFrozenWriterCannotOverwriteRestoredMaps verifies reload single-writer
// handoff: after FreezeDomainRouting, the retiring core's ReplaceDomain is a
// no-op and cannot clobber state owned by the new core.
func TestFrozenWriterCannotOverwriteRestoredMaps(t *testing.T) {
	ip := "192.0.2.11"
	addr := netip.MustParseAddr(ip)

	oldCore := newTestControlPlaneCore()
	newCore := newTestControlPlaneCore()

	match := testDnsCache("a.example.", testDomainBitmap(0), ip)
	conflict := testDnsCache("b.example.", testDomainBitmap(1), ip)

	// Old plane before reload: two domains share one IP.
	if _, err := oldCore.replaceDomainStateLocked(nil, match); err != nil {
		t.Fatalf("seed match: %v", err)
	}
	if _, err := oldCore.replaceDomainStateLocked(nil, conflict); err != nil {
		t.Fatalf("seed conflict: %v", err)
	}

	// New plane restores only match (diff rebuild without old writer).
	if err := newCore.ReplaceAllDomainRouting([]*DnsCache{match}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	newCore.domainMapMu.Lock()
	newMaps, ok, err := newCore.domainRoutingMapsForIPLocked(addr)
	newCore.domainMapMu.Unlock()
	if err != nil || !ok {
		t.Fatalf("new maps after restore: ok=%v err=%v", ok, err)
	}
	if !bitSet(newMaps.routing, 0) || bitSet(newMaps.routing, 1) {
		t.Fatalf("expected single-domain routing after restore: %+v", newMaps.routing.Bitmap)
	}

	// Retiring plane is frozen before any further map writes.
	oldCore.FreezeDomainRouting()
	if err := oldCore.ReplaceDomain(match, match); err != nil {
		t.Fatalf("frozen replace: %v", err)
	}

	// newCore state must remain the restored single-domain view.
	newCore.domainMapMu.Lock()
	after, ok, err := newCore.domainRoutingMapsForIPLocked(addr)
	newCore.domainMapMu.Unlock()
	if err != nil || !ok {
		t.Fatalf("new maps after frozen write: ok=%v err=%v", ok, err)
	}
	if !bitSet(after.routing, 0) || bitSet(after.bump, 1) {
		t.Fatalf("frozen old writer must not affect new core view: routing=%v bump=%v",
			after.routing.Bitmap, after.bump.Bitmap)
	}

	// oldCore still holds stale multi-domain refs in memory, but must not sync.
	oldCore.domainMapMu.Lock()
	oldMaps, ok, err := oldCore.domainRoutingMapsForIPLocked(addr)
	oldCore.domainMapMu.Unlock()
	if err != nil || !ok {
		t.Fatalf("old maps: ok=%v err=%v", ok, err)
	}
	if bitSet(oldMaps.routing, 0) {
		t.Fatal("old core still has multi-domain intersection empty on bit0 (stale refs expected)")
	}
}

func TestReplaceAllDomainRoutingRebuildsRefs(t *testing.T) {
	core := newTestControlPlaneCore()
	ip := "192.0.2.20"
	first := testDnsCache("a.example.", testDomainBitmap(0), ip)
	second := testDnsCache("b.example.", testDomainBitmap(1), "192.0.2.21")

	if err := core.ReplaceAllDomainRouting([]*DnsCache{first, second}); err != nil {
		t.Fatalf("replace all: %v", err)
	}

	assertDomainRefPresent := func(raw string, want bool) {
		t.Helper()
		core.domainMapMu.Lock()
		defer core.domainMapMu.Unlock()
		_, ok, err := core.domainRoutingMapsForIPLocked(netip.MustParseAddr(raw))
		if err != nil {
			t.Fatalf("lookup %s: %v", raw, err)
		}
		if ok != want {
			t.Fatalf("ip %s present=%v, want %v", raw, ok, want)
		}
	}
	assertDomainRefPresent(ip, true)
	assertDomainRefPresent("192.0.2.21", true)

	// Rebuild with only first → second IP must disappear from refs.
	if err := core.ReplaceAllDomainRouting([]*DnsCache{first}); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	assertDomainRefPresent(ip, true)
	assertDomainRefPresent("192.0.2.21", false)
}

func bitSet(r bpfDomainRouting, bit int) bool {
	return r.Bitmap[bit/32]&(1<<(bit%32)) != 0
}

// TestDnsCacheUpdateCallbackFailureRollsBackCache verifies hot-path update
// rolls back user-space cache when eBPF sync fails (same as import).
func TestDnsCacheUpdateCallbackFailureRollsBackCache(t *testing.T) {
	var (
		mu       sync.Mutex
		failNext bool
	)
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
			mu.Lock()
			defer mu.Unlock()
			if failNext {
				failNext = false
				return errors.New("simulated eBPF map update failure")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewDnsController: %v", err)
	}

	first := testDnsCache("", nil, "192.0.2.1")
	if err := controller.UpdateDnsCacheTtl("example.com", dnsmessage.TypeA, first.Answer, 60); err != nil {
		t.Fatalf("first update: %v", err)
	}

	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	got := controller.LookupDnsRespCache(cacheKey, false)
	if got == nil || !got.IncludeIp(testAddr("192.0.2.1")) {
		t.Fatal("precondition: cache should hold 192.0.2.1")
	}

	mu.Lock()
	failNext = true
	mu.Unlock()
	second := testDnsCache("", nil, "192.0.2.2")
	err = controller.UpdateDnsCacheTtl("example.com", dnsmessage.TypeA, second.Answer, 60)
	if err == nil {
		t.Fatal("expected callback failure")
	}

	got = controller.LookupDnsRespCache(cacheKey, false)
	if got == nil {
		t.Fatal("cache entry missing after failed update")
	}
	if !got.IncludeIp(testAddr("192.0.2.1")) {
		t.Fatalf("cache should roll back to 192.0.2.1, got %v", formatAnswers(got.Answer))
	}
	if got.IncludeIp(testAddr("192.0.2.2")) {
		t.Fatal("failed update must not leave new IP in cache")
	}
}

// TestDnsCacheImportCallbackFailureRollsBack documents import transactional behavior.
func TestDnsCacheImportCallbackFailureRollsBack(t *testing.T) {
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
			return errors.New("simulated eBPF map update failure")
		},
	})
	if err != nil {
		t.Fatalf("NewDnsController: %v", err)
	}

	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	deadline := time.Now().Add(time.Minute)
	_, err = controller.ImportDnsCache(map[string]*DnsCache{
		cacheKey: newTestImportDnsCache(cacheKey, deadline, deadline),
	})
	if err == nil {
		t.Fatal("expected import failure")
	}
	if cache := controller.LookupDnsRespCache(cacheKey, false); cache != nil {
		t.Fatalf("import correctly rolled back, but found cache: %v", formatAnswers(cache.Answer))
	}
}

// TestLookupDnsRespCacheDataRace must pass under go test -race.
func TestLookupDnsRespCacheDataRace(t *testing.T) {
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

	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	if err := controller.UpdateDnsCacheTtl("example.com", dnsmessage.TypeA, testDnsCache("", nil, "192.0.2.1").Answer, 60); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const (
		readers = 8
		writers = 4
		iters   = 200
	)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range iters {
				cache := controller.LookupDnsRespCache(cacheKey, false)
				if cache == nil {
					continue
				}
				_ = cache.IncludeAnyIp()
				msg := new(dnsmessage.Msg)
				cache.FillInto(msg)
				_ = len(msg.Answer)
			}
		}()
	}
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			for j := range iters {
				ip := fmt.Sprintf("192.0.2.%d", 1+(j+i)%200)
				_ = controller.UpdateDnsCacheTtl("example.com", dnsmessage.TypeA, testDnsCache("", nil, ip).Answer, 60)
			}
		}(i)
	}

	close(start)
	wg.Wait()
}

// TestUserspaceBumpOutboundReturnsControlPlane verifies userspace Match aligns
// with kernel: an explicit bump/control-plane outbound is a terminal hit.
func TestUserspaceBumpOutboundReturnsControlPlane(t *testing.T) {
	matcher := &RoutingMatcher{
		matches: []bpfMatchSet{
			{
				Type:     uint8(consts.MatchType_Port),
				Outbound: uint8(consts.OutboundControlPlaneRouting),
				Value:    portRangeValue(1, 65535),
			},
			{
				Type:     uint8(consts.MatchType_Fallback),
				Outbound: uint8(consts.OutboundDirect),
			},
		},
	}

	src := net.ParseIP("192.0.2.1").To16()
	dst := net.ParseIP("198.51.100.1").To16()
	mac := make([]byte, net.IPv6len)

	outbound, _, _, err := matcher.Match(
		src, dst,
		12345, 443,
		consts.IpVersion_4,
		consts.L4ProtoType_TCP,
		"",
		[16]uint8{},
		0,
		mac,
	)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if outbound != consts.OutboundControlPlaneRouting {
		t.Fatalf("got outbound %v, want control-plane routing", outbound)
	}
}

func portRangeValue(start, end uint16) [16]uint8 {
	var v [16]uint8
	v[0] = byte(start)
	v[1] = byte(start >> 8)
	v[2] = byte(end)
	v[3] = byte(end >> 8)
	return v
}

func formatAnswers(answers []dnsmessage.RR) string {
	parts := make([]string, 0, len(answers))
	for _, ans := range answers {
		parts = append(parts, ans.String())
	}
	return fmt.Sprint(parts)
}
