/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type dnsCacheUpdate struct {
	oldCache *DnsCache
	newCache *DnsCache
}

type dnsCacheLifecycleRecorder struct {
	updates []dnsCacheUpdate
	removed []*DnsCache
}

func TestDnsCacheUpdateCallbackReceivesReplace(t *testing.T) {
	recorder := new(dnsCacheLifecycleRecorder)
	controller := newDnsCacheLifecycleController(t, recorder)

	updateTestDnsCache(t, controller, "192.0.2.1", 60)
	updateTestDnsCache(t, controller, "192.0.2.2", 60)

	if len(recorder.updates) != 2 {
		t.Fatalf("unexpected update count: got %d, want 2", len(recorder.updates))
	}
	if recorder.updates[0].oldCache != nil {
		t.Fatal("first update should not have old cache")
	}
	if recorder.updates[0].newCache.CacheKey == "" {
		t.Fatal("new cache should have cache key")
	}
	if !recorder.updates[0].newCache.IncludeIp(testAddr("192.0.2.1")) {
		t.Fatal("first update should include first IP")
	}
	if !recorder.updates[1].oldCache.IncludeIp(testAddr("192.0.2.1")) {
		t.Fatal("second update old cache should include first IP")
	}
	if !recorder.updates[1].newCache.IncludeIp(testAddr("192.0.2.2")) {
		t.Fatal("second update new cache should include second IP")
	}
}

func TestDnsCacheRemoveCallback(t *testing.T) {
	recorder := new(dnsCacheLifecycleRecorder)
	controller := newDnsCacheLifecycleController(t, recorder)

	updateTestDnsCache(t, controller, "192.0.2.1", 60)
	controller.RemoveDnsRespCache(controller.cacheKey("example.com.", dnsmessage.TypeA))

	assertRemovedCache(t, recorder.removed, "192.0.2.1")
}

func TestDnsCacheExpiredLookupRemovesMapping(t *testing.T) {
	recorder := new(dnsCacheLifecycleRecorder)
	controller := newDnsCacheLifecycleController(t, recorder)

	updateTestDnsCache(t, controller, "192.0.2.1", -1)
	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	if cache := controller.LookupDnsRespCache(cacheKey, false); cache != nil {
		t.Fatal("expired cache lookup should miss")
	}

	assertRemovedCache(t, recorder.removed, "192.0.2.1")
}

func TestDnsCacheImportRebuildsDomainBitmap(t *testing.T) {
	recorder := new(dnsCacheLifecycleRecorder)
	controller := newDnsCacheLifecycleControllerWithBitmap(t, recorder, testDomainBitmap(1))
	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	deadline := time.Now().Add(time.Minute)
	caches := map[string]*DnsCache{
		cacheKey: newTestImportDnsCache(cacheKey, deadline, deadline),
	}

	imported, err := controller.ImportDnsCache(caches)
	if err != nil {
		t.Fatalf("import DNS cache: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("imported count: got %d, want 1", len(imported))
	}

	cache := controller.LookupDnsRespCache(cacheKey, false)
	if cache == nil {
		t.Fatal("imported cache should be available")
	}
	assertDomainBitmapBit(t, cache.DomainBitmap, 0, false)
	assertDomainBitmapBit(t, cache.DomainBitmap, 1, true)
	if len(recorder.updates) != 1 {
		t.Fatalf("unexpected update count: got %d, want 1", len(recorder.updates))
	}
	if recorder.updates[0].newCache.CacheKey != cacheKey {
		t.Fatalf("imported cache key: got %q, want %q", recorder.updates[0].newCache.CacheKey, cacheKey)
	}
}

func TestDnsCacheImportSkipsExpiredCache(t *testing.T) {
	recorder := new(dnsCacheLifecycleRecorder)
	controller := newDnsCacheLifecycleController(t, recorder)
	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	deadline := time.Now().Add(-time.Minute)
	caches := map[string]*DnsCache{
		cacheKey: newTestImportDnsCache(cacheKey, deadline, deadline),
	}

	imported, err := controller.ImportDnsCache(caches)
	if err != nil {
		t.Fatalf("import DNS cache: %v", err)
	}
	if len(imported) != 0 {
		t.Fatalf("imported count: got %d, want 0", len(imported))
	}
	if cache := controller.LookupDnsRespCache(cacheKey, false); cache != nil {
		t.Fatal("expired cache should not be imported")
	}
	if len(recorder.updates) != 0 {
		t.Fatalf("unexpected update count: got %d, want 0", len(recorder.updates))
	}
}

func TestDnsCacheImportSkipsInvalidCacheKey(t *testing.T) {
	recorder := new(dnsCacheLifecycleRecorder)
	controller := newDnsCacheLifecycleController(t, recorder)
	deadline := time.Now().Add(time.Minute)
	caches := map[string]*DnsCache{
		"invalid": newTestImportDnsCache("invalid", deadline, deadline),
	}

	imported, err := controller.ImportDnsCache(caches)
	if err != nil {
		t.Fatalf("import DNS cache: %v", err)
	}
	if len(imported) != 0 {
		t.Fatalf("imported count: got %d, want 0", len(imported))
	}
	if len(recorder.updates) != 0 {
		t.Fatalf("unexpected update count: got %d, want 0", len(recorder.updates))
	}
}

func TestDnsCacheImportKeepsOriginalDeadlineCache(t *testing.T) {
	recorder := new(dnsCacheLifecycleRecorder)
	controller := newDnsCacheLifecycleController(t, recorder)
	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	deadline := time.Now().Add(-time.Minute)
	originalDeadline := time.Now().Add(time.Minute)
	caches := map[string]*DnsCache{
		cacheKey: newTestImportDnsCache(cacheKey, deadline, originalDeadline),
	}

	imported, err := controller.ImportDnsCache(caches)
	if err != nil {
		t.Fatalf("import DNS cache: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("imported count: got %d, want 1", len(imported))
	}
	if cache := controller.LookupDnsRespCache(cacheKey, true); cache == nil {
		t.Fatal("cache with live original deadline should be available when fixed TTL is ignored")
	}
}

func newDnsCacheLifecycleController(t *testing.T, recorder *dnsCacheLifecycleRecorder) *DnsController {
	t.Helper()
	return newDnsCacheLifecycleControllerWithBitmap(t, recorder, testDomainBitmap(0))
}

func newDnsCacheLifecycleControllerWithBitmap(t *testing.T, recorder *dnsCacheLifecycleRecorder, bitmap []uint32) *DnsController {
	t.Helper()

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				DomainBitmap:     bitmap,
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		CacheUpdateCallback: func(oldCache, newCache *DnsCache) error {
			recorder.updates = append(recorder.updates, dnsCacheUpdate{
				oldCache: cloneDnsCache(oldCache),
				newCache: cloneDnsCache(newCache),
			})
			return nil
		},
		CacheRemoveCallback: func(cache *DnsCache) error {
			recorder.removed = append(recorder.removed, cloneDnsCache(cache))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("new DNS controller: %v", err)
	}
	return controller
}

func updateTestDnsCache(t *testing.T, controller *DnsController, ip string, ttl int) {
	t.Helper()

	cache := testDnsCache("", testDomainBitmap(0), ip)
	if err := controller.UpdateDnsCacheTtl("example.com", dnsmessage.TypeA, cache.Answer, ttl); err != nil {
		t.Fatalf("update DNS cache: %v", err)
	}
}

func newTestImportDnsCache(cacheKey string, deadline time.Time, originalDeadline time.Time) *DnsCache {
	return &DnsCache{
		CacheKey:         cacheKey,
		DomainBitmap:     testDomainBitmap(0),
		Answer:           testDnsCache("", nil, "192.0.2.1").Answer,
		Deadline:         deadline,
		OriginalDeadline: originalDeadline,
	}
}

func assertRemovedCache(t *testing.T, removed []*DnsCache, ip string) {
	t.Helper()

	if len(removed) != 1 {
		t.Fatalf("unexpected remove count: got %d, want 1", len(removed))
	}
	if removed[0].CacheKey == "" {
		t.Fatal("removed cache should have cache key")
	}
	if !removed[0].IncludeIp(testAddr(ip)) {
		t.Fatalf("removed cache should include %s", ip)
	}
}

func assertDomainBitmapBit(t *testing.T, bitmap []uint32, bit int, want bool) {
	t.Helper()
	got := bitmap[bit/32]&(1<<(bit%32)) != 0
	if got != want {
		t.Fatalf("domain bitmap bit %d: got %v, want %v", bit, got, want)
	}
}
