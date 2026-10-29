/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package control

import (
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func TestDnsCacheAnswerCopyIsolation(t *testing.T) {
	svcb := func() dnsmessage.SVCB {
		return dnsmessage.SVCB{
			Priority: 1, Target: "svc.example.",
			Value: []dnsmessage.SVCBKeyValue{
				&dnsmessage.SVCBMandatory{Code: []dnsmessage.SVCBKey{dnsmessage.SVCB_ALPN}},
				&dnsmessage.SVCBAlpn{Alpn: []string{"h2"}},
				&dnsmessage.SVCBIPv4Hint{Hint: []net.IP{net.IP{192, 0, 2, 1}}},
				&dnsmessage.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2001:db8::1")}},
				&dnsmessage.SVCBECHConfig{ECH: []byte{1, 2}},
				&dnsmessage.SVCBLocal{KeyCode: 65400, Data: []byte{3, 4}},
			},
		}
	}
	mutateSVCB := func(rr *dnsmessage.SVCB) {
		rr.Target = "changed.example."
		rr.Value[0].(*dnsmessage.SVCBMandatory).Code[0]++
		rr.Value[1].(*dnsmessage.SVCBAlpn).Alpn[0] = "changed"
		rr.Value[2].(*dnsmessage.SVCBIPv4Hint).Hint[0][0]++
		rr.Value[3].(*dnsmessage.SVCBIPv6Hint).Hint[0][0]++
		rr.Value[4].(*dnsmessage.SVCBECHConfig).ECH[0]++
		rr.Value[5].(*dnsmessage.SVCBLocal).Data[0]++
	}
	tests := []struct {
		name   string
		rr     dnsmessage.RR
		mutate func(dnsmessage.RR)
	}{
		{"A", &dnsmessage.A{A: net.IP{192, 0, 2, 1}}, func(rr dnsmessage.RR) { rr.(*dnsmessage.A).A[0]++ }},
		{"AAAA", &dnsmessage.AAAA{AAAA: net.ParseIP("2001:db8::1")}, func(rr dnsmessage.RR) { rr.(*dnsmessage.AAAA).AAAA[0]++ }},
		{"CNAME", &dnsmessage.CNAME{Target: "target.example."}, func(rr dnsmessage.RR) { rr.(*dnsmessage.CNAME).Target = "changed.example." }},
		{"TXT", &dnsmessage.TXT{Txt: []string{"first", "second"}}, func(rr dnsmessage.RR) { rr.(*dnsmessage.TXT).Txt[0] = "changed" }},
		{"SOA", &dnsmessage.SOA{Ns: "ns.example.", Mbox: "host.example.", Serial: 1}, func(rr dnsmessage.RR) { rr.(*dnsmessage.SOA).Serial++ }},
		{"RFC3597", &dnsmessage.RFC3597{Rdata: "0102"}, func(rr dnsmessage.RR) { rr.(*dnsmessage.RFC3597).Rdata = "0304" }},
		{"SVCB", func() dnsmessage.RR { r := svcb(); return &r }(), func(rr dnsmessage.RR) { mutateSVCB(rr.(*dnsmessage.SVCB)) }},
		{"HTTPS", &dnsmessage.HTTPS{SVCB: svcb()}, func(rr dnsmessage.RR) { mutateSVCB(&rr.(*dnsmessage.HTTPS).SVCB) }},
		{"APL", &dnsmessage.APL{Prefixes: []dnsmessage.APLPrefix{{Network: net.IPNet{IP: net.IP{192, 0, 2, 0}, Mask: net.CIDRMask(24, 32)}}}}, func(rr dnsmessage.RR) {
			rr.(*dnsmessage.APL).Prefixes[0].Network.IP[0]++
			rr.(*dnsmessage.APL).Prefixes[0].Network.Mask[0]--
		}},
		{"OPT", &dnsmessage.OPT{Option: []dnsmessage.EDNS0{
			&dnsmessage.EDNS0_SUBNET{Code: dnsmessage.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IP{192, 0, 2, 0}},
			&dnsmessage.EDNS0_DAU{Code: dnsmessage.EDNS0DAU, AlgCode: []uint8{8}},
			&dnsmessage.EDNS0_DHU{Code: dnsmessage.EDNS0DHU, AlgCode: []uint8{2}},
			&dnsmessage.EDNS0_N3U{Code: dnsmessage.EDNS0N3U, AlgCode: []uint8{1}},
			&dnsmessage.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2}},
			&dnsmessage.EDNS0_PADDING{Padding: []byte{0, 0}},
		}}, func(rr dnsmessage.RR) {
			options := rr.(*dnsmessage.OPT).Option
			options[0].(*dnsmessage.EDNS0_SUBNET).Address[0]++
			options[1].(*dnsmessage.EDNS0_DAU).AlgCode[0]++
			options[2].(*dnsmessage.EDNS0_DHU).AlgCode[0]++
			options[3].(*dnsmessage.EDNS0_N3U).AlgCode[0]++
			options[4].(*dnsmessage.EDNS0_LOCAL).Data[0]++
			options[5].(*dnsmessage.EDNS0_PADDING).Padding[0]++
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &DnsCache{Answer: []dnsmessage.RR{tt.rr}, DomainBitmap: []uint32{1, 2}}
			cloned := cloneDnsCache(source)
			if !reflect.DeepEqual(cloned, source) {
				t.Fatal("clone changed cache contents")
			}
			before := source.Answer[0].String()
			tt.mutate(cloned.Answer[0])
			cloned.Answer[0].Header().Name = "changed.example."
			cloned.DomainBitmap[0]++
			if source.Answer[0].String() != before || source.DomainBitmap[0] != 1 {
				t.Fatal("clone mutation changed source cache")
			}

			var msg dnsmessage.Msg
			source.FillInto(&msg)
			if !reflect.DeepEqual(msg.Answer, source.Answer) {
				t.Fatal("FillInto changed answer contents")
			}
			tt.mutate(msg.Answer[0])
			if source.Answer[0].String() != before {
				t.Fatal("response mutation changed source cache")
			}
			beforeClone := cloned.Answer[0].String()
			beforeMsg := msg.Answer[0].String()
			tt.mutate(source.Answer[0])
			tt.mutate(source.Answer[0])
			if cloned.Answer[0].String() != beforeClone || msg.Answer[0].String() != beforeMsg {
				t.Fatal("source mutation changed clone or response")
			}
		})
	}
}

func TestDnsCacheCopySliceShape(t *testing.T) {
	for _, answer := range [][]dnsmessage.RR{nil, {}, {nil}} {
		cache := &DnsCache{Answer: answer, DomainBitmap: []uint32{}}
		cloned := cloneDnsCache(cache)
		if !reflect.DeepEqual(cloned, cache) {
			t.Fatalf("clone changed nil/empty shape: got %#v, want %#v", cloned, cache)
		}
		var msg dnsmessage.Msg
		cache.FillInto(&msg)
		if !reflect.DeepEqual(msg.Answer, answer) {
			t.Fatalf("FillInto changed nil/empty shape: got %#v, want %#v", msg.Answer, answer)
		}
	}
	if cloneDnsCache(nil) != nil {
		t.Fatal("nil cache should remain nil")
	}
}

func TestDnsCacheCopyNestedSliceShape(t *testing.T) {
	records := []dnsmessage.RR{
		&dnsmessage.A{}, &dnsmessage.A{A: net.IP{}},
		&dnsmessage.AAAA{}, &dnsmessage.AAAA{AAAA: net.IP{}},
		&dnsmessage.TXT{}, &dnsmessage.TXT{Txt: []string{}},
		&dnsmessage.SVCB{}, &dnsmessage.SVCB{Value: []dnsmessage.SVCBKeyValue{}},
		&dnsmessage.HTTPS{}, &dnsmessage.HTTPS{SVCB: dnsmessage.SVCB{Value: []dnsmessage.SVCBKeyValue{}}},
		&dnsmessage.SVCB{Value: []dnsmessage.SVCBKeyValue{
			&dnsmessage.SVCBAlpn{Alpn: []string{}},
			&dnsmessage.SVCBECHConfig{ECH: []byte{}},
			&dnsmessage.SVCBIPv4Hint{Hint: []net.IP{nil, {}}},
		}},
		&dnsmessage.OPT{}, &dnsmessage.OPT{Option: []dnsmessage.EDNS0{}},
		&dnsmessage.OPT{Option: []dnsmessage.EDNS0{
			&dnsmessage.EDNS0_SUBNET{Address: net.IP{}},
			&dnsmessage.EDNS0_DAU{AlgCode: []uint8{}},
			&dnsmessage.EDNS0_DHU{AlgCode: []uint8{}},
			&dnsmessage.EDNS0_N3U{AlgCode: []uint8{}},
			&dnsmessage.EDNS0_LOCAL{Data: []byte{}},
			&dnsmessage.EDNS0_PADDING{Padding: []byte{}},
		}},
		&dnsmessage.APL{}, &dnsmessage.APL{Prefixes: []dnsmessage.APLPrefix{}},
	}
	for _, record := range records {
		cache := &DnsCache{Answer: []dnsmessage.RR{record}}
		if cloned := cloneDnsCache(cache); !reflect.DeepEqual(cloned, cache) {
			t.Fatalf("clone changed nested nil/empty slices in %T: got %#v, want %#v", record, cloned.Answer[0], record)
		}
		var msg dnsmessage.Msg
		cache.FillInto(&msg)
		if !reflect.DeepEqual(msg.Answer, cache.Answer) {
			t.Fatalf("FillInto changed nested nil/empty slices in %T: got %#v, want %#v", record, msg.Answer[0], record)
		}
	}
}

func TestDnsCacheFillIntoPreservesOtherFields(t *testing.T) {
	msg := dnsmessage.Msg{
		MsgHdr:   dnsmessage.MsgHdr{Id: 42, Opcode: dnsmessage.OpcodeQuery, Authoritative: true, RecursionDesired: true, CheckingDisabled: true, AuthenticatedData: true, Zero: true, Truncated: true},
		Compress: true,
		Question: []dnsmessage.Question{{Name: "example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET}},
		Ns:       []dnsmessage.RR{&dnsmessage.SOA{Ns: "ns.example."}},
		Extra:    []dnsmessage.RR{&dnsmessage.TXT{Txt: []string{"extra"}}},
	}
	want := msg
	cache := benchmarkDnsCacheCopyInput()
	cache.Rcode = dnsmessage.RcodeNameError
	want.Answer = cache.Answer
	want.Rcode = cache.Rcode
	want.Response = true
	want.RecursionAvailable = true
	want.Truncated = false
	cache.FillInto(&msg)
	if !reflect.DeepEqual(msg, want) {
		t.Fatalf("FillInto changed unrelated fields: got %#v, want %#v", msg, want)
	}
}

func TestDnsCacheImportCopyIsolation(t *testing.T) {
	controller, err := NewDnsController(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cache := benchmarkDnsCacheCopyInput()
	cache.CacheKey = controller.cacheKey("example.com.", dnsmessage.TypeA)
	imported, err := controller.ImportDnsCache(map[string]*DnsCache{cache.CacheKey: cache})
	if err != nil || len(imported) != 1 {
		t.Fatalf("import cache: count=%d, err=%v", len(imported), err)
	}
	before := imported[0].Answer[0].String()
	cache.Answer[0].(*dnsmessage.A).A[0]++
	imported[0].Answer[0].(*dnsmessage.A).A[0]++
	got := controller.LookupDnsRespCache(cache.CacheKey, false)
	if got == nil || got.Answer[0].String() != before {
		t.Fatal("imported cache shares answer with source or returned snapshot")
	}
}

func TestDnsCacheSnapshotConcurrentPublication(t *testing.T) {
	controller, err := NewDnsController(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := benchmarkDnsCacheCopyInput()
	key := controller.cacheKey("example.com.", dnsmessage.TypeA)
	if err := controller.UpdateDnsCacheTtl("example.com.", dnsmessage.TypeA, input.Answer, 60); err != nil {
		t.Fatal(err)
	}
	before := input.Answer[0].String()
	input.Answer[0].(*dnsmessage.A).A[0]++
	snapshot := controller.cloneDnsCache()
	snapshot[key].Answer[0].(*dnsmessage.A).A[0]++
	delete(snapshot, key)
	lookup := controller.LookupDnsRespCache(key, false)
	if lookup == nil || lookup.Answer[0].String() != before {
		t.Fatal("published cache shares answer with update input or snapshot")
	}
	lookup.Answer[0].(*dnsmessage.A).A[0]++
	lookup = controller.LookupDnsRespCache(key, false)
	if lookup == nil || lookup.Answer[0].String() != before {
		t.Fatal("lookup mutation changed published cache")
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			if err := controller.UpdateDnsCacheTtl("example.com.", dnsmessage.TypeA, input.Answer, 60); err != nil {
				t.Errorf("update cache: %v", err)
				return
			}
			controller.RemoveDnsRespCache(controller.cacheKey("example.com.", dnsmessage.TypeA))
		}
	})
	for range 100 {
		for _, cache := range controller.cloneDnsCache() {
			cache.Answer[0].(*dnsmessage.A).A[0]++
		}
	}
	wg.Wait()
}

func benchmarkDnsCacheCopyInput() *DnsCache {
	answer := make([]dnsmessage.RR, 4)
	for i := range answer {
		answer[i] = &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
			A:   net.IP{192, 0, 2, byte(i + 1)},
		}
	}
	deadline := time.Now().Add(time.Hour)
	return &DnsCache{Answer: answer, DomainBitmap: []uint32{1}, Deadline: deadline, OriginalDeadline: deadline}
}

func BenchmarkDnsCacheCopy(b *testing.B) {
	cache := benchmarkDnsCacheCopyInput()
	var msg dnsmessage.Msg
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		cloneDnsCache(cache).FillInto(&msg)
	}
}

func BenchmarkDnsCacheLookupFillInto(b *testing.B) {
	controller, err := NewDnsController(nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	cache := benchmarkDnsCacheCopyInput()
	key := controller.cacheKey("example.com.", dnsmessage.TypeA)
	controller.dnsCache[key] = cache
	var msg dnsmessage.Msg
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		controller.LookupDnsRespCache(key, false).FillInto(&msg)
	}
}
