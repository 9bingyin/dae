/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package control

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	dnscomponent "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestParseEndpointsSupportsMultipleAddresses(t *testing.T) {
	endpoints, err := ParseEndpoints("tcp+udp://127.0.0.1:5353, udp://192.0.2.1:53 tcp://[::1]:5353")
	if err != nil {
		t.Fatalf("parse endpoints: %v", err)
	}
	if len(endpoints) != 3 {
		t.Fatalf("unexpected endpoint count: got %d, want 3", len(endpoints))
	}

	checks := []Endpoint{
		{TCP: true, UDP: true, Addr: "127.0.0.1:5353"},
		{UDP: true, Addr: "192.0.2.1:53"},
		{TCP: true, Addr: "[::1]:5353"},
	}
	for i, want := range checks {
		if endpoints[i] != want {
			t.Fatalf("endpoint %d: got %+v, want %+v", i, endpoints[i], want)
		}
	}
}

func TestParseEndpointSupportsBareHostPort(t *testing.T) {
	for _, raw := range []string{":53", "localhost:5353", "192.0.2.1:53"} {
		endpoint, err := ParseEndpoint(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if endpoint != (Endpoint{UDP: true, Addr: raw}) {
			t.Fatalf("endpoint for %q: got %+v", raw, endpoint)
		}
	}
}

func TestAddrPortFromNetAddrUsesConcreteListenerAddress(t *testing.T) {
	addr, err := addrPortFromNetAddr(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53})
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}

	want := netip.MustParseAddrPort("192.0.2.1:53")
	if addr != want {
		t.Fatalf("unexpected addr: got %v, want %v", addr, want)
	}
}

func TestWriteDNSResponseUsesResponseWriter(t *testing.T) {
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	writer := new(recordingDNSResponseWriter)

	if err := writeDNSResponse(nil, msg, 0x1234, &udpRequest{}, writer); err != nil {
		t.Fatalf("write dns response: %v", err)
	}
	if writer.msg == nil {
		t.Fatal("response writer was not used")
	}
	if writer.msg.Id != 0x1234 {
		t.Fatalf("unexpected response id: got %d, want %d", writer.msg.Id, 0x1234)
	}
	if !writer.msg.Compress {
		t.Fatal("response should be compressed")
	}
}

func TestWriteDnsCacheToClientPreservesRequestWireContext(t *testing.T) {
	request := new(dnsmessage.Msg)
	request.Id = 0x1234
	request.RecursionDesired = true
	request.CheckingDisabled = true
	request.Question = []dnsmessage.Question{
		{Name: "example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		{Name: "example.net.", Qtype: dnsmessage.TypeAAAA, Qclass: dnsmessage.ClassINET},
	}
	opt := &dnsmessage.OPT{Hdr: dnsmessage.RR_Header{Name: ".", Rrtype: dnsmessage.TypeOPT, Class: 1232}}
	opt.SetDo()
	request.Extra = []dnsmessage.RR{opt}

	cache := &DnsCache{
		Rcode: dnsmessage.RcodeNameError,
	}
	writer := new(recordingDNSResponseWriter)
	controller := &DnsController{}
	if err := controller.writeDnsCacheToClient(cache, request, &udpRequest{}, writer); err != nil {
		t.Fatalf("write DNS cache: %v", err)
	}
	if writer.msg == nil {
		t.Fatal("response writer was not used")
	}
	if writer.msg.Id != request.Id {
		t.Fatalf("response id = %d, want %d", writer.msg.Id, request.Id)
	}
	if !writer.msg.RecursionDesired || !writer.msg.CheckingDisabled {
		t.Fatal("response did not preserve RD/CD request flags")
	}
	if !writer.msg.Response || !writer.msg.RecursionAvailable || writer.msg.Truncated {
		t.Fatal("response did not contain the expected cached response flags")
	}
	if writer.msg.Rcode != dnsmessage.RcodeNameError || len(writer.msg.Answer) != 0 {
		t.Fatalf("cached NXDOMAIN = rcode %d, answers %d", writer.msg.Rcode, len(writer.msg.Answer))
	}
	if len(writer.msg.Question) != len(request.Question) {
		t.Fatalf("response question count = %d, want %d", len(writer.msg.Question), len(request.Question))
	}
	if len(writer.msg.Extra) != 1 {
		t.Fatalf("response extra count = %d, want 1", len(writer.msg.Extra))
	}
	responseOpt, ok := writer.msg.Extra[0].(*dnsmessage.OPT)
	if !ok || !responseOpt.Do() || responseOpt.UDPSize() != 1232 {
		t.Fatalf("response did not preserve EDNS OPT: %#v", writer.msg.Extra[0])
	}
	if request.Response || request.Rcode != dnsmessage.RcodeSuccess || len(request.Answer) != 0 {
		t.Fatal("rendering cache response mutated the request")
	}
}

func TestHandleWithResponseWriterSkipsRejectWhenResponseNotNeeded(t *testing.T) {
	dnsRouting, err := dnscomponent.New(&config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: "reject"},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	}, &dnscomponent.NewOption{
		Logger: logrus.New(),
		UpstreamReadyCallback: func(*dnscomponent.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("new DNS routing: %v", err)
	}

	controller, err := NewDnsController(dnsRouting, &DnsControllerOption{Log: logrus.New()})
	if err != nil {
		t.Fatalf("new DNS controller: %v", err)
	}

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	writer := new(recordingDNSResponseWriter)
	req := &udpRequest{
		realSrc:       netip.MustParseAddrPort("192.0.2.2:12345"),
		realDst:       netip.MustParseAddrPort("192.0.2.1:53"),
		src:           netip.MustParseAddrPort("192.0.2.2:12345"),
		routingResult: &bpfRoutingResult{},
	}

	if err := controller.handleWithResponseWriter_(msg, req, false, writer); err != nil {
		t.Fatalf("handle DNS request: %v", err)
	}
	if writer.msg != nil {
		t.Fatalf("unexpected response: %+v", writer.msg)
	}
}

func TestHandleWithResponseWriterCacheHitBypassesHandlingLock(t *testing.T) {
	dnsRouting, err := dnscomponent.New(&config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: "asis"},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	}, &dnscomponent.NewOption{
		Logger: logrus.New(),
		UpstreamReadyCallback: func(*dnscomponent.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("new DNS routing: %v", err)
	}

	controller, err := NewDnsController(dnsRouting, &DnsControllerOption{Log: logrus.New()})
	if err != nil {
		t.Fatalf("new DNS controller: %v", err)
	}
	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	controller.dnsCache[cacheKey] = &DnsCache{
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    0,
				},
				A: net.ParseIP("192.0.2.10").To4(),
			},
		},
		Deadline:         time.Now().Add(time.Minute),
		OriginalDeadline: time.Now().Add(time.Minute),
	}

	state := new(handlingState)
	state.mu.Lock()
	controller.handling.Store(cacheKey, state)
	defer state.mu.Unlock()

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	writer := new(recordingDNSResponseWriter)
	req := &udpRequest{
		realSrc:       netip.MustParseAddrPort("192.0.2.2:12345"),
		realDst:       netip.MustParseAddrPort("192.0.2.1:53"),
		src:           netip.MustParseAddrPort("192.0.2.2:12345"),
		routingResult: &bpfRoutingResult{},
	}

	done := make(chan error, 1)
	go func() {
		done <- controller.handleWithResponseWriter_(msg, req, true, writer)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handle DNS request: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cache hit waited for the handling lock")
	}
	if writer.msg == nil || len(writer.msg.Answer) != 1 {
		t.Fatalf("unexpected cache response: %+v", writer.msg)
	}
}

func TestDNSListenerStartReturnsListenError(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen occupied port: %v", err)
	}
	defer tcpListener.Close()

	_, port, err := net.SplitHostPort(tcpListener.Addr().String())
	if err != nil {
		t.Fatalf("parse occupied port: %v", err)
	}

	listener := &DNSListener{
		endpoints: []Endpoint{{TCP: true, Addr: fmt.Sprintf("127.0.0.1:%s", port)}},
	}
	if err := listener.Start(); err == nil {
		_ = listener.Stop()
		t.Fatal("expected listen error")
	}
}

func TestDNSListenerStartStopMultipleEndpoints(t *testing.T) {
	listener := &DNSListener{
		log: logrus.New(),
		endpoints: []Endpoint{
			{TCP: true, UDP: true, Addr: "127.0.0.1:0"},
			{UDP: true, Addr: "127.0.0.1:0"},
		},
	}

	if err := listener.Start(); err != nil {
		t.Fatalf("start DNS listener: %v", err)
	}
	if len(listener.servers) != 3 {
		t.Fatalf("unexpected server count: got %d, want 3", len(listener.servers))
	}
	if err := listener.Stop(); err != nil {
		t.Fatalf("stop DNS listener: %v", err)
	}
}

type recordingDNSResponseWriter struct {
	msg *dnsmessage.Msg
}

func (w *recordingDNSResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
}

func (w *recordingDNSResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 12345}
}

func (w *recordingDNSResponseWriter) WriteMsg(msg *dnsmessage.Msg) error {
	copied := *msg
	w.msg = &copied
	return nil
}

func (w *recordingDNSResponseWriter) Write(data []byte) (int, error) {
	return len(data), nil
}

func (w *recordingDNSResponseWriter) Close() error {
	return nil
}

func (w *recordingDNSResponseWriter) TsigStatus() error {
	return nil
}

func (w *recordingDNSResponseWriter) TsigTimersOnly(bool) {}

func (w *recordingDNSResponseWriter) Hijack() {}
