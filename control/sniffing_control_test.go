/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package control

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

type sniffingTestConn struct {
	net.Conn
	reader *bytes.Reader
	reads  int
}

func (c *sniffingTestConn) Read(p []byte) (int, error) {
	c.reads++
	return c.reader.Read(p)
}

func (c *sniffingTestConn) Close() error { return nil }

func TestSniffTCPSkipIPDoesNotRead(t *testing.T) {
	payload := []byte("not a TLS handshake")
	conn := &sniffingTestConn{reader: bytes.NewReader(payload)}
	plane := &ControlPlane{
		sniffingTimeout: time.Second,
		sniffingMatcher: sniffingMatcherForTest(t, "dip(192.0.2.0/24) -> skip"),
	}
	relay, domain, err := plane.sniffTCP(conn, netip.MustParseAddrPort("192.0.2.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	if relay != conn || domain != "" || conn.reads != 0 {
		t.Fatalf("skip returned relay=%T domain=%q reads=%d", relay, domain, conn.reads)
	}
	got, err := io.ReadAll(relay)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relayed payload = %q, want %q", got, payload)
	}
}

func TestSniffTCPDomainExclusionsKeepPayload(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: push.apple.com\r\n\r\npayload")
	dst := netip.MustParseAddrPort("192.0.2.1:80")
	for _, tt := range []struct {
		name   string
		rules  string
		domain string
	}{
		{name: "default", domain: "push.apple.com"},
		{name: "excluded", rules: "domain(suffix: apple.com) -> skip"},
		{name: "unmatched", rules: "domain(full: example.com) -> skip", domain: "push.apple.com"},
		{name: "mixed excluded", rules: "domain(suffix: apple.com) && dip(192.0.2.0/24) -> skip"},
		{name: "mixed unmatched", rules: "domain(suffix: apple.com) && dip(198.51.100.0/24) -> skip", domain: "push.apple.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := &sniffingTestConn{reader: bytes.NewReader(payload)}
			plane := &ControlPlane{
				log:             sniffingLogForTest(),
				dialMode:        consts.DialMode_DomainCao,
				sniffingTimeout: time.Second,
			}
			if tt.rules != "" {
				plane.sniffingMatcher = sniffingMatcherForTest(t, tt.rules)
			}
			relay, domain, err := plane.sniffTCP(conn, dst)
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Close()
			if domain != tt.domain {
				t.Fatalf("domain = %q, want %q", domain, tt.domain)
			}
			got, err := io.ReadAll(relay)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("relayed payload = %q, want %q", got, payload)
			}
			if domain == "" {
				target, reroute, dialIP := plane.ChooseDialTarget(consts.OutboundUserDefinedMin, dst, domain)
				if target != dst.String() || reroute || !dialIP {
					t.Fatalf("excluded domain changed target: target=%q reroute=%v dialIP=%v", target, reroute, dialIP)
				}
			}
		})
	}
}

func TestSniffUDPSkipIPDrainsPendingSession(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.201:51321")
	dst := netip.MustParseAddrPort("198.51.100.1:443")
	key := PacketSnifferKey{LAddr: src, RAddr: dst}
	pending, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, &PacketSnifferOptions{Timeout: time.Hour})
	t.Cleanup(func() {
		if DefaultPacketSnifferSessionMgr.Get(key) == pending {
			_ = DefaultPacketSnifferSessionMgr.Remove(key, pending)
		}
	})
	pending.Mu.Lock()
	err := pending.HoldLocked([]byte("buffered before reload"))
	pending.Mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	plane := &ControlPlane{
		log:             sniffingLogForTest(),
		sniffingTimeout: time.Second,
		sniffingMatcher: sniffingMatcherForTest(t, "dip(198.51.100.0/24) -> skip"),
	}
	// With no configured outbounds, forwarding fails before opening a socket.
	err = plane.handlePkt(nil, []byte("current packet"), src, dst, dst, &bpfRoutingResult{}, false, "")
	if err == nil {
		t.Fatal("expected forwarding to fail without outbounds")
	}
	if DefaultPacketSnifferSessionMgr.Get(key) != nil {
		t.Fatal("skipped flow retained a pending QUIC sniffer")
	}
	pending.Mu.Lock()
	defer pending.Mu.Unlock()
	if !pending.closed || len(pending.heldPackets) != 0 || pending.deadlineTimer != nil {
		t.Fatal("pending QUIC state was not released")
	}
}
