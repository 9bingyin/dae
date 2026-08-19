/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func testPacketSnifferKey(port uint16) PacketSnifferKey {
	return PacketSnifferKey{
		LAddr: netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), port),
		RAddr: netip.MustParseAddrPort("2.2.2.2:443"),
	}
}

func TestPacketSnifferTimeoutReturnsHeldPacketsInOrder(t *testing.T) {
	manager := NewPacketSnifferPool()
	key := testPacketSnifferKey(1111)
	timedOut := make(chan *PacketSniffer, 1)
	sniffer, _ := manager.GetOrCreate(key, &PacketSnifferOptions{
		Timeout: 10 * time.Millisecond,
		OnTimeout: func(expired *PacketSniffer) {
			timedOut <- expired
		},
	})
	sniffer.Mu.Lock()
	if err := sniffer.HoldLocked([]byte("first")); err != nil {
		sniffer.Mu.Unlock()
		t.Fatal(err)
	}
	if err := sniffer.HoldLocked([]byte("second")); err != nil {
		sniffer.Mu.Unlock()
		t.Fatal(err)
	}
	sniffer.Mu.Unlock()

	var expired *PacketSniffer
	select {
	case expired = <-timedOut:
	case <-time.After(time.Second):
		t.Fatal("packet sniffer did not reach its deadline")
	}
	if got := manager.Get(key); got != sniffer {
		t.Fatal("deadline callback removed the session outside the UDP task queue")
	}
	packets := manager.expire(key, expired)
	defer putHeldPackets(packets)
	if len(packets) != 2 || string(packets[0]) != "first" || string(packets[1]) != "second" {
		t.Fatalf("timed out packets = %q", packets)
	}
	if got := manager.Get(key); got != nil {
		t.Fatal("expired packet sniffer remains in pool")
	}
}

func TestPacketSnifferHeldPacketLimits(t *testing.T) {
	t.Run("datagrams", func(t *testing.T) {
		manager := NewPacketSnifferPool()
		key := testPacketSnifferKey(1111)
		sniffer, _ := manager.GetOrCreate(key, &PacketSnifferOptions{Timeout: time.Hour})
		sniffer.Mu.Lock()
		for range maxQuicHeldDatagrams {
			if err := sniffer.HoldLocked([]byte{1}); err != nil {
				sniffer.Mu.Unlock()
				t.Fatal(err)
			}
		}
		if err := sniffer.HoldLocked([]byte{1}); err == nil {
			sniffer.Mu.Unlock()
			t.Fatal("expected held datagram limit error")
		}
		sniffer.Mu.Unlock()
		if err := manager.Remove(key, sniffer); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("bytes", func(t *testing.T) {
		manager := NewPacketSnifferPool()
		key := testPacketSnifferKey(1112)
		sniffer, _ := manager.GetOrCreate(key, &PacketSnifferOptions{Timeout: time.Hour})
		sniffer.Mu.Lock()
		if err := sniffer.HoldLocked(make([]byte, maxQuicHeldBytes)); err != nil {
			sniffer.Mu.Unlock()
			t.Fatal(err)
		}
		if err := sniffer.HoldLocked([]byte{1}); err == nil {
			sniffer.Mu.Unlock()
			t.Fatal("expected held byte limit error")
		}
		sniffer.Mu.Unlock()
		if err := manager.Remove(key, sniffer); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPacketSnifferRequiresTimeout(t *testing.T) {
	manager := NewPacketSnifferPool()
	key := testPacketSnifferKey(1111)

	if sniffer, created := manager.GetOrCreate(key, nil); sniffer != nil || created {
		t.Fatal("packet sniffer was created without options")
	}
	if sniffer, created := manager.GetOrCreate(key, &PacketSnifferOptions{}); sniffer != nil || created {
		t.Fatal("packet sniffer was created with a zero timeout")
	}
}

func TestPacketSnifferStaleExpiryDoesNotDeleteReplacement(t *testing.T) {
	manager := NewPacketSnifferPool()
	key := testPacketSnifferKey(1111)
	old, _ := manager.GetOrCreate(key, &PacketSnifferOptions{Timeout: time.Hour})
	if err := manager.Remove(key, old); err != nil {
		t.Fatal(err)
	}
	replacement, _ := manager.GetOrCreate(key, &PacketSnifferOptions{Timeout: time.Hour})

	putHeldPackets(manager.expire(key, old))
	if got := manager.Get(key); got != replacement {
		t.Fatalf("replacement was removed by stale expiry: got %p, want %p", got, replacement)
	}
	if err := manager.Remove(key, replacement); err != nil {
		t.Fatal(err)
	}
}

func TestPacketSnifferConcurrentCreationUsesOneSession(t *testing.T) {
	const workers = 64
	manager := NewPacketSnifferPool()
	key := testPacketSnifferKey(1111)
	type result struct {
		sniffer *PacketSniffer
		created bool
	}
	results := make(chan result, workers)
	start := make(chan struct{})

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			sniffer, created := manager.GetOrCreate(key, &PacketSnifferOptions{Timeout: time.Hour})
			results <- result{sniffer: sniffer, created: created}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var first *PacketSniffer
	created := 0
	for result := range results {
		if first == nil {
			first = result.sniffer
		}
		if result.sniffer != first {
			t.Fatal("concurrent creation returned different sessions")
		}
		if result.created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created sessions = %d, want 1", created)
	}
	if err := manager.Remove(key, first); err != nil {
		t.Fatal(err)
	}
}
