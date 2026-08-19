/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/pool"
)

const (
	MaxQuicHeldDatagrams  = 16
	MaxQuicHeldBytes      = 32 << 10
	MaxActiveQuicSniffers = 1024
)

type PacketSniffer struct {
	Sniffer *sniffing.QuicSniffer
	Mu      sync.Mutex

	deadlineTimer *time.Timer
	heldPackets   []pool.PB
	heldBytes     int
	onTimeout     func(*PacketSniffer)
	closed        bool
}

type PacketSnifferPool struct {
	pool      sync.Map
	createMu  sync.Mutex
	active    atomic.Int64
	maxActive int64
}

type PacketSnifferOptions struct {
	Timeout   time.Duration
	OnTimeout func(*PacketSniffer)
}

type PacketSnifferKey struct {
	LAddr netip.AddrPort
	RAddr netip.AddrPort
}

var DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()

func NewPacketSnifferPool() *PacketSnifferPool {
	return newPacketSnifferPool(MaxActiveQuicSniffers)
}

func newPacketSnifferPool(maxActive int64) *PacketSnifferPool {
	return &PacketSnifferPool{maxActive: maxActive}
}

func (p *PacketSnifferPool) Remove(key PacketSnifferKey, sniffer *PacketSniffer) error {
	sniffer.Mu.Lock()
	defer sniffer.Mu.Unlock()
	if !p.removeLocked(key, sniffer) {
		return fmt.Errorf("packet sniffer is not in the pool")
	}
	sniffer.releaseHeldLocked()
	return sniffer.closeLocked()
}

func (p *PacketSnifferPool) removeLocked(key PacketSnifferKey, sniffer *PacketSniffer) bool {
	if !p.pool.CompareAndDelete(key, sniffer) {
		return false
	}
	p.active.Add(-1)
	if sniffer.deadlineTimer != nil {
		sniffer.deadlineTimer.Stop()
		sniffer.deadlineTimer = nil
	}
	return true
}

func (p *PacketSnifferPool) Get(key PacketSnifferKey) *PacketSniffer {
	value, ok := p.pool.Load(key)
	if !ok {
		return nil
	}
	return value.(*PacketSniffer)
}

func (p *PacketSnifferPool) GetOrCreate(key PacketSnifferKey, options *PacketSnifferOptions) (*PacketSniffer, bool) {
	if value, ok := p.pool.Load(key); ok {
		return value.(*PacketSniffer), false
	}

	p.createMu.Lock()
	defer p.createMu.Unlock()

	if value, ok := p.pool.Load(key); ok {
		return value.(*PacketSniffer), false
	}
	if p.maxActive > 0 && p.active.Load() >= p.maxActive {
		return nil, false
	}
	if options == nil || options.Timeout <= 0 {
		return nil, false
	}

	sniffer := &PacketSniffer{
		Sniffer:   sniffing.NewQuicSniffer(),
		onTimeout: options.OnTimeout,
	}
	// Publish the session while holding its mutex so consumers cannot finish it
	// before the expiry timer has been installed.
	sniffer.Mu.Lock()
	sniffer.deadlineTimer = time.AfterFunc(options.Timeout, func() {
		if sniffer.onTimeout != nil {
			sniffer.onTimeout(sniffer)
			return
		}
		putHeldPackets(p.expire(key, sniffer))
	})
	p.active.Add(1)
	p.pool.Store(key, sniffer)
	sniffer.Mu.Unlock()
	return sniffer, true
}

func (p *PacketSnifferPool) expire(key PacketSnifferKey, sniffer *PacketSniffer) []pool.PB {
	sniffer.Mu.Lock()
	defer sniffer.Mu.Unlock()
	if !p.removeLocked(key, sniffer) {
		return nil
	}
	packets := sniffer.takeHeldLocked()
	_ = sniffer.closeLocked()
	return packets
}

func (s *PacketSniffer) HoldLocked(data []byte) error {
	if s.closed {
		return fmt.Errorf("packet sniffer is closed")
	}
	if len(s.heldPackets) >= MaxQuicHeldDatagrams || len(data) > MaxQuicHeldBytes-s.heldBytes {
		return fmt.Errorf("quic held packet limit exceeded")
	}
	packet := pool.Get(len(data))
	copy(packet, data)
	s.heldPackets = append(s.heldPackets, packet)
	s.heldBytes += len(packet)
	return nil
}

func (s *PacketSniffer) TakeHeldLocked() []pool.PB {
	return s.takeHeldLocked()
}

func (s *PacketSniffer) takeHeldLocked() []pool.PB {
	packets := s.heldPackets
	s.heldPackets = nil
	s.heldBytes = 0
	return packets
}

func (s *PacketSniffer) releaseHeldLocked() {
	putHeldPackets(s.takeHeldLocked())
}

func (s *PacketSniffer) closeLocked() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.deadlineTimer != nil {
		s.deadlineTimer.Stop()
		s.deadlineTimer = nil
	}
	return s.Sniffer.Close()
}

func putHeldPackets(packets []pool.PB) {
	for _, packet := range packets {
		packet.Put()
	}
}
