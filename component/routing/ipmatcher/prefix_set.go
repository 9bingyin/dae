/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package ipmatcher

import (
	"net/netip"

	"github.com/gaissmai/bart"
)

var mappedIPv4Base = [16]byte{10: 0xff, 11: 0xff}

// PrefixSet is a read-optimized userspace IP prefix set backed by BART.
type PrefixSet struct {
	table bart.Lite
}

func NewPrefixSet(prefixes []netip.Prefix) *PrefixSet {
	set := new(PrefixSet)
	for _, prefix := range prefixes {
		set.table.Insert(prefix)
		if projected, ok := projectMappedIPv4Prefix(prefix); ok {
			set.table.Insert(projected)
		}
	}
	return set
}

// Contains reports whether an IP address is covered by the set. Native IPv4
// and IPv4-mapped IPv6 addresses share the same namespace for compatibility
// with the previous 128-bit userspace trie.
func (s *PrefixSet) Contains(addr netip.Addr) bool {
	return s.table.Contains(addr.Unmap())
}

// ContainsRaw reports whether a 128-bit value is covered without unmapping it.
// MAC routing uses this method because a MAC can resemble an IPv4-mapped IP.
func (s *PrefixSet) ContainsRaw(addr netip.Addr) bool {
	return s.table.Contains(addr)
}

func projectMappedIPv4Prefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() || prefix.Addr().Is4() {
		return netip.Prefix{}, false
	}

	bits := prefix.Bits()
	compareBits := min(bits, 96)
	addr := prefix.Addr().As16()
	if !equalLeadingBits(addr, mappedIPv4Base, compareBits) {
		return netip.Prefix{}, false
	}
	if bits <= 96 {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0), true
	}
	return netip.PrefixFrom(netip.AddrFrom4([4]byte(addr[12:])), bits-96), true
}

func equalLeadingBits(a, b [16]byte, n int) bool {
	fullBytes := n / 8
	for i := 0; i < fullBytes; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	if remaining := n % 8; remaining != 0 {
		mask := byte(0xff << (8 - remaining))
		return a[fullBytes]&mask == b[fullBytes]&mask
	}
	return true
}
