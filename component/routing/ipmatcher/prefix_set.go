/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package ipmatcher

import (
	"net/netip"

	"github.com/gaissmai/bart"
)

var mappedIPv4Prefix = netip.MustParsePrefix("::ffff:0.0.0.0/96")

// PrefixSet is a read-optimized userspace IP prefix set backed by BART.
type PrefixSet struct {
	table bart.Lite
}

// NewPrefixSet builds a prefix set and preserves the legacy mapped IPv4 namespace.
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
	if !prefix.IsValid() || prefix.Addr().Is4() || !prefix.Overlaps(mappedIPv4Prefix) {
		return netip.Prefix{}, false
	}
	if prefix.Bits() <= mappedIPv4Prefix.Bits() {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}

	addr := prefix.Addr().As16()
	return netip.PrefixFrom(netip.AddrFrom4([4]byte(addr[12:])), prefix.Bits()-mappedIPv4Prefix.Bits()), true
}
