/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/ipmatcher"
)

type RoutingMatcher struct {
	lpmMatcher    []*ipmatcher.PrefixSet
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.

	matches []bpfMatchSet
}

// Match is modified from kern/tproxy.c; please keep sync.
func (m *RoutingMatcher) Match(
	sourceAddr []byte,
	destAddr []byte,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	tos uint8,
	mac []byte,
) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	if len(sourceAddr) != net.IPv6len || len(destAddr) != net.IPv6len || len(mac) != net.IPv6len {
		return 0, 0, false, fmt.Errorf("bad address length")
	}

	var lpmAddrs [consts.MatchType_Mac + 1]netip.Addr
	var lpmAddrPrepared [consts.MatchType_Mac + 1]bool
	var preparedDomain routing.PreparedDomain
	domainPrepared := false

	goodSubrule := false
	badRule := false
	for i, match := range m.matches {
		matchType := consts.MatchType(match.Type)
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch matchType {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
			if !lpmAddrPrepared[matchType] {
				switch matchType {
				case consts.MatchType_IpSet:
					lpmAddrs[matchType] = netip.AddrFrom16(*(*[16]byte)(destAddr))
				case consts.MatchType_SourceIpSet:
					lpmAddrs[matchType] = netip.AddrFrom16(*(*[16]byte)(sourceAddr))
				case consts.MatchType_Mac:
					lpmAddrs[matchType] = netip.AddrFrom16(*(*[16]byte)(mac))
				}
				lpmAddrPrepared[matchType] = true
			}
			lpmIndex := binary.LittleEndian.Uint16(match.Value[:])
			if matchType == consts.MatchType_Mac {
				goodSubrule = m.lpmMatcher[lpmIndex].ContainsRaw(lpmAddrs[matchType])
			} else {
				goodSubrule = m.lpmMatcher[lpmIndex].Contains(lpmAddrs[matchType])
			}
		case consts.MatchType_DomainSet:
			if domain != "" {
				if !domainPrepared {
					preparedDomain = routing.PrepareDomain(domain)
					domainPrepared = true
				}
				if m.domainMatcher.MatchPreparedDomain(&preparedDomain, i) {
					goodSubrule = true
				}
			}
		case consts.MatchType_Port:
			portStart, portEnd := ParsePortRange(match.Value[:])
			if destPort >= portStart &&
				destPort <= portEnd {
				goodSubrule = true
			}
		case consts.MatchType_SourcePort:
			portStart, portEnd := ParsePortRange(match.Value[:])
			if sourcePort >= portStart &&
				sourcePort <= portEnd {
				goodSubrule = true
			}
		case consts.MatchType_IpVersion:
			// LittleEndian
			if ipVersion&consts.IpVersionType(match.Value[0]) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_L4Proto:
			// LittleEndian
			if l4proto&consts.L4ProtoType(match.Value[0]) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_ProcessName:
			if processName[0] != 0 && match.Value == processName {
				goodSubrule = true
			}
		case consts.MatchType_Dscp:
			if tos == match.Value[0] {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		default:
			return 0, 0, false, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		outbound := consts.OutboundIndex(match.Outbound)
		if outbound != consts.OutboundLogicalOr {
			// This match_set reaches the end of subrule.
			// We are now at end of rule, or next match_set belongs to another
			// subrule.

			if goodSubrule == match.Not {
				// This subrule does not hit.
				badRule = true
			}

			// Reset goodSubrule.
			goodSubrule = false
		}

		if outbound&consts.OutboundLogicalMask !=
			consts.OutboundLogicalMask {
			// Tail of a rule (line).
			// Decide whether to hit.
			if !badRule {
				if outbound == consts.OutboundMustRules {
					must = true
					continue
				}
				// Keep sync with kern/tproxy.c: control-plane / bump is a terminal hit.
				if outbound == consts.OutboundControlPlaneRouting {
					if must {
						match.Must = true
					}
					return outbound, match.Mark, must || match.Must, nil
				}
				if must {
					match.Must = true
				}
				return outbound, match.Mark, match.Must, nil
			}
			badRule = false
		}
	}
	return 0, 0, false, fmt.Errorf("no match set hit")
}
