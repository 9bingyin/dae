/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 * Copyright (c) 2026, 9bingyin
 */

package control

import (
	"net/netip"
	"slices"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
)

type DnsCache struct {
	CacheKey         string
	DomainBitmap     []uint32
	Answer           []dnsmessage.RR
	Rcode            int // DNS RCODE; 0 (RcodeSuccess) for positive/NODATA answers.
	Deadline         time.Time
	OriginalDeadline time.Time // This field is not impacted by `fixed_domain_ttl`.
}

func copyDnsAnswers(answers []dnsmessage.RR) []dnsmessage.RR {
	if answers == nil {
		return nil
	}
	copied := make([]dnsmessage.RR, len(answers))
	for i, answer := range answers {
		switch answer := answer.(type) {
		case nil:
		case *dnsmessage.A:
			cloned := *answer
			cloned.A = slices.Clone(answer.A)
			copied[i] = &cloned
		case *dnsmessage.AAAA:
			cloned := *answer
			cloned.AAAA = slices.Clone(answer.AAAA)
			copied[i] = &cloned
		case *dnsmessage.CNAME, *dnsmessage.NS, *dnsmessage.MX, *dnsmessage.SOA, *dnsmessage.PTR, *dnsmessage.DNAME:
			copied[i] = dnsmessage.Copy(answer)
		default:
			// Preserve nested slice shapes and isolation for uncommon records.
			copied[i] = deepcopy.Copy(answer).(dnsmessage.RR)
		}
	}
	return copied
}

func (c *DnsCache) FillInto(req *dnsmessage.Msg) {
	req.Answer = copyDnsAnswers(c.Answer)
	req.Rcode = c.Rcode
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false
}

// IsNegative reports NXDOMAIN or NODATA (NOERROR with empty answer).
// CNAME-only success answers are not negative.
func (c *DnsCache) IsNegative() bool {
	if c == nil {
		return false
	}
	return dnsCacheIsNegative(c.Rcode, c.Answer)
}

func (c *DnsCache) IncludeIp(ip netip.Addr) bool {
	for _, ans := range c.Answer {
		switch body := ans.(type) {
		case *dnsmessage.A:
			if !ip.Is4() {
				continue
			}
			if a, ok := netip.AddrFromSlice(body.A); ok && a == ip {
				return true
			}
		case *dnsmessage.AAAA:
			if !ip.Is6() {
				continue
			}
			if a, ok := netip.AddrFromSlice(body.AAAA); ok && a == ip {
				return true
			}
		}
	}
	return false
}

func (c *DnsCache) IncludeAnyIp() bool {
	for _, ans := range c.Answer {
		switch ans.(type) {
		case *dnsmessage.A, *dnsmessage.AAAA:
			return true
		}
	}
	return false
}
