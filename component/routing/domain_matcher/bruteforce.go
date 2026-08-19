/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"regexp"
	"strings"
)

type Bruteforce struct {
	simulatedDomainSet []routing.DomainSet
	err                error
}

func NewBruteforce(bitLength int) *Bruteforce {
	return &Bruteforce{
		simulatedDomainSet: make([]routing.DomainSet, bitLength),
	}
}
func (n *Bruteforce) AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey) {
	if n.err != nil {
		return
	}
	if len(n.simulatedDomainSet[bitIndex].Domains) != 0 {
		n.err = fmt.Errorf("duplicated RuleIndex: %v", bitIndex)
		return
	}
	n.simulatedDomainSet[bitIndex] = routing.DomainSet{
		Key:       typ,
		RuleIndex: bitIndex,
		Domains:   patterns,
	}
}
func (n *Bruteforce) MatchDomainBitmap(domain string) (bitmap []uint32) {
	prepared := routing.PrepareDomain(domain)
	N := len(n.simulatedDomainSet) / 32
	if len(n.simulatedDomainSet)%32 != 0 {
		N++
	}
	bitmap = make([]uint32, N)
	for i, s := range n.simulatedDomainSet {
		if n.MatchPreparedDomain(&prepared, i) {
			bitmap[s.RuleIndex/32] |= 1 << (s.RuleIndex % 32)
		}
	}
	return bitmap
}

func (n *Bruteforce) MatchPreparedDomain(domain *routing.PreparedDomain, bitIndex int) bool {
	if bitIndex < 0 || bitIndex >= len(n.simulatedDomainSet) {
		return false
	}
	s := n.simulatedDomainSet[bitIndex]
	normalized := domain.Normalized()
	for _, d := range s.Domains {
		switch s.Key {
		case consts.RoutingDomainKey_Suffix:
			if normalized == d || strings.HasSuffix(normalized, "."+strings.TrimPrefix(d, ".")) {
				return true
			}
		case consts.RoutingDomainKey_Full:
			if strings.EqualFold(normalized, d) {
				return true
			}
		case consts.RoutingDomainKey_Keyword:
			if strings.Contains(normalized, strings.ToLower(d)) {
				return true
			}
		case consts.RoutingDomainKey_Regex:
			if regexp.MustCompile(d).MatchString(normalized) {
				return true
			}
		}
	}
	return false
}
func (n *Bruteforce) Build() error {
	if n.err != nil {
		return n.err
	}
	return nil
}
