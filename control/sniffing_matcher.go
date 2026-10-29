/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package control

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

const sniffingSkipOutbound consts.OutboundIndex = 1

// SniffingMatcher holds independent, read-only pre-sniff and post-sniff rules.
// All rules select skip, so splitting them does not introduce rule precedence.
type SniffingMatcher struct {
	pre  *RoutingMatcher
	post *RoutingMatcher
}

func NewSniffingMatcher(log *logrus.Logger, rules []*config_parser.RoutingRule, locationFinder *assets.LocationFinder) (*SniffingMatcher, error) {
	m := new(SniffingMatcher)
	if len(rules) == 0 {
		return m, nil
	}
	if err := (&config.Sniffing{Rules: rules}).Validate(); err != nil {
		return nil, fmt.Errorf("validate sniffing rules: %w", err)
	}
	if log == nil {
		log = logrus.New()
	}
	if locationFinder == nil {
		locationFinder = assets.NewLocationFinder(nil)
	}
	optimized, err := routing.ApplyRulesOptimizers(rules,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{Logger: log, LocationFinder: locationFinder},
		&routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		return nil, fmt.Errorf("optimize sniffing rules: %w", err)
	}
	var pre, post []*config_parser.RoutingRule
	for _, rule := range optimized {
		hasDomain := false
		for _, f := range rule.AndFunctions {
			hasDomain = hasDomain || f.Name == consts.Function_Domain
			if len(f.Params) == 0 {
				// Empty geodata is an empty set, not an omitted AND predicate.
				f.Name = consts.Function_Ip
				f.Not = !f.Not
				f.Params = []*config_parser.Param{{Val: "0.0.0.0/0"}, {Val: "::/0"}}
			}
		}
		if hasDomain {
			post = append(post, rule)
		} else {
			pre = append(pre, rule)
		}
	}
	if m.pre, err = buildSniffingPlane(log, pre); err != nil {
		return nil, fmt.Errorf("build pre-sniff rules: %w", err)
	}
	if m.post, err = buildSniffingPlane(log, post); err != nil {
		return nil, fmt.Errorf("build post-sniff rules: %w", err)
	}
	return m, nil
}

func buildSniffingPlane(log *logrus.Logger, rules []*config_parser.RoutingRule) (*RoutingMatcher, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	builder, err := NewRoutingMatcherBuilder(log, rules, map[string]uint8{
		"skip": uint8(sniffingSkipOutbound), "continue": 0,
	}, nil, "continue")
	if err != nil {
		return nil, fmt.Errorf("create routing matcher builder: %w", err)
	}
	if len(builder.rules) > consts.MaxMatchSetLen {
		return nil, fmt.Errorf("match set length %d exceeds limit %d", len(builder.rules), consts.MaxMatchSetLen)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, fmt.Errorf("build userspace routing matcher: %w", err)
	}
	return matcher, nil
}

// SkipIP evaluates only rules without domain predicates before sniffing.
func (m *SniffingMatcher) SkipIP(dst netip.AddrPort) (bool, error) {
	if m == nil {
		return false, nil
	}
	return matchSniffingPlane(m.pre, dst, "")
}

// SkipDomain evaluates domain-containing rules after sniffing. Empty domains
// never match, including when a rule negates its domain predicate.
func (m *SniffingMatcher) SkipDomain(dst netip.AddrPort, domain string) (bool, error) {
	if m == nil || domain == "" {
		return false, nil
	}
	return matchSniffingPlane(m.post, dst, domain)
}

func matchSniffingPlane(m *RoutingMatcher, dst netip.AddrPort, domain string) (bool, error) {
	if m == nil {
		return false, nil
	}
	if !dst.IsValid() {
		return false, fmt.Errorf("sniffing match: invalid destination address")
	}
	addr := dst.Addr().As16()
	var unused [16]byte
	outbound, _, _, err := m.Match(unused[:], addr[:], 0, dst.Port(),
		consts.IpVersion_X, 0, domain, unused, 0, unused[:])
	if err != nil {
		return false, fmt.Errorf("match sniffing rules: %w", err)
	}
	return outbound == sniffingSkipOutbound, nil
}
