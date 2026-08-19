/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"math/rand/v2"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

func TestAhocorasickSlimtriePreparedDomain(t *testing.T) {
	matcher := NewAhocorasickSlimtrie(logrus.New(), 8)
	matcher.AddSet(1, []string{"example.com"}, consts.RoutingDomainKey_Suffix)
	matcher.AddSet(3, []string{"api.example.net"}, consts.RoutingDomainKey_Full)
	matcher.AddSet(5, []string{"tracking"}, consts.RoutingDomainKey_Keyword)
	matcher.AddSet(7, []string{`^r[0-9]+\.example\.org$`}, consts.RoutingDomainKey_Regex)
	if err := matcher.Build(); err != nil {
		t.Fatal(err)
	}

	for _, domain := range []string{
		"WWW.Example.COM.",
		"api.example.net",
		"cdn-tracking.example",
		"r123.example.org",
		"unmatched.invalid",
	} {
		prepared := routing.PrepareDomain(domain)
		bitmap := matcher.MatchDomainBitmap(domain)
		for bitIndex := 0; bitIndex < 8; bitIndex++ {
			got := matcher.MatchPreparedDomain(&prepared, bitIndex)
			want := bitmap[bitIndex/32]&(1<<uint(bitIndex%32)) != 0
			if got != want {
				t.Fatalf("domain=%q bit=%d prepared=%v bitmap=%v", domain, bitIndex, got, want)
			}
		}
	}
}

func TestAhocorasickSlimtrie(t *testing.T) {

	logrus.SetLevel(logrus.TraceLevel)
	simulatedDomainSet, err := getDomain()
	if err != nil {
		t.Fatal(err)
	}
	bf := NewBruteforce(consts.MaxMatchSetLen)
	actrie := NewAhocorasickSlimtrie(logrus.StandardLogger(), consts.MaxMatchSetLen)
	for _, domains := range simulatedDomainSet {
		bf.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
		actrie.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = bf.Build(); err != nil {
		t.Fatal(err)
	}
	if err = actrie.Build(); err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewPCG(200, 0))
	for i := 0; i < 10000; i++ {
		sample := randomDomainSample(rng)
		bitmap := bf.MatchDomainBitmap(sample)
		bitmap2 := actrie.MatchDomainBitmap(sample)
		if !slices.Equal(bitmap, bitmap2) {
			t.Fatal(i, sample, bitmap, bitmap2)
		}
	}
}
