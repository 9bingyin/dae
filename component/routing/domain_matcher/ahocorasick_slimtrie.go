/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/ahocorasick-domain"
)

var ValidDomainChars = trie.NewValidChars([]byte("0123456789abcdefghijklmnopqrstuvwxyz-.^_"))

type AhocorasickSlimtrie struct {
	log *logrus.Logger

	validAcIndexes     []int
	validTrieIndexes   []int
	validRegexpIndexes []int
	ac                 []*ahocorasick.Matcher
	trie               []*trie.Trie
	regexp             [][]*regexp.Regexp

	toBuildAc   [][][]byte
	toBuildTrie [][]string
	err         error
}

func NewAhocorasickSlimtrie(log *logrus.Logger, bitLength int) *AhocorasickSlimtrie {
	return &AhocorasickSlimtrie{
		log:         log,
		ac:          make([]*ahocorasick.Matcher, bitLength),
		trie:        make([]*trie.Trie, bitLength),
		regexp:      make([][]*regexp.Regexp, bitLength),
		toBuildAc:   make([][][]byte, bitLength),
		toBuildTrie: make([][]string, bitLength),
	}
}

func (n *AhocorasickSlimtrie) AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey) {
	if n.err != nil {
		return
	}
nextPattern:
	for _, d := range patterns {
		switch typ {
		case consts.RoutingDomainKey_Full:
			for _, r := range []byte(d) {
				if !ValidDomainChars.IsValidChar(r) {
					n.log.Warnf("DomainMatcher: skip bad full domain: %v: unexpected char: %v", d, string(r))
					continue nextPattern
				}
			}
			n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "^"+d+"$")
		case consts.RoutingDomainKey_Suffix:
			for _, r := range []byte(d) {
				if !ValidDomainChars.IsValidChar(r) {
					n.log.Warnf("DomainMatcher: skip bad suffix domain: %v: unexpected char: %v", d, string(r))
					continue nextPattern
				}
			}
			if strings.HasPrefix(d, ".") {
				// abc.example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], d+"$")
				// cannot match example.com
			} else {
				// xxx.example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "."+d+"$")
				// example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "^"+d+"$")
				// cannot match abcexample.com
			}
		case consts.RoutingDomainKey_Keyword:
			// Only use ac automaton for "keyword" matching to save memory.
			n.toBuildAc[bitIndex] = append(n.toBuildAc[bitIndex], []byte(d))
		case consts.RoutingDomainKey_Regex:
			r, err := regexp.Compile(d)
			if err != nil {
				n.err = fmt.Errorf("failed to compile regex: %v", d)
				return
			}
			n.regexp[bitIndex] = append(n.regexp[bitIndex], r)
		default:
			n.err = fmt.Errorf("unknown RoutingDomainKey: %v", typ)
			return
		}
	}
}

func (n *AhocorasickSlimtrie) MatchDomainBitmap(domain string) (bitmap []uint32) {
	prepared := routing.PrepareDomain(domain)
	bitmap = make([]uint32, (len(n.ac)+31)/32)

	// Domain should consist of 'a'-'z' and '.' and '-'
	// NOTE: DO NOT VERIFY THE DOMAIN TO MATCH: https://github.com/daeuniverse/dae/issues/528
	// for _, b := range []byte(prepared.Normalized()) {
	// 	if !ahocorasick.IsValidChar(b) {
	// 		return bitmap
	// 	}
	// }
	for _, i := range n.validTrieIndexes {
		if n.matchPreparedTrie(&prepared, i) {
			bitmap[i/32] |= 1 << (i % 32)
		}
	}
	for _, i := range n.validAcIndexes {
		if bitmap[i/32]&(1<<(i%32)) == 0 && n.matchPreparedAC(&prepared, i) {
			bitmap[i/32] |= 1 << (i % 32)
		}
	}
	for _, i := range n.validRegexpIndexes {
		if bitmap[i/32]&(1<<(i%32)) == 0 && n.matchPreparedRegexp(&prepared, i) {
			bitmap[i/32] |= 1 << (i % 32)
		}
	}
	return bitmap
}

func (n *AhocorasickSlimtrie) MatchPreparedDomain(domain *routing.PreparedDomain, bitIndex int) bool {
	if bitIndex < 0 || bitIndex >= len(n.ac) {
		return false
	}
	return n.matchPreparedTrie(domain, bitIndex) ||
		n.matchPreparedAC(domain, bitIndex) ||
		n.matchPreparedRegexp(domain, bitIndex)
}

func (n *AhocorasickSlimtrie) matchPreparedTrie(domain *routing.PreparedDomain, bitIndex int) bool {
	return n.trie[bitIndex] != nil && n.trie[bitIndex].HasPrefix(domain.SuffixTrieKey())
}

func (n *AhocorasickSlimtrie) matchPreparedAC(domain *routing.PreparedDomain, bitIndex int) bool {
	return n.ac[bitIndex] != nil && n.ac[bitIndex].Contains(domain.KeywordInput())
}

func (n *AhocorasickSlimtrie) matchPreparedRegexp(domain *routing.PreparedDomain, bitIndex int) bool {
	for _, r := range n.regexp[bitIndex] {
		if r.MatchString(domain.Normalized()) {
			return true
		}
	}
	return false
}

func ToSuffixTrieString(s string) string {
	// No need for end char "$".
	b := []byte(strings.TrimSuffix(s, "$"))
	// Reverse.
	half := len(b) / 2
	for i := 0; i < half; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	return string(b)
}

func ToSuffixTrieStrings(s []string) []string {
	to := make([]string, len(s))
	for i := range s {
		to[i] = ToSuffixTrieString(s[i])
	}
	return to
}

func (n *AhocorasickSlimtrie) Build() (err error) {
	if n.err != nil {
		return n.err
	}
	n.validAcIndexes = make([]int, 0, len(n.toBuildAc)/8)
	n.validTrieIndexes = make([]int, 0, len(n.toBuildAc)/8)
	n.validRegexpIndexes = make([]int, 0, len(n.toBuildAc)/8)
	// Build AC automaton.
	for i, toBuild := range n.toBuildAc {
		if len(toBuild) == 0 {
			continue
		}
		n.ac[i], err = ahocorasick.NewMatcher(toBuild)
		if err != nil {
			return err
		}
		n.validAcIndexes = append(n.validAcIndexes, i)
	}

	// Build succinct trie.
	for i, toBuild := range n.toBuildTrie {
		if len(toBuild) == 0 {
			continue
		}
		toBuild = ToSuffixTrieStrings(toBuild)
		n.trie[i], err = trie.NewTrie(toBuild, ValidDomainChars)
		if err != nil {
			return err
		}
		n.validTrieIndexes = append(n.validTrieIndexes, i)
	}

	// Regexp.
	for i := range n.regexp {
		if len(n.regexp[i]) == 0 {
			continue
		}
		n.validRegexpIndexes = append(n.validRegexpIndexes, i)
	}

	// Release unused data.
	n.toBuildAc = nil
	n.toBuildTrie = nil
	return nil
}
