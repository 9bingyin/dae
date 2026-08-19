/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 * Copyright (c) 2026, 9bingyin
 */

package routing

import (
	"strings"

	"github.com/daeuniverse/dae/common/consts"
)

// PreparedDomain stores the normalized and lazily derived forms of one domain.
// It is mutable and scoped to one matching operation.
type PreparedDomain struct {
	normalized    string
	suffixTrieKey string
	keywordInput  []byte
}

// PrepareDomain normalizes a domain for one matching operation.
func PrepareDomain(domain string) PreparedDomain {
	return PreparedDomain{normalized: strings.ToLower(strings.TrimSuffix(domain, "."))}
}

// Normalized returns the lower-case domain without a trailing dot.
func (d *PreparedDomain) Normalized() string {
	return d.normalized
}

// SuffixTrieKey returns the cached reversed key used by the suffix trie.
func (d *PreparedDomain) SuffixTrieKey() string {
	if d.suffixTrieKey != "" {
		return d.suffixTrieKey
	}
	key := []byte("^" + d.normalized)
	for i, j := 0, len(key)-1; i < j; i, j = i+1, j-1 {
		key[i], key[j] = key[j], key[i]
	}
	d.suffixTrieKey = string(key)
	return d.suffixTrieKey
}

// KeywordInput returns the cached anchored input used by the keyword matcher.
func (d *PreparedDomain) KeywordInput() []byte {
	if d.keywordInput == nil {
		d.keywordInput = make([]byte, 0, len(d.normalized)+2)
		d.keywordInput = append(d.keywordInput, '^')
		d.keywordInput = append(d.keywordInput, d.normalized...)
		d.keywordInput = append(d.keywordInput, '$')
	}
	return d.keywordInput
}

type DomainMatcher interface {
	AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey)
	Build() error
	MatchDomainBitmap(domain string) (bitmap []uint32)
	MatchPreparedDomain(domain *PreparedDomain, bitIndex int) bool
}
