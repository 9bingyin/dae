/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package routing

import "testing"

func TestPreparedDomainCachesDerivedForms(t *testing.T) {
	prepared := PrepareDomain("WWW.Example.COM.")
	if prepared.Normalized() != "www.example.com" {
		t.Fatalf("normalized domain = %q", prepared.Normalized())
	}

	const wantSuffixKey = "moc.elpmaxe.www^"
	if got := prepared.SuffixTrieKey(); got != wantSuffixKey {
		t.Fatalf("suffix trie key = %q, want %q", got, wantSuffixKey)
	}
	if got := prepared.SuffixTrieKey(); got != wantSuffixKey {
		t.Fatalf("cached suffix trie key = %q, want %q", got, wantSuffixKey)
	}

	first := prepared.KeywordInput()
	if got, want := string(first), "^www.example.com$"; got != want {
		t.Fatalf("keyword input = %q, want %q", got, want)
	}
	second := prepared.KeywordInput()
	if len(first) == 0 || &first[0] != &second[0] {
		t.Fatal("keyword input was rebuilt instead of reused")
	}
}
