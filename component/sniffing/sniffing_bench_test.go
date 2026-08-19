/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"testing"

	"github.com/daeuniverse/dae/common"

	"github.com/daeuniverse/outbound/pkg/fastrand"
)

var (
	httpMethodSet     map[string]struct{}
	httpMethodMatches int
)

func init() {
	httpMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "COPY", "HEAD", "OPTIONS", "LINK", "UNLINK", "PURGE", "LOCK", "UNLOCK", "PROPFIND", "CONNECT", "TRACE"}
	httpMethodSet = make(map[string]struct{})
	for _, method := range httpMethods {
		httpMethodSet[method] = struct{}{}
	}
}

func BenchmarkStringSet(b *testing.B) {
	matches := 0
	for b.Loop() {
		var test [5]byte
		fastrand.Read(test[:])
		if _, ok := httpMethodSet[string(test[:])]; ok {
			matches++
		}
	}
	httpMethodMatches = matches
}

func BenchmarkStringSwitch(b *testing.B) {
	matches := 0
	for b.Loop() {
		var test [5]byte
		fastrand.Read(test[:])
		if common.IsValidHttpMethod(string(test[:])) {
			matches++
		}
	}
	httpMethodMatches = matches
}
