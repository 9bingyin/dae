/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"testing"

	"github.com/daeuniverse/outbound/pool"
)

func TestFlushQuicPacketBatchPreservesOrder(t *testing.T) {
	first := pool.Get(len("first"))
	copy(first, "first")
	second := pool.Get(len("second"))
	copy(second, "second")

	var got []string
	err := flushQuicPacketBatch([]pool.PB{first, second}, []byte("current"), func(packet []byte) error {
		got = append(got, string(packet))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"first", "second", "current"}
	if len(got) != len(want) {
		t.Fatalf("packets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("packets = %v, want %v", got, want)
		}
	}
}

func TestFlushQuicPacketBatchStopsOnError(t *testing.T) {
	first := pool.Get(1)
	first[0] = 1
	second := pool.Get(1)
	second[0] = 2
	wantErr := errors.New("write packet")

	calls := 0
	err := flushQuicPacketBatch([]pool.PB{first, second}, []byte{3}, func([]byte) error {
		calls++
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Fatalf("send calls = %d, want 1", calls)
	}
}
