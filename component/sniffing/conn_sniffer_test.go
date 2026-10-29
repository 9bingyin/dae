/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package sniffing

import (
	"errors"
	"net"
	"testing"
)

type halfCloseTestConn struct {
	net.Conn
	calls int
	err   error
}

func (c *halfCloseTestConn) CloseWrite() error {
	c.calls++
	return c.err
}

func TestConnSnifferCloseWrite(t *testing.T) {
	for _, want := range []error{nil, errors.New("close write failed")} {
		conn := &halfCloseTestConn{err: want}
		sniffer := &ConnSniffer{Conn: conn}
		if err := sniffer.CloseWrite(); !errors.Is(err, want) {
			t.Fatalf("CloseWrite() = %v, want %v", err, want)
		}
		if conn.calls != 1 {
			t.Fatalf("underlying CloseWrite calls = %d, want 1", conn.calls)
		}
	}
}

func TestConnSnifferCloseWriteWithoutSupport(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close() })
	t.Cleanup(func() { _ = right.Close() })
	sniffer := &ConnSniffer{Conn: left}
	if err := sniffer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}
