/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package control

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

func tcpPairForTest(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func TestRelayTCPPropagatesHalfCloseThroughSniffer(t *testing.T) {
	client, local := tcpPairForTest(t)
	remote, server := tcpPairForTest(t)
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := server.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	response := []byte("response before EOF")
	afterEOF := []byte("client can still write after receiving EOF")
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, len(request))
		if _, err := io.ReadFull(server, buffer); err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(buffer, request) {
			serverDone <- fmt.Errorf("request = %q, want %q", buffer, request)
			return
		}
		if _, err := server.Write(response); err != nil {
			serverDone <- err
			return
		}
		if err := server.CloseWrite(); err != nil {
			serverDone <- err
			return
		}
		buffer = make([]byte, len(afterEOF))
		if _, err := io.ReadFull(server, buffer); err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(buffer, afterEOF) {
			serverDone <- fmt.Errorf("after EOF = %q, want %q", buffer, afterEOF)
			return
		}
		serverDone <- nil
	}()
	relayDone := make(chan error, 1)
	go func() {
		conn := sniffing.NewConnSniffer(local, time.Second)
		defer conn.Close()
		defer remote.Close()
		if _, err := conn.SniffTcp(); err != nil {
			relayDone <- err
			return
		}
		relayDone <- RelayTCP(conn, remote)
	}()
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("waiting for response EOF: %v (received %q)", err, got)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("response = %q, want %q", got, response)
	}
	if _, err := client.Write(afterEOF); err != nil {
		t.Fatalf("write after response EOF: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan error{serverDone, relayDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("half-closed relay did not finish")
		}
	}
}
