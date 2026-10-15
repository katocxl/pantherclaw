// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package relay

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestHR228_TheRelayCapsConcurrentConnections: beyond the limit a
// connection is refused, and a slot frees when one ends.
func TestHR228_TheRelayCapsConcurrentConnections(t *testing.T) {
	svc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Close() }()
	go func() {
		for {
			c, err := svc.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	r, err := Listen(t.Context(), "127.0.0.1", svc.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	r.limit = 2
	r.Allow(netip.MustParseAddr("127.0.0.1"))
	open := func() net.Conn {
		c, err := net.Dial("tcp", r.Addr())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	works := func(c net.Conn) bool {
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			return false
		}
		_, err := io.ReadFull(c, make([]byte, 1))
		return err == nil
	}
	a, b := open(), open()
	if !works(a) || !works(b) {
		t.Fatal("the first two connections were not relayed")
	}
	if c := open(); works(c) {
		t.Fatal("a connection beyond the limit was relayed")
	}
	_ = a.Close()
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if c := open(); works(c) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no slot freed after a connection ended")
		}
	}
}
