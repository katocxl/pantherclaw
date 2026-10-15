// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package relay_test

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/sandbox/relay"
)

// echo is a service on the host: it answers each byte it reads.
func echo(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func start(t *testing.T) *relay.Relay {
	t.Helper()
	r, err := relay.Listen(t.Context(), "127.0.0.1", echo(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func roundTrip(t *testing.T, addr string) error {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		return err
	}
	b := make([]byte, 1)
	_, err = io.ReadFull(c, b)
	return err
}

// TestHR228_TheRelayRefusesAnotherSource: nothing is relayed before the edge
// is named, nor from any other address, and a relayed connection reaches the
// service byte for byte.
func TestHR228_TheRelayRefusesAnotherSource(t *testing.T) {
	r := start(t)
	if err := roundTrip(t, r.Addr()); err == nil {
		t.Fatal("relayed before the edge was named")
	}
	r.Allow(netip.MustParseAddr("192.0.2.9"))
	if err := roundTrip(t, r.Addr()); err == nil {
		t.Fatal("relayed for another source")
	}
	r.Allow(netip.MustParseAddr("127.0.0.1"))
	if err := roundTrip(t, r.Addr()); err != nil {
		t.Fatalf("the edge's address: %v", err)
	}
}

// TestHR228_TheRelayClosesWithTheSession: closing the relay closes its
// listener and a connection open through it.
func TestHR228_TheRelayClosesWithTheSession(t *testing.T) {
	r := start(t)
	r.Allow(netip.MustParseAddr("127.0.0.1"))
	c, err := net.Dial("tcp", r.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	addr := r.Addr()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(b); err == nil {
		t.Fatal("a connection survived the relay")
	}
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Fatal("the listener survived the relay")
	}
}

// TestHR228_TheRelayRefusesAllInterfaces: an unspecified or non-IPv4 bind
// address is refused by the relay itself.
func TestHR228_TheRelayRefusesAllInterfaces(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "", "::", "localhost", "::1"} {
		if r, err := relay.Listen(t.Context(), bind, "127.0.0.1:1", nil); err == nil {
			_ = r.Close()
			t.Errorf("bound %q", bind)
		}
	}
}
