// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectors

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/relay"
)

// inspectFake answers `container inspect` with an edge that has address ip
// on network, and everything else with nothing.
type inspectFake struct{ network, ip string }

func (f inspectFake) Run(_ context.Context, args ...string) ([]byte, error) {
	if len(args) > 1 && args[0] == "container" && args[1] == "inspect" {
		return []byte(`{"Name":"pc-cedge-1","NetworkSettings":{"Networks":{"` + f.network + `":{"IPAddress":"` + f.ip + `"}}}}`), nil
	}
	return nil, nil
}

// egressService is the gateway's egress listener: it echoes.
func egressService(t *testing.T) string {
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

func relayed(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		return false
	}
	_, err = io.ReadFull(c, make([]byte, 1))
	return err == nil
}

func uplink(gateway string) docker.NetworkInfo {
	var n docker.NetworkInfo
	n.IPAM.Config = append(n.IPAM.Config, struct {
		Subnet  string `json:"Subnet"`
		Gateway string `json:"Gateway"`
	}{Subnet: "172.30.0.0/16", Gateway: gateway})
	return n
}

// TestHR228_AConnectorsRelayTakesOnlyItsEdge: the relay opens on the uplink
// network's gateway address towards the egress listener, takes nothing
// until the edge's address is named, and then only that address.
func TestHR228_AConnectorsRelayTakesOnlyItsEdge(t *testing.T) {
	s := &Supervisor{cfg: Config{EgressListen: egressService(t)}, log: slog.New(slog.DiscardHandler)}
	if _, err := s.openRelay(t.Context(), uplink("")); err == nil {
		t.Fatal("a relay without a gateway address")
	}
	if r, err := s.openRelay(t.Context(), uplink("0.0.0.0")); err == nil {
		_ = r.Close()
		t.Fatal("a relay on all interfaces")
	}
	r, err := s.openRelay(t.Context(), uplink("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if relayed(r.Addr()) {
		t.Fatal("relayed before the edge was named")
	}
	s.c = docker.New(inspectFake{network: "pc-cup-1", ip: "192.0.2.7"})
	if err := s.allowEdge(t.Context(), r, "pc-cedge-1", "pc-cup-1"); err != nil {
		t.Fatal(err)
	}
	if relayed(r.Addr()) {
		t.Fatal("relayed for another address")
	}
	s.c = docker.New(inspectFake{network: "pc-cup-1", ip: "127.0.0.1"})
	if err := s.allowEdge(t.Context(), r, "pc-cedge-1", "pc-cup-1"); err != nil {
		t.Fatal(err)
	}
	if !relayed(r.Addr()) {
		t.Fatal("the edge's address was not relayed")
	}
	s.c = docker.New(inspectFake{network: "other", ip: "127.0.0.1"})
	if err := s.allowEdge(t.Context(), r, "pc-cedge-1", "pc-cup-1"); err == nil {
		t.Fatal("an edge with no address on its uplink was allowed")
	}
}

// TestHR228_AConnectorsRelayClosesWithTheConnector: the relay closes when a
// start fails after the edge (cleanup), and when the connector stops, which
// is also how a connector is replaced on CA renewal or a new revision.
func TestHR228_AConnectorsRelayClosesWithTheConnector(t *testing.T) {
	s := &Supervisor{cfg: Config{EgressListen: egressService(t)}, log: slog.New(slog.DiscardHandler), c: docker.New(inspectFake{}), running: map[string]*instance{}}
	open := func() *mediatedRelay {
		r, err := s.openRelay(t.Context(), uplink("127.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		return &mediatedRelay{r: r, addr: r.Addr()}
	}

	failed := open()
	mediated{relay: failed.r, dir: t.TempDir()}.cleanup()
	if _, err := net.DialTimeout("tcp", failed.addr, time.Second); err == nil {
		t.Fatal("the relay survived a failed start")
	}

	stopped := open()
	in, cancel := &instance{relay: stopped.r, stdio: NewStdio(io.Discard, nopReader{}, 0), done: make(chan struct{})}, func() {}
	in.stop = cancel
	close(in.done)
	s.running["c1"] = in
	s.stop(t.Context(), "c1")
	if _, err := net.DialTimeout("tcp", stopped.addr, time.Second); err == nil {
		t.Fatal("the relay survived the connector's stop")
	}
}

type mediatedRelay struct {
	r    *relay.Relay
	addr string
}

type nopReader struct{}

func (nopReader) Read([]byte) (int, error) { return 0, io.EOF }
