// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package relay is the per-session path from an edge container to a service
// on the host on a native Linux engine (HR-228). Docker Desktop gives a
// container host.docker.internal; a native engine does not, and no container
// may be given extra host entries (HR-216). The relay listens on the address
// the host has on the edge's uplink network, takes connections from that
// edge's address only, and passes each one on byte for byte to the service:
// it terminates no TLS and reads nothing.
package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// dialTimeout bounds the connection to the service.
const dialTimeout = 10 * time.Second

// maxConns caps the connections relayed at once; a further one is refused and
// logged. There is no idle timeout on purpose: an edge's streams to the
// gateway can be long-lived, and the edge is the only source.
const maxConns = 256

// Relay is one listener, closed with its session.
type Relay struct {
	ln     net.Listener
	target string
	log    *slog.Logger

	mu      sync.Mutex
	allowed netip.Addr
	conns   map[net.Conn]struct{}
	active  int
	limit   int
	closed  bool
	wg      sync.WaitGroup
}

// Listen starts a relay on bind (an IP address, the host's address on the
// uplink network) and a port the system chooses. It takes nothing until
// Allow names the edge. Connections go to target, a host:port.
func Listen(ctx context.Context, bind, target string, log *slog.Logger) (*Relay, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ip, err := netip.ParseAddr(bind)
	if err != nil || !ip.Is4() || ip.IsUnspecified() {
		// Never all interfaces (HR-228): the caller names the host's address on one network.
		return nil, errors.New("relay: bind must be one IPv4 address, not an unspecified one")
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", net.JoinHostPort(bind, "0"))
	if err != nil {
		return nil, err
	}
	r := &Relay{ln: ln, target: target, log: log, conns: map[net.Conn]struct{}{}, limit: maxConns}
	r.wg.Add(1)
	go r.accept()
	return r, nil
}

// Addr is where the edge dials the relay: host:port.
func (r *Relay) Addr() string { return r.ln.Addr().String() }

// Port is the relay's port.
func (r *Relay) Port() int {
	if a, ok := r.ln.Addr().(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}

// Allow names the one address the relay takes connections from: the edge's
// address on the uplink network.
func (r *Relay) Allow(ip netip.Addr) {
	r.mu.Lock()
	r.allowed = ip.Unmap()
	r.mu.Unlock()
}

// Close stops the listener and closes every connection.
func (r *Relay) Close() error {
	r.mu.Lock()
	r.closed = true
	err := r.ln.Close()
	for c := range r.conns {
		_ = c.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
	return err
}

func (r *Relay) accept() {
	defer r.wg.Done()
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		if !r.admit(c) {
			_ = c.Close()
			continue
		}
		r.wg.Add(1)
		go r.serve(c)
	}
}

// admit records c when it comes from the allowed address and the relay is
// open; any other connection is refused and logged.
func (r *Relay) admit(c net.Conn) bool {
	from := netip.Addr{}
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		from = a.AddrPort().Addr().Unmap()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.allowed.IsValid() || from != r.allowed {
		r.log.Warn("relay.refused", slog.String("from", c.RemoteAddr().String()))
		return false
	}
	if r.active >= r.limit {
		r.log.Warn("relay.full", slog.String("from", c.RemoteAddr().String()), slog.Int("limit", r.limit))
		return false
	}
	r.active++
	r.conns[c] = struct{}{}
	return true
}

func (r *Relay) serve(in net.Conn) {
	defer r.wg.Done()
	defer func() {
		r.forget(in)
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
	}()
	out, err := (&net.Dialer{Timeout: dialTimeout}).Dial("tcp", r.target)
	if err != nil {
		r.log.Warn("relay.unreachable", slog.String("error", err.Error()))
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = out.Close()
		return
	}
	r.conns[out] = struct{}{}
	r.mu.Unlock()
	defer r.forget(out)
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if t, ok := dst.(*net.TCPConn); ok {
			_ = t.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(out, in)
	go pipe(in, out)
	<-done
	<-done
}

func (r *Relay) forget(c net.Conn) {
	_ = c.Close()
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}
