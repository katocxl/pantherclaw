// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sni routes agent connections on a shared hosting host to their
// org's gateway process by the TLS server name, without terminating TLS
// (G0 M19 D203): the router reads only the ClientHello's server_name and
// then copies bytes both ways, so the gateway's own TLS, and the agent's
// client certificate where one is used, stay end to end. A name that is
// not exactly "<slug>.gw.<domain>" of a routed org is closed unanswered.
// Each org's process gets a bounded number of concurrent connections, so
// one org's agents cannot take the host's sockets from another (T-218).
package sni

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Bounds.
const (
	// HelloTimeout bounds how long a client may take to send its
	// ClientHello.
	HelloTimeout = 5 * time.Second
	// MaxHello bounds the bytes read before the server name is known.
	MaxHello = 16 << 10
	// DefaultPerOrg is an org's concurrent connection cap.
	DefaultPerOrg = 512
	dialTimeout   = 5 * time.Second
)

// SlugRE is the form of an org's hosting slug: a DNS label.
var SlugRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Router forwards connections to the backend of their server name.
type Router struct {
	// Domain is the hosting domain: names are "<slug>.gw.<Domain>".
	Domain string
	// PerOrg caps an org's concurrent connections (DefaultPerOrg if 0).
	PerOrg int
	Log    *slog.Logger

	mu     sync.Mutex
	routes map[string]string
	open   map[string]int
}

// Set replaces the routing table: slug → backend address (host:port on
// the org's own network). Slugs that are not DNS labels are dropped.
func (r *Router) Set(routes map[string]string) {
	m := make(map[string]string, len(routes))
	for s, addr := range routes {
		if SlugRE.MatchString(s) && addr != "" {
			m[s] = addr
		}
	}
	r.mu.Lock()
	r.routes = m
	r.mu.Unlock()
}

// Slug returns the org slug of a server name, or "" when the name is not
// exactly one label under "gw.<Domain>".
func (r *Router) Slug(name string) string {
	suffix := ".gw." + strings.ToLower(r.Domain)
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	s, ok := strings.CutSuffix(name, suffix)
	if !ok || r.Domain == "" || !SlugRE.MatchString(s) {
		return ""
	}
	return s
}

// errHello stops the handshake once the ClientHello was read.
var errHello = errors.New("sni: hello read")

// readOnly records what a TLS server reads and drops what it writes, so
// the handshake can be abandoned after the ClientHello.
type readOnly struct {
	net.Conn
	r io.Reader
}

func (c readOnly) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (readOnly) Write(p []byte) (int, error)      { return len(p), nil }
func (readOnly) SetWriteDeadline(time.Time) error { return nil }

// ServerName reads a ClientHello from conn and returns its server name
// and the bytes read, which the backend must receive first.
func ServerName(conn net.Conn) (string, []byte, error) {
	var seen bytes.Buffer
	lr := &io.LimitedReader{R: conn, N: MaxHello}
	var name string
	err := tls.Server(readOnly{Conn: conn, r: io.TeeReader(lr, &seen)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			name = h.ServerName
			return nil, errHello
		},
	}).Handshake() //nolint:noctx // reads one hello from memory-bounded input under the connection's deadline
	if name == "" {
		if err == nil || errors.Is(err, errHello) {
			err = errors.New("sni: no server name")
		}
		return "", nil, err
	}
	return name, seen.Bytes(), nil
}

// Serve accepts connections from ln until ctx ends.
func (r *Router) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil //nolint:nilerr // shutdown, not a failure
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go r.handle(ctx, c)
	}
}

func (r *Router) acquire(slug string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	addr, ok := r.routes[slug]
	limit := r.PerOrg
	if limit <= 0 {
		limit = DefaultPerOrg
	}
	if !ok || r.open[slug] >= limit {
		return "", false
	}
	if r.open == nil {
		r.open = map[string]int{}
	}
	r.open[slug]++
	return addr, true
}

func (r *Router) release(slug string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.open[slug]--; r.open[slug] <= 0 {
		delete(r.open, slug)
	}
}

func (r *Router) handle(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(HelloTimeout))
	name, hello, err := ServerName(c)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	slug := r.Slug(name)
	if slug == "" {
		return
	}
	addr, ok := r.acquire(slug)
	if !ok {
		if r.Log != nil {
			r.Log.DebugContext(ctx, "hosting.sni_refused", slog.String("slug", slug))
		}
		return
	}
	defer r.release(slug)
	d := net.Dialer{Timeout: dialTimeout}
	b, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer func() { _ = b.Close() }()
	if _, err := b.Write(hello); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(b, c)
	go pipe(c, b)
	for range 2 {
		select {
		case <-done:
		case <-ctx.Done():
			return
		}
	}
}
