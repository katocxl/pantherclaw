// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package simcheck is the gateway's simulator check (HR-221, G0 M12 D7): a
// simulated connection is dispatched to only after its target answered the
// simulator handshake, and only while its base URL host is a loopback or
// private IP literal. The server enforces the literal when the connection
// is created; the gateway checks it again, so a configuration that was
// changed on the way never sends a thing to a real service.
//
// The handshake carries no credential. A success is remembered for ten
// minutes per connection and base URL.
package simcheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
)

// Code is the local refusal code of a simulated connection that is not
// verified.
const Code = "simulator_unverified"

// ErrUnverified reports that the connection is not (or no longer) a
// verified simulator target; nothing was sent to it besides the handshake.
var ErrUnverified = errors.New("simcheck: the target is not a verified simulator")

// TTL is how long a successful handshake is trusted.
const TTL = 10 * time.Minute

// path is the well-known handshake path.
const path = "/.well-known/pantherclaw-sim"

// Client is the part of a connection's egress client the check uses.
type Client interface {
	HTTPRequest(ctx context.Context, r egress.Request) (*http.Request, error)
	Open(req *http.Request) (*http.Response, error)
}

// Checker remembers verified connections.
type Checker struct {
	now func() time.Time
	mu  sync.Mutex
	ok  map[string]time.Time
}

// New returns a Checker.
func New() *Checker { return &Checker{now: time.Now, ok: map[string]time.Time{}} }

// Verify returns nil when the connection may be dispatched to: its base URL
// host is a loopback or private IP literal and its target answered the
// handshake (now, or within the last TTL). cl is the connection's egress
// client.
func (c *Checker) Verify(ctx context.Context, connectionID, baseURL string, cl Client) error {
	u, err := LocalLiteral(baseURL)
	if err != nil {
		return err
	}
	key := connectionID + "\x00" + baseURL
	c.mu.Lock()
	at, found := c.ok[key]
	c.mu.Unlock()
	if found && c.now().Sub(at) < TTL {
		return nil
	}
	if err := handshake(ctx, u, cl); err != nil {
		c.mu.Lock()
		delete(c.ok, key)
		c.mu.Unlock()
		return err
	}
	c.mu.Lock()
	c.ok[key] = c.now()
	c.mu.Unlock()
	return nil
}

// LocalLiteral returns the parsed base URL when its host is an IP literal
// in 127.0.0.0/8, ::1, 10/8, 172.16/12, 192.168/16 or fc00::/7 (D3), and
// ErrUnverified otherwise. A host name is never accepted.
func LocalLiteral(baseURL string) (*url.URL, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, fmt.Errorf("%w: base URL", ErrUnverified)
	}
	a, err := netip.ParseAddr(u.Hostname())
	if err != nil || a.Zone() != "" {
		return nil, fmt.Errorf("%w: host is not an IP literal", ErrUnverified)
	}
	a = a.Unmap()
	if !a.IsLoopback() && !a.IsPrivate() {
		return nil, fmt.Errorf("%w: host is not loopback or private", ErrUnverified)
	}
	return u, nil
}

type answer struct {
	Simulator string `json:"simulator"`
	Kind      string `json:"kind"`
	Nonce     string `json:"nonce"`
}

func handshake(ctx context.Context, base *url.URL, cl Client) error {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	nonce := hex.EncodeToString(raw[:])
	target := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: path, RawQuery: "nonce=" + nonce}
	req, err := cl.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: target})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := cl.Open(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1024))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	var a answer
	switch {
	case res.StatusCode != http.StatusOK:
		return fmt.Errorf("%w: status %d", ErrUnverified, res.StatusCode)
	case res.Header.Get("Simulated") != "true":
		return fmt.Errorf("%w: no Simulated header", ErrUnverified)
	case json.UnmarshalRead(bytes.NewReader(body), &a) != nil:
		return fmt.Errorf("%w: answer", ErrUnverified)
	case a.Simulator != "pantherclaw-sim" || a.Nonce != nonce:
		return fmt.Errorf("%w: answer", ErrUnverified)
	case !slices.Contains(simKinds, a.Kind):
		return fmt.Errorf("%w: kind", ErrUnverified)
	}
	return nil
}

// simKinds are the simulators a handshake may name: payments, mcp and
// github, the M14 simulators stripe, slack and a2a (G0 M14 D46), and the M20
// simulators jira and gitlab (D254).
var simKinds = []string{"payments", "mcp", "github", "stripe", "slack", "a2a", "jira", "gitlab"}
