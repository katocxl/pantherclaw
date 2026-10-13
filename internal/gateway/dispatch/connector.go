// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// Connectors are a customer-hosted gateway's running connectors (G0 M9
// track C): third-party stdio MCP servers in containers.
type Connectors interface {
	// Client returns a running connector's MCP client at the connection's
	// revision, which speaks over its container's standard input and output;
	// a connector of another revision, or one whose last exchange was
	// abandoned, is not running.
	Client(connection string, revision int32) (*upstream.Client, error)
	// Fly binds a connector's egress to this one call until the returned
	// function lands it (design decision 6). A connector runs one call at
	// a time: Fly waits, within ctx, for the call before it to land, and
	// refuses a connector that cannot take a call.
	Fly(ctx context.Context, connection string, f Flight) (land func(), err error)
}

// Flight is one call a connector runs (design decision 6). While it is in
// flight, the connector's egress may send the call's own action once,
// exactly as authorized (the same action hash), and read the call's target
// through reviewed access: read operations; nothing else. Its requests are
// mapped with the call's own ids and go out with its transaction, and
// stop when the containment epoch moves past the call's permit or the
// connector connection is contained.
type Flight struct {
	Txn string
	// Action is the bound action: the one the permit authorized, with its
	// obligations applied.
	Action    actionir.Parsed
	Epoch     int64
	Connector *control.Connection
	// access keeps what the egress connection's credential gave the call's
	// write, for the call's receipt (ADR-0021); nil keeps nothing.
	access *flightAccess
}

// flightAccess is the credential access of a call's egress: what was
// minted, granted and revoked, or what was granted when the scope did not
// match. The last request that placed a credential wins.
type flightAccess struct {
	mu  sync.Mutex
	got *pb.CredentialAccess
}

func (f *flightAccess) set(a *pb.CredentialAccess) {
	if f == nil || a == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = a
}

func (f *flightAccess) get() *pb.CredentialAccess {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got
}

// ErrNoConnectors reports a connector connection on a gateway that runs no
// connectors (HR-084): nothing is sent.
var ErrNoConnectors = errors.New("dispatch: this gateway runs no connectors")

// ErrEgressContained refuses a connector's egress request while a dispatch
// through its egress connection would be refused (the kill switch, a
// quarantined connection, an open circuit), while its connector connection
// is contained, or once the containment epoch moved past the call's.
var ErrEgressContained = errors.New("dispatch: containment stops connector egress")

// connectorEntry is a connector connection's MCP client. It has no egress
// client: the connector reaches nothing itself, and calls go over stdio.
func (e *Engine) connectorEntry(conn *control.Connection) (clientEntry, error) {
	if e.connectors == nil {
		return clientEntry{}, ErrNoConnectors
	}
	c, err := e.connectors.Client(conn.GetId(), conn.GetRevision())
	return clientEntry{revision: conn.GetRevision(), mcp: c}, err
}

// defaultConnectorTimeout bounds a connector call when the connection names
// no timeout.
const defaultConnectorTimeout = 30 * time.Second

// callWindow is the context a call to conn runs in: a connector's call is
// bounded by the connection's timeout, so its window (and its egress,
// which is bound to the call) closes; any other connection's runs as it is.
func callWindow(ctx context.Context, conn *control.Connection) (context.Context, context.CancelFunc) {
	if conn.GetKind() != "mcp_container" {
		return ctx, func() {}
	}
	d := defaultConnectorTimeout
	if ms := conn.GetTimeoutMs(); ms > 0 {
		d = time.Duration(ms) * time.Millisecond
	}
	return context.WithTimeout(ctx, d)
}

// fly binds a connector connection's egress to the call it is about to
// run; it does nothing for any other connection. access returns what the
// call's egress credential gave, for its receipt (nil when none was
// placed).
func (e *Engine) fly(ctx context.Context, conn *control.Connection, a actionir.Parsed, want permitWant) (land func(), access func() *pb.CredentialAccess, err error) {
	if conn.GetKind() != "mcp_container" || e.connectors == nil {
		return func() {}, func() *pb.CredentialAccess { return nil }, nil
	}
	got := &flightAccess{}
	land, err = e.connectors.Fly(ctx, conn.GetId(), Flight{Txn: want.Txn, Action: a, Epoch: want.Epoch, Connector: conn, access: got})
	return land, got.get, err
}

// ConnectorEgress sends one request a connector made while running a call,
// already mapped through its egress connection and checked against the
// call (G0 M9 design decision 6): it is re-serialized from the reviewed
// definition (HR-075), carries the egress connection's credential, placed
// here (decision 18), and goes through that connection's hardened egress
// client. The answer comes back without the credential.
func (e *Engine) ConnectorEgress(ctx context.Context, conn *control.Connection, a actionir.Parsed, f Flight) (egress.Response, error) {
	epoch, class, _ := e.contained(conn)
	if class != "" || epoch > f.Epoch {
		return egress.Response{}, ErrEgressContained
	}
	if _, class, _ := e.contained(f.Connector); class != "" {
		return egress.Response{}, ErrEgressContained
	}
	if e.breaker.open(ctx, conn) {
		return egress.Response{}, ErrEgressContained
	}
	def, ok := conn.Package.Definition(a.Action.Operation)
	if !ok {
		return egress.Response{}, fmt.Errorf("%w: %s is not in the egress connection's package", egress.ErrBuild, a.Action.Operation)
	}
	p, err := e.prepare(ctx, conn, def, a, f.Txn)
	if err != nil {
		return egress.Response{}, err
	}
	var secret []byte
	if conn.GetAccessMode() == "pantherclaw_held" {
		// A GitHub App connection gets a token minted for this action alone,
		// revoked once it is sent (HR-203, HR-204).
		s, release, used, err := e.credential(ctx, conn, def, a.Action.Target, p.req, p.client)
		if err != nil {
			// What GitHub granted when the scope did not match goes on the
			// call's receipt (ADR-0021 items 3 and 6).
			if sm := (*broker.ScopeMismatchError)(nil); errors.As(err, &sm) {
				f.access.set(accessOf(sm.Access))
			}
			return egress.Response{}, err
		}
		defer func() {
			release()
			f.access.set(used())
		}()
		secret = s
	}
	res, err := p.client.Do(p.req)
	outcome, _, _ := classify(res.Status, err)
	e.breaker.record(ctx, conn, outcome)
	e.log.InfoContext(ctx, "gateway.connector_egress", slog.String("transaction_id", f.Txn), slog.String("connection_id", conn.GetId()),
		slog.String("connector_id", f.Connector.GetId()), slog.String("operation", a.Action.Operation), slog.Int("status", res.Status))
	res.Body = egress.Redacted(res.Body, secret)
	res.ContentType = string(egress.Redacted([]byte(res.ContentType), secret))
	res.RequestID = string(egress.Redacted([]byte(res.RequestID), secret))
	return res, err
}
