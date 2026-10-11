// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
)

// Connectors are a customer-hosted gateway's running connectors (G0 M9
// track C): third-party stdio MCP servers in containers.
type Connectors interface {
	// Client returns a running connector's MCP client, which speaks over
	// its container's standard input and output.
	Client(connection string) (*upstream.Client, error)
	// Fly binds a connector's egress to the call it runs until the
	// returned function lands it (design decision 6).
	Fly(connection string, f Flight) (land func())
}

// Flight is the call a connector runs: its egress may only do the same
// operation on the same target, or a reviewed read of that target, and
// is mapped with the call's own ids.
type Flight struct {
	Txn    string
	Action actionir.ActionIR
}

// ErrNoConnectors reports a connector connection on a gateway that runs no
// connectors (HR-084): nothing is sent.
var ErrNoConnectors = errors.New("dispatch: this gateway runs no connectors")

// ErrEgressContained refuses a connector's egress request while a dispatch
// through its egress connection would be refused: the kill switch, a
// quarantined connection or an open circuit.
var ErrEgressContained = errors.New("dispatch: containment stops connector egress")

// connectorEntry is a connector connection's MCP client. It has no egress
// client: the connector reaches nothing itself, and calls go over stdio.
func (e *Engine) connectorEntry(conn *control.Connection) (clientEntry, error) {
	if e.connectors == nil {
		return clientEntry{}, ErrNoConnectors
	}
	c, err := e.connectors.Client(conn.GetId())
	return clientEntry{revision: conn.GetRevision(), mcp: c}, err
}

// fly binds a connector connection's egress to the call it is about to
// run; it does nothing for any other connection.
func (e *Engine) fly(conn *control.Connection, a actionir.Parsed, txn string) (land func()) {
	if conn.GetKind() != "mcp_container" || e.connectors == nil {
		return func() {}
	}
	return e.connectors.Fly(conn.GetId(), Flight{Txn: txn, Action: a.Action})
}

// ConnectorEgress sends one request a connector made while running a call,
// already mapped through its egress connection and checked against the
// call (G0 M9 design decision 6): it is re-serialized from the reviewed
// definition (HR-075), carries the egress connection's credential, placed
// here (decision 18), and goes through that connection's hardened egress
// client. The answer comes back without the credential.
func (e *Engine) ConnectorEgress(ctx context.Context, conn *control.Connection, a actionir.Parsed, txn string) (egress.Response, error) {
	if _, class, _ := e.contained(conn); class != "" {
		return egress.Response{}, ErrEgressContained
	}
	if e.breaker.open(ctx, conn) {
		return egress.Response{}, ErrEgressContained
	}
	def, ok := conn.Package.Definition(a.Action.Operation)
	if !ok {
		return egress.Response{}, fmt.Errorf("%w: %s is not in the egress connection's package", egress.ErrBuild, a.Action.Operation)
	}
	p, err := e.prepare(ctx, conn, def, a, txn)
	if err != nil {
		return egress.Response{}, err
	}
	var secret []byte
	if conn.GetAccessMode() == "pantherclaw_held" {
		if secret, err = e.credential(conn, p.req); err != nil {
			return egress.Response{}, err
		}
		defer clear(secret)
	}
	res, err := p.client.Do(p.req)
	outcome, _, _ := classify(res.Status, err)
	e.breaker.record(ctx, conn, outcome)
	e.log.InfoContext(ctx, "gateway.connector_egress", slog.String("transaction_id", txn), slog.String("connection_id", conn.GetId()),
		slog.String("operation", a.Action.Operation), slog.Int("status", res.Status))
	res.Body = egress.Redacted(res.Body, secret)
	res.ContentType = string(egress.Redacted([]byte(res.ContentType), secret))
	res.RequestID = string(egress.Redacted([]byte(res.RequestID), secret))
	return res, err
}
