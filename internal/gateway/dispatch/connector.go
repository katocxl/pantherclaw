// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
)

// Connectors are a customer-hosted gateway's running connectors (G0 M9
// track C): third-party stdio MCP servers in containers.
type Connectors interface {
	// Client returns a running connector's MCP client at the connection's
	// revision, which speaks over its container's standard input and output;
	// a connector of another revision, or one whose last exchange was
	// abandoned, is not running.
	Client(connection string, revision int32) (*upstream.Client, error)
}

// ErrNoConnectors reports a connector connection on a gateway that runs no
// connectors (HR-084): nothing is sent.
var ErrNoConnectors = errors.New("dispatch: this gateway runs no connectors")

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
