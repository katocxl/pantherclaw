// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"errors"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
)

// Connectors are a customer-hosted gateway's running connectors (G0 M9
// track C): third-party stdio MCP servers in containers.
type Connectors interface {
	// Client returns a running connector's MCP client, which speaks over
	// its container's standard input and output.
	Client(connection string) (*upstream.Client, error)
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
	c, err := e.connectors.Client(conn.GetId())
	return clientEntry{revision: conn.GetRevision(), mcp: c}, err
}
