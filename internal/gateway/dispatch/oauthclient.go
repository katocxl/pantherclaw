// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"time"

	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
)

// maxTokenAnswer caps a token endpoint's answer.
const maxTokenAnswer = 64 << 10

// clientToken opens the connection's OAuth client credential and mints an
// access token for one dispatch at its token endpoint (G0 M20 D254,
// HR-524), through an egress client pinned to the endpoint's host, which
// the seal must bind. The client secret is cleared as soon as the token
// request is sent; the caller clears the token when the dispatch ends.
func (e *Engine) clientToken(ctx context.Context, conn *control.Connection) (*broker.ClientToken, error) {
	plain, err := e.openCredential(conn)
	if err != nil {
		return nil, err
	}
	oc, err := credentials.DecodeOAuthClient(plain)
	clear(plain)
	if err != nil {
		return nil, err
	}
	defer oc.Clear()
	c, err := e.tokenClient(conn, oc.TokenURL)
	if err != nil {
		return nil, err
	}
	return broker.MintClientToken(ctx, c, conn.Credential.GetAllowedHosts(), oc)
}

// tokenClient returns the egress client of a connection's token endpoint,
// new for each revision of the connection: the hardened client under the
// connection's timeout and the egress allow-list (HR-070..074).
func (e *Engine) tokenClient(conn *control.Connection, tokenURL string) (*egress.Client, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ce, ok := e.tokenClients[conn.GetId()]; ok && ce.revision == conn.GetRevision() && ce.base == tokenURL {
		return ce.client, nil
	}
	timeout := time.Duration(conn.GetTimeoutMs()) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	c, err := egress.NewClient(tokenURL, timeout, maxTokenAnswer, e.allowed)
	if err != nil {
		return nil, err
	}
	e.tokenClients[conn.GetId()] = clientEntry{revision: conn.GetRevision(), base: tokenURL, client: c}
	return c, nil
}
