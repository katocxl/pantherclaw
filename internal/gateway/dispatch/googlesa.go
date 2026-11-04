// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"time"

	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// serviceAccountToken opens the connection's Google service account
// credential and mints an access token for one dispatch at its token
// endpoint (G0 M31 D952, HR-721), through an egress client pinned to the
// endpoint's host, which the seal must bind. The key is cleared as soon as
// the assertion is signed and sent; the caller clears the token when the
// dispatch ends. Nothing is cached.
func (e *Engine) serviceAccountToken(ctx context.Context, conn *control.Connection) (*broker.ClientToken, error) {
	if conn.Credential.GetKind() != credentials.KindGoogleServiceAccount {
		return nil, errKind
	}
	plain, err := e.openCredential(ctx, conn)
	if err != nil {
		return nil, err
	}
	sa, err := credentials.DecodeGoogleServiceAccount(plain)
	clear(plain)
	defer sa.Clear()
	if err != nil {
		return nil, err
	}
	c, err := e.tokenClient(conn, sa.TokenURI)
	if err != nil {
		return nil, err
	}
	return broker.MintServiceAccountToken(ctx, c, conn.Credential.GetAllowedHosts(), sa, time.Now())
}
