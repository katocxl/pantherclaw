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

// snowflakeToken opens the connection's Snowflake key-pair credential and
// signs a key-pair JWT for one dispatch (G0 M31 D962, HR-726). The key is
// cleared as soon as the JWT is signed; the caller clears the JWT when the
// dispatch ends. Nothing is cached.
func (e *Engine) snowflakeToken(ctx context.Context, conn *control.Connection) (*broker.SnowflakeToken, error) {
	if conn.Credential.GetKind() != credentials.KindSnowflakeKeypair {
		return nil, errKind
	}
	plain, err := e.openCredential(ctx, conn)
	if err != nil {
		return nil, err
	}
	kp, err := credentials.DecodeSnowflakeKeypair(plain)
	clear(plain)
	defer kp.Clear()
	if err != nil {
		return nil, err
	}
	return broker.MintSnowflakeToken(conn.Credential.GetAllowedHosts(), kp, time.Now())
}
