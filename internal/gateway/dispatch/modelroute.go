// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/simcheck"
)

// ModelCallTimeout bounds one model call on the model face, its stream
// included (G0 M25 D313).
const ModelCallTimeout = 5 * time.Minute

// IsModelRelay reports whether conn is what the model face may serve: an http
// connection marked model relay and simulated, with no package (D313).
func IsModelRelay(conn *control.Connection) bool {
	return conn != nil && conn.GetModelRelay() && conn.GetSimulated() && conn.GetKind() == "http" && conn.Mapper == nil
}

// ModelContained refuses a model call under containment, as any dispatch
// (HR-010): the kill switch, a revoked gateway, stale containment, or a
// quarantined connection. It returns the code, "" when the call may go on.
func (e *Engine) ModelContained(conn *control.Connection) string {
	_, _, code := e.contained(conn)
	return code
}

// ModelClient returns the relay's egress client once the relay has answered
// the handshake as a model relay, on a loopback or private literal (HR-221,
// D313). It sends nothing else. ok is false when it did not.
func (e *Engine) ModelClient(ctx context.Context, conn *control.Connection) (*egress.Client, bool) {
	if !IsModelRelay(conn) {
		return nil, false
	}
	ce, err := e.entry(conn)
	if err != nil {
		return nil, false
	}
	if err := e.sims.VerifyKind(ctx, conn.GetId(), conn.GetBaseUrl(), simcheck.ModelRelayKind, ce.client); err != nil {
		e.log.WarnContext(ctx, "gateway.simulator_unverified", slog.String("connection_id", conn.GetId()), slog.String("reason", err.Error()))
		return nil, false
	}
	return ce.client, true
}
