// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/payments/sandbox"
)

// CodePaymentsLiveRefused: a payment-class action through a connection
// whose merchant endpoint is not an https URL on the sandbox host
// allow-list (G0 M39 D1124c, HR-831). Nothing is decided or sent, and the
// connection's circuit opens (TripPaymentsLive).
const CodePaymentsLiveRefused = "PAYMENTS_LIVE_REFUSED"

// agentPayPackage is the agent payments package (G0 M39 D1124).
const agentPayPackage = "pc.agentpay"

// paymentsEndpointRefused reports whether a payment-class action must be
// refused because its connection's endpoint left the sandbox; it then
// trips the connection's circuit. The server checks the endpoint again
// when it decides, and when the connection is created or changed.
func (e *Engine) paymentsEndpointRefused(ctx context.Context, conn *control.Connection, a actionir.ActionIR) bool {
	if conn.Package == nil {
		return false
	}
	def, ok := conn.Package.Definition(a.Operation)
	if !ok || def.Payment == nil {
		return false
	}
	if ok, isSandbox := sandbox.URL(conn.GetBaseUrl()); ok && isSandbox {
		return false
	}
	e.TripPaymentsLive(ctx, conn, "dispatch")
	return true
}
