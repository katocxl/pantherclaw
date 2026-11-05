// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// QuarantinePaymentsLive is the reason a connection's circuit opens when
// an agent payment through it leaves the sandbox: a mandate or key from a
// live anchor or host (G0 M39 D1120, HR-831). The server records it as
// security.payments_live_refused.
const QuarantinePaymentsLive = "payments_live_refused"

// TripPaymentsLive opens the connection's circuit at once, whatever its
// outcomes, as the Stripe live-mode guard does (livemode.go): the payment
// is refused with PAYMENTS_LIVE_REFUSED (ap2.ErrLiveRefused) and the
// gateway dispatches nothing to the connection until a person restores
// it. where says which step saw it (fact or dispatch).
func (e *Engine) TripPaymentsLive(ctx context.Context, conn *control.Connection, where string) {
	e.log.WarnContext(ctx, "security.payments_live_refused", slog.String("connection_id", conn.GetId()), slog.String("seen_in", where))
	e.breaker.trip(ctx, conn, QuarantinePaymentsLive)
}
