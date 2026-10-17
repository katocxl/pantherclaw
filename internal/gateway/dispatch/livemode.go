// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// QuarantineStripeLivemode is the reason a connection's circuit opens when
// Stripe answers in live mode (G0 M14 D54).
const QuarantineStripeLivemode = "stripe_livemode"

// stripeLivemode opens the connection's circuit at once, whatever its
// outcomes: Stripe answered in live mode through a connection that may
// hold only a test key (HR-303, D54). The gateway then dispatches nothing
// to it until a person restores it; where says which read saw it (fact,
// dispatch or verify).
func (e *Engine) stripeLivemode(ctx context.Context, conn *control.Connection, where string) {
	e.log.WarnContext(ctx, "security.stripe_livemode", slog.String("connection_id", conn.GetId()), slog.String("seen_in", where))
	e.breaker.trip(ctx, conn, QuarantineStripeLivemode)
}

// answersLivemode reports whether a Stripe answer body is an object, or a
// list of objects, that says livemode true.
func answersLivemode(body []byte) bool {
	var v struct {
		Livemode bool `json:"livemode"`
		Data     []struct {
			Livemode bool `json:"livemode"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &v) != nil {
		return false
	}
	if v.Livemode {
		return true
	}
	for _, d := range v.Data {
		if d.Livemode {
			return true
		}
	}
	return false
}

// trip opens the connection's circuit for reason, without the outcome
// thresholds, and reports it.
func (b *breaker) trip(ctx context.Context, conn *control.Connection, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.circuits[conn.GetId()]
	if c == nil {
		c = &circuit{}
		b.circuits[conn.GetId()] = c
	}
	if c.open {
		return
	}
	c.open, c.revision, c.unknown, c.total, c.outcomes, c.reason = true, conn.GetRevision(), 0, 0, nil, reason
	b.reportLocked(ctx, conn.GetId(), c)
}

// ReasonReporter tells the server that a connection's circuit opened for
// reason (GatewayService.ReportCircuit with a reason).
type ReasonReporter func(ctx context.Context, connection, reason string) error

func (b *breaker) withReason(r ReasonReporter) *breaker {
	b.reportReason = r
	return b
}

// stripeAnswerLive watches an answer through a pc.stripe connection: one
// that reports livemode true opens the circuit (D54), and is reported so
// the caller treats it as inconclusive where it can.
func (e *Engine) stripeAnswerLive(ctx context.Context, conn *control.Connection, body []byte, where string) bool {
	if conn.Package == nil || conn.Package.Name != StripePackage || !answersLivemode(body) {
		return false
	}
	e.stripeLivemode(ctx, conn, where)
	return true
}

// StripePackage is the package whose answers the live-mode guard watches.
const StripePackage = "pc.stripe"
