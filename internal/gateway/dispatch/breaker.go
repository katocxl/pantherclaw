// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Circuit breaker (G0 M6 design decision 12, HR-078): per connection, over
// BreakerWindow, at least BreakerMinUnknown UNKNOWN outcomes making up at
// least half of all outcomes open the circuit. The gateway then dispatches
// nothing to the connection and reports it; the server quarantines the
// connection, and only a person restores it.
const (
	BreakerWindow     = 60 * time.Second
	BreakerMinUnknown = 5
	reportTimeout     = 5 * time.Second
)

// Reporter tells the server that a connection's circuit opened
// (GatewayService.ReportCircuit).
type Reporter func(ctx context.Context, connection string, unknown, total int32) error

type outcomeAt struct {
	at      time.Time
	unknown bool
}

// circuit is one connection's recent outcomes and, once open, the
// connection revision it opened under and whether the server knows.
type circuit struct {
	outcomes       []outcomeAt
	open           bool
	revision       int32
	unknown, total int32
	reported       bool
	reporting      bool
	// reason, when set, opened the circuit without the thresholds
	// (stripe_livemode, G0 M14 D54).
	reason string
}

type breaker struct {
	now    func() time.Time
	report Reporter
	// reportReason reports a circuit a reason opened; nil reports nothing.
	reportReason ReasonReporter
	log    *slog.Logger

	mu       sync.Mutex
	circuits map[string]*circuit
}

func newBreaker(now func() time.Time, report Reporter, log *slog.Logger) *breaker {
	return &breaker{now: now, report: report, log: log, circuits: map[string]*circuit{}}
}

// open reports whether the connection's circuit is open, and asks again
// for a report the server has not acknowledged. A circuit closes when the
// connection is active under a newer revision: after the server
// quarantined it, only a person's restore makes it active again.
func (b *breaker) open(ctx context.Context, conn *control.Connection) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.circuits[conn.GetId()]
	if c == nil || !c.open {
		return false
	}
	if conn.GetRevision() > c.revision && conn.GetState() == "ACTIVE" {
		delete(b.circuits, conn.GetId())
		return false
	}
	b.reportLocked(ctx, conn.GetId(), c)
	return true
}

// record adds an outcome of a request that was sent, or tried to be, and
// opens the circuit when it crosses the thresholds.
func (b *breaker) record(ctx context.Context, conn *control.Connection, o pb.Outcome) {
	now := b.now()
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
	kept := c.outcomes[:0]
	for _, x := range c.outcomes {
		if now.Sub(x.at) < BreakerWindow {
			kept = append(kept, x)
		}
	}
	kept = append(kept, outcomeAt{at: now, unknown: o == pb.Outcome_OUTCOME_UNKNOWN})
	c.outcomes = kept
	var unknown int32
	for _, x := range c.outcomes {
		if x.unknown {
			unknown++
		}
	}
	total := int32(len(c.outcomes)) //nolint:gosec // G115: bounded by the requests of one window
	if unknown < BreakerMinUnknown || unknown*2 < total {
		return
	}
	c.open, c.revision, c.unknown, c.total, c.outcomes = true, conn.GetRevision(), unknown, total, nil
	b.log.WarnContext(ctx, "security.circuit_opened", slog.String("connection_id", conn.GetId()), slog.Int("unknown", int(unknown)),
		slog.Int("outcomes", int(total)))
	b.reportLocked(ctx, conn.GetId(), c)
}

// reportLocked sends the report in the background, one at a time, until
// the server acknowledges it.
func (b *breaker) reportLocked(ctx context.Context, id string, c *circuit) {
	if c.reported || c.reporting || b.report == nil {
		return
	}
	c.reporting = true
	unknown, total, reason := c.unknown, c.total, c.reason
	if reason != "" && b.reportReason == nil {
		c.reporting = false
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reportTimeout)
		defer cancel()
		var err error
		if reason != "" {
			err = b.reportReason(ctx, id, reason)
		} else {
			err = b.report(ctx, id, unknown, total)
		}
		b.mu.Lock()
		c.reporting, c.reported = false, err == nil
		b.mu.Unlock()
		if err != nil {
			b.log.ErrorContext(ctx, "gateway.circuit_report_failed", slog.String("connection_id", id), pclog.Err(err))
		}
	}()
}
