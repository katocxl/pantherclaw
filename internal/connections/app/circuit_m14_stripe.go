// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// QuarantineStripeLivemode is the quarantine reason of a connection whose
// gateway saw Stripe answer in live mode (G0 M14 D54, HR-303).
const QuarantineStripeLivemode = "stripe_livemode"

// ErrCircuitReason reports a circuit reason the server does not know.
var ErrCircuitReason = pcerr.New(pcerr.InvalidArgument, "CIRCUIT_REASON_UNKNOWN", "the only circuit reason is stripe_livemode")

// OpenCircuitFor records that a gateway opened a connection's circuit for
// reason, without the outcome thresholds: Stripe answered in live mode
// through a connection that may hold only a test key (D54). Like
// OpenCircuit it quarantines the connection with the gateway as actor,
// raises the epoch and notifies the org admins; it also records the
// security audit event security.stripe_livemode. A connection of another
// gateway or org is not found. It reports whether the connection is
// quarantined.
func (s *Service) OpenCircuitFor(ctx context.Context, org ids.OrgID, gateway, id ids.UUID, reason string) (bool, error) {
	if reason != QuarantineStripeLivemode {
		return false, ErrCircuitReason
	}
	c := actor{Org: org, By: "gateway:" + gateway.String(), Audit: evdomain.Actor{Type: "gateway", ID: gateway.String()}}
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := lock(ctx, q, org, id)
		if err != nil {
			return err
		}
		if conn.GatewayID != gateway {
			return ErrNotFound
		}
		if err := q.OpenCircuit(ctx, dbq.OpenCircuitParams{OrgID: org, ConnectionID: id, GatewayID: gateway}); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "security.stripe_livemode", Actor: c.Audit, Outcome: audit.Denied, ReasonCode: "STRIPE_LIVEMODE",
			Object:  &audit.Object{Type: "connection", ID: id.String()},
			Details: map[string]string{"gateway": gateway.String(), "connection": conn.Name},
		}); err != nil {
			return err
		}
		if conn.State != StateActive {
			return nil // already quarantined: the circuit and the event are recorded
		}
		p := params(c, conn)
		r := reason
		p.State, p.QuarantineReason = StateQuarantined, &r
		after, err := s.apply(ctx, tx, c, conn, p, []change{{field: "state", from: conn.State, to: StateQuarantined}}, "connection.quarantined",
			map[string]string{"reason_code": reason})
		if err != nil {
			return err
		}
		return s.notifyQuarantined(ctx, tx, c, after, reason)
	})
	if err != nil {
		return false, err
	}
	return true, nil
}
