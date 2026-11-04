// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"context"
	"strconv"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Circuit breaker thresholds (G0 M6 design decision 12, HR-078): over the
// gateway's 60-second window, at least MinUnknown UNKNOWN outcomes making
// up at least half of all outcomes open it.
const MinUnknown = 5

// QuarantineCircuitOpen is the quarantine reason of a connection whose
// circuit a gateway opened.
const QuarantineCircuitOpen = "circuit_open"

// ErrCircuit reports a circuit report below the thresholds.
var ErrCircuit = pcerr.New(pcerr.InvalidArgument, "CIRCUIT_BELOW_THRESHOLD",
	"a circuit opens at 5 or more unknown outcomes making up at least half of all outcomes")

// OpenCircuit records that a gateway's breaker opened for a connection it
// serves (HR-078) and quarantines the connection: the epoch rises, so
// outstanding permits fail BeginDispatch, every gateway stops, the change
// is audited with the gateway as actor, and org admins are notified. The
// connection stays quarantined until a person restores it (HR-183), which
// closes the circuit. A connection of another gateway or org is not found.
// It reports whether the connection is quarantined.
func (s *Service) OpenCircuit(ctx context.Context, org ids.OrgID, gateway, id ids.UUID, unknown, total int32) (bool, error) {
	if unknown < MinUnknown || total < unknown || unknown*2 < total {
		return false, ErrCircuit
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
		if err := q.OpenCircuit(ctx, dbq.OpenCircuitParams{
			OrgID: org, ConnectionID: id, GatewayID: gateway, UnknownCount: unknown, TotalCount: total,
		}); err != nil {
			return err
		}
		if conn.State != StateActive {
			return nil // already quarantined: the circuit is recorded
		}
		p := params(c, conn)
		reason := QuarantineCircuitOpen
		p.State, p.QuarantineReason = StateQuarantined, &reason
		after, err := s.apply(ctx, tx, c, conn, p, []change{{field: "state", from: conn.State, to: StateQuarantined}}, auditkind.ConnectionQuarantined,
			map[string]string{"reason_code": reason, "unknown_outcomes": strconv.Itoa(int(unknown)), "outcomes": strconv.Itoa(int(total))})
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
