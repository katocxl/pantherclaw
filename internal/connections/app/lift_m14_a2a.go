// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// LiftA2ACardDriftTx lifts an a2a connection's card-drift quarantine in
// the caller's transaction, the one that confirms the connection's new pin
// (G0 M14 D86, D118): only a quarantine whose reason is a2a_card_drift is
// lifted, as Restore lifts one (circuits closed, configuration bumped,
// audited, a weakening notified); any other state or reason is left as it
// is. It reports whether it lifted one.
//
// Precondition (D122): it checks no permission itself. Its one caller is the
// a2a pin confirmation (a2astore.Pins.Confirm), which has verified, in this
// same tx, that the caller is a person holding connection.manage with a
// fresh security-key step-up. Exported only for that cross-package caller;
// call it from nowhere else.
func (s *Service) LiftA2ACardDriftTx(ctx context.Context, tx db.TenantTx, caller tenancy.Caller, id ids.UUID) (bool, error) {
	c := actor{Org: caller.Org, By: caller.Principal.String(), Audit: caller.Actor(), Caller: caller}
	q := dbq.New(tx)
	conn, err := lock(ctx, q, c.Org, id)
	if err != nil {
		return false, err
	}
	if conn.Kind != KindA2A || conn.State != StateQuarantined || conn.QuarantineReason == nil || *conn.QuarantineReason != ReasonA2ACardDrift {
		return false, nil
	}
	details := map[string]string{"reason": ReasonA2ACardDrift}
	n, err := q.CloseCircuits(ctx, c.Org, id)
	if err != nil {
		return false, err
	}
	if n > 0 {
		details["circuits_closed"] = strconv.FormatInt(n, 10)
	}
	p := params(c, conn)
	p.State, p.QuarantineReason = StateActive, nil
	_, err = s.apply(ctx, tx, c, conn, p, []change{{field: "state", from: conn.State, to: StateActive, weakens: true}}, "connection.restored", details)
	return err == nil, err
}
