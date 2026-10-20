// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// A2A card drift (G0 M14 D86).
const (
	// ToolA2ACard is the "tool" of a drift report about an a2a connection's
	// agent card: expected and observed are the pinned and the fetched
	// card digests.
	ToolA2ACard = "a2a.card"
	// ReasonA2ACardDrift is the quarantine reason of a connection whose
	// peer's card changed.
	ReasonA2ACardDrift = "a2a_card_drift"
)

// reportCardDrift quarantines an a2a connection whose peer agent's card no
// longer has the pinned digest (HR-322): the connection itself, not a
// package version, since the card is the connection's own pin. One
// transaction calls the kind's drift hook (which may refuse a stale
// report), moves the connection to QUARANTINED (a strengthening change,
// so the epoch rises and outstanding permits fail BeginDispatch), audits
// it with the gateway as actor and notifies. Only the kind's confirmed
// re-pin lifts it. A simulated connection's report is audited and changes
// nothing else (HR-222).
func (s *Service) reportCardDrift(ctx context.Context, c actor, gateway, id ids.UUID, expected, observed string) (bool, error) {
	quarantined := false
	err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		quarantined = false
		q := dbq.New(tx)
		conn, err := lock(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if conn.GatewayID != gateway || conn.Kind != KindA2A {
			return ErrNotFound
		}
		details := map[string]string{"upstream_tool": ToolA2ACard, "expected_digest": expected, "observed_digest": observed}
		if conn.Simulated {
			details["simulated"] = "true"
			_, err := audit.Record(ctx, tx, audit.Event{
				Name: "connection.drift_reported", Actor: c.Audit, Outcome: audit.Success,
				Object: &audit.Object{Type: "connection", ID: conn.ID.String()}, Details: details,
			})
			return err
		}
		if hook, ok := s.kinds.Drift(KindA2A); ok {
			if err := hook.Drift(ctx, tx, c.Org, conn.ID, expected, observed); err != nil {
				return err
			}
		}
		switch conn.State {
		case StateQuarantined:
			quarantined = true
			return nil
		case StateActive:
		default:
			return nil // retired: nothing to stop
		}
		p := params(c, conn)
		reason := ReasonA2ACardDrift
		p.State, p.QuarantineReason = StateQuarantined, &reason
		details["reason"] = reason
		after, err := s.apply(ctx, tx, c, conn, p, []change{{field: "state", from: conn.State, to: StateQuarantined}},
			"connection.quarantined", details)
		if err != nil {
			return err
		}
		if err := s.notifyQuarantined(ctx, tx, c, after, reason); err != nil {
			return err
		}
		quarantined = true
		return nil
	})
	return quarantined, err
}
