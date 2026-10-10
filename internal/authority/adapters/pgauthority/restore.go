// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"errors"

	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// sweeperActor records what the sweeper does on its own.
var sweeperActor = evdomain.Actor{Type: "system", ID: "sweeper"}

// releasedUnused settles a permit that was just released from ISSUED, in
// the caller's transaction: its reservation and its dedupe claim are
// released (HR-003), and an approval it consumed is restored, because a
// permit that never reached DISPATCHING sent nothing (HR-011).
func releasedUnused(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, permit, txn ids.UUID, actor evdomain.Actor) error {
	if err := pgbudgets.Settle(ctx, q, org, permit, bdomain.Release); err != nil {
		return err
	}
	if err := q.SettleDedupeClaim(ctx, string(pipeline.ClaimReleased), org, txn); err != nil {
		return err
	}
	_, err := pgapprovals.Restore(ctx, tx, org, permit, finalize.MaxEvaluations, actor)
	return err
}

// releaseRefused releases a permit BeginDispatch just refused when it can
// never pass (it expired, or containment moved past its epoch), so its
// approval is restored at once rather than when the sweeper finds it
// expired (HR-011). A permit that may still pass is left alone.
func releaseRefused(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, gatewayID string, permit ids.UUID, refusal error) error {
	if !errors.Is(refusal, finalize.ErrPermitExpired) && !errors.Is(refusal, finalize.ErrEpochStale) &&
		!errors.Is(refusal, finalize.ErrKillSwitch) {
		return nil
	}
	p, err := q.ReleaseRefusedPermit(ctx, org, permit, gatewayID)
	if db.IsNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return releasedUnused(ctx, tx, q, org, p.ID, p.TransactionID, evdomain.Actor{Type: "gateway", ID: gatewayID})
}
