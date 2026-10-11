// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgapprovals

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ReasonPermitReleased is why an approval is restored: its permit was
// released without reaching DISPATCHING.
const ReasonPermitReleased = "PERMIT_RELEASED"

// maxSlots is the schema's bound on a hold-slot counter.
const maxSlots = 100

// Restore returns the approval a released permit consumed to APPROVED, in
// the caller's transaction (HR-011, founder decision 2026-10-10). Only the
// server's own proof counts: a permit is RELEASED only from ISSUED (it
// expired, or BeginDispatch refused it), so nothing was sent. Any outcome
// after BeginDispatch never restores: FAILED needs a new approval and
// UNKNOWN goes to reconciliation. The request must still be usable (before
// its consume-by time and deadline), its transaction an approval-based
// ALLOW evaluated fewer than maxEvaluations times, with no other live
// request. The request takes its hold slots back, because an approved
// request not yet used counts as pending (HR-037), and the transaction is
// reopened, so the agent's resubmission of the same run and action is
// evaluated again and the approval is used by a new permit (PAP-1 §7.1,
// §8). It reports whether it restored anything.
func Restore(ctx context.Context, tx db.TenantTx, org ids.OrgID, permit ids.UUID, maxEvaluations int, actor evdomain.Actor) (bool, error) {
	q := dbq.New(tx)
	row, err := q.RestorableApproval(ctx, org, &permit, int32(maxEvaluations)) //nolint:gosec // small
	if db.IsNoRows(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// The slots this request gave back when it was consumed, moments ago,
	// are taken again whatever the org's cap, so the count stays exact; a
	// counter at the schema's bound leaves the approval used.
	var taken []slot
	for _, s := range slots(row.GrantID, row.RunID, maxSlots, maxSlots) {
		if s.id == nil {
			continue
		}
		n, err := q.TakeHoldSlot(ctx, dbq.TakeHoldSlotParams{OrgID: org, ScopeKind: s.kind, ScopeID: *s.id, Cap: s.cap})
		if err != nil {
			return false, err
		}
		if n == 0 {
			for _, t := range taken {
				if _, err := q.ReleaseHoldSlot(ctx, org, t.kind, *t.id); err != nil {
					return false, err
				}
			}
			return false, nil
		}
		taken = append(taken, s)
	}
	// RestorableApproval locked both rows with these conditions, so each
	// update changes exactly one.
	if n, err := q.RestoreApprovalRequest(ctx, org, row.ID); err != nil || n != 1 {
		return false, changed(err)
	}
	if row.TransactionID == nil {
		return false, ErrChanged
	}
	if n, err := q.ReopenTransaction(ctx, org, *row.TransactionID); err != nil || n != 1 {
		return false, changed(err)
	}
	return true, event(ctx, tx, "approval.restored", actor, audit.Success, ReasonPermitReleased, row.ID, map[string]string{
		"permit": permit.String(), "transaction": row.TransactionID.String(),
	})
}

func changed(err error) error {
	if err != nil {
		return err
	}
	return ErrChanged
}
