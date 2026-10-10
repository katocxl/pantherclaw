// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgwaitlist

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Resolutions of a reconciliation, the reason a RECONCILIATION entry ends
// with (G0 M7 design decision 3).
const (
	ResolvedOccurred    = "OCCURRED"
	ResolvedNotOccurred = "NOT_OCCURRED"
)

// CloseReconciliation ends the open RECONCILIATION entry of a transaction
// whose unknown outcome was resolved, in the transaction that resolved it
// (G0 M7 slice A11; M5 part 2 decision 20: the entry never ends by
// itself). A person's resolution (by a user: "occurred", or the release on
// the reconciliation page) decides the entry: APPROVED, with the
// resolution as its reason. Evidence that the effect happened (the
// verifier, a late report, the target log) leaves nothing to decide:
// CANCELLED, with the resolution as its reason. A transaction without an
// open entry changes nothing.
func CloseReconciliation(ctx context.Context, tx db.TenantTx, org ids.OrgID, transaction ids.UUID, resolution string,
	by evdomain.Actor,
) error {
	state := wdomain.StateCancelled
	if by.Type == "user" {
		state = wdomain.StateApproved
	}
	decided := by.Type + ":" + by.ID
	q := dbq.New(tx)
	entry, err := q.OpenEntryOf(ctx, org, "transaction", transaction)
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	n, err := q.CloseEntryOf(ctx, dbq.CloseEntryOfParams{
		State: state, DecidedBy: &decided, Reason: resolution, OrgID: org, Kind: wdomain.KindReconciliation,
		SubjectType: "transaction", SubjectID: transaction,
	})
	if err != nil || n == 0 {
		return err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "waitlist.entry_closed", Actor: by, Outcome: audit.Success, ReasonCode: resolution,
		Object:  &audit.Object{Type: "waitlist_entry", ID: entry.String()},
		Details: map[string]string{"kind": wdomain.KindReconciliation, "state": state, "subject": "transaction:" + transaction.String()},
	})
	return err
}
