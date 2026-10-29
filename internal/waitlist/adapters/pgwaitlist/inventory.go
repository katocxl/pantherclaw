// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgwaitlist

import (
	"context"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// SubjectInventory is the subject type of an inventory item's TOOL_REVIEW
// entry (G0 M15 D21).
const SubjectInventory = "connection_inventory"

// OpenInventoryReview opens the TOOL_REVIEW entry of a NEW inventory item
// (F352, G0 M15 D22): what a connection's upstream server lists that no
// active reviewed package version covers. Only what PantherClaw
// established goes in the trusted block; the upstream description never
// does (HR-415). It returns the item's open entry when there is one.
func OpenInventoryReview(ctx context.Context, tx db.TenantTx, org ids.OrgID, item, connection ids.UUID, kind, name string,
	actor evdomain.Actor,
) (ids.UUID, error) {
	return open(ctx, tx, org, entry{
		kind: wdomain.KindToolReview, subjectType: SubjectInventory, subject: item,
		trusted: map[string]string{"connection": connection.String(), "kind": kind, "name": name},
	}, actor)
}

// CloseInventoryReview settles an inventory item's open TOOL_REVIEW entry
// (HR-417): APPROVED when a reviewed version covers the item, REJECTED
// when a person dismissed it (reason is theirs), EXPIRED when a complete
// listing no longer has it. Nothing else closes it; an item without an
// open entry changes nothing.
func CloseInventoryReview(ctx context.Context, tx db.TenantTx, org ids.OrgID, item ids.UUID, state, by, reason string) error {
	_, err := dbq.New(tx).CloseEntryOf(ctx, dbq.CloseEntryOfParams{
		State: state, DecidedBy: &by, Reason: reason, OrgID: org, Kind: wdomain.KindToolReview, SubjectType: SubjectInventory,
		SubjectID: item,
	})
	return err
}
