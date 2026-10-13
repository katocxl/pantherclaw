// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgapprovals

import (
	"context"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// SupersedeByKey supersedes every live request whose invalidation key is
// key, inside the caller's transaction (G0 M8, HR-205): the fact the key
// names changed for its target, so what the requests were bound to (a
// pull request's head) is no longer current. Each one releases its hold
// slots, closes its entry and is audited with the fact, as a material
// change; a new decision makes a new request. It returns how many it
// superseded.
func SupersedeByKey(ctx context.Context, tx db.TenantTx, org ids.OrgID, key string, actor evdomain.Actor) (int, error) {
	q := dbq.New(tx)
	live, err := q.LiveRequestsByInvalidationKey(ctx, org, &key)
	if err != nil {
		return 0, err
	}
	for _, id := range live {
		prev, err := q.SupersedeApprovalRequest(ctx, org, id)
		if err != nil {
			return 0, err
		}
		if err := release(ctx, q, org, prev.GrantID, prev.RunID); err != nil {
			return 0, err
		}
		if err := closeEntry(ctx, q, org, id, entryCancelled, apdomain.EndBindingChanged); err != nil {
			return 0, err
		}
		if err := event(ctx, tx, "approval.superseded", actor, audit.Success, apdomain.EndBindingChanged, id,
			map[string]string{"changed": key}); err != nil {
			return 0, err
		}
	}
	return len(live), nil
}
