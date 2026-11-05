// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// NeedsSecondPerson is what a change request of a partner-origin version
// waits for while the org has fewer than two people who may confirm it
// (G0 M38 D1102, HR-815).
const NeedsSecondPerson = "NEEDS_SECOND_PERSON"

// partnerOrigin returns "partner:<partner org>" when the version a PUBLISH
// or ROLLOUT change request is about was drafted from an accepted MSSP
// partner proposal (pc.partner_proposals.draft_ref), else "".
func partnerOrigin(ctx context.Context, q *dbq.Queries, org ids.OrgID, kind ChangeKind, subject ids.UUID) (string, error) {
	if kind != ChangePublish && kind != ChangeRollout {
		return "", nil
	}
	partner, err := q.PartnerOriginOfChange(ctx, org.UUID(), string(kind), subject)
	if db.IsNoRows(err) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return "partner:" + partner.String(), nil
}
