// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// NudgeForAutomationTx reminds or escalates an approval request's open
// waitlist entry for a governed automation's approval routing steps (G0
// M11 part 2 D31), in the caller's transaction. Without escalate it sends
// the approval.reminder notice to the eligible deciders already told;
// with escalate the approval.escalated notice to the eligible deciders not
// told yet. The deciders are computed as routing computes them, so it
// never makes anyone eligible (HR-173), and every recipient is recorded in
// waitlist_routes like a routing step's. dedupe makes a repeat send
// nothing. It returns how many people it told; a request without an open
// entry tells no one.
func (r *Router) NudgeForAutomationTx(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID, escalate bool, dedupe string) (int, error) {
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return 0, err
	}
	q := dbq.New(ttx)
	entry, err := q.OpenEntryOf(ctx, org, "approval_request", request)
	if db.IsNoRows(err) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	e, err := q.EntryForRouting(ctx, org, entry)
	if db.IsNoRows(err) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	ds, err := deciders(ctx, q, org, e)
	if err != nil {
		return 0, err
	}
	told, err := q.EntryRecipients(ctx, org, entry)
	if err != nil {
		return 0, err
	}
	var to []ids.UUID
	for _, c := range ds {
		if slices.Contains(told, c.User) != escalate {
			to = append(to, c.User)
		}
	}
	if len(to) == 0 {
		return 0, nil
	}
	m, fam, err := notice(ctx, q, org, e)
	if err != nil {
		return 0, err
	}
	m.Personal, m.PersonalOnly, m.DedupeKey, m.Type = to, true, "automation:"+dedupe, fam.reminder
	if escalate {
		m.Type = fam.escalated
	}
	enq, err := r.Notify.Enqueue(ctx, ttx, m)
	if err != nil || enq.Duplicate {
		return 0, err
	}
	if err := recordRoutes(ctx, q, org, entry, e.EscalationStep, "decider", to, nil); err != nil {
		return 0, err
	}
	return len(to), nil
}
