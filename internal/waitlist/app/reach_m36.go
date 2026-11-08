// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"

	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Approval reach in routing (G0 M36 D1063, D1064). Both change only who is
// routed and told, and when; neither changes who is eligible (HR-173) or
// decides anything (HR-789).

// fatigueLast drops the deciders with a live fatigue flag from a step's
// reach unless it is the chain's final step or every decider at the step
// is flagged, when the org routes on fatigue (the default). They stay
// eligible throughout (HR-791).
func fatigueLast(ctx context.Context, q *dbq.Queries, org ids.OrgID, reached []wdomain.Candidate, final bool) ([]wdomain.Candidate, error) {
	if final || len(reached) == 0 {
		return reached, nil
	}
	r, err := q.GetFatigueRouting(ctx, org)
	if err != nil && !db.IsNoRows(err) {
		return nil, err
	}
	if err == nil && r.Routing == "off" {
		return reached, nil
	}
	users := make([]ids.UUID, len(reached))
	for i, c := range reached {
		users[i] = c.User
	}
	flags, err := q.ActiveFatigueFlags(ctx, org, false, users)
	if err != nil || len(flags) == 0 {
		return reached, err
	}
	rest := slices.DeleteFunc(slices.Clone(reached), func(c wdomain.Candidate) bool {
		return slices.ContainsFunc(flags, func(f dbq.ActiveFatigueFlagsRow) bool { return f.UserID == c.User })
	})
	if len(rest) == 0 {
		// "Last" means after the others: a step where every decider is
		// flagged still reaches them, so no step goes untold (D1063a).
		return reached, nil
	}
	return rest, nil
}

// deputiesOf returns the deputies to route a hold to alongside persons,
// the deciders a step reaches for the first time: those whose window is
// open now and whom apdomain.Check makes eligible for one of the hold's
// requirements. A deputy who is not eligible is skipped and audited
// (approval.deputy_not_eligible); deputies never widen eligibility
// (HR-790).
func deputiesOf(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, e dbq.EntryForRoutingRow,
	persons, told []ids.UUID,
) ([]ids.UUID, error) {
	if e.Kind != wdomain.KindActionHold || len(persons) == 0 {
		return nil, nil
	}
	rows, err := q.ActiveDeputiesOf(ctx, org, persons)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	var cand []ids.UUID
	for _, r := range rows {
		if !slices.Contains(persons, r.DeputyID) && !slices.Contains(told, r.DeputyID) && !slices.Contains(cand, r.DeputyID) {
			cand = append(cand, r.DeputyID)
		}
	}
	if len(cand) == 0 {
		return nil, nil
	}
	el, err := pgapprovals.LoadEligibility(ctx, q, org, e.SubjectID, cand)
	if err != nil {
		return nil, err
	}
	var out []ids.UUID
	for _, r := range rows {
		if !slices.Contains(cand, r.DeputyID) || slices.Contains(out, r.DeputyID) {
			continue
		}
		if slices.ContainsFunc(el.Requirements, func(req apdomain.Requirement) bool {
			ok, _ := apdomain.Check(req, el.People[r.DeputyID], el.Context, ids.UUID{})
			return ok
		}) {
			out = append(out, r.DeputyID)
			continue
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: auditkind.ApprovalDeputyNotEligible, Actor: pgwaitlist.System, Outcome: audit.Success,
			Object: &audit.Object{Type: "waitlist_entry", ID: e.ID.String()},
			Details: map[string]string{
				"person": r.PersonID.String(), "deputy": r.DeputyID.String(), "request": e.SubjectID.String(),
			},
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}
