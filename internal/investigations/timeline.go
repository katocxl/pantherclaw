// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package investigations

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Timeline event kinds.
const (
	EventDecision  = "DECISION"
	EventHold      = "HOLD"
	EventApproval  = "APPROVAL"
	EventDispatch  = "DISPATCH"
	EventResult    = "RESULT"
	EventAuthority = "AUTHORITY"
	EventLane      = "LANE"
	EventRunEnd    = "RUN_END"
)

// Gap kinds: evidence the timeline expected and did not find.
const (
	GapNoDecisionReceipt = "NO_DECISION_RECEIPT"
	GapOutcomeUnknown    = "OUTCOME_UNKNOWN"
	GapNoOutcome         = "NO_OUTCOME_RECORDED"
)

// Event is one point on a run's timeline.
type Event struct {
	At          time.Time
	Kind        string
	Transaction *ids.UUID
	Approval    *ids.UUID
	Grant       *ids.UUID
	Run         *ids.UUID
	Operation   string
	Connection  *ids.UUID
	// Detail is the decision, approval state, outcome, authority change or
	// lane state.
	Detail string
}

// Gap is missing evidence on the timeline. Transaction is zero for a
// telemetry gap, which names its Gateway instead.
type Gap struct {
	Kind        string
	Transaction ids.UUID
	At          time.Time
	Gateway     *ids.UUID
	Connection  *ids.UUID
	Operation   string
}

// Lane is a child run.
type Lane struct {
	Run     ids.UUID
	Agent   ids.UUID
	State   string
	Created time.Time
	Ended   *time.Time
}

// Phase is a stretch of the run's actions. Phases are inferred from the
// order of actions on connections unless workflow evidence says otherwise.
type Phase struct {
	Start, End  time.Time
	Connection  *ids.UUID
	Actions     int
	Operations  []string
	Basis       Basis
	FirstAction ids.UUID
}

// Timeline is a run's actions, holds, approvals, authority changes,
// dispatches, results, gaps and child lanes (F284), with inferred phases
// when asked (F232).
type Timeline struct {
	Run, Agent ids.UUID
	State      string
	Start      time.Time
	End        *time.Time
	Events     []Event
	Gaps       []Gap
	Lanes      []Lane
	Phases     []Phase
	// Truncated: the run has more than MaxTimelineActions actions; the
	// timeline covers the first ones.
	Truncated    bool
	ScopeLimited bool
}

// RunTimeline assembles run's timeline; phases are filled when withPhases
// (Team, F232).
func RunTimeline(ctx context.Context, tx db.TenantTx, s Scope, run ids.UUID, withPhases bool) (Timeline, error) {
	q := dbq.New(tx)
	r, err := q.InvRun(ctx, tx.OrgID(), run)
	if db.IsNoRows(err) {
		return Timeline{}, ErrRunNotFound
	} else if err != nil {
		return Timeline{}, err
	}
	if ok, err := s.Visible(ctx, r.AgentID); err != nil {
		return Timeline{}, err
	} else if !ok {
		return Timeline{}, ErrRunNotFound
	}
	tl := Timeline{Run: r.ID, Agent: r.AgentID, State: r.State, Start: r.CreatedAt, End: r.EndedAt, ScopeLimited: s.Limited()}

	txns, err := runTransactions(ctx, q, tx.OrgID(), run, MaxTimelineActions+1)
	if err != nil {
		return Timeline{}, err
	}
	if len(txns) > MaxTimelineActions {
		txns, tl.Truncated = txns[:MaxTimelineActions], true
	}
	for _, t := range txns {
		id := t.ID
		tl.Events = append(tl.Events, Event{
			At: t.CreatedAt, Kind: EventDecision, Transaction: &id, Operation: t.Operation,
			Connection: t.ConnectionID, Detail: t.Decision,
		})
		if !t.HasReceipt {
			tl.Gaps = append(tl.Gaps, Gap{Kind: GapNoDecisionReceipt, Transaction: id, At: t.CreatedAt})
		}
		if t.DispatchingAt != nil {
			tl.Events = append(tl.Events, Event{
				At: *t.DispatchingAt, Kind: EventDispatch, Transaction: &id,
				Operation: t.Operation, Connection: t.ConnectionID,
			})
		}
		switch {
		case t.Outcome != nil && t.OutcomeAt != nil:
			tl.Events = append(tl.Events, Event{
				At: *t.OutcomeAt, Kind: EventResult, Transaction: &id,
				Operation: t.Operation, Connection: t.ConnectionID, Detail: *t.Outcome,
			})
			if *t.Outcome == "unknown" {
				tl.Gaps = append(tl.Gaps, Gap{Kind: GapOutcomeUnknown, Transaction: id, At: *t.OutcomeAt})
			}
		case t.DispatchingAt != nil && t.PermitState != nil && *t.PermitState == "UNKNOWN":
			tl.Gaps = append(tl.Gaps, Gap{Kind: GapOutcomeUnknown, Transaction: id, At: *t.DispatchingAt})
		case t.DispatchingAt != nil && r.EndedAt != nil:
			tl.Gaps = append(tl.Gaps, Gap{Kind: GapNoOutcome, Transaction: id, At: *t.DispatchingAt})
		}
	}

	aps, err := q.InvApprovals(ctx, dbq.InvApprovalsParams{OrgID: tx.OrgID(), RunID: &run, MaxRows: MaxApprovals})
	if err != nil {
		return Timeline{}, err
	}
	for _, a := range aps {
		id := a.ID
		tl.Events = append(tl.Events, Event{
			At: a.CreatedAt, Kind: EventHold, Approval: &id, Transaction: a.TransactionID,
			Operation: a.Operation, Detail: "PENDING",
		})
		if end := firstTime(a.ApprovedAt, a.EndedAt); end != nil {
			tl.Events = append(tl.Events, Event{
				At: *end, Kind: EventApproval, Approval: &id, Transaction: a.TransactionID,
				Operation: a.Operation, Detail: a.State,
			})
		}
	}

	until := time.Now()
	if r.EndedAt != nil {
		until = *r.EndedAt
	}
	changes, err := q.InvGrantChanges(ctx, dbq.InvGrantChangesParams{
		OrgID: tx.OrgID(), AgentID: r.AgentID, StartTime: r.CreatedAt, EndTime: until.Add(time.Microsecond),
	})
	if err != nil {
		return Timeline{}, err
	}
	for _, c := range changes {
		g := c.GrantID
		tl.Events = append(tl.Events, Event{At: c.At, Kind: EventAuthority, Grant: &g, Detail: authorityDetail(c)})
	}

	// Lanes are the first MaxChildren children the caller may read, so
	// hidden children never push visible ones out (HR-401).
	lanes, _, err := children(ctx, q, tx.OrgID(), s, run)
	if err != nil {
		return Timeline{}, err
	}
	tl.Lanes = lanes
	for _, l := range lanes {
		id := l.Run
		tl.Events = append(tl.Events, Event{At: l.Created, Kind: EventLane, Run: &id, Detail: l.State})
	}
	if r.EndedAt != nil {
		tl.Events = append(tl.Events, Event{At: *r.EndedAt, Kind: EventRunEnd, Detail: str(r.EndReason)})
	}
	slices.SortStableFunc(tl.Events, func(a, b Event) int { return a.At.Compare(b.At) })
	if withPhases {
		tl.Phases = phases(txns)
	}
	return tl, nil
}

func authorityDetail(c dbq.InvGrantChangesRow) string {
	if c.Change == "REVISED" && c.Widens {
		return "REVISED_WIDER"
	}
	return c.Change
}

func firstTime(ts ...*time.Time) *time.Time {
	for _, t := range ts {
		if t != nil {
			return t
		}
	}
	return nil
}

// runTransactions reads up to limit transactions of run, oldest first.
func runTransactions(ctx context.Context, q *dbq.Queries, org ids.OrgID, run ids.UUID, limit int) ([]dbq.InvRunTransactionsRow, error) {
	var out []dbq.InvRunTransactionsRow
	var afterT time.Time
	var afterID ids.UUID
	for len(out) < limit {
		n := min(limit-len(out), 500)
		rows, err := q.InvRunTransactions(ctx, dbq.InvRunTransactionsParams{
			OrgID: org, RunID: run, AfterTime: afterT, AfterID: afterID, MaxRows: int32(n), //nolint:gosec // G115: n ≤ 500
		})
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		if len(rows) < n {
			break
		}
		last := rows[len(rows)-1]
		afterT, afterID = last.CreatedAt, last.ID
	}
	return out, nil
}

// phases splits the actions into stretches on one connection (inferred).
func phases(txns []dbq.InvRunTransactionsRow) []Phase {
	var out []Phase
	for _, t := range txns {
		if n := len(out); n > 0 && sameConnection(out[n-1].Connection, t.ConnectionID) {
			p := &out[n-1]
			p.End, p.Actions = t.CreatedAt, p.Actions+1
			if !slices.Contains(p.Operations, t.Operation) {
				p.Operations = append(p.Operations, t.Operation)
			}
			continue
		}
		out = append(out, Phase{
			Start: t.CreatedAt, End: t.CreatedAt, Connection: t.ConnectionID, Actions: 1,
			Operations: []string{t.Operation}, Basis: BasisInferred, FirstAction: t.ID,
		})
	}
	for i := range out {
		slices.SortFunc(out[i].Operations, cmp.Compare[string])
	}
	return out
}

func sameConnection(a, b *ids.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
