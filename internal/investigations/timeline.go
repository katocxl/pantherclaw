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
	// ReadClass is the class of the data the transaction read (F285); it
	// marks the read and claims nothing about what followed.
	ReadClass string
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
	// Events and Gaps are the child's own, for a timeline (F284); a lane
	// holds at most MaxLaneActions actions, and EventsTruncated says so.
	Events          []Event
	Gaps            []Gap
	EventsTruncated bool
	// EventsNotLoaded: this read did not load the lane's events, so their
	// being empty says nothing about the run.
	EventsNotLoaded bool
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
	return runTimeline(ctx, tx, s, run, withPhases, true)
}

// runTimeline assembles the timeline; lanes without laneEvents keep their
// state and leave their events unread, for a reader of the run's own gaps.
func runTimeline(ctx context.Context, tx db.TenantTx, s Scope, run ids.UUID, withPhases, laneEvents bool) (Timeline, error) {
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
	tl.Events, tl.Gaps = actionEvents(txns, r.EndedAt)
	holds, err := approvalEvents(ctx, q, tx.OrgID(), run)
	if err != nil {
		return Timeline{}, err
	}
	tl.Events = append(tl.Events, holds...)

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
	for i := range lanes {
		l := &lanes[i]
		id := l.Run
		tl.Events = append(tl.Events, Event{At: l.Created, Kind: EventLane, Run: &id, Detail: l.State})
	}
	if laneEvents {
		if err := fillLanes(ctx, q, tx.OrgID(), lanes); err != nil {
			return Timeline{}, err
		}
	}
	tl.Lanes = lanes
	if r.EndedAt != nil {
		tl.Events = append(tl.Events, Event{At: *r.EndedAt, Kind: EventRunEnd, Detail: str(r.EndReason)})
	}
	slices.SortStableFunc(tl.Events, func(a, b Event) int { return a.At.Compare(b.At) })
	if withPhases {
		tl.Phases = phases(txns)
	}
	return tl, nil
}

// MaxLaneActions bounds the actions one lane of a timeline holds.
const MaxLaneActions = 100

// fillLanes reads the child runs' own events and gaps in one read, however
// many lanes there are (D35), within the timeline's bound on actions. The
// caller may read the children: hidden children never become lanes
// (HR-401), and a lane holds no lanes of its own, so nothing below it is
// shown unchecked.
func fillLanes(ctx context.Context, q *dbq.Queries, org ids.OrgID, lanes []Lane) error {
	if len(lanes) == 0 {
		return nil
	}
	runs := make([]ids.UUID, 0, len(lanes))
	for _, l := range lanes {
		runs = append(runs, l.Run)
	}
	rows, err := q.InvLaneTransactions(ctx, dbq.InvLaneTransactionsParams{
		OrgID: org, RunIds: runs, LaneRows: MaxLaneActions + 1, MaxRows: MaxTimelineActions,
	})
	if err != nil {
		return err
	}
	aps, err := q.InvLaneApprovals(ctx, org, runs, MaxTimelineActions)
	if err != nil {
		return err
	}
	txns := map[ids.UUID][]dbq.InvRunTransactionsRow{}
	over := map[ids.UUID]bool{}
	for _, x := range rows {
		if x.Round > MaxLaneActions {
			over[x.RunID] = true
			continue
		}
		txns[x.RunID] = append(txns[x.RunID], laneTransaction(x))
	}
	holds := map[ids.UUID][]Event{}
	for _, a := range aps {
		holds[a.RunID] = append(holds[a.RunID], holdEvents(a.ID, a.TransactionID, a.Operation, a.State, a.CreatedAt, a.ApprovedAt, a.EndedAt)...)
	}
	// Rows come a round at a time, so the bound cuts every lane still going
	// at its last round, or one short of it.
	reached := int64(MaxLaneActions + 1)
	if len(rows) == MaxTimelineActions {
		reached = rows[len(rows)-1].Round - 1
	}
	for i := range lanes {
		l := &lanes[i]
		l.EventsNotLoaded = false
		l.EventsTruncated = over[l.Run] || int64(len(txns[l.Run])) >= reached || len(aps) == MaxTimelineActions
		l.Events, l.Gaps = actionEvents(txns[l.Run], l.Ended)
		l.Events = append(l.Events, holds[l.Run]...)
		slices.SortStableFunc(l.Events, func(a, b Event) int { return a.At.Compare(b.At) })
	}
	return nil
}

func laneTransaction(x dbq.InvLaneTransactionsRow) dbq.InvRunTransactionsRow {
	return dbq.InvRunTransactionsRow{
		ID: x.ID, Operation: x.Operation, Decision: x.Decision, ReasonCode: x.ReasonCode, Mode: x.Mode, Channel: x.Channel,
		ConnectionID: x.ConnectionID, TargetType: x.TargetType, TargetID: x.TargetID, GrantID: x.GrantID, EffectState: x.EffectState,
		ReadClass: x.ReadClass, CreatedAt: x.CreatedAt, PermitState: x.PermitState, DispatchingAt: x.DispatchingAt, Outcome: x.Outcome,
		OutcomeAt: x.OutcomeAt, HasReceipt: x.HasReceipt, DestinationClass: x.DestinationClass,
	}
}

// actionEvents are the decisions, dispatches and results of a run's
// actions, and the evidence they lack. ended is when the run ended.
func actionEvents(txns []dbq.InvRunTransactionsRow, ended *time.Time) ([]Event, []Gap) {
	var events []Event
	var gaps []Gap
	for _, t := range txns {
		id := t.ID
		class := str(t.ReadClass)
		events = append(events, Event{
			At: t.CreatedAt, Kind: EventDecision, Transaction: &id, Operation: t.Operation,
			Connection: t.ConnectionID, Detail: t.Decision, ReadClass: class,
		})
		if !t.HasReceipt {
			gaps = append(gaps, Gap{Kind: GapNoDecisionReceipt, Transaction: id, At: t.CreatedAt})
		}
		if t.DispatchingAt != nil {
			events = append(events, Event{
				At: *t.DispatchingAt, Kind: EventDispatch, Transaction: &id,
				Operation: t.Operation, Connection: t.ConnectionID, ReadClass: class,
			})
		}
		switch {
		case t.Outcome != nil && t.OutcomeAt != nil:
			events = append(events, Event{
				At: *t.OutcomeAt, Kind: EventResult, Transaction: &id,
				Operation: t.Operation, Connection: t.ConnectionID, Detail: *t.Outcome, ReadClass: class,
			})
			if *t.Outcome == "unknown" {
				gaps = append(gaps, Gap{Kind: GapOutcomeUnknown, Transaction: id, At: *t.OutcomeAt})
			}
		case t.DispatchingAt != nil && t.PermitState != nil && *t.PermitState == "UNKNOWN":
			gaps = append(gaps, Gap{Kind: GapOutcomeUnknown, Transaction: id, At: *t.DispatchingAt})
		case t.DispatchingAt != nil && ended != nil:
			gaps = append(gaps, Gap{Kind: GapNoOutcome, Transaction: id, At: *t.DispatchingAt})
		}
	}
	return events, gaps
}

// approvalEvents are a run's holds and how they ended.
func approvalEvents(ctx context.Context, q *dbq.Queries, org ids.OrgID, run ids.UUID) ([]Event, error) {
	aps, err := q.InvApprovals(ctx, dbq.InvApprovalsParams{OrgID: org, RunID: &run, MaxRows: MaxApprovals})
	if err != nil {
		return nil, err
	}
	var events []Event
	for _, a := range aps {
		events = append(events, holdEvents(a.ID, a.TransactionID, a.Operation, a.State, a.CreatedAt, a.ApprovedAt, a.EndedAt)...)
	}
	return events, nil
}

// holdEvents are one approval request's hold and how it ended.
func holdEvents(id ids.UUID, txn *ids.UUID, operation, state string, created time.Time, approved, ended *time.Time) []Event {
	events := []Event{{At: created, Kind: EventHold, Approval: &id, Transaction: txn, Operation: operation, Detail: "PENDING"}}
	if end := firstTime(approved, ended); end != nil {
		events = append(events, Event{At: *end, Kind: EventApproval, Approval: &id, Transaction: txn, Operation: operation, Detail: state})
	}
	return events
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
