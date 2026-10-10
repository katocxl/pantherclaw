// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgwaitlist opens and closes Agent Waitlist entries inside the
// transaction of the change that creates or settles their subject (G0 M5
// part 2). An entry's kind, subject, priority and deadline come from
// PantherClaw's records, never from agent input (HR-177), and there is at
// most one open entry per subject.
package pgwaitlist

import (
	"context"
	"encoding/json/v2"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// System is the actor of entries the server opens or ends by itself.
var System = evdomain.Actor{Type: "system", ID: "system"}

// entry is an entry a producer opens.
type entry struct {
	kind, subjectType string
	subject           ids.UUID
	agent, run, txn   *ids.UUID
	requestedBy       *string
	// trusted is what PantherClaw established about the subject.
	trusted map[string]string
	// untrusted was written by a person or a workload and is shown only
	// in the untrusted block.
	untrusted map[string]string
	// deadline, when set, is the subject's own deadline (a restoration
	// request's), which the entry shares.
	deadline time.Time
}

// evidence is the stored shape of waitlist_entries.evidence.
type evidence struct {
	Trusted   map[string]string `json:"trusted,omitzero"`
	Untrusted map[string]string `json:"untrusted,omitzero"`
}

// configured is the org's deadline setting for kind, if any.
func configured(s dbq.PcWaitlistSetting, kind string) *int32 {
	switch kind {
	case wdomain.KindAccessRequest:
		return s.AccessRequestDeadlineS
	case wdomain.KindToolReview:
		return s.ToolReviewDeadlineS
	case wdomain.KindRestoration:
		return s.RestorationDeadlineS
	case wdomain.KindReconciliation:
		return s.ReconciliationDeadlineS
	}
	return nil
}

// open opens e, or returns the subject's open entry when it has one.
func open(ctx context.Context, tx db.TenantTx, org ids.OrgID, e entry, actor evdomain.Actor) (ids.UUID, error) {
	q := dbq.New(tx)
	s, err := q.GetWaitlistSettings(ctx, org)
	if err != nil && !db.IsNoRows(err) {
		return ids.UUID{}, err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	deadline := e.deadline
	if deadline.IsZero() {
		deadline = now.Add(wdomain.Deadline(e.kind, configured(s, e.kind)))
	}
	ev, err := json.Marshal(evidence{Trusted: e.trusted, Untrusted: e.untrusted})
	if err != nil {
		return ids.UUID{}, err
	}
	id, err := q.OpenWaitlistEntry(ctx, dbq.OpenWaitlistEntryParams{
		OrgID: org, ID: ids.NewV7(), Kind: e.kind, SubjectType: e.subjectType, SubjectID: e.subject, AgentID: e.agent,
		RunID: e.run, TransactionID: e.txn, RequestedBy: e.requestedBy, Evidence: ev,
		Priority: int16(wdomain.Priority(e.kind, "", deadline, now)), DeadlineAt: deadline, //nolint:gosec // 1..4
	})
	if db.IsNoRows(err) {
		return q.OpenEntryOf(ctx, org, e.subjectType, e.subject)
	}
	if err != nil {
		return ids.UUID{}, err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "waitlist.entry_opened", Actor: actor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "waitlist_entry", ID: id.String()},
		Details: map[string]string{"kind": e.kind, "subject": e.subjectType + ":" + e.subject.String()},
	})
	return id, err
}

// OpenToolReview opens the TOOL_REVIEW entry of an imported package version
// that is not active yet: a package.activate holder reviews it within 30
// days, or it stays inactive.
func OpenToolReview(ctx context.Context, tx db.TenantTx, org ids.OrgID, version ids.UUID, pkg, ver string, actor evdomain.Actor) (ids.UUID, error) {
	return open(ctx, tx, org, entry{
		kind: wdomain.KindToolReview, subjectType: "package_version", subject: version,
		trusted: map[string]string{"package": pkg, "version": ver},
	}, actor)
}

// CloseToolReview settles a version's TOOL_REVIEW entry when it moves:
// APPROVED when it becomes active, REJECTED when it is quarantined or
// retired. Any other move leaves the entry open.
func CloseToolReview(ctx context.Context, tx db.TenantTx, org ids.OrgID, version ids.UUID, to, by string) error {
	var state string
	switch to {
	case "ACTIVE":
		state = wdomain.StateApproved
	case "QUARANTINED", "RETIRED":
		state = wdomain.StateRejected
	default:
		return nil
	}
	_, err := dbq.New(tx).CloseEntryOf(ctx, dbq.CloseEntryOfParams{
		State: state, DecidedBy: &by, Reason: to, OrgID: org, Kind: wdomain.KindToolReview, SubjectType: "package_version",
		SubjectID: version,
	})
	return err
}

// OpenReconciliation opens the RECONCILIATION entry of a transaction whose
// outcome became UNKNOWN (HR-003), in the transaction that recorded it. It
// returns the transaction's open entry when there is one. The entry never
// resolves by itself: M7 resolves it, and until then it escalates.
func OpenReconciliation(ctx context.Context, tx db.TenantTx, org ids.OrgID, transaction ids.UUID, actor evdomain.Actor) (ids.UUID, error) {
	t, err := dbq.New(tx).TransactionOfRun(ctx, org, transaction)
	if err != nil {
		return ids.UUID{}, err
	}
	return open(ctx, tx, org, entry{
		kind: wdomain.KindReconciliation, subjectType: "transaction", subject: transaction,
		agent: &t.AgentID, run: &t.RunID, txn: &transaction,
		trusted: map[string]string{"operation": t.Operation, "outcome": "UNKNOWN"},
	}, actor)
}

// ExpireEntries ends the open entries past their deadline whose kind ends
// there (access requests and tool reviews) as EXPIRED; nothing changes
// (HR-177). It returns how many ended.
func ExpireEntries(ctx context.Context, tx db.TenantTx, org ids.OrgID) (int, error) {
	var kinds []string
	for k := range wdomain.DefaultDeadlines {
		if wdomain.Expires(k) {
			kinds = append(kinds, k)
		}
	}
	rows, err := dbq.New(tx).ExpireWaitlistEntries(ctx, org, kinds)
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "waitlist.entry_expired", Actor: System, Outcome: audit.Denied, ReasonCode: "EXPIRED",
			Object:  &audit.Object{Type: "waitlist_entry", ID: r.ID.String()},
			Details: map[string]string{"kind": r.Kind},
		}); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

// OpenRestoration opens the RESTORATION entry of a restoration request
// (decision 11). Its subject is the request, it shares the request's
// deadline, and it ends with the request.
func OpenRestoration(ctx context.Context, tx db.TenantTx, org ids.OrgID, request, agent, requester ids.UUID, deadline time.Time) (ids.UUID, error) {
	by := "user:" + requester.String()
	return open(ctx, tx, org, entry{
		kind: wdomain.KindRestoration, subjectType: "approval_request", subject: request, agent: &agent, requestedBy: &by,
		deadline: deadline, trusted: map[string]string{"agent": agent.String()},
	}, evdomain.Actor{Type: "user", ID: requester.String()})
}
