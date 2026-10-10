// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgapprovals

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strconv"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Errors of the hold path. Each one rolls back the caller's transaction.
var (
	// ErrHoldLimit: the grant or the run has its maximum of pending holds
	// (HR-037, decision 7).
	ErrHoldLimit = errors.New("approvals: hold limit reached")
	// ErrNotMet: an approver is no longer eligible, so the approval is no
	// longer met (HR-170); Revalidate records why.
	ErrNotMet = errors.New("approvals: the approval is no longer met")
	// ErrChanged: the request changed since it was read (a lost race,
	// HR-004).
	ErrChanged = errors.New("approvals: the request changed")
)

// VariantThreshold is the number of variants of one grant, operation and
// target in 24 hours that raises security.variant_suspected (decision 7).
const VariantThreshold = 3

// Hold is a hold the finalization records (HR-171).
type Hold struct {
	RequestID     ids.UUID
	TransactionID ids.UUID
	Evaluation    int
	AgentID       ids.UUID
	RunID         ids.UUID
	GrantID       ids.UUID
	GrantRevision int
	Operation     string
	Reversibility string
	VariantKey    [32]byte
	// Previous is the transaction's live request this one supersedes;
	// First is set when the transaction had no request before.
	Previous     *ids.UUID
	First        bool
	Binding      apdomain.Binding
	Requirements []apdomain.Requirement
	Display      apdomain.Display
	DisplayHash  [32]byte
	Deadline     time.Time
	// Action is the canonical action held (HR-172).
	Action []byte
	// Actor is the gateway that asked.
	Actor evdomain.Actor
}

const (
	scopeGrant = "grant"
	scopeRun   = "run"
	system     = "system"
	// entryCancelled is the stored state of an entry whose request was
	// superseded or invalidated.
	entryCancelled = "CANCELLED" //nolint:misspell // stored value, British spelling as in ARCHITECTURE §6.2
)

// slot is one hold-slot counter.
type slot struct {
	kind string
	id   *ids.UUID
	cap  int32
}

// slots lists a request's counters in the one lock order every
// transaction uses, the grant's before the run's, so concurrent holds and
// releases never wait for each other in a cycle.
func slots(grant, run *ids.UUID, perGrant, perRun int32) []slot {
	return []slot{{scopeGrant, grant, perGrant}, {scopeRun, run, perRun}}
}

// release gives back a request's hold slots.
func release(ctx context.Context, q *dbq.Queries, org ids.OrgID, grant, run *ids.UUID) error {
	for _, s := range slots(grant, run, 0, 0) {
		if s.id == nil {
			continue
		}
		if _, err := q.ReleaseHoldSlot(ctx, org, s.kind, *s.id); err != nil {
			return err
		}
	}
	return nil
}

func closeEntry(ctx context.Context, q *dbq.Queries, org ids.OrgID, request ids.UUID, state, reason string) error {
	by := system
	_, err := q.CloseRequestEntry(ctx, dbq.CloseRequestEntryParams{State: state, DecidedBy: &by, Reason: reason, OrgID: org, RequestID: request})
	return err
}

func event(ctx context.Context, tx db.TenantTx, name string, actor evdomain.Actor, outcome audit.Outcome, reason string,
	request ids.UUID, details map[string]string,
) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: outcome, ReasonCode: reason,
		Object: &audit.Object{Type: "approval_request", ID: request.String()}, Details: details,
	})
	return err
}

// RecordHold records a hold inside the finalization (HR-171, HR-037): it
// supersedes the transaction's live request, if any, inserts the new one
// with its binding fixed, takes a hold slot for the grant and for the run
// (ErrHoldLimit when either is full), opens its ACTION_HOLD entry, and
// audits the request, and the third variant of one grant, operation and
// target within 24 hours.
func RecordHold(ctx context.Context, tx db.TenantTx, org ids.OrgID, h Hold) error {
	q := dbq.New(tx)
	if h.Previous != nil {
		prev, err := q.SupersedeApprovalRequest(ctx, org, *h.Previous)
		if db.IsNoRows(err) {
			return ErrChanged
		}
		if err != nil {
			return err
		}
		if err := release(ctx, q, org, prev.GrantID, prev.RunID); err != nil {
			return err
		}
		if err := closeEntry(ctx, q, org, *h.Previous, entryCancelled, apdomain.EndBindingChanged); err != nil {
			return err
		}
		if err := event(ctx, tx, "approval.superseded", h.Actor, audit.Success, apdomain.EndBindingChanged, *h.Previous,
			map[string]string{"by": h.RequestID.String()}); err != nil {
			return err
		}
	}
	caps, err := q.HoldCaps(ctx, org)
	if err != nil {
		return err
	}
	for _, s := range slots(&h.GrantID, &h.RunID, caps.PerGrant, caps.PerRun) {
		n, err := q.TakeHoldSlot(ctx, dbq.TakeHoldSlotParams{OrgID: org, ScopeKind: s.kind, ScopeID: *s.id, Cap: s.cap})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrHoldLimit
		}
	}
	reqs, err := json.Marshal(h.Requirements)
	if err != nil {
		return err
	}
	display, err := h.Display.Canonical()
	if err != nil {
		return err
	}
	if err := q.InsertApprovalRequest(ctx, dbq.InsertApprovalRequestParams{
		OrgID: org, ID: h.RequestID, AgentID: h.AgentID, TransactionID: &h.TransactionID, Evaluation: ptr(int32(h.Evaluation)), //nolint:gosec // ≤ 64
		RunID: &h.RunID, GrantID: &h.GrantID, GrantRevision: ptr(int32(h.GrantRevision)), VariantKey: h.VariantKey[:], //nolint:gosec // small
		Operation: h.Operation, PreviousID: h.Previous, Binding: h.Binding.Hash[:], BindingInput: h.Binding.Input,
		Requirements: reqs, Display: display.Input, DisplayHash: h.DisplayHash[:], ActionIr: h.Action, DeadlineAt: h.Deadline,
	}); err != nil {
		return err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	if err := q.InsertHoldEntry(ctx, dbq.InsertHoldEntryParams{
		OrgID: org, ID: ids.NewV7(), RequestID: h.RequestID, AgentID: &h.AgentID, RunID: &h.RunID, TransactionID: &h.TransactionID,
		Priority:   int16(wdomain.Priority(wdomain.KindActionHold, h.Reversibility, h.Deadline, now)), //nolint:gosec // 1..4
		DeadlineAt: h.Deadline,
	}); err != nil {
		return err
	}
	if err := event(ctx, tx, "approval.requested", h.Actor, audit.Success, "", h.RequestID, map[string]string{
		"transaction": h.TransactionID.String(), "binding": h.Binding.String(), "operation": h.Operation,
	}); err != nil {
		return err
	}
	if !h.First {
		return nil
	}
	n, err := q.CountRecentVariants(ctx, org, h.VariantKey[:])
	if err != nil || n < VariantThreshold {
		return err
	}
	return event(ctx, tx, "security.variant_suspected", h.Actor, audit.Denied, "VARIANT_SHOPPING", h.RequestID, map[string]string{
		"variants_24h": strconv.Itoa(int(n)), "operation": h.Operation,
	})
}

func ptr[T any](v T) *T { return &v }

// Consume uses an approved request inside the finalization that issues
// the permit (HR-031, HR-171): every counting response's person must
// still be eligible (HR-170, else ErrNotMet), and the request moves
// APPROVED → CONSUMED by a conditional update, at most once, before its
// deadline and its consume-by time (else ErrChanged).
func Consume(ctx context.Context, tx db.TenantTx, org ids.OrgID, request ids.UUID, binding [32]byte, permit ids.UUID, actor evdomain.Actor) error {
	q := dbq.New(tx)
	e, cs, err := tally(ctx, q, org, request)
	if err != nil {
		return err
	}
	if !apdomain.Met(e.Requirements, responses(cs)) {
		return ErrNotMet
	}
	row, err := q.ConsumeApprovalRequest(ctx, dbq.ConsumeApprovalRequestParams{PermitID: &permit, OrgID: org, ID: request, Binding: binding[:]})
	if db.IsNoRows(err) {
		return ErrChanged
	}
	if err != nil {
		return err
	}
	if err := release(ctx, q, org, row.GrantID, row.RunID); err != nil {
		return err
	}
	return event(ctx, tx, "approval.consumed", actor, audit.Success, "", request, map[string]string{"permit": permit.String()})
}

// Expire records that a request expired at use (HR-039): only a live
// request past its deadline, evidence deadline or consume-by time, by the
// database clock. A request already ended is left alone.
func Expire(ctx context.Context, tx db.TenantTx, org ids.OrgID, request ids.UUID, actor evdomain.Actor) error {
	q := dbq.New(tx)
	row, err := q.ExpireApprovalRequest(ctx, org, request)
	if db.IsNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := release(ctx, q, org, row.GrantID, row.RunID); err != nil {
		return err
	}
	if err := closeEntry(ctx, q, org, request, "EXPIRED", apdomain.EndExpired); err != nil {
		return err
	}
	return event(ctx, tx, "approval.expired", actor, audit.Denied, apdomain.EndExpired, request, nil)
}

// Revalidate voids the responses of a request whose people are no longer
// eligible and, when an approved request is no longer met, returns it to
// PENDING with a new open entry (HR-170). It runs in its own transaction
// after Consume reported ErrNotMet, so the queue shows the truth.
func Revalidate(ctx context.Context, tx db.TenantTx, org ids.OrgID, request ids.UUID) error {
	q := dbq.New(tx)
	if _, err := q.LockApprovalRequest(ctx, org, request); err != nil {
		return err
	}
	e, cs, err := tally(ctx, q, org, request)
	if err != nil {
		return err
	}
	for _, c := range cs {
		if !c.Response.Voided {
			continue
		}
		reason := voidReason(c.Code)
		if _, err := q.VoidResponse(ctx, &reason, org, c.ID); err != nil {
			return err
		}
		if err := event(ctx, tx, "approval.response_voided", evdomain.Actor{Type: system, ID: system}, audit.Success, reason,
			request, map[string]string{"response": c.ID.String(), "user": c.Response.UserID.String()}); err != nil {
			return err
		}
	}
	if apdomain.Met(e.Requirements, responses(cs)) {
		return nil
	}
	n, err := q.ReopenApprovalRequest(ctx, org, request)
	if err != nil || n == 0 {
		return err
	}
	_, err = q.ReopenHoldEntry(ctx, ids.NewV7(), org, request)
	return err
}

// End ends a waiting request as DECLINED with endReason (a decline or a
// narrower proposal, HR-171), frees its hold slots and closes its entry
// with entryState. It returns ErrChanged when the request was no longer
// waiting.
func End(ctx context.Context, tx db.TenantTx, org ids.OrgID, request ids.UUID, endReason, entryState string) error {
	q := dbq.New(tx)
	row, err := q.DeclineApprovalRequest(ctx, &endReason, org, request)
	if db.IsNoRows(err) {
		return ErrChanged
	}
	if err != nil {
		return err
	}
	if err := release(ctx, q, org, row.GrantID, row.RunID); err != nil {
		return err
	}
	return closeEntry(ctx, q, org, request, entryState, endReason)
}

// Invalidate ends a live request made moot by a change (decision 6): it
// becomes INVALIDATED with the change as its reason, its slots are freed
// and its entry is closed. The next evaluation of the action decides
// again; correctness never depends on this, because the change already
// gives a different binding.
func Invalidate(ctx context.Context, tx db.TenantTx, org ids.OrgID, request ids.UUID, reason string) error {
	q := dbq.New(tx)
	row, err := q.InvalidateApprovalRequest(ctx, &reason, org, request)
	if db.IsNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := release(ctx, q, org, row.GrantID, row.RunID); err != nil {
		return err
	}
	if err := closeEntry(ctx, q, org, request, entryCancelled, reason); err != nil {
		return err
	}
	return event(ctx, tx, "approval.invalidated", evdomain.Actor{Type: system, ID: system}, audit.Success, reason, request, nil)
}
