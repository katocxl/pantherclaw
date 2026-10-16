// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"context"
	"strconv"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Approvals routes and reads the approval request of a held action
// (waitlist routing, approvals).
type Approvals interface {
	// RequestOf is the approval request the trigger's held transaction
	// made; ok is false when it made none.
	RequestOf(ctx context.Context, tx pgx.Tx, org ids.OrgID, transaction ids.UUID) (request ids.UUID, ok bool, err error)
	// Nudge sends the existing approval.reminder notice to the eligible
	// deciders already told who have not responded, or, with escalate, the
	// approval.escalated notice to the eligible deciders not told yet (the
	// backup approvers). It never makes anyone eligible and returns how
	// many people it told; dedupe makes a repeat send nothing.
	Nudge(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID, escalate bool, dedupe string) (int, error)
	// Resolution is the request's state and, once resolved, what became of
	// the held action.
	Resolution(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID) (Resolution, error)
}

// Resolution is what became of an approval request.
type Resolution struct {
	// State is the request's state (PENDING, EVIDENCE_REQUESTED, APPROVED,
	// CONSUMED, DECLINED, EXPIRED, INVALIDATED, SUPERSEDED).
	State string
	// Resolved is false while people may still decide it.
	Resolved bool
	// Transaction is the held action; Outcome its recorded outcome when
	// it ran after the approval (empty until then).
	Transaction *ids.UUID
	Outcome     string
}

// Output keys of the approval kinds.
const (
	OutRequest    = "request_id"
	OutTold       = "told"
	OutResolution = "resolution"
	OutOutcome    = "outcome"
	OutTxn        = "transaction_id"
)

// triggerRequest checks the TRIGGER_REQUEST scope and returns the trigger's
// held transaction.
func triggerRequest(sc autodomain.StepContext, kind string) (ids.UUID, string) {
	w, ok := sc.With.(*autodomain.ApprovalRequestWith)
	if !ok || w.Request != autodomain.ScopeTriggerRequest {
		return ids.UUID{}, ReasonBadWith
	}
	if !inScope(sc.Def, kind, autodomain.ScopeTriggerRequest) {
		return ids.UUID{}, ReasonOutsideScope
	}
	txn, ok := triggerSubject(sc, reflexdomain.SubjectTransaction)
	if !ok {
		return ids.UUID{}, ReasonNoSubject
	}
	return txn, ""
}

// routeApproval reminds the approvers of the trigger's request
// (remind_approvers) or tells its backup approvers (escalate_approval)
// with the existing approval.reminder and approval.escalated notices
// (D31). Telling people changes nothing about who may decide.
type routeApproval struct {
	d    Deps
	kind string
}

func (s *routeApproval) Kind() string { return s.kind }

func (s *routeApproval) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	txn, reason := triggerRequest(sc, s.kind)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Approvals == nil {
		return unwired()
	}
	req, ok, err := s.d.Approvals.RequestOf(ctx, tx, sc.Org, txn)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	if !ok {
		return failed(ReasonNoSubject)
	}
	told, err := s.d.Approvals.Nudge(ctx, tx, sc.Org, req, s.kind == autodomain.KindEscalateApproval, idempotency(sc))
	if err != nil {
		if r, ok := refusal(err); ok {
			return failed(r)
		}
		return autodomain.StepResult{}, err
	}
	effect := autodomain.EffectUnchanged
	if told > 0 {
		effect = autodomain.EffectChanged
	}
	return autodomain.StepResult{
		State: autodomain.StepDone, Effect: effect,
		Output: map[string]string{OutRequest: req.String(), OutTold: strconv.Itoa(told)},
		Refs:   []reflexdomain.EvidenceRef{ref(RefApproval, req)},
	}, nil
}

func (s *routeApproval) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *routeApproval) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	txn, reason := triggerRequest(sc, s.kind)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{OutTxn: txn.String()})
}

// waitResolution waits until the trigger's request is resolved (D31,
// APPROVAL_RESOLVED): its resolution and, when the held action ran, its
// outcome. It reads only.
type waitResolution struct{ d Deps }

func (*waitResolution) Kind() string { return autodomain.KindWaitResolution }

func (s *waitResolution) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	txn, reason := triggerRequest(sc, autodomain.KindWaitResolution)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Approvals == nil {
		return unwired()
	}
	req, ok, err := s.d.Approvals.RequestOf(ctx, tx, sc.Org, txn)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	if !ok {
		return failed(ReasonNoSubject)
	}
	res, err := s.d.Approvals.Resolution(ctx, tx, sc.Org, req)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	out := map[string]string{OutRequest: req.String(), OutResolution: res.State}
	refs := []reflexdomain.EvidenceRef{ref(RefApproval, req)}
	if res.Transaction != nil {
		out[OutTxn] = res.Transaction.String()
	}
	if res.Outcome != "" {
		out[OutOutcome] = res.Outcome
	}
	if !res.Resolved {
		return waiting(out, refs, sc.Now.Add(pollEvery))
	}
	if res.Transaction != nil {
		refs = append(refs, ref(string(reflexdomain.SubjectTransaction), *res.Transaction))
	}
	return autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone, Output: out, Refs: refs}, nil
}

func (s *waitResolution) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *waitResolution) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	txn, reason := triggerRequest(sc, autodomain.KindWaitResolution)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{OutTxn: txn.String()})
}
