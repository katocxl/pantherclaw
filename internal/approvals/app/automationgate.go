// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

// Bounds of a gate (G0 M11 part 2 D25).
const (
	MaxGateDeadline  = 72 * time.Hour
	MaxGateApprovals = 2
)

// ErrGateInvalid refuses a gate request the engine should never make.
var ErrGateInvalid = pcerr.New(pcerr.InvalidArgument, "GATE_INVALID", "the automation gate request is invalid")

// AutomationGate is a gate the engine asks for (D25, D25a, HR-281): one
// step of one execution, bound to the parameters' digest, decided by
// MinApprovals people holding automation.approve at the org (narrowed to
// Roles and Users when they are listed), never by Exclude.
type AutomationGate struct {
	Org            ids.OrgID
	Automation     ids.UUID
	AutomationName string
	ServiceAccount ids.UUID
	Execution      ids.UUID
	StepID         string
	Attempt        int
	ParamsDigest   []byte
	// Params are the trigger's parameters as text, shown as untrusted.
	Params       map[string]string
	Summary      string
	Roles        []string
	Users        []ids.UUID
	Exclude      []ids.UUID
	MinApprovals int
	Deadline     time.Duration
	// Agent is set when the gate concerns one agent; usually nil (D25a).
	Agent *ids.UUID
}

func (g AutomationGate) valid() bool {
	return !g.Org.IsZero() && !g.Automation.IsZero() && !g.Execution.IsZero() && g.StepID != "" && g.Attempt >= 1 &&
		len(g.ParamsDigest) == 32 && g.MinApprovals >= 1 && g.MinApprovals <= MaxGateApprovals &&
		g.Deadline > 0 && g.Deadline <= MaxGateDeadline &&
		!slices.ContainsFunc(g.Roles, func(r string) bool { return !apdomain.GateRole(r) })
}

// automationActor is the audit actor of an automation's own requests.
func automationActor(sa ids.UUID) evdomain.Actor {
	return evdomain.Actor{Type: string(td.KindServiceAccount), ID: sa.String()}
}

// RequestAutomationGateTx creates a gate's approval request and its
// AUTOMATION_GATE waitlist entry in the engine's transaction, modeled on
// RequestRestoration. It returns the request and how many people may
// decide it now; when nobody may, it writes nothing and returns a zero id
// (the step fails GATE_NO_APPROVER). A step that already has a live gate
// gets that one.
func (s *Service) RequestAutomationGateTx(ctx context.Context, tx pgx.Tx, g AutomationGate) (ids.UUID, int, error) {
	if !g.valid() {
		return ids.UUID{}, 0, ErrGateInvalid
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, g.Org)
	if err != nil {
		return ids.UUID{}, 0, err
	}
	q := dbq.New(ttx)
	if live, err := q.LiveAutomationGate(ctx, g.Org, &g.Execution, &g.StepID); err == nil {
		n, err := gateEligible(ctx, q, g.Org, live)
		return live, n, err
	} else if !db.IsNoRows(err) {
		return ids.UUID{}, 0, err
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return ids.UUID{}, 0, err
	}
	id, n, err := insertGate(ctx, dbq.New(sp), g)
	if err != nil || n == 0 {
		return ids.UUID{}, 0, errors.Join(err, sp.Rollback(ctx))
	}
	if err := sp.Commit(ctx); err != nil {
		return ids.UUID{}, 0, err
	}
	row, err := q.GetApprovalRequest(ctx, g.Org, id)
	if err != nil {
		return ids.UUID{}, 0, err
	}
	actor := automationActor(g.ServiceAccount)
	if _, err := pgwaitlist.OpenAutomationGate(ctx, ttx, g.Org, id, g.Automation, g.StepID, row.DeadlineAt, actor); err != nil {
		return ids.UUID{}, 0, err
	}
	if err := event(ctx, ttx, "approval.gate_requested", actor, "", id, map[string]string{
		"automation": g.Automation.String(), "execution": g.Execution.String(), "step": g.StepID,
	}); err != nil {
		return ids.UUID{}, 0, err
	}
	return id, n, nil
}

// EligibleAutomationGateTx counts who could decide such a gate now and
// writes nothing (SHADOW previews, HR-288).
func (s *Service) EligibleAutomationGateTx(ctx context.Context, tx pgx.Tx, g AutomationGate) (int, error) {
	if !g.valid() {
		return 0, ErrGateInvalid
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return 0, err
	}
	_, n, err := insertGate(ctx, dbq.New(sp), g)
	return n, errors.Join(err, sp.Rollback(ctx))
}

// insertGate renders, binds and inserts a gate and counts its eligible
// deciders.
func insertGate(ctx context.Context, q *dbq.Queries, g AutomationGate) (ids.UUID, int, error) {
	now, err := q.DBNow(ctx)
	if err != nil {
		return ids.UUID{}, 0, err
	}
	deadline := now.Add(g.Deadline).Truncate(time.Second)
	reqs := []apdomain.Requirement{apdomain.GateRequirement(g.MinApprovals, g.Roles, g.Users, g.Exclude)}
	display, err := apdomain.RenderGate(apdomain.GateInput{
		Automation: g.Automation, AutomationName: g.AutomationName, Execution: g.Execution, StepID: g.StepID,
		Attempt: g.Attempt, Params: g.Params, Summary: g.Summary, Requirements: reqs, Deadline: deadline,
	}).Canonical()
	if err != nil {
		return ids.UUID{}, 0, err
	}
	binding, err := apdomain.GateParts{
		Automation: g.Automation, Execution: g.Execution, StepID: g.StepID, Attempt: g.Attempt,
		ParamsDigest: g.ParamsDigest, Summary: g.Summary, Requirements: reqs, ExpiresAt: deadline, DisplayHash: display.Hash,
	}.Binding()
	if err != nil {
		return ids.UUID{}, 0, err
	}
	rs, err := json.Marshal(reqs)
	if err != nil {
		return ids.UUID{}, 0, err
	}
	id := ids.NewV7()
	if err := q.InsertAutomationGateRequest(ctx, dbq.InsertAutomationGateRequestParams{
		OrgID: g.Org, ID: id, AgentID: g.Agent, AutomationID: &g.Automation, ExecutionID: &g.Execution, StepID: &g.StepID,
		Binding: binding.Hash[:], BindingInput: binding.Input, Requirements: rs, Display: display.Input,
		DisplayHash: display.Hash[:], DeadlineAt: deadline,
	}); err != nil {
		return ids.UUID{}, 0, err
	}
	n, err := gateEligible(ctx, q, g.Org, id)
	return id, n, err
}

// gateEligible counts the people who may decide the gate now.
func gateEligible(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (int, error) {
	var roles []string
	for _, r := range td.Roles() {
		if r.Has(td.PermAutomationApprove) {
			roles = append(roles, string(r.Name))
		}
	}
	users, err := q.GateCandidates(ctx, org, roles)
	if err != nil || len(users) == 0 {
		return 0, err
	}
	e, err := pgapprovals.LoadEligibility(ctx, q, org, id, users)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		if slices.ContainsFunc(e.Requirements, func(r apdomain.Requirement) bool {
			ok, _ := apdomain.MayRespond(r, e.People[u], e.Context)
			return ok
		}) {
			n++
		}
	}
	return n, nil
}

// AutomationGateState is a gate's request state and who approved it.
type AutomationGateState struct {
	State     string
	Approvers []ids.UUID
}

// AutomationGateStateTx reads a gate for its step.
func (s *Service) AutomationGateStateTx(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) (AutomationGateState, error) {
	r, err := dbq.New(tx).AutomationGateState(ctx, org, id)
	if err != nil {
		return AutomationGateState{}, err
	}
	if r.SubjectKind != subjectGate {
		return AutomationGateState{}, ErrNotFound
	}
	return AutomationGateState{State: r.State, Approvers: r.Approvers}, nil
}

// ConsumeAutomationGateTx uses an APPROVED gate once (HR-281): its step goes
// on and the approval can never count again.
func (s *Service) ConsumeAutomationGateTx(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) error {
	n, err := dbq.New(tx).ConsumeAutomationGate(ctx, org, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotWaiting
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return err
	}
	return event(ctx, ttx, "approval.gate_consumed", evdomain.Actor{Type: "system", ID: "automation_engine"}, "", id, nil)
}

// EndAutomationGateTx ends an open gate: EXPIRED at its deadline
// (GATE_EXPIRED), else INVALIDATED with reason (its execution ended). Its
// entry closes and the people it was routed to are told.
func (s *Service) EndAutomationGateTx(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID, reason string) error {
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return err
	}
	q := dbq.New(ttx)
	state, entry, typ := "INVALIDATED", "CANCELLED", "approval.invalidated" //nolint:misspell // stored entry state
	if reason == "GATE_EXPIRED" {
		state, entry, typ = "EXPIRED", "EXPIRED", "approval.expired"
	}
	n, err := q.EndAutomationGate(ctx, dbq.EndAutomationGateParams{State: state, Reason: &reason, OrgID: org, ID: id})
	if err != nil || n == 0 {
		return err
	}
	system := "system"
	if _, err := q.CloseRequestEntry(ctx, dbq.CloseRequestEntryParams{
		State: entry, DecidedBy: &system, Reason: reason, OrgID: org, RequestID: id,
	}); err != nil {
		return err
	}
	if err := event(ctx, ttx, "approval.gate_ended", evdomain.Actor{Type: "system", ID: "automation_engine"}, reason, id, nil); err != nil {
		return err
	}
	var params map[string]string
	if state == "INVALIDATED" {
		params = map[string]string{"reason": reason}
	}
	return tell(ctx, ttx, s.Notify, org, id, state, typ, params)
}

// OpenAutomationGatesTx lists an execution's open gates (cleanup, D24).
func (s *Service) OpenAutomationGatesTx(ctx context.Context, tx pgx.Tx, org ids.OrgID, execution ids.UUID) ([]ids.UUID, error) {
	return dbq.New(tx).OpenAutomationGates(ctx, org, &execution)
}
