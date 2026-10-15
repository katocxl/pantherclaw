// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// Restoration limits.
const (
	MaxPlanControls = 50
	MaxStages       = 20
	MaxStageTests   = 20
)

// Plan states (D24).
const (
	PlanRequested = "REQUESTED"
	PlanApproved  = "APPROVED"
	PlanStaging   = "STAGING"
	PlanCompleted = "COMPLETED"
	PlanRefused   = "REFUSED"
)

// Test expectations of a staged restoration.
const (
	ExpectPermitted  = "PERMITTED"
	ExpectProhibited = "PROHIBITED"
)

// Precondition states (F564): only UNMET blocks a lift.
const (
	PreMet   = "MET"
	PreUnmet = "UNMET"
	PreInfo  = "INFO"
)

// Errors of restorations (D24, HR-250).
var (
	ErrPlanInvalid = pcerr.New(pcerr.InvalidArgument, "PLAN_INVALID",
		"a restoration lifts 1 to 50 active controls once each; a staged one puts each in exactly one of up to 20 stages, each with up to 20 test actions")
	ErrControlNotActive  = pcerr.New(pcerr.FailedPrecondition, "CONTROL_NOT_ACTIVE", "a control is lifted or expired, or not the org's")
	ErrControlPlanned    = pcerr.New(pcerr.FailedPrecondition, "CONTROL_IN_PLAN", "a control is already in an unfinished restoration plan")
	ErrPlanNotFound      = pcerr.New(pcerr.NotFound, "PLAN_NOT_FOUND", "restoration plan not found")
	ErrPlanState         = pcerr.New(pcerr.FailedPrecondition, "PLAN_STATE", "the restoration plan is not in a state that allows this")
	ErrRequesterDecides  = pcerr.New(pcerr.PermissionDenied, "REQUESTER_EXCLUDED", "the person who asked for a restoration never decides it")
	ErrPreconditions     = pcerr.New(pcerr.FailedPrecondition, "PRECONDITIONS_UNMET", "a precondition of the restoration is not met; see the plan")
	ErrStageOrder        = pcerr.New(pcerr.FailedPrecondition, "STAGE_ORDER", "stages are applied in order, each once its tests pass")
	ErrStagedEdition     = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "staged restoration needs the Team edition or above")
	ErrNoReplay          = pcerr.New(pcerr.Unavailable, "REPLAY_UNAVAILABLE", "test actions cannot be evaluated: decision replay is not configured")
	ErrTestNotReplayable = pcerr.New(pcerr.InvalidArgument, "TEST_INVALID", "a test action names a recorded evaluation (1..64) and PERMITTED or PROHIBITED")
)

// TestAction is a staged restoration's test (D24): a recorded evaluation
// whose action is re-decided, dry run, with the controls that would remain.
type TestAction struct {
	Transaction ids.UUID `json:"transaction"`
	Evaluation  int      `json:"evaluation"`
	Expect      string   `json:"expect"`
}

// TestResult is one test's outcome.
type TestResult struct {
	TestAction
	Decision string `json:"decision,omitzero"`
	Reason   string `json:"reason,omitzero"`
	Complete bool   `json:"complete"`
	Passed   bool   `json:"passed"`
}

// StageSpec is one stage: the controls it lifts and its tests.
type StageSpec struct {
	Controls []ids.UUID
	Tests    []TestAction
}

// RestorationRequest asks for controls to be lifted (D24).
type RestorationRequest struct {
	Controls []ids.UUID
	Reason   string
	// Stages, when set, make a staged restoration (Team, F568).
	Stages    []StageSpec
	Requester ids.UUID
}

// Precondition is one recorded precondition (F564).
type Precondition struct {
	Check   string `json:"check"`
	Subject string `json:"subject,omitzero"`
	State   string `json:"state"`
	Detail  string `json:"detail"`
}

// Replayer re-decides a recorded evaluation with other controls
// (replay.Engine).
type Replayer interface {
	ReplayContained(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, controls []pipeline.Control) (*replay.Outcome, error)
}

// RequestRestorationIn records a restoration plan for active controls in
// tx, with its preconditions computed now (D24, F564). The requester is a
// person; they never decide it.
func (s *Containment) RequestRestorationIn(ctx context.Context, tx db.TenantTx, r RestorationRequest) (ids.UUID, []Precondition, error) {
	org := tx.OrgID()
	q := dbq.New(tx)
	if n := len(r.Controls); n == 0 || n > MaxPlanControls || hasDup(r.Controls) || !reasonOK1000(r.Reason) || len(r.Stages) > MaxStages {
		return ids.UUID{}, nil, ErrPlanInvalid
	}
	if len(r.Stages) > 0 {
		var all []ids.UUID
		for _, st := range r.Stages {
			if len(st.Controls) == 0 || len(st.Tests) > MaxStageTests {
				return ids.UUID{}, nil, ErrPlanInvalid
			}
			for _, t := range st.Tests {
				if t.Evaluation < 1 || t.Evaluation > 64 || (t.Expect != ExpectPermitted && t.Expect != ExpectProhibited) {
					return ids.UUID{}, nil, ErrTestNotReplayable
				}
			}
			all = append(all, st.Controls...)
		}
		if hasDup(all) || len(all) != len(r.Controls) || !sameSet(all, r.Controls) {
			return ids.UUID{}, nil, ErrPlanInvalid
		}
	}
	controls := make([]dbq.PcContainmentControl, 0, len(r.Controls))
	for _, id := range r.Controls {
		c, err := q.GetContainmentControl(ctx, org, id)
		if db.IsNoRows(err) || (err == nil && c.LiftedAt != nil) {
			return ids.UUID{}, nil, ErrControlNotActive
		} else if err != nil {
			return ids.UUID{}, nil, err
		}
		if _, err := q.OpenPlanOfControl(ctx, org, id); err == nil {
			return ids.UUID{}, nil, ErrControlPlanned
		} else if !db.IsNoRows(err) {
			return ids.UUID{}, nil, err
		}
		controls = append(controls, c)
	}
	pre, err := preconditions(ctx, q, org, controls, len(r.Stages) > 0)
	if err != nil {
		return ids.UUID{}, nil, err
	}
	preJSON, err := json.Marshal(map[string]any{"checks": pre}, json.Deterministic(true))
	if err != nil {
		return ids.UUID{}, nil, err
	}
	plan := ids.NewV7()
	requester := "user:" + r.Requester.String()
	if _, err := q.InsertRestorationPlan(ctx, dbq.InsertRestorationPlanParams{
		OrgID: org, ID: plan, Reason: r.Reason, Staged: len(r.Stages) > 0, Preconditions: preJSON, RequestedBy: requester,
	}); err != nil {
		return ids.UUID{}, nil, err
	}
	for _, c := range r.Controls {
		if err := q.InsertRestorationPlanControl(ctx, org, plan, c); err != nil {
			return ids.UUID{}, nil, err
		}
	}
	for i, st := range r.Stages {
		scope, err := json.Marshal(map[string]any{"controls": idStrings(st.Controls)}, json.Deterministic(true))
		if err != nil {
			return ids.UUID{}, nil, err
		}
		tests, err := json.Marshal(nonNilTests(st.Tests), json.Deterministic(true))
		if err != nil {
			return ids.UUID{}, nil, err
		}
		if err := q.InsertRestorationStage(ctx, dbq.InsertRestorationStageParams{
			OrgID: org, PlanID: plan, Ordinal: int32(i + 1), Scope: scope, Tests: tests,
		}); err != nil {
			return ids.UUID{}, nil, err
		}
	}
	if _, err := auditRecord(ctx, tx, userActor(r.Requester), "response.restoration_requested", "restoration_plan", plan.String(),
		withReason(map[string]string{"controls": strconv.Itoa(len(r.Controls)), "stages": strconv.Itoa(len(r.Stages))}, r.Reason)); err != nil {
		return ids.UUID{}, nil, err
	}
	return plan, pre, nil
}

// DecideRestorationIn records a reviewer's decision in tx (D24, HR-250).
// The service checks the reviewer holds agent.restore and stepped up with
// a security key; here they must not be the requester. Approving recomputes
// the preconditions, records them, and refuses while one is unmet. An
// unstaged plan then lifts every control (each lift raises the epoch); a
// staged plan waits for its stages. Declining refuses the plan. Nothing
// that ended (a denied, expired or voided action, a revoked run) is revived:
// a new attempt needs fresh authorization.
func (s *Containment) DecideRestorationIn(ctx context.Context, tx db.TenantTx, plan, reviewer ids.UUID, approve bool) (string, []Precondition, error) {
	org := tx.OrgID()
	q := dbq.New(tx)
	p, err := q.LockRestorationPlan(ctx, org, plan)
	if db.IsNoRows(err) {
		return "", nil, ErrPlanNotFound
	} else if err != nil {
		return "", nil, err
	}
	if p.RequestedBy == "user:"+reviewer.String() {
		return "", nil, ErrRequesterDecides
	}
	if p.State != PlanRequested {
		return "", nil, ErrPlanState
	}
	controls, err := q.RestorationPlanControls(ctx, org, plan)
	if err != nil {
		return "", nil, err
	}
	pre, err := preconditions(ctx, q, org, controls, p.Staged)
	if err != nil {
		return "", nil, err
	}
	preJSON, err := json.Marshal(map[string]any{"checks": pre, "reviewer": "user:" + reviewer.String()}, json.Deterministic(true))
	if err != nil {
		return "", nil, err
	}
	next := PlanRefused
	switch {
	case !approve:
	case slices.ContainsFunc(pre, func(c Precondition) bool { return c.State == PreUnmet }):
		// Record what blocked it; the plan stays REQUESTED.
		if _, err := q.SetRestorationPlanState(ctx, dbq.SetRestorationPlanStateParams{
			OrgID: org, ID: plan, Expected: PlanRequested, State: PlanRequested, Preconditions: preJSON,
		}); err != nil {
			return "", nil, err
		}
		return PlanRequested, pre, ErrPreconditions
	case p.Staged:
		next = PlanStaging
	default:
		next = PlanCompleted
	}
	if next == PlanCompleted {
		for _, c := range controls {
			if c.LiftedAt != nil {
				continue
			}
			if err := pgresponse.LiftControl(ctx, tx, org, c.ID, plan, "user:"+reviewer.String()); err != nil {
				return "", nil, err
			}
		}
	}
	if n, err := q.SetRestorationPlanState(ctx, dbq.SetRestorationPlanStateParams{
		OrgID: org, ID: plan, Expected: PlanRequested, State: next, Preconditions: preJSON,
	}); err != nil {
		return "", nil, err
	} else if n == 0 {
		return "", nil, ErrPlanState
	}
	name := map[string]string{
		PlanRefused: "response.restoration_declined", PlanStaging: "response.restoration_approved",
		PlanCompleted: "response.restoration_completed",
	}[next]
	if _, err := auditRecord(ctx, tx, userActor(reviewer), name, "restoration_plan", plan.String(),
		map[string]string{"controls": strconv.Itoa(len(controls)), "state": next}); err != nil {
		return "", nil, err
	}
	return next, pre, nil
}

// StagePlan is what ApplyStage needs, read before its tests run.
type StagePlan struct {
	Plan    ids.UUID
	Ordinal int32
	Lifts   []ids.UUID
	Tests   []TestAction
	// Remaining are the org's active controls other than the stage's: what
	// the tests are decided with.
	Remaining []pipeline.Control
}

// StageToApply reads the next stage of a staged plan in tx: the plan is
// STAGING, the stage is the first not applied, and ordinal names it.
func (s *Containment) StageToApply(ctx context.Context, tx db.TenantTx, plan ids.UUID, ordinal int32) (StagePlan, error) {
	org := tx.OrgID()
	q := dbq.New(tx)
	p, err := q.GetRestorationPlan(ctx, org, plan)
	if db.IsNoRows(err) {
		return StagePlan{}, ErrPlanNotFound
	} else if err != nil {
		return StagePlan{}, err
	}
	if p.State != PlanStaging {
		return StagePlan{}, ErrPlanState
	}
	stages, err := q.RestorationStages(ctx, org, plan)
	if err != nil {
		return StagePlan{}, err
	}
	i := slices.IndexFunc(stages, func(st dbq.PcRestorationStage) bool { return st.State != "APPLIED" })
	if i < 0 || stages[i].Ordinal != ordinal {
		return StagePlan{}, ErrStageOrder
	}
	st := stages[i]
	out := StagePlan{Plan: plan, Ordinal: ordinal}
	var scope struct {
		Controls []string `json:"controls"`
	}
	if err := json.Unmarshal(st.Scope, &scope); err != nil {
		return StagePlan{}, err
	}
	for _, c := range scope.Controls {
		id, err := ids.ParseUUID(c)
		if err != nil {
			return StagePlan{}, err
		}
		out.Lifts = append(out.Lifts, id)
	}
	if err := json.Unmarshal(st.Tests, &out.Tests); err != nil {
		return StagePlan{}, err
	}
	active, err := q.ActiveContainmentControls(ctx, org)
	if err != nil {
		return StagePlan{}, err
	}
	for _, c := range active {
		if slices.Contains(out.Lifts, c.ID) {
			continue
		}
		ctl := pipeline.Control{ID: c.ID, ScopeType: c.ScopeType, ScopeID: c.ScopeID, Control: c.Control, ExpiresAt: c.ExpiresAt}
		if c.Operation != nil {
			ctl.Operation = *c.Operation
		}
		out.Remaining = append(out.Remaining, ctl)
	}
	return out, nil
}

// RunStageTests decides each test action again, dry run, with the
// controls that would remain (HR-250): a PERMITTED test passes only when
// the replay is complete and permits, a PROHIBITED one only when it is
// complete and does not. It runs outside any write transaction.
func RunStageTests(ctx context.Context, r Replayer, org ids.OrgID, sp StagePlan) ([]TestResult, bool, error) {
	if r == nil {
		return nil, false, ErrNoReplay
	}
	all := true
	out := make([]TestResult, 0, len(sp.Tests))
	for _, t := range sp.Tests {
		res := TestResult{TestAction: t}
		o, err := r.ReplayContained(ctx, org, t.Transaction, t.Evaluation, sp.Remaining)
		switch {
		case err != nil:
			res.Reason = "NOT_REPLAYABLE"
		default:
			res.Decision, res.Reason, res.Complete = string(o.Decision), o.Reason, o.Complete
			permits := o.Decision.Permits()
			res.Passed = o.Complete && ((t.Expect == ExpectPermitted && permits) || (t.Expect == ExpectProhibited && !permits))
		}
		all = all && res.Passed
		out = append(out, res)
	}
	return out, all, nil
}

// ApplyStageIn records a stage's test results in tx and, when every test
// passed, lifts its controls (each lift raises the epoch); the last stage
// completes the plan. A failing stage lifts nothing and may be run again.
func (s *Containment) ApplyStageIn(ctx context.Context, tx db.TenantTx, sp StagePlan, reviewer ids.UUID, results []TestResult, passed bool) (string, error) {
	org := tx.OrgID()
	q := dbq.New(tx)
	p, err := q.LockRestorationPlan(ctx, org, sp.Plan)
	if err != nil {
		return "", err
	}
	if p.RequestedBy == "user:"+reviewer.String() {
		return "", ErrRequesterDecides
	}
	if p.State != PlanStaging {
		return "", ErrPlanState
	}
	resJSON, err := json.Marshal(nonNilResults(results), json.Deterministic(true))
	if err != nil {
		return "", err
	}
	state := "FAILED"
	if passed {
		state = "APPLIED"
	}
	if n, err := q.SetRestorationStage(ctx, dbq.SetRestorationStageParams{
		OrgID: org, PlanID: sp.Plan, Ordinal: sp.Ordinal, Results: resJSON, State: state,
	}); err != nil {
		return "", err
	} else if n == 0 {
		return "", ErrStageOrder
	}
	details := map[string]string{"stage": strconv.Itoa(int(sp.Ordinal)), "tests": strconv.Itoa(len(results)), "passed": strconv.FormatBool(passed)}
	if !passed {
		if _, err := auditRecord(ctx, tx, userActor(reviewer), "response.restoration_stage_failed", "restoration_plan", sp.Plan.String(), details); err != nil {
			return "", err
		}
		return PlanStaging, nil
	}
	for _, c := range sp.Lifts {
		if err := pgresponse.LiftControl(ctx, tx, org, c, sp.Plan, "user:"+reviewer.String()); err != nil {
			return "", err
		}
	}
	stages, err := q.RestorationStages(ctx, org, sp.Plan)
	if err != nil {
		return "", err
	}
	next := PlanStaging
	if !slices.ContainsFunc(stages, func(st dbq.PcRestorationStage) bool { return st.State != "APPLIED" }) {
		next = PlanCompleted
		if _, err := q.SetRestorationPlanState(ctx, dbq.SetRestorationPlanStateParams{
			OrgID: org, ID: sp.Plan, Expected: PlanStaging, State: PlanCompleted, Preconditions: p.Preconditions,
		}); err != nil {
			return "", err
		}
	} else if s.Notify != nil {
		if _, err := s.Notify.Enqueue(ctx, tx, napp.Message{Org: org, Type: reflexdomain.NotifyRestorationReady, Params: map[string]string{
			"plan": sp.Plan.String(), "stage": strconv.Itoa(int(sp.Ordinal)),
		}}); err != nil {
			return "", err
		}
	}
	if _, err := auditRecord(ctx, tx, userActor(reviewer), "response.restoration_stage_applied", "restoration_plan", sp.Plan.String(), details); err != nil {
		return "", err
	}
	return next, nil
}

// preconditions computes a plan's preconditions now (F564): the identity
// behind each principal and agent control is usable again, each contained
// connection and its gateway are healthy (both block when not), and, for
// the reviewer, the grants still active, the approvals waiting and the
// tests a staged plan will run.
func preconditions(ctx context.Context, q *dbq.Queries, org ids.OrgID, controls []dbq.PcContainmentControl, staged bool) ([]Precondition, error) {
	out := []Precondition{}
	var agents []ids.UUID
	for _, c := range controls {
		switch c.ScopeType {
		case rdomain.ScopeAgent:
			id, err := ids.ParseUUID(c.ScopeID)
			if err != nil {
				return nil, err
			}
			agents = append(agents, id)
			st, err := q.AgentStateOf(ctx, org, id)
			if err != nil && !db.IsNoRows(err) {
				return nil, err
			}
			pc := Precondition{Check: "identity_reverified", Subject: "agent:" + c.ScopeID, State: PreMet, Detail: "the agent is " + st}
			if st == "" || st == "SUSPENDED" || st == "RETIRED" {
				pc.State, pc.Detail = PreUnmet, "the agent is "+orUnknown(st)+": restore or replace it first"
			}
			out = append(out, pc)
		case rdomain.ScopePrincipal:
			kind, id, _ := cutPrincipal(c.ScopeID)
			pc := Precondition{Check: "identity_reverified", Subject: c.ScopeID, State: PreInfo, Detail: "a service account's credentials are not checked here"}
			if kind == "user" {
				u, err := ids.ParseUUID(id)
				if err != nil {
					return nil, err
				}
				st, err := q.UserStateOf(ctx, org, u)
				if err != nil && !db.IsNoRows(err) {
					return nil, err
				}
				pc.State, pc.Detail = PreMet, "the user is "+st
				if st != "ACTIVE" {
					pc.State, pc.Detail = PreUnmet, "the user is "+orUnknown(st)+": the person must sign in again with a re-verified identity first"
				}
			}
			out = append(out, pc)
		case rdomain.ScopeConnection:
			id, err := ids.ParseUUID(c.ScopeID)
			if err != nil {
				return nil, err
			}
			h, err := q.ConnectionHealth(ctx, org, id)
			if err != nil && !db.IsNoRows(err) {
				return nil, err
			}
			pc := Precondition{
				Check: "connection_health", Subject: "connection:" + c.ScopeID, State: PreMet,
				Detail: "the connection is " + h.State + " on a " + h.GatewayState + " gateway",
			}
			if h.State != "ACTIVE" || h.GatewayState != "ACTIVE" {
				pc.State, pc.Detail = PreUnmet, "the connection is "+orUnknown(h.State)+" on a "+orUnknown(h.GatewayState)+" gateway"
			}
			out = append(out, pc)
		}
	}
	if len(agents) > 0 {
		n, err := q.ActiveGrantsOfAgents(ctx, org, agents)
		if err != nil {
			return nil, err
		}
		out = append(out, Precondition{Check: "remaining_grants", State: PreInfo, Detail: strconv.FormatInt(n, 10) + " grants of the agents are still active"})
		runs := []ids.UUID{}
		for _, a := range agents {
			rs, err := q.ScopeActiveRuns(ctx, org, rdomain.ScopeAgent, a.String())
			if err != nil {
				return nil, err
			}
			for _, r := range rs {
				runs = append(runs, r.ID)
			}
		}
		w, err := q.WaitingHoldsOfRuns(ctx, org, runs)
		if err != nil {
			return nil, err
		}
		out = append(out, Precondition{
			Check: "waiting_approvals", State: PreInfo,
			Detail: strconv.FormatInt(w, 10) + " approval requests of their runs are waiting; none is revived by the restoration",
		})
	}
	test := Precondition{Check: "remediation_tests", State: PreInfo, Detail: "an unstaged restoration runs no test actions"}
	if staged {
		test.Detail = "each stage's test actions run, dry run, before it lifts anything"
	}
	return append(out, test), nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func userActor(u ids.UUID) evdomain.Actor { return evdomain.Actor{Type: "user", ID: u.String()} }

func hasDup(xs []ids.UUID) bool {
	seen := map[ids.UUID]bool{}
	for _, x := range xs {
		if seen[x] {
			return true
		}
		seen[x] = true
	}
	return false
}

func sameSet(a, b []ids.UUID) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return len(a) == len(b)
}

func idStrings(xs []ids.UUID) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.String()
	}
	return out
}

func nonNilTests(t []TestAction) []TestAction {
	if t == nil {
		return []TestAction{}
	}
	return t
}

func nonNilResults(r []TestResult) []TestResult {
	if r == nil {
		return []TestResult{}
	}
	return r
}
