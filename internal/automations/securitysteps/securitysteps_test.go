// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// fakes records every effect a step asks for.
type fakes struct {
	contains  []reflexdomain.ContainRequest
	status    string
	revokes   []steps.GrantRevoke
	revoked   []ids.UUID
	revokeErr error
	cases     []reflexdomain.CaseSeed
	failures  []reflexdomain.Failure
	pauses    []autodomain.PauseSelector
	paused    []ids.UUID
	coverage  string
	snapshot  ids.UUID
	agentOwn  *ids.UUID
	request   ids.UUID
	nudges    []bool
	told      int
	res       Resolution
}

func (f *fakes) Contain(_ context.Context, _ pgx.Tx, r reflexdomain.ContainRequest) (reflexdomain.ContainResult, error) {
	f.contains = append(f.contains, r)
	return reflexdomain.ContainResult{ActionID: actionID, Status: f.status}, nil
}

func (f *fakes) Status(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (string, error) {
	return f.status, nil
}

func (f *fakes) IssueForAutomation(context.Context, pgx.Tx, steps.LaunchIssue) (ids.UUID, error) {
	panic("never issues")
}

func (f *fakes) RevokeForAutomation(_ context.Context, _ pgx.Tx, in steps.GrantRevoke) ([]ids.UUID, error) {
	f.revokes = append(f.revokes, in)
	return f.revoked, f.revokeErr
}

func (f *fakes) Open(_ context.Context, _ pgx.Tx, s reflexdomain.CaseSeed) (ids.UUID, error) {
	f.cases = append(f.cases, s)
	return caseID, nil
}

func (f *fakes) Report(_ context.Context, _ pgx.Tx, fl reflexdomain.Failure) (ids.UUID, error) {
	f.failures = append(f.failures, fl)
	return failureID, nil
}

func (f *fakes) Pause(_ context.Context, _ pgx.Tx, _ ids.OrgID, sel autodomain.PauseSelector, _ autodomain.PauseReason) ([]ids.UUID, error) {
	f.pauses = append(f.pauses, sel)
	return f.paused, nil
}

func (f *fakes) RouteState(context.Context, pgx.Tx, ids.OrgID, ids.UUID, ids.UUID, string) (string, ids.UUID, error) {
	return f.coverage, f.snapshot, nil
}

func (f *fakes) AgentOwner(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (*ids.UUID, error) {
	return f.agentOwn, nil
}

func (f *fakes) ConnectionOwner(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (*ids.UUID, error) {
	return nil, nil
}

func (f *fakes) RequestOf(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (ids.UUID, bool, error) {
	return f.request, !f.request.IsZero(), nil
}

func (f *fakes) Nudge(_ context.Context, _ pgx.Tx, _ ids.OrgID, _ ids.UUID, escalate bool, _ string) (int, error) {
	f.nudges = append(f.nudges, escalate)
	return f.told, nil
}

func (f *fakes) Resolution(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (Resolution, error) {
	return f.res, nil
}

// effects counts what the fakes were asked to do.
func (f *fakes) effects() int {
	return len(f.contains) + len(f.revokes) + len(f.cases) + len(f.failures) + len(f.pauses) + len(f.nudges)
}

func (f *fakes) deps() Deps {
	return Deps{
		Grants: f, Container: f, Actions: f, Cases: f, Failures: f, Pauser: f, Coverage: f, Owners: f, Approvals: f,
	}
}

var (
	org        = ids.New[ids.Org]()
	actionID   = ids.NewV7()
	caseID     = ids.NewV7()
	failureID  = ids.NewV7()
	execution  = ids.NewV7()
	automation = ids.NewV7()
	owner      = ids.NewV7()
	trigRun    = ids.NewV7()
	trigGrant  = ids.NewV7()
	trigAgent  = ids.NewV7()
	trigConn   = ids.NewV7()
	trigTxn    = ids.NewV7()
	now        = time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
)

// sc is a step context for kind with with and the platform scopes.
func sc(kind string, with any, scopes ...string) autodomain.StepContext {
	return autodomain.StepContext{
		Org: org,
		Execution: autodomain.ExecutionView{
			ID: execution, Automation: automation, AutomationName: "contain-alerts", Owner: owner, Mode: autodomain.ModeLive,
			Trigger: autodomain.TriggerRef{Subjects: []reflexdomain.Subject{
				{Type: reflexdomain.SubjectRun, ID: trigRun.String()},
				{Type: reflexdomain.SubjectGrant, ID: trigGrant.String()},
				{Type: reflexdomain.SubjectAgent, ID: trigAgent.String()},
				{Type: reflexdomain.SubjectConnection, ID: trigConn.String()},
				{Type: reflexdomain.SubjectTransaction, ID: trigTxn.String()},
			}},
		},
		Def:     &autodomain.Definition{Authority: autodomain.Authority{Platform: []autodomain.PlatformScope{{Step: kind, Scopes: scopes}}}},
		Spec:    autodomain.StepSpec{ID: "step-1", Step: kind},
		With:    with,
		Attempt: 1,
		Params:  map[string]autodomain.Value{ParamOperation: {Type: autodomain.ParamString, String: "payments.refund"}},
		Outputs: map[string]map[string]string{},
		Mode:    autodomain.ModeLive,
		Now:     now,
	}
}

func run(t *testing.T, s interface {
	Run(context.Context, pgx.Tx, autodomain.StepContext) (autodomain.StepResult, error)
}, c autodomain.StepContext,
) autodomain.StepResult {
	t.Helper()
	r, err := s.Run(t.Context(), nil, c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestHR284_ContainActsOnlyOnTheTriggersRunOrGrant: SUSPEND_RUN asks the
// Container for a DENY_ALL on the trigger's own run, as the automation,
// with the execution's per-step idempotency key; REVOKE_GRANT revokes the
// trigger's own grant through the automation revocation (TRIGGER_GRANT).
// Nothing else can be named.
func TestHR284_ContainActsOnlyOnTheTriggersRunOrGrant(t *testing.T) {
	f := &fakes{status: actionConfirmed}
	s := &contain{d: f.deps()}
	r := run(t, s, sc(autodomain.KindContain, &autodomain.ContainWith{Action: autodomain.ContainSuspendRun, Subject: autodomain.SubjectTriggerRun}, autodomain.ScopeTriggerRun))
	if r.State != autodomain.StepDone || r.Effect != autodomain.EffectChanged || len(r.Refs) != 1 || r.Refs[0].ID != actionID {
		t.Fatalf("result = %+v", r)
	}
	c := f.contains[0]
	if c.Scope != (reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: trigRun.String()}) || c.Control != reflexdomain.ControlDenyAll ||
		c.Actor != (reflexdomain.Subject{Type: reflexdomain.SubjectAutomation, ID: automation.String()}) ||
		c.Idempotency != "auto:"+execution.String()+":step-1" {
		t.Fatalf("contain request = %+v", c)
	}

	f = &fakes{revoked: []ids.UUID{trigGrant}}
	s = &contain{d: f.deps()}
	r = run(t, s, sc(autodomain.KindContain, &autodomain.ContainWith{Action: autodomain.ContainRevokeGrant, Subject: autodomain.SubjectTriggerGrant}, autodomain.ScopeTriggerGrant))
	if r.State != autodomain.StepDone || len(f.revokes) != 1 || *f.revokes[0].Grant != trigGrant || f.revokes[0].Scope != autodomain.RevokeTriggerGrant ||
		f.revokes[0].Execution != execution {
		t.Fatalf("result = %+v, revokes %+v", r, f.revokes)
	}

	for name, tc := range map[string]struct {
		with   autodomain.ContainWith
		scopes []string
		strip  reflexdomain.SubjectType
		reason string
	}{
		"suspend a grant":   {autodomain.ContainWith{Action: autodomain.ContainSuspendRun, Subject: autodomain.SubjectTriggerGrant}, []string{autodomain.ScopeTriggerGrant}, "", ReasonBadWith},
		"revoke a run":      {autodomain.ContainWith{Action: autodomain.ContainRevokeGrant, Subject: autodomain.SubjectTriggerRun}, []string{autodomain.ScopeTriggerRun}, "", ReasonBadWith},
		"another action":    {autodomain.ContainWith{Action: "SUSPEND_AGENT", Subject: autodomain.SubjectTriggerRun}, []string{autodomain.ScopeTriggerRun}, "", ReasonBadWith},
		"scope not granted": {autodomain.ContainWith{Action: autodomain.ContainSuspendRun, Subject: autodomain.SubjectTriggerRun}, []string{autodomain.ScopeTriggerGrant}, "", ReasonOutsideScope},
		"no trigger run":    {autodomain.ContainWith{Action: autodomain.ContainSuspendRun, Subject: autodomain.SubjectTriggerRun}, []string{autodomain.ScopeTriggerRun}, reflexdomain.SubjectRun, ReasonNoSubject},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakes{status: actionConfirmed}
			c := sc(autodomain.KindContain, &tc.with, tc.scopes...)
			c.Execution.Trigger.Subjects = slices.DeleteFunc(slices.Clone(c.Execution.Trigger.Subjects), func(s reflexdomain.Subject) bool { return s.Type == tc.strip })
			r := run(t, &contain{d: f.deps()}, c)
			if r.State != autodomain.StepFailed || r.Reason != tc.reason || f.effects() != 0 {
				t.Fatalf("result = %+v, effects %d", r, f.effects())
			}
		})
	}
}

// TestHR284_ContainmentThatDoesNotHoldEscalates: PARTIAL, FAILED and
// UNSUPPORTED fail the step and tell a person: an owned failure for the
// automation's owner and a case carrying the response action (F696).
// REQUESTED waits and is polled.
func TestHR284_ContainmentThatDoesNotHoldEscalates(t *testing.T) {
	with := &autodomain.ContainWith{Action: autodomain.ContainSuspendRun, Subject: autodomain.SubjectTriggerRun}
	for status, reason := range map[string]string{
		actionPartial: ReasonContainPartial, actionFailed: ReasonContainFailed, actionUnsupported: ReasonUnsupportedAct,
	} {
		t.Run(status, func(t *testing.T) {
			f := &fakes{status: status}
			r := run(t, &contain{d: f.deps()}, sc(autodomain.KindContain, with, autodomain.ScopeTriggerRun))
			if r.State != autodomain.StepFailed || r.Reason != reason {
				t.Fatalf("result = %+v", r)
			}
			if len(f.failures) != 1 || f.failures[0].Kind != FailureContainment || f.failures[0].Owner.ID != owner.String() {
				t.Fatalf("failures = %+v", f.failures)
			}
			if len(f.cases) != 1 || !slices.Contains(f.cases[0].Evidence, ref(RefResponseAction, actionID)) {
				t.Fatalf("cases = %+v", f.cases)
			}
		})
	}

	f := &fakes{status: actionRequested}
	s := &contain{d: f.deps()}
	c := sc(autodomain.KindContain, with, autodomain.ScopeTriggerRun)
	r := run(t, s, c)
	if r.State != autodomain.StepWaiting || r.Output[OutAction] != actionID.String() || !r.WakeAt.After(now) {
		t.Fatalf("result = %+v", r)
	}
	c.Outputs[c.Spec.ID] = r.Output
	f.status = actionConfirmed
	if r, _ := s.Poll(t.Context(), nil, c); r.State != autodomain.StepDone || len(f.contains) != 1 {
		t.Fatalf("poll = %+v, contains %d", r, len(f.contains))
	}
	// Still requested at the timeout: escalated as not holding in time.
	f.status = actionRequested
	if r, _ := s.Expire(t.Context(), nil, c); r.State != autodomain.StepFailed || r.Reason != engine.ReasonTimeout || len(f.failures) != 1 {
		t.Fatalf("expire = %+v", r)
	}
}

// TestSecuritySteps_PreviewsActOnNothing: every kind of this file's
// Preview is effect-free and reports a would-be result.
func TestSecuritySteps_PreviewsActOnNothing(t *testing.T) {
	cases := []autodomain.StepContext{
		sc(autodomain.KindContain, &autodomain.ContainWith{Action: autodomain.ContainSuspendRun, Subject: autodomain.SubjectTriggerRun}, autodomain.ScopeTriggerRun),
		sc(autodomain.KindOpenCase, &autodomain.OpenCaseWith{Title: "Look"}, autodomain.ScopeTriggerSubjects),
		sc(autodomain.KindPauseLaunches, &autodomain.PauseLaunchesWith{Selector: autodomain.SelectAffected}, autodomain.ScopeAffected),
		sc(autodomain.KindWaitCoverage, &autodomain.WaitCoverageWith{MinState: "ENFORCED", Timeout: autodomain.Duration(time.Hour)}, autodomain.ScopeTriggerScope),
		sc(autodomain.KindAssignOwner, &autodomain.AssignOwnerWith{To: autodomain.ScopeOwner}, autodomain.ScopeOwner),
		sc(autodomain.KindRemindApprovers, &autodomain.ApprovalRequestWith{Request: autodomain.ScopeTriggerRequest}, autodomain.ScopeTriggerRequest),
		sc(autodomain.KindEscalateApproval, &autodomain.ApprovalRequestWith{Request: autodomain.ScopeTriggerRequest}, autodomain.ScopeTriggerRequest),
		sc(autodomain.KindWaitResolution, &autodomain.ApprovalRequestWith{Request: autodomain.ScopeTriggerRequest}, autodomain.ScopeTriggerRequest),
	}
	f := &fakes{status: actionConfirmed, request: ids.NewV7()}
	reg := All(f.deps())
	for _, c := range cases {
		c.Mode = autodomain.ModeShadow
		r, err := reg[c.Spec.Step].Preview(t.Context(), nil, c)
		if err != nil || r.State != autodomain.StepShadowed || r.Output["shadow"] != "true" {
			t.Errorf("%s preview = %+v, %v", c.Spec.Step, r, err)
		}
	}
	if f.effects() != 0 {
		t.Fatalf("previews asked for %d effects", f.effects())
	}
}

// TestT126_OpenCaseCarriesOnlyTheTriggersSubjects: a case an automation
// opens names the execution and the trigger's subjects and evidence,
// opened by the automation.
func TestT126_OpenCaseCarriesOnlyTheTriggersSubjects(t *testing.T) {
	f := &fakes{}
	c := sc(autodomain.KindOpenCase, &autodomain.OpenCaseWith{Title: "Refund spike", Questions: []string{"Who approved?"}}, autodomain.ScopeTriggerSubjects)
	c.Execution.Trigger.Evidence = []reflexdomain.EvidenceRef{{Kind: "transaction", ID: trigTxn}}
	r := run(t, &openCase{d: f.deps()}, c)
	if r.State != autodomain.StepDone || len(f.cases) != 1 {
		t.Fatalf("result = %+v", r)
	}
	got := f.cases[0]
	want := append([]reflexdomain.Subject{{Type: reflexdomain.SubjectAutomationExecution, ID: execution.String()}}, c.Execution.Trigger.Subjects...)
	if !slices.Equal(got.Subjects, want) || !slices.Equal(got.Evidence, c.Execution.Trigger.Evidence) ||
		got.Opener.Type != reflexdomain.SubjectAutomation || got.Title != "Refund spike" {
		t.Fatalf("case = %+v", got)
	}
	if r := run(t, &openCase{d: f.deps()}, sc(autodomain.KindOpenCase, &autodomain.OpenCaseWith{Title: "x"})); r.Reason != ReasonOutsideScope {
		t.Fatalf("without the scope = %+v", r)
	}
}

func TestPauseLaunches_PausesTheAffectedButNeverItself(t *testing.T) {
	other := ids.NewV7()
	f := &fakes{paused: []ids.UUID{other, automation}}
	r := run(t, &pauseLaunches{d: f.deps()}, sc(autodomain.KindPauseLaunches, &autodomain.PauseLaunchesWith{Selector: autodomain.SelectAffected}, autodomain.ScopeAffected))
	if r.State != autodomain.StepDone || r.Output[OutPaused] != "1" || *f.pauses[0].AffectingAgent != trigAgent {
		t.Fatalf("result = %+v, pauses %+v", r, f.pauses)
	}
	if slices.Contains(r.Refs, ref(RefAutomation, automation)) || !slices.Contains(r.Refs, ref(RefAutomation, other)) {
		t.Fatalf("refs = %+v", r.Refs)
	}
	list := &autodomain.PauseLaunchesWith{Selector: autodomain.SelectList, Automations: []autodomain.RefID{autodomain.RefID(automation)}}
	if r := run(t, &pauseLaunches{d: f.deps()}, sc(autodomain.KindPauseLaunches, list, autodomain.ScopeList)); r.Reason != ReasonBadWith {
		t.Fatalf("pausing only itself = %+v", r)
	}
}

func TestWaitCoverage_WaitsForTheTriggersRoute(t *testing.T) {
	f := &fakes{coverage: "PARTIAL", snapshot: ids.NewV7()}
	s := &waitCoverage{d: f.deps()}
	c := sc(autodomain.KindWaitCoverage, &autodomain.WaitCoverageWith{MinState: "ENFORCED", Timeout: autodomain.Duration(time.Hour)}, autodomain.ScopeTriggerScope)
	if r := run(t, s, c); r.State != autodomain.StepWaiting {
		t.Fatalf("partial = %+v", r)
	}
	f.coverage = "ENFORCED"
	if r := run(t, s, c); r.State != autodomain.StepDone || r.Refs[0].ID != f.snapshot {
		t.Fatalf("enforced = %+v", r)
	}
	delete(c.Params, ParamOperation)
	if r := run(t, s, c); r.Reason != ReasonNoSubject {
		t.Fatalf("no operation = %+v", r)
	}
}

func TestAssignOwner_GoesToTheResolvedOwner(t *testing.T) {
	agentOwner := ids.NewV7()
	f := &fakes{agentOwn: &agentOwner}
	r := run(t, &assignOwner{d: f.deps()}, sc(autodomain.KindAssignOwner, &autodomain.AssignOwnerWith{To: autodomain.ScopeAgentOwner, Summary: "Fix the route"}, autodomain.ScopeAgentOwner))
	if r.State != autodomain.StepDone || f.failures[0].Owner.ID != agentOwner.String() || f.failures[0].Kind != FailureAssigned {
		t.Fatalf("result = %+v, failures %+v", r, f.failures)
	}
	f = &fakes{}
	if r := run(t, &assignOwner{d: f.deps()}, sc(autodomain.KindAssignOwner, &autodomain.AssignOwnerWith{To: autodomain.ScopeConnectionOwner}, autodomain.ScopeConnectionOwner)); r.Reason != ReasonNoOwner || len(f.failures) != 0 {
		t.Fatalf("no connection owner = %+v", r)
	}
}

func TestApprovalRouting_RemindsEscalatesAndWaits(t *testing.T) {
	f := &fakes{request: ids.NewV7(), told: 2}
	with := &autodomain.ApprovalRequestWith{Request: autodomain.ScopeTriggerRequest}
	remind := run(t, &routeApproval{d: f.deps(), kind: autodomain.KindRemindApprovers}, sc(autodomain.KindRemindApprovers, with, autodomain.ScopeTriggerRequest))
	escalate := run(t, &routeApproval{d: f.deps(), kind: autodomain.KindEscalateApproval}, sc(autodomain.KindEscalateApproval, with, autodomain.ScopeTriggerRequest))
	if remind.State != autodomain.StepDone || escalate.State != autodomain.StepDone || !slices.Equal(f.nudges, []bool{false, true}) {
		t.Fatalf("remind %+v escalate %+v nudges %v", remind, escalate, f.nudges)
	}
	s := &waitResolution{d: f.deps()}
	c := sc(autodomain.KindWaitResolution, with, autodomain.ScopeTriggerRequest)
	f.res = Resolution{State: "APPROVED"}
	if r := run(t, s, c); r.State != autodomain.StepWaiting {
		t.Fatalf("approved, not yet used = %+v", r)
	}
	f.res = Resolution{State: "CONSUMED", Resolved: true, Transaction: &trigTxn, Outcome: "SUCCEEDED/CONFIRMED"}
	if r := run(t, s, c); r.State != autodomain.StepDone || r.Output[OutOutcome] != "SUCCEEDED/CONFIRMED" || len(r.Refs) != 2 {
		t.Fatalf("consumed = %+v", r)
	}
}

// A use case's refusal becomes the step's reason; anything else is an
// error that rolls the transaction back.
func TestRefusalsBecomeReasons(t *testing.T) {
	f := &fakes{revokeErr: pcerr.New(pcerr.FailedPrecondition, "OUTSIDE_REVOCABLE", "not revocable")}
	r := run(t, &contain{d: f.deps()}, sc(autodomain.KindContain, &autodomain.ContainWith{Action: autodomain.ContainRevokeGrant, Subject: autodomain.SubjectTriggerGrant}, autodomain.ScopeTriggerGrant))
	if r.State != autodomain.StepFailed || r.Reason != "OUTSIDE_REVOCABLE" || len(f.failures) != 1 {
		t.Fatalf("result = %+v", r)
	}
}

// TestHR284_ContainWithoutItsEscalationDoesNotAct: escalation (an owned
// failure and a case) is part of contain, so without either tie, or without
// the containment itself, the step fails DEPENDENCY_UNAVAILABLE before it
// contains anything (D108).
func TestHR284_ContainWithoutItsEscalationDoesNotAct(t *testing.T) {
	for name, strip := range map[string]func(*Deps){
		"no failures":  func(d *Deps) { d.Failures = nil },
		"no cases":     func(d *Deps) { d.Cases = nil },
		"no container": func(d *Deps) { d.Container = nil },
		"no grants":    func(d *Deps) { d.Grants = nil },
	} {
		for _, w := range []autodomain.ContainWith{
			{Action: autodomain.ContainSuspendRun, Subject: autodomain.SubjectTriggerRun},
			{Action: autodomain.ContainRevokeGrant, Subject: autodomain.SubjectTriggerGrant},
		} {
			if (name == "no container" && w.Action != autodomain.ContainSuspendRun) || (name == "no grants" && w.Action != autodomain.ContainRevokeGrant) {
				continue
			}
			f := &fakes{status: actionConfirmed, revoked: []ids.UUID{trigGrant}}
			d := f.deps()
			strip(&d)
			r := run(t, &contain{d: d}, sc(autodomain.KindContain, &w, autodomain.ScopeTriggerRun, autodomain.ScopeTriggerGrant))
			if r.State != autodomain.StepFailed || r.Reason != ReasonDependency || f.effects() != 0 {
				t.Errorf("%s, %s: %+v, %d effects", name, w.Action, r, f.effects())
			}
		}
	}
}
