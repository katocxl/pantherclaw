// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// ActionStatus reads a response action's status (REQUESTED, PARTIAL,
// CONFIRMED, FAILED, UNSUPPORTED).
type ActionStatus interface {
	Status(ctx context.Context, tx pgx.Tx, org ids.OrgID, action ids.UUID) (string, error)
}

// Response action statuses (response, D21).
const (
	actionRequested   = "REQUESTED"
	actionPartial     = "PARTIAL"
	actionConfirmed   = "CONFIRMED"
	actionFailed      = "FAILED"
	actionUnsupported = "UNSUPPORTED"
)

// Bounds of a contain or open_case step (D31).
const (
	MaxReason    = 1000
	MaxCaseTitle = 200
	MaxQuestion  = 500
	MaxQuestions = 10
	// escalateWithin is the deadline of the owned failure a containment
	// that did not hold opens (F696).
	escalateWithin = 24 * time.Hour
)

// Output keys.
const (
	OutAction  = "action_id"
	OutStatus  = "status"
	OutCase    = "case_id"
	OutTarget  = "target"
	OutFailure = "failure_id"
)

// Owned failure kinds this package records.
const (
	FailureContainment = "automation.containment_failed"
	FailureAssigned    = "automation.assigned"
)

// contain contains the trigger's run or grant (Business, HR-284, F562):
// SUSPEND_RUN puts a DENY_ALL control on the triggering run through the
// Container with a per-execution idempotency key, recorded as a playbook
// action of the automation (D61); REVOKE_GRANT revokes the triggering grant
// through RevokeForAutomationTx (TRIGGER_GRANT, within the version's
// revocable agents, D65). It never touches agents, credentials,
// connections or the kill switch. A containment that ends PARTIAL, FAILED
// or UNSUPPORTED is escalated: an owned failure for the automation's owner
// and a case with the unresolved paths (F696).
type contain struct{ d Deps }

func (*contain) Kind() string { return autodomain.KindContain }

// plan checks the step and returns its target.
func (s *contain) plan(sc autodomain.StepContext) (*autodomain.ContainWith, ids.UUID, string) {
	w, ok := sc.With.(*autodomain.ContainWith)
	if !ok || len([]rune(w.Reason)) > MaxReason {
		return nil, ids.UUID{}, ReasonBadWith
	}
	var t reflexdomain.SubjectType
	switch {
	case w.Action == autodomain.ContainSuspendRun && w.Subject == autodomain.SubjectTriggerRun:
		t = reflexdomain.SubjectRun
	case w.Action == autodomain.ContainRevokeGrant && w.Subject == autodomain.SubjectTriggerGrant:
		t = reflexdomain.SubjectGrant
	default:
		return nil, ids.UUID{}, ReasonBadWith
	}
	if !inScope(sc.Def, autodomain.KindContain, w.Subject) {
		return nil, ids.UUID{}, ReasonOutsideScope
	}
	target, ok := triggerSubject(sc, t)
	if !ok {
		return nil, ids.UUID{}, ReasonNoSubject
	}
	return w, target, ""
}

func (s *contain) reason(sc autodomain.StepContext, w *autodomain.ContainWith) string {
	if r := strings.TrimSpace(w.Reason); r != "" {
		return r
	}
	return "Contained by automation " + sc.Execution.AutomationName
}

func (s *contain) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, target, reason := s.plan(sc)
	if reason != "" {
		return failed(reason)
	}
	// Escalation (an owned failure and a case) is part of the step: without
	// its ties the step does not act at all (HR-284).
	if s.d.Failures == nil || s.d.Cases == nil {
		return unwired()
	}
	if w.Action == autodomain.ContainRevokeGrant {
		return s.revoke(ctx, tx, sc, w, target)
	}
	if s.d.Container == nil || s.d.Actions == nil {
		return unwired()
	}
	res, err := s.d.Container.Contain(ctx, tx, reflexdomain.ContainRequest{
		Org: sc.Org, Scope: reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: target.String()},
		Control: reflexdomain.ControlDenyAll, Reason: s.reason(sc, w), Actor: automationActor(sc),
		Idempotency: idempotency(sc), Execution: &sc.Execution.ID,
	})
	if err != nil {
		if r, ok := refusal(err); ok {
			return failed(r)
		}
		return autodomain.StepResult{}, err
	}
	return s.settle(ctx, tx, sc, res.ActionID, res.Status)
}

// revoke revokes the triggering grant. Revoking a grant is final when it
// returns; a grant already revoked is containment that holds.
func (s *contain) revoke(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, w *autodomain.ContainWith, grant ids.UUID) (autodomain.StepResult, error) {
	if s.d.Grants == nil {
		return unwired()
	}
	revoked, err := s.d.Grants.RevokeForAutomation(ctx, tx, steps.GrantRevoke{
		Org: sc.Org, Execution: sc.Execution.ID, Grant: &grant, Scope: autodomain.RevokeTriggerGrant, Reason: s.reason(sc, w),
	})
	if err != nil {
		if r, ok := refusal(err); ok {
			return s.escalate(ctx, tx, sc, nil, r)
		}
		return autodomain.StepResult{}, err
	}
	effect := autodomain.EffectUnchanged
	if len(revoked) > 0 {
		effect = autodomain.EffectChanged
	}
	refs := []reflexdomain.EvidenceRef{ref(steps.RefGrant, grant)}
	for _, g := range revoked {
		if g != grant {
			refs = append(refs, ref(steps.RefGrant, g))
		}
	}
	return autodomain.StepResult{
		State: autodomain.StepDone, Effect: effect, Refs: refs,
		Output: map[string]string{OutTarget: grant.String(), OutStatus: actionConfirmed},
	}, nil
}

// settle maps a response action's status to the step's result: CONFIRMED
// is done, REQUESTED waits, the rest escalate.
func (s *contain) settle(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, action ids.UUID, status string) (autodomain.StepResult, error) {
	out := map[string]string{OutAction: action.String(), OutStatus: status}
	refs := []reflexdomain.EvidenceRef{ref(RefResponseAction, action)}
	switch status {
	case actionConfirmed:
		return autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectChanged, Output: out, Refs: refs}, nil
	case actionRequested:
		return waiting(out, refs, sc.Now.Add(pollEvery))
	case actionPartial:
		return s.escalate(ctx, tx, sc, &action, ReasonContainPartial)
	case actionUnsupported:
		return s.escalate(ctx, tx, sc, &action, ReasonUnsupportedAct)
	}
	return s.escalate(ctx, tx, sc, &action, ReasonContainFailed)
}

func (s *contain) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	action, ok := parseID(own(sc)[OutAction])
	if !ok {
		return s.Run(ctx, tx, sc)
	}
	if s.d.Actions == nil {
		return unwired()
	}
	status, err := s.d.Actions.Status(ctx, tx, sc.Org, action)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	return s.settle(ctx, tx, sc, action, status)
}

// Expire escalates a containment still REQUESTED at the step's timeout:
// it did not hold in time (engine.Expirer).
func (s *contain) Expire(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	var action *ids.UUID
	if a, ok := parseID(own(sc)[OutAction]); ok {
		action = &a
	}
	return s.escalate(ctx, tx, sc, action, engine.ReasonTimeout)
}

var _ engine.Expirer = (*contain)(nil)

// escalate tells a person that containment did not hold (F696): an owned
// failure for the automation's owner, deduplicated per execution and
// step, and a case with the trigger's subjects and evidence and the
// response action. The step then fails with reason.
func (s *contain) escalate(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, action *ids.UUID, reason string) (autodomain.StepResult, error) {
	out := map[string]string{}
	refs := make([]reflexdomain.EvidenceRef, 0, 3)
	scope := append([]reflexdomain.Subject{automationSubject(sc)}, sc.Execution.Trigger.Subjects...)
	evidence := append([]reflexdomain.EvidenceRef(nil), sc.Execution.Trigger.Evidence...)
	if action != nil {
		out[OutAction] = action.String()
		refs = append(refs, ref(RefResponseAction, *action))
		evidence = append(evidence, ref(RefResponseAction, *action))
	}
	summary := "Automation " + sc.Execution.AutomationName + " could not confirm containment (" + reason + ")."
	owner := reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: sc.Execution.Owner.String()}
	f, err := s.d.Failures.Report(ctx, tx, reflexdomain.Failure{
		Org: sc.Org, Kind: FailureContainment, Summary: summary,
		NextStep: "Review the response action's unresolved paths and in-flight actions, and contain them by hand.",
		Scope:    clip(scope), Owner: &owner, Deadline: sc.Now.Add(escalateWithin), DedupeKey: idempotency(sc),
	})
	if err != nil {
		return autodomain.StepResult{}, err
	}
	out[OutFailure] = f.String()
	refs = append(refs, ref(RefFailure, f))
	// One case per execution and step: a retry of the step finds the same
	// response action and escalates through the same failure, so only its
	// first attempt opens the case.
	if sc.Attempt <= 1 {
		c, err := s.d.Cases.Open(ctx, tx, reflexdomain.CaseSeed{
			Org: sc.Org, Title: clipText("Containment did not hold: "+sc.Execution.AutomationName, MaxCaseTitle),
			Source: caseSource, Subjects: clip(scope), Evidence: clipEvidence(evidence),
			Questions: []string{"Which paths and in-flight actions are still unresolved?"}, Opener: automationActor(sc),
		})
		if err != nil {
			if _, ok := refusal(err); !ok {
				return autodomain.StepResult{}, err
			}
		} else {
			out[OutCase] = c.String()
			refs = append(refs, ref(RefCase, c))
		}
	}
	return autodomain.StepResult{State: autodomain.StepFailed, Reason: reason, Effect: autodomain.EffectUnknown, Output: out, Refs: refs}, nil
}

func (s *contain) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, target, reason := s.plan(sc)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{"action": w.Action, OutTarget: target.String()})
}

// caseSource is the source of cases automations open.
const caseSource = "automation"

// openCase opens a case with the trigger's subjects and evidence (D31,
// Team). The driver's transaction makes it once per attempt; it is not
// retried after it opened.
type openCase struct{ d Deps }

func (*openCase) Kind() string { return autodomain.KindOpenCase }

func (s *openCase) check(sc autodomain.StepContext) (*autodomain.OpenCaseWith, string) {
	w, ok := sc.With.(*autodomain.OpenCaseWith)
	if !ok || strings.TrimSpace(w.Title) == "" || len([]rune(w.Title)) > MaxCaseTitle || len(w.Questions) > MaxQuestions {
		return nil, ReasonBadWith
	}
	for _, q := range w.Questions {
		if strings.TrimSpace(q) == "" || len([]rune(q)) > MaxQuestion {
			return nil, ReasonBadWith
		}
	}
	if !inScope(sc.Def, autodomain.KindOpenCase, autodomain.ScopeTriggerSubjects) {
		return nil, ReasonOutsideScope
	}
	return w, ""
}

func (s *openCase) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, reason := s.check(sc)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Cases == nil {
		return unwired()
	}
	subjects := append([]reflexdomain.Subject{automationSubject(sc)}, sc.Execution.Trigger.Subjects...)
	c, err := s.d.Cases.Open(ctx, tx, reflexdomain.CaseSeed{
		Org: sc.Org, Title: w.Title, Source: caseSource, Subjects: clip(subjects),
		Evidence: clipEvidence(sc.Execution.Trigger.Evidence), Questions: w.Questions, Opener: automationActor(sc),
	})
	if err != nil {
		if r, ok := refusal(err); ok {
			return failed(r)
		}
		return autodomain.StepResult{}, err
	}
	return autodomain.StepResult{
		State: autodomain.StepDone, Effect: autodomain.EffectChanged,
		Output: map[string]string{OutCase: c.String()}, Refs: []reflexdomain.EvidenceRef{ref(RefCase, c)},
	}, nil
}

func (s *openCase) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *openCase) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, reason := s.check(sc)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{"title": clipText(w.Title, autodomain.MaxOutputValue)})
}

// automationSubject is the execution's automation as a case or failure
// subject.
func automationSubject(sc autodomain.StepContext) reflexdomain.Subject {
	return reflexdomain.Subject{Type: reflexdomain.SubjectAutomationExecution, ID: sc.Execution.ID.String()}
}

// maxSubjects bounds the subjects a case or failure carries.
const maxSubjects = 20

func clip(s []reflexdomain.Subject) []reflexdomain.Subject {
	if len(s) > maxSubjects {
		return s[:maxSubjects]
	}
	return s
}

func clipEvidence(e []reflexdomain.EvidenceRef) []reflexdomain.EvidenceRef {
	if len(e) > reflexdomain.MaxEvidence {
		return e[:reflexdomain.MaxEvidence]
	}
	return e
}

func clipText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
