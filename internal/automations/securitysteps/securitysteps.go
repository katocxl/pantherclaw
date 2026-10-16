// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package securitysteps holds the security-work step kinds of governed
// automations (G0 M11 part 2 D31): containment, cases, launch pauses,
// coverage waits, owned failures, approval routing, agent intake,
// least-privilege drafts and digests. Like the engine's generic steps they
// run in the driver's transaction as the automation's service account and
// act only through dedicated use-case functions (D8): never an RPC handler
// and never a role check. In SHADOW and TEST modes the engine calls
// Preview, which writes nothing outside the execution's own rows (HR-288).
//
// They act only on the trigger's own subjects (HR-284), and what they find
// becomes a proposal or a draft, never a grant, a promotion or a published
// policy (HR-286, F599).
package securitysteps

import (
	"errors"
	"regexp"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
)

// Step reasons beyond D24's and the engine's, stable codes.
const (
	ReasonOutsideScope   = steps.ReasonOutsideScope
	ReasonBadWith        = steps.ReasonBadWith
	ReasonDependency     = "DEPENDENCY_UNAVAILABLE"
	ReasonNoSubject      = "TRIGGER_SUBJECT_MISSING"
	ReasonContainPartial = "CONTAINMENT_PARTIAL"
	ReasonContainFailed  = "CONTAINMENT_FAILED"
	ReasonUnsupportedAct = "CONTAINMENT_UNSUPPORTED"
	ReasonNoOwner        = "OWNER_MISSING"
	ReasonPausedElse     = "PAUSED_FOR_ANOTHER_REASON"
	ReasonNotResolved    = "REQUEST_NOT_RESOLVED"
	ReasonNotClaimed     = "AGENT_NOT_CLAIMED"
)

// Evidence and output ref kinds beside the Reflex and engine kinds.
const (
	RefResponseAction = "response_action"
	RefCase           = "case"
	RefFailure        = "owned_failure"
	RefAutomation     = "automation"
	RefProposal       = "automation_proposal"
	RefCoverage       = "coverage"
	RefApproval       = "approval_request"
	RefPolicyVersion  = "policy_version"
	RefSimulation     = "policy_simulation"
	RefPack           = "evidence_pack"
	RefAgent          = "agent"
)

// Deps are the steps' ties to the platform. A nil dependency refuses the
// kinds that need it (FAILED UNSUPPORTED_CAPABILITY) rather than pretend.
type Deps struct {
	// Grants revokes the trigger's grant (contain REVOKE_GRANT, D9).
	Grants steps.Grants
	// Container applies containment controls (contain SUSPEND_RUN).
	Container reflexports.Container
	// Actions reads a response action's status.
	Actions ActionStatus
	// Cases opens cases (open_case; contain's escalation).
	Cases reflexports.CaseOpener
	// Failures records owned failures (assign_owner; escalations).
	Failures reflexports.FailureSink
	// Pauser pauses automations (pause_launches).
	Pauser autoports.Pauser
	// Resumer resumes what a pause_launches step paused.
	Resumer Resumer
	// Coverage reads a route's coverage (wait_coverage).
	Coverage Coverage
	// Owners resolves owners (assign_owner).
	Owners Owners
	// Approvals reminds and escalates approval requests and reads their
	// resolution.
	Approvals Approvals
	// Intake serves the agent intake kinds.
	Intake IntakeDeps
	// Review serves the least-privilege and digest kinds.
	Review ReviewDeps
}

// ErrUnwired reports a dependency that is not wired.
var ErrUnwired = errors.New("securitysteps: dependency not wired")

// All returns the security-work step kinds.
func All(d Deps) autoports.StepRegistry {
	r := autoports.StepRegistry{
		autodomain.KindContain:          &contain{d: d},
		autodomain.KindOpenCase:         &openCase{d: d},
		autodomain.KindPauseLaunches:    &pauseLaunches{d: d},
		autodomain.KindResumeLaunches:   &resumeLaunches{d: d},
		autodomain.KindWaitCoverage:     &waitCoverage{d: d},
		autodomain.KindAssignOwner:      &assignOwner{d: d},
		autodomain.KindRemindApprovers:  &routeApproval{d: d, kind: autodomain.KindRemindApprovers},
		autodomain.KindEscalateApproval: &routeApproval{d: d, kind: autodomain.KindEscalateApproval},
		autodomain.KindWaitResolution:   &waitResolution{d: d},
	}
	for k, s := range intakeSteps(d) {
		r[k] = s
	}
	for k, s := range reviewSteps(d) {
		r[k] = s
	}
	return r
}

func failed(reason string) (autodomain.StepResult, error) {
	return autodomain.StepResult{State: autodomain.StepFailed, Reason: reason, Effect: autodomain.EffectNone}, nil
}

// unwired fails a step whose dependency this server lacks (D108): it never
// acts in part.
func unwired() (autodomain.StepResult, error) { return failed(ReasonDependency) }

// previewRefused is a preview that would be refused: FAILED with the
// would-be decision (HR-288).
func previewRefused(reason string) (autodomain.StepResult, error) {
	return autodomain.StepResult{
		State: autodomain.StepFailed, Reason: reason, Effect: autodomain.EffectNone,
		Output: map[string]string{"shadow": "true", "decision": "REFUSED"},
	}, nil
}

// shadowed is a preview's would-be result: SHADOWED with the would-be
// decision in the output (HR-288).
func shadowed(out map[string]string) (autodomain.StepResult, error) {
	if out == nil {
		out = map[string]string{}
	}
	out["shadow"] = "true"
	return autodomain.StepResult{State: autodomain.StepShadowed, Effect: autodomain.EffectNone, Output: out}, nil
}

// waiting is a WAITING result polled again at wake.
func waiting(out map[string]string, refs []reflexdomain.EvidenceRef, wake time.Time) (autodomain.StepResult, error) {
	return autodomain.StepResult{State: autodomain.StepWaiting, Effect: autodomain.EffectNone, Output: out, Refs: refs, WakeAt: wake}, nil
}

// pollEvery is how often a waiting kind looks again (D24).
const pollEvery = 15 * time.Second

// reasonPattern is a stable code.
var reasonPattern = regexp.MustCompile(`^[A-Z][A-Z_]{1,63}$`)

// refusal turns a use case's refusal into the step's reason; anything that
// is not a refusal with a stable code is returned as an error (the
// transaction rolls back and the driver retries).
func refusal(err error) (string, bool) {
	var e *pcerr.Error
	if !errors.As(err, &e) {
		return "", false
	}
	if c := e.Code(); c == pcerr.Internal || c == pcerr.Unavailable {
		return "", false
	}
	if r := e.Reason(); reasonPattern.MatchString(r) {
		return r, true
	}
	return "", false
}

// inScope reports whether the version's `platform` section lists kind with
// scope (HR-279).
func inScope(def *autodomain.Definition, kind, scope string) bool {
	if def == nil {
		return false
	}
	for _, p := range def.Authority.Platform {
		if p.Step != kind {
			continue
		}
		for _, s := range p.Scopes {
			if s == scope {
				return true
			}
		}
	}
	return false
}

// own is the output a waiting step recorded when it started.
func own(sc autodomain.StepContext) map[string]string { return sc.Outputs[sc.Spec.ID] }

func parseID(s string) (ids.UUID, bool) {
	u, err := ids.ParseUUID(s)
	return u, err == nil && !u.IsZero()
}

func ref(kind string, id ids.UUID) reflexdomain.EvidenceRef {
	return reflexdomain.EvidenceRef{Kind: kind, ID: id}
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseRFC(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// triggerSubject returns the first subject of a type among the trigger's
// subjects (HR-284: only the trigger's own subjects).
func triggerSubject(sc autodomain.StepContext, t reflexdomain.SubjectType) (ids.UUID, bool) {
	for _, s := range sc.Execution.Trigger.Subjects {
		if s.Type == t {
			if id, ok := parseID(s.ID); ok {
				return id, true
			}
		}
	}
	return ids.UUID{}, false
}

// automationActor is the actor the automation's actions record (D61).
func automationActor(sc autodomain.StepContext) reflexdomain.Subject {
	return reflexdomain.Subject{Type: reflexdomain.SubjectAutomation, ID: sc.Execution.Automation.String()}
}

// idempotency is the per-execution, per-step key of an effect (HR-284).
func idempotency(sc autodomain.StepContext) string {
	return "auto:" + sc.Execution.ID.String() + ":" + sc.Spec.ID
}
