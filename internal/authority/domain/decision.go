// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the Transaction Authority's decisions and reason
// codes. Since M4 decisions come from the ten-step pipeline
// (internal/authority/pipeline, ARCHITECTURE §6.1); the M1.5 development
// grant is gone.
package domain

// Decision is an authorization decision (PAP-1 §7.1).
type Decision string

// The six decisions.
const (
	Allow                Decision = "ALLOW"
	AllowWithObligations Decision = "ALLOW_WITH_OBLIGATIONS"
	RequireApproval      Decision = "REQUIRE_APPROVAL"
	RequireStepUp        Decision = "REQUIRE_STEP_UP"
	Deny                 Decision = "DENY"
	CannotAuthorize      Decision = "CANNOT_AUTHORIZE"
)

// Permits reports whether the decision allows dispatch (subject to the
// permit and the BeginDispatch commit point).
func (d Decision) Permits() bool { return d == Allow || d == AllowWithObligations }

// Reason explains one checklist outcome.
type Reason struct {
	Code     string `json:"code"`
	Check    string `json:"check"`
	Detail   string `json:"detail,omitempty"`
	Decisive bool   `json:"decisive"`
}

// Stable reason codes of the service layer (identity, binding) shared with
// the pipeline.
const (
	ReasonAmbiguousInput   = "AMBIGUOUS_INPUT"
	ReasonNoGrant          = "NO_GRANT"
	ReasonOrgMismatch      = "ORG_MISMATCH"
	ReasonKillSwitch       = "KILL_SWITCH_ENGAGED"
	ReasonBudgetExhausted  = "BUDGET_EXHAUSTED"
	ReasonActionTampered   = "ACTION_TAMPERED"
	ReasonDuplicateRequest = "DUPLICATE_REQUEST"
	// Workload identity and run binding (M3; HR-021, HR-022). The detail of an
	// identity reason is the PAP-Error code (PAP-1 §12).
	ReasonIdentityUnverified = "IDENTITY_UNVERIFIED"
	ReasonIdentityMismatch   = "IDENTITY_MISMATCH"
	ReasonAgentUnusable      = "AGENT_UNUSABLE"
	ReasonRunMismatch        = "RUN_MISMATCH"
)

// Outcome is the result of evaluating one action before finalization.
type Outcome struct {
	Decision Decision
	Reasons  []Reason
}

// Decisive returns the decisive reason code.
func (o Outcome) Decisive() string {
	for _, r := range o.Reasons {
		if r.Decisive {
			return r.Code
		}
	}
	if len(o.Reasons) > 0 {
		return o.Reasons[0].Code
	}
	return ""
}

// Presentation is how a decision is shown to people and agents (F069).
type Presentation string

// The five presentations.
const (
	PresentAllow           Presentation = "ALLOW"
	PresentConstrain       Presentation = "CONSTRAIN"
	PresentHold            Presentation = "HOLD"
	PresentDeny            Presentation = "DENY"
	PresentCannotAuthorize Presentation = "CANNOT_AUTHORIZE"
)

// Presentation maps the decision: ALLOW_WITH_OBLIGATIONS is Constrain and
// both REQUIRE_* decisions are Hold. An unknown decision is presented as
// Cannot authorize, never as an allow.
func (d Decision) Presentation() Presentation {
	switch d {
	case Allow:
		return PresentAllow
	case AllowWithObligations:
		return PresentConstrain
	case RequireApproval, RequireStepUp:
		return PresentHold
	case Deny:
		return PresentDeny
	}
	return PresentCannotAuthorize
}

// Label is the presentation's display name.
func (p Presentation) Label() string {
	switch p {
	case PresentAllow:
		return "Allow"
	case PresentConstrain:
		return "Constrain"
	case PresentHold:
		return "Hold"
	case PresentDeny:
		return "Deny"
	}
	return "Cannot authorize"
}

// Explains reports whether the presentation names a failing category:
// only a decision that did not plainly allow does (F330).
func (p Presentation) Explains() bool { return p != PresentAllow && p != PresentConstrain }
