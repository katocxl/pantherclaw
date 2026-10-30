// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"fmt"
	"time"
	"unicode"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/statemachine"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

type grantKind struct{}

func (grantKind) KindName() string { return "grant" }

type envelopeKind struct{}

func (envelopeKind) KindName() string { return "envelope" }

// GrantID and EnvelopeID are typed UUIDv7 identifiers.
type (
	GrantID    = ids.ID[grantKind]
	EnvelopeID = ids.ID[envelopeKind]
)

// NewGrantID returns a fresh grant id.
func NewGrantID() GrantID { return ids.New[grantKind]() }

// ParseGrantID parses a grant id.
func ParseGrantID(s string) (GrantID, error) { return ids.Parse[grantKind](s) }

// NewEnvelopeID returns a fresh envelope id.
func NewEnvelopeID() EnvelopeID { return ids.New[envelopeKind]() }

// ParseEnvelopeID parses an envelope id.
func ParseEnvelopeID(s string) (EnvelopeID, error) { return ids.Parse[envelopeKind](s) }

// ErrOutside reports a grant that would hold more authority than its
// parent, its guardrails or the delegation caps allow.
var ErrOutside = errors.New("grants: outside the allowed authority")

func outside(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrOutside}, args...)...)
}

// PrincipalKind is the kind of a represented principal or grantor.
type PrincipalKind string

// Principal kinds. A workload instance can be the grantor of a delegated
// grant only; it is never a represented principal.
const (
	PrincipalUser           PrincipalKind = "user"
	PrincipalServiceAccount PrincipalKind = "service_account"
	PrincipalInstance       PrincipalKind = "instance"
)

// Principal identifies a user, a service account or (as a grantor of a
// delegation) a workload instance.
type Principal struct {
	Kind PrincipalKind
	ID   ids.UUID
}

func (p Principal) String() string { return string(p.Kind) + ":" + p.ID.String() }

// State is a grant's state. Expiry is a time check at use time, not a state.
type State string

// Grant states.
const (
	StateActive  State = "ACTIVE"
	StateRevoked State = "REVOKED"
)

// Lifecycle is the grant state machine: revocation is final.
var Lifecycle = statemachine.New("grant", map[State][]State{StateActive: {StateRevoked}})

// Delegation says how a grant may be handed down (F045, HR-047).
type Delegation struct {
	// Depth is how many further levels may be created below this grant:
	// 0 means it cannot delegate. A child's Depth is below its parent's.
	Depth int
	// MaxChildren caps the active children of this grant (fan-out).
	MaxChildren int
}

// Requirement makes an approval or a step-up necessary for the operations
// it names (F043). When Param and Unless are set, the requirement applies
// unless that parameter fits the bound: {"param": "amount", "unless":
// {"max": {"USD": "50.00"}}} holds every refund over 50 USD, and any refund
// in another currency or without an amount. Requirements accumulate: every
// level's requirements apply to an action (HR-046).
type Requirement struct {
	Operations Ops                          `json:"operations"`
	Param      string                       `json:"param,omitzero"`
	Unless     *ParamBound                  `json:"unless,omitzero"`
	Approval   *pdomain.ApprovalRequirement `json:"approval,omitzero"`
	StepUp     *pdomain.StepUpRequirement   `json:"step_up,omitzero"`
	Reason     string                       `json:"reason"`
}

const maxRequirements = 32

func (r Requirement) validate(name string) error {
	if len(r.Operations) == 0 {
		return invalid("%s: name the operations it applies to", name)
	}
	if err := r.Operations.validate(name + ".operations"); err != nil {
		return err
	}
	if (r.Approval == nil) == (r.StepUp == nil) {
		return invalid("%s: set exactly one of approval, step_up", name)
	}
	// From M5 (G0 M5 part 2 decisions 2, 4 and 6): an approval names a
	// default role holding approval.respond, a step-up the launcher or the
	// principal by WebAuthn, and a deadline, if any, is 300..604800 seconds.
	// Requirements stored before M5 are read as they are; the decision
	// pipeline answers REQUIREMENT_INVALID for those.
	if a := r.Approval; a != nil && (!pdomain.ApprovalRole(a.Role) || a.Count < 1 || a.Count > 5 || !pdomain.ValidDeadline(a.DeadlineSeconds)) {
		return invalid("%s: an approval names a default role holding approval.respond (approver), 1..5 approvers and a deadline of 300..604800 seconds if any", name)
	}
	if s := r.StepUp; s != nil && ((s.Subject != "launcher" && s.Subject != "principal") || s.Method != "webauthn" || !pdomain.ValidDeadline(s.DeadlineSeconds)) {
		return invalid("%s: a step-up names the launcher or the principal, the method webauthn and a deadline of 300..604800 seconds if any", name)
	}
	if (r.Param == "") != (r.Unless == nil) {
		return invalid("%s: param and unless go together", name)
	}
	if r.Unless != nil {
		if err := r.Unless.validate(name + ".unless"); err != nil {
			return err
		}
	}
	if !reasonPattern.MatchString(r.Reason) {
		return invalid("%s: reason must be an UPPER_SNAKE code", name)
	}
	return nil
}

// Applies reports whether the requirement applies to the action. An absent
// or unreadable parameter cannot show it is exempt, so it applies.
func (r Requirement) Applies(a Action) bool {
	if !r.Operations.Matches(a.Operation) {
		return false
	}
	if r.Unless == nil {
		return true
	}
	return r.Unless.check("params."+r.Param, a.Params, r.Param).Outcome != Allowed
}

// Grant is one revision of a grant: bounded authority for one agent, acting
// for one principal, in one environment, for one task (F038–F044).
type Grant struct {
	ID       GrantID
	Org      ids.OrgID
	Revision int
	State    State
	// Subject: the agent (by id, never by name, HR-147) and optionally one
	// of its instances; the represented principal; the environment.
	AgentID       ids.UUID
	InstanceID    ids.UUID
	Principal     Principal
	EnvironmentID ids.UUID
	// TaskRef is an untrusted label (HR-023).
	TaskRef   string
	NotBefore time.Time
	ExpiresAt time.Time
	Bounds    Bounds
	// Requirements add approvals or step-ups (F043).
	Requirements []Requirement
	// Limits are the grant's task budgets and counters (F110, F111).
	Limits Limits
	// Flows are the data flows the grant allows after a sensitive read (G0
	// M16 D75); nil allows none.
	Flows      []FlowAllowance
	Delegation Delegation
	// MinAttestation is the lowest workload attestation level (0, 1, 2)
	// that may use the grant.
	MinAttestation int
	// Lineage: the parent (zero for a root grant) and the depth (0 for a
	// root grant).
	Parent GrantID
	Depth  int
	// Provenance (F039): who issued it, and on what basis: a permission at
	// a scope, or a parent grant's revision.
	Grantor Principal
	Basis   string
	// Ceiling and Execution name the automation ceiling and execution an
	// automation-issued grant was issued under (zero otherwise; G0 M11
	// part 2 D9). Neither ever changes.
	Ceiling   ids.UUID
	Execution ids.UUID
	// RevisedAt is when the current revision was stored (zero before it is).
	RevisedAt time.Time
}

// IsRoot reports whether the grant was issued by a person, not delegated.
func (g Grant) IsRoot() bool { return g.Parent.IsZero() }

// Usable reports whether the grant can be used at now: active and inside
// its validity window. It returns the reason code when it cannot.
func (g Grant) Usable(now time.Time) (string, bool) {
	switch {
	case g.State != StateActive:
		return ReasonGrantRevoked, false
	case now.Before(g.NotBefore):
		return ReasonGrantNotYetValid, false
	case !now.Before(g.ExpiresAt):
		return ReasonGrantExpired, false
	}
	return "", true
}

// Covers reports whether the grant is meant for this agent, instance,
// principal and environment (the run binding, HR-022).
func (g Grant) Covers(agent, instance ids.UUID, principal Principal, env ids.UUID) bool {
	return g.AgentID == agent && (g.InstanceID.IsZero() || g.InstanceID == instance) &&
		g.Principal == principal && g.EnvironmentID == env
}

const maxTaskRef = 256

// checkLabel accepts untrusted display text: bounded, and free of control,
// format and bidi characters (HR-102, HR-023).
func checkLabel(name, s string, maxLen int) error {
	if len(s) > maxLen {
		return invalid("%s: at most %d bytes", name, maxLen)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) || r == unicode.ReplacementChar {
			return invalid("%s contains a control, format or bidi character (HR-102)", name)
		}
	}
	return nil
}

// validate checks the grant on its own.
func (g Grant) validate(lookup func(op string) *defs.Definition) error {
	switch {
	case g.ID.IsZero() || g.Org.IsZero() || g.AgentID.IsZero() || g.EnvironmentID.IsZero() || g.Principal.ID.IsZero():
		return invalid("grant: id, org, agent, environment and principal are required")
	case g.Principal.Kind != PrincipalUser && g.Principal.Kind != PrincipalServiceAccount:
		return invalid("grant: the represented principal is a user or a service account")
	case g.Revision < 1:
		return invalid("grant: revisions start at 1")
	case !g.NotBefore.Before(g.ExpiresAt):
		return invalid("grant: not_before must be before expires_at")
	case g.Delegation.Depth < 0 || g.Delegation.MaxChildren < 0:
		return invalid("grant: delegation settings cannot be negative")
	case g.Delegation.Depth > 0 && g.Delegation.MaxChildren < 1:
		return invalid("grant: a grant that may delegate needs max_children of at least 1")
	case g.MinAttestation < 0 || g.MinAttestation > 2:
		return invalid("grant: min_attestation is 0, 1 or 2")
	case len(g.Requirements) > maxRequirements:
		return invalid("grant: at most %d requirements", maxRequirements)
	case g.Grantor.ID.IsZero() || g.Basis == "":
		return invalid("grant: grantor and basis are required (F039)")
	}
	if err := checkLabel("task_ref", g.TaskRef, maxTaskRef); err != nil {
		return err
	}
	if err := g.Bounds.Validate(); err != nil {
		return err
	}
	if err := g.Bounds.TypeCheck(lookup); err != nil {
		return err
	}
	for i, r := range g.Requirements {
		if err := r.validate(fmt.Sprintf("requirements[%d]", i)); err != nil {
			return err
		}
	}
	if err := validateFlows(g.Flows); err != nil {
		return err
	}
	if err := g.Limits.validate(true); err != nil {
		return err
	}
	return g.Limits.checkDispatched(lookup)
}
