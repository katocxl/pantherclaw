// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the governed-automation contracts every M11 stream
// codes against (G0 M11 part 2 D1–D4, D11): the definition document v1, the
// closed step catalogue and each kind's `with` schema, the state and reason
// vocabularies, the ports implemented by the engine, triggers, assurance
// and protect streams, and the Step interface.
//
// Import it as autodomain. It imports only the standard library, ids, money,
// pgx, the grants domain and the Reflex domain. Implementations are wired in
// internal/server; packages never import each other's adapters.
package domain

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// RefID is a UUID written as its canonical string in definitions and
// stored JSON (ids.UUID itself has no text form).
type RefID ids.UUID

// UUID returns the id as an ids.UUID.
func (r RefID) UUID() ids.UUID { return ids.UUID(r) }

// IsZero reports whether the id is unset.
func (r RefID) IsZero() bool { return ids.UUID(r).IsZero() }

// String is the canonical lowercase form.
func (r RefID) String() string { return ids.UUID(r).String() }

// MarshalText implements encoding.TextMarshaler.
func (r RefID) MarshalText() ([]byte, error) { return []byte(ids.UUID(r).String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler: a canonical UUID.
func (r *RefID) UnmarshalText(b []byte) error {
	u, err := ids.ParseUUID(string(b))
	if err != nil {
		return invalid("%q is not a UUID", string(b))
	}
	*r = RefID(u)
	return nil
}

// WorkKind says what an automation is for (D2).
type WorkKind string

// Work kinds.
const (
	WorkAgent    WorkKind = "AGENT_WORK"
	WorkSecurity WorkKind = "SECURITY_WORK"
)

// Valid reports whether k is a known work kind.
func (k WorkKind) Valid() bool { return k == WorkAgent || k == WorkSecurity }

// State is an automation's lifecycle state (D5).
type State string

// Automation states. RETIRED is final.
const (
	StateDraft   State = "DRAFT"
	StateActive  State = "ACTIVE"
	StatePaused  State = "PAUSED"
	StateRetired State = "RETIRED"
)

// Rollout is how far an enabled version reaches (D5, D7).
type Rollout string

// Rollout stages, narrowest first.
const (
	RolloutShadow Rollout = "SHADOW"
	RolloutCohort Rollout = "COHORT"
	RolloutFull   Rollout = "FULL"
)

// Valid reports whether r is a known rollout stage.
func (r Rollout) Valid() bool { return r == RolloutShadow || r == RolloutCohort || r == RolloutFull }

// Rank orders the stages: SHADOW < COHORT < FULL. Unknown stages rank 0.
func (r Rollout) Rank() int {
	return slices.Index([]Rollout{RolloutShadow, RolloutCohort, RolloutFull}, r) + 1
}

// VersionState is an automation version's state (D5).
type VersionState string

// Version states.
const (
	VersionDraft      VersionState = "DRAFT"
	VersionValidated  VersionState = "VALIDATED"
	VersionTested     VersionState = "TESTED"
	VersionPublished  VersionState = "PUBLISHED"
	VersionSuperseded VersionState = "SUPERSEDED"
	VersionRetired    VersionState = "RETIRED"
)

// CeilingState is an issuance ceiling's state (D5).
type CeilingState string

// Ceiling states. Only ACTIVE issues.
const (
	CeilingActive     CeilingState = "ACTIVE"
	CeilingSuperseded CeilingState = "SUPERSEDED"
	CeilingExpired    CeilingState = "EXPIRED"
	CeilingVoid       CeilingState = "VOID"
	CeilingRevoked    CeilingState = "REVOKED"
)

// PauseReason says why an automation is paused (D5).
type PauseReason string

// Pause reasons.
const (
	PauseUser                 PauseReason = "USER"
	PauseKillSwitch           PauseReason = "KILL_SWITCH"
	PauseCeilingVoid          PauseReason = "CEILING_VOID"
	PauseCeilingExpired       PauseReason = "CEILING_EXPIRED"
	PauseOwnerInactive        PauseReason = "OWNER_INACTIVE"
	PauseContained            PauseReason = "CONTAINED"
	PauseCompromisedPublisher PauseReason = "COMPROMISED_PUBLISHER"
	PauseAuthorityRevoked     PauseReason = "AUTHORITY_REVOKED"
	PauseCoverageRecovery     PauseReason = "COVERAGE_RECOVERY"
	PauseLoop                 PauseReason = "LOOP"
)

var pauseReasons = []PauseReason{
	PauseUser, PauseKillSwitch, PauseCeilingVoid, PauseCeilingExpired, PauseOwnerInactive, PauseContained,
	PauseCompromisedPublisher, PauseAuthorityRevoked, PauseCoverageRecovery, PauseLoop,
}

// Valid reports whether r is a known pause reason.
func (r PauseReason) Valid() bool { return slices.Contains(pauseReasons, r) }

// PauseReasons returns every pause reason in a stable order.
func PauseReasons() []PauseReason { return slices.Clone(pauseReasons) }

// TriggerKind is how an execution was asked for (D11).
type TriggerKind string

// Trigger kinds.
const (
	TriggerSchedule  TriggerKind = "SCHEDULE"
	TriggerEvent     TriggerKind = "EVENT"
	TriggerInbound   TriggerKind = "INBOUND"
	TriggerCondition TriggerKind = "CONDITION"
	TriggerThreshold TriggerKind = "THRESHOLD"
	TriggerManual    TriggerKind = "MANUAL"
)

// Authenticity is how a trigger's origin was established (D11, D16).
type Authenticity string

// Authenticity kinds.
const (
	AuthScheduler    Authenticity = "SCHEDULER"
	AuthPlatformFeed Authenticity = "PLATFORM_FEED"
	AuthSignedSource Authenticity = "SIGNED_SOURCE"
	AuthUserStepUp   Authenticity = "USER_STEP_UP"
	AuthUserSession  Authenticity = "USER_SESSION"
)

// Mode is whether an execution acts (D11, HR-288).
type Mode string

// Modes. SHADOW and TEST never write outside the execution's own rows.
const (
	ModeLive   Mode = "LIVE"
	ModeShadow Mode = "SHADOW"
	ModeTest   Mode = "TEST"
)

// ExecutionState is an execution's state (D24).
type ExecutionState string

// Execution states. Terminal states are final except NEEDS_RECONCILIATION,
// which resolves to a final one.
const (
	ExecPending             ExecutionState = "PENDING"
	ExecRunning             ExecutionState = "RUNNING"
	ExecWaiting             ExecutionState = "WAITING"
	ExecSucceeded           ExecutionState = "SUCCEEDED"
	ExecPartiallyCompleted  ExecutionState = "PARTIALLY_COMPLETED"
	ExecFailed              ExecutionState = "FAILED"
	ExecCancelled           ExecutionState = "CANCELLED"
	ExecNeedsReconciliation ExecutionState = "NEEDS_RECONCILIATION"
)

// Active reports whether the execution has not reached a terminal state.
func (s ExecutionState) Active() bool {
	return s == ExecPending || s == ExecRunning || s == ExecWaiting
}

// StepState is one step attempt's state (D11).
type StepState string

// Step states.
const (
	StepRunning      StepState = "RUNNING"
	StepWaiting      StepState = "WAITING"
	StepDone         StepState = "DONE"
	StepFailed       StepState = "FAILED"
	StepSkipped      StepState = "SKIPPED"
	StepUnknown      StepState = "UNKNOWN"
	StepShadowed     StepState = "SHADOWED"
	StepCompensation StepState = "COMPENSATION"
)

// Effect says what a step changed outside the execution (D11, HR-282).
type Effect string

// Effects.
const (
	EffectChanged   Effect = "CHANGED"
	EffectUnchanged Effect = "UNCHANGED"
	EffectUnknown   Effect = "UNKNOWN"
	EffectNone      Effect = "NONE"
)

// Execution and step reasons (D24), stable codes.
const (
	ReasonAuthorityChanged    = "AUTHORITY_CHANGED"
	ReasonCeilingVoid         = "CEILING_VOID"
	ReasonOwnerInactive       = "OWNER_INACTIVE"
	ReasonContained           = "CONTAINED"
	ReasonKillSwitch          = "KILL_SWITCH"
	ReasonDeadline            = "DEADLINE"
	ReasonStepFailed          = "STEP_FAILED"
	ReasonGateDeclined        = "GATE_DECLINED"
	ReasonGateExpired         = "GATE_EXPIRED"
	ReasonGateNoApprover      = "GATE_NO_APPROVER"
	ReasonLaunchNotClaimed    = "LAUNCH_NOT_CLAIMED"
	ReasonOutsideCohort       = "OUTSIDE_COHORT"
	ReasonCancelledByUser     = "CANCELLED_BY_USER"
	ReasonDestinationInactive = "DESTINATION_INACTIVE"
	ReasonToolQuarantined     = "TOOL_QUARANTINED"
	ReasonUsageExceeded       = "USAGE_EXCEEDED"
	ReasonNotPromoted         = "NOT_PROMOTED"
)

// FinishCondition is what a finish_when entry requires of its step (D3).
// Each is satisfied only by the step's DONE output carrying evidence refs;
// no "sent" or "requested" condition exists (F689, F721).
type FinishCondition string

// Finish conditions.
const (
	FinishEffectConfirmed      FinishCondition = "EFFECT_CONFIRMED"
	FinishRunEnded             FinishCondition = "RUN_ENDED"
	FinishApprovalResolved     FinishCondition = "APPROVAL_RESOLVED"
	FinishDeliveryConfirmed    FinishCondition = "DELIVERY_CONFIRMED"
	FinishCaseOpened           FinishCondition = "CASE_OPENED"
	FinishContainmentConfirmed FinishCondition = "CONTAINMENT_CONFIRMED"
	FinishCoverageRestored     FinishCondition = "COVERAGE_RESTORED"
	FinishGrantRevoked         FinishCondition = "GRANT_REVOKED"
	FinishAgentClaimed         FinishCondition = "AGENT_CLAIMED"
	FinishProposalRecorded     FinishCondition = "PROPOSAL_RECORDED"
	FinishSimulationDone       FinishCondition = "SIMULATION_DONE"
)

var finishConditions = []FinishCondition{
	FinishEffectConfirmed, FinishRunEnded, FinishApprovalResolved, FinishDeliveryConfirmed, FinishCaseOpened,
	FinishContainmentConfirmed, FinishCoverageRestored, FinishGrantRevoked, FinishAgentClaimed,
	FinishProposalRecorded, FinishSimulationDone,
}

// Valid reports whether c is in the finish vocabulary.
func (c FinishCondition) Valid() bool { return slices.Contains(finishConditions, c) }

// FinishConditions returns the finish vocabulary in a stable order.
func FinishConditions() []FinishCondition { return slices.Clone(finishConditions) }

// OnFailure is what a failed step does to its execution (D2, D27).
type OnFailure string

// Failure behaviours.
const (
	OnFailureStop     OnFailure = "STOP"
	OnFailureContinue OnFailure = "CONTINUE"
	OnFailureEscalate OnFailure = "ESCALATE"
)

// PausedTriggers is what happens to triggers of a paused automation (D23).
type PausedTriggers string

// Paused-trigger policies.
const (
	PausedDiscard PausedTriggers = "DISCARD"
	PausedQueue   PausedTriggers = "QUEUE"
	PausedExpire  PausedTriggers = "EXPIRE"
)

// Edition is the least edition a step kind needs (D3, D12).
type Edition string

// Editions a step kind can need.
const (
	EditionTeam     Edition = "TEAM"
	EditionBusiness Edition = "BUSINESS"
)
