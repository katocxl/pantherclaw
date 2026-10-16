// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
)

// Each step kind's `with` schema (D3, D25, D31). Limits that are not
// expressible as types (lengths, ranges, membership in the ceiling) are
// checked by Validate and again by the step's runtime.

// LaunchRunWith launches one run of a ceiling agent under a fresh grant
// (D25).
type LaunchRunWith struct {
	Agent       RefID             `json:"agent"`
	Instance    *RefID            `json:"instance,omitzero"`
	TaskRef     string            `json:"task_ref,omitzero"` // ≤ 256, templatable
	TTL         Duration          `json:"ttl,omitzero"`      // ≤ per_grant.ttl
	Grant       LaunchGrant       `json:"grant,omitzero"`
	RunParams   map[string]string `json:"run_params,omitzero"` // ≤ 16, templatable
	Delivery    string            `json:"delivery,omitzero"`   // PULL (default) | WEBHOOK
	Destination *RefID            `json:"destination,omitzero"`
	ClaimWithin Duration          `json:"claim_within,omitzero"` // ≤ 1h, default 15m
	Calls       []RunnerCall      `json:"calls,omitzero"`        // ≤ 10
}

// Launch deliveries.
const (
	DeliveryPull    = "PULL"
	DeliveryWebhook = "WEBHOOK"
)

// LaunchGrant narrows the ceiling for one launch. Operations must sit
// inside the ceiling; target, account and parameter values may be
// templated, and a rendered value must still fit the ceiling (HR-276).
type LaunchGrant struct {
	Operations   *gdomain.Ops                             `json:"operations,omitzero"`
	Targets      *map[string]gdomain.Match                `json:"targets,omitzero"`
	Accounts     *gdomain.Match                           `json:"accounts,omitzero"`
	Destinations *gdomain.Match                           `json:"destinations,omitzero"`
	Params       map[string]map[string]gdomain.ParamBound `json:"params,omitzero"`
	Limits       *gdomain.Limits                          `json:"limits,omitzero"`
}

// RunnerCall is one tool call the runner agent makes through the gateway
// (D33). It is part of the reviewed version.
type RunnerCall struct {
	Connection RefID             `json:"connection"`
	Face       string            `json:"face"` // MCP | HTTP
	Tool       string            `json:"tool,omitzero"`
	Method     string            `json:"method,omitzero"`
	Path       string            `json:"path,omitzero"`
	Input      map[string]string `json:"input,omitzero"` // templatable
}

// Runner call faces.
const (
	FaceMCP  = "MCP"
	FaceHTTP = "HTTP"
)

// WaitRunWith waits for a launch_run step's run to end.
type WaitRunWith struct {
	Step string `json:"step"`
}

// WaitEffectWith waits for confirmed effects of one ceiling operation in a
// launch_run step's run (F500).
type WaitEffectWith struct {
	Step      string   `json:"step"`
	Operation string   `json:"operation"`
	States    []string `json:"states,omitzero"` // default [CONFIRMED]
	Min       int      `json:"min,omitzero"`    // 1..100; absent (0) means 1
}

// Effects is how many confirmed effects the step waits for: absent or 0
// means 1 (D102 C2).
func (x WaitEffectWith) Effects() int { return max(x.Min, 1) }

// GateWith asks people for an approval bound to this execution, step and
// parameters (HR-281).
type GateWith struct {
	Approvers    GateApprovers `json:"approvers"`
	Exclude      []string      `json:"exclude,omitzero"`       // OWNER | CONFIRMERS | PRINCIPAL; default [OWNER]
	MinApprovals int           `json:"min_approvals,omitzero"` // 1..2; absent (0) means 1
	Deadline     Duration      `json:"deadline"`               // ≤ 72h
	Summary      string        `json:"summary,omitzero"`       // templatable
}

// GateApprovers names who may decide a gate.
type GateApprovers struct {
	Roles []string `json:"roles,omitzero"`
	Users []RefID  `json:"users,omitzero"`
}

// Approvals is how many approvals the gate needs: absent or 0 means 1
// (D102 C2).
func (x GateWith) Approvals() int { return max(x.MinApprovals, 1) }

// Gate exclusions.
const (
	ExcludeOwner      = "OWNER"
	ExcludeConfirmers = "CONFIRMERS"
	ExcludePrincipal  = "PRINCIPAL"
)

// RevokeGrantWith revokes grants within the declared scope.
type RevokeGrantWith struct {
	Scope  string `json:"scope"`           // EXECUTION | TRIGGER_GRANT | CEILING_AGENTS
	Reason string `json:"reason,omitzero"` // templatable
}

// Revocation scopes (D9; CEILING is for RevokeAuthority only).
const (
	RevokeExecution     = "EXECUTION"
	RevokeTriggerGrant  = "TRIGGER_GRANT"
	RevokeCeilingAgents = "CEILING_AGENTS"
	RevokeCeiling       = "CEILING"
)

// NotifyWith sends a notice to people or a destination.
type NotifyWith struct {
	To          []string      `json:"to,omitzero"` // OWNER | CONFIRMERS | APPROVERS | TRIGGER_OWNER
	Destination *RefID        `json:"destination,omitzero"`
	Message     NotifyMessage `json:"message"`
}

// NotifyMessage is a notice's text (templatable).
type NotifyMessage struct {
	Title string `json:"title"`         // ≤ 120
	Body  string `json:"body,omitzero"` // ≤ 1000
}

// DeliverWith delivers a build_digest step's report to a destination.
type DeliverWith struct {
	Destination RefID  `json:"destination"`
	From        string `json:"from"`
}

// WaitWith waits a fixed time (≤ 24h).
type WaitWith struct {
	Duration Duration `json:"duration"`
}

// ContainWith contains the trigger's run or grant (Business, HR-284).
type ContainWith struct {
	Action  string `json:"action"`          // SUSPEND_RUN | REVOKE_GRANT
	Subject string `json:"subject"`         // TRIGGER_RUN | TRIGGER_GRANT
	Reason  string `json:"reason,omitzero"` // templatable
}

// Containment actions and subjects.
const (
	ContainSuspendRun   = "SUSPEND_RUN"
	ContainRevokeGrant  = "REVOKE_GRANT"
	SubjectTriggerRun   = "TRIGGER_RUN"
	SubjectTriggerGrant = "TRIGGER_GRANT"
)

// OpenCaseWith opens a case with the trigger's subjects and evidence.
type OpenCaseWith struct {
	Title     string   `json:"title"`              // templatable
	Questions []string `json:"questions,omitzero"` // ≤ 10, templatable
}

// PauseLaunchesWith pauses automations whose launches are affected.
type PauseLaunchesWith struct {
	Selector    string  `json:"selector"` // AFFECTED | LIST
	Automations []RefID `json:"automations,omitzero"`
}

// Pause selectors.
const (
	SelectAffected = "AFFECTED"
	SelectList     = "LIST"
)

// ResumeLaunchesWith resumes exactly what a pause_launches step paused.
type ResumeLaunchesWith struct {
	Step string `json:"step"`
}

// WaitCoverageWith waits until the trigger's route is covered again.
type WaitCoverageWith struct {
	MinState string   `json:"min_state"` // ENFORCED | PARTIAL
	Timeout  Duration `json:"timeout"`   // ≤ 7d
}

// AssignOwnerWith records an owned failure for a person to act on.
type AssignOwnerWith struct {
	To       string   `json:"to"`                 // AGENT_OWNER | CONNECTION_OWNER | OWNER
	Summary  string   `json:"summary,omitzero"`   // templatable
	NextStep string   `json:"next_step,omitzero"` // templatable
	Deadline Duration `json:"deadline,omitzero"`  // ≤ 7d
}

// ApprovalRequestWith names the trigger's approval request
// (remind_approvers, escalate_approval, wait_resolution).
type ApprovalRequestWith struct {
	Request string `json:"request"` // TRIGGER_REQUEST
}

// IntakeWith is the empty schema of propose_owner, inspect_routes and
// run_safe_tests.
type IntakeWith struct{}

// DraftBaselineWith drafts a grant baseline proposal (never issued).
type DraftBaselineWith struct {
	From string `json:"from"` // COHORT_BASELINE | TEMPLATE
}

// WaitClaimWith waits until the trigger's agent is claimed with an owner.
type WaitClaimWith struct {
	Timeout Duration `json:"timeout"` // ≤ 30d
}

// DraftRestrictionWith drafts a policy restriction from unused grants.
type DraftRestrictionWith struct {
	From string `json:"from"` // UNUSED_GRANTS
	Days int    `json:"days"` // ≥ 7
}

// SimulateRestrictionWith simulates a draft_restriction step's draft.
type SimulateRestrictionWith struct {
	Step string `json:"step"`
	Days int    `json:"days,omitzero"` // ≤ 30
}

// BuildDigestWith builds a report and evidence pack as the automation's
// identity (D85).
type BuildDigestWith struct {
	Scope string `json:"scope"`         // TIME_RANGE | TRIGGER_CASE
	Days  int    `json:"days,omitzero"` // ≤ 31 for TIME_RANGE
	// Evidence is whose evidence the pack may hold: listed agents or the
	// whole org. Confirmers hold evidence.read and evidence.export there.
	Evidence DigestEvidence `json:"evidence"`
	Sections []string       `json:"sections"`       // ⊆ decisions, effects, holds, alerts, open_items
	Title    string         `json:"title,omitzero"` // templatable
}

// DigestEvidence is a build_digest step's evidence scope: {agents: [ids]}
// or {all: true}, exactly one (D85).
type DigestEvidence = AgentScope
