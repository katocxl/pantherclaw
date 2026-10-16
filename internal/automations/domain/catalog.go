// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
	"sort"
)

// Step kinds (D3). The catalog is closed: a kind not listed here never
// runs (HR-279).
const (
	KindLaunchRun           = "launch_run"
	KindWaitRun             = "wait_run"
	KindWaitEffect          = "wait_effect"
	KindGate                = "gate"
	KindRevokeGrant         = "revoke_grant"
	KindNotify              = "notify"
	KindDeliver             = "deliver"
	KindWait                = "wait"
	KindContain             = "contain"
	KindOpenCase            = "open_case"
	KindPauseLaunches       = "pause_launches"
	KindResumeLaunches      = "resume_launches"
	KindWaitCoverage        = "wait_coverage"
	KindAssignOwner         = "assign_owner"
	KindRemindApprovers     = "remind_approvers"
	KindEscalateApproval    = "escalate_approval"
	KindWaitResolution      = "wait_resolution"
	KindProposeOwner        = "propose_owner"
	KindInspectRoutes       = "inspect_routes"
	KindDraftBaseline       = "draft_baseline"
	KindRunSafeTests        = "run_safe_tests"
	KindWaitClaim           = "wait_claim"
	KindDraftRestriction    = "draft_restriction"
	KindSimulateRestriction = "simulate_restriction"
	KindBuildDigest         = "build_digest"
)

// Stream owning a kind's runtime (D1).
const (
	OwnerEngine    = "engine"
	OwnerTemplates = "templates"
)

// ConfirmAt is where an enabling confirmer must hold a kind's confirmer
// permissions (D7): on the path of every ceiling agent, or at the org.
type ConfirmAt string

// Confirmer scopes.
const (
	ConfirmNone          ConfirmAt = ""
	ConfirmCeilingAgents ConfirmAt = "CEILING_AGENTS"
	ConfirmOrg           ConfirmAt = "ORG"
	// ConfirmEvidence: at the paths of a build_digest step's evidence
	// agents, or at the org for all (D85).
	ConfirmEvidence ConfirmAt = "EVIDENCE"
)

// Platform scope options (D3 column "scope"). Destination ids are also
// valid scopes of notify and deliver.
const (
	ScopeExecution       = "EXECUTION"
	ScopeTriggerGrant    = "TRIGGER_GRANT"
	ScopeCeilingAgents   = "CEILING_AGENTS"
	ScopeOwner           = "OWNER"
	ScopeConfirmers      = "CONFIRMERS"
	ScopeApprovers       = "APPROVERS"
	ScopeTriggerOwner    = "TRIGGER_OWNER"
	ScopeTriggerRun      = "TRIGGER_RUN"
	ScopeTriggerSubjects = "TRIGGER_SUBJECTS"
	ScopeAffected        = "AFFECTED"
	ScopeList            = "LIST"
	ScopeTriggerScope    = "TRIGGER_SCOPE"
	ScopeAgentOwner      = "AGENT_OWNER"
	ScopeConnectionOwner = "CONNECTION_OWNER"
	ScopeTriggerRequest  = "TRIGGER_REQUEST"
	ScopeTriggerAgent    = "TRIGGER_AGENT"
	ScopeOrg             = "ORG"
	ScopeTimeRange       = "TIME_RANGE"
	ScopeTriggerCase     = "TRIGGER_CASE"
)

// KindSpec describes one catalog kind (D3).
type KindSpec struct {
	Kind    string
	Owner   string
	Edition Edition
	// Effectful kinds change something outside the execution; in SHADOW
	// and TEST modes they return SHADOWED (HR-288). Narrowing kinds only
	// remove authority; ProposalOnly kinds only record drafts or
	// proposals (HR-286).
	Effectful    bool
	Narrowing    bool
	ProposalOnly bool
	// Wait kinds park the execution until their condition or timeout.
	Wait bool
	// RetrySafe kinds may declare retry; launch_run is retry-safe only
	// until its run binds (RetryUntilBind).
	RetrySafe      bool
	RetryUntilBind bool
	// ConfirmerPermissions are the tenancy permission names every enabling
	// confirmer must hold at ConfirmAt (D7, HR-272).
	ConfirmerPermissions []string
	ConfirmAt            ConfirmAt
	// ConfirmRevocable: a use that revokes beyond the execution's own
	// grants (revoke_grant TRIGGER_GRANT or CEILING_AGENTS, contain
	// REVOKE_GRANT) needs grant.revoke at authority.revocable instead: each
	// listed agent's path, or the org for all (D65).
	ConfirmRevocable bool
	// DeciderPermission is what a gate's deciders need.
	DeciderPermission string
	// Templatable are the `with` fields that may hold {{params.x}} or
	// {{steps.id.output.k}}, as JSON Pointers where "*" is any member or
	// index (HR-276).
	Templatable []string
	// Scopes are the scope options of the kind's `platform` entry; empty
	// for kinds bounded by the ceiling or needing no scope.
	Scopes []string
	// DestinationScope: destination ids are valid scopes too, for these
	// purposes.
	DestinationPurposes []string
	// Finishes are the finish conditions a DONE step of this kind can
	// satisfy.
	Finishes []FinishCondition
	newWith  func() any
}

// NewWith returns a pointer to a zero `with` of this kind.
func (k KindSpec) NewWith() any { return k.newWith() }

// DecodeWith decodes raw strictly into the kind's `with` (an empty value
// is the zero `with`) and returns a pointer to it.
func (k KindSpec) DecodeWith(raw jsontext.Value) (any, error) {
	w := k.newWith()
	if len(raw) == 0 {
		raw = jsontext.Value("{}")
	}
	if err := json.Unmarshal(raw, w, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalid("%s.with: %v", k.Kind, err)
	}
	return w, nil
}

// Permission names (tenancy domain) the catalog refers to.
const (
	permGrantIssue      = "grant.issue"
	permGrantRevoke     = "grant.revoke"
	permRunStart        = "run.start"
	permEvidenceExport  = "evidence.export"
	permIncidentRespond = "incident.respond"
	permCaseManage      = "case.manage"
	permAutomationPub   = "automation.publish"
	permEvidenceRead    = "evidence.read"
	permAutomationAppr  = "automation.approve"
	permCoverageRead    = "coverage.read"
	permAgentRead       = "agent.read"
	permPolicyAuthor    = "policy.author"
	permPolicySimulate  = "policy.simulate"
)

func newOf[T any]() func() any { return func() any { return new(T) } }

// Catalog is the closed step catalog, the single source of D3.
var Catalog = map[string]KindSpec{
	KindLaunchRun: {
		Kind: KindLaunchRun, Owner: OwnerEngine, Edition: EditionTeam, Effectful: true, RetrySafe: true, RetryUntilBind: true,
		ConfirmerPermissions: []string{permGrantIssue, permRunStart}, ConfirmAt: ConfirmCeilingAgents,
		Templatable: []string{
			"/task_ref", "/run_params/*", "/grant/targets/*/ids/*", "/grant/accounts/ids/*",
			"/grant/params/*/*/values/ids/*", "/calls/*/input/*",
		},
		newWith: newOf[LaunchRunWith](),
	},
	KindWaitRun: {
		Kind: KindWaitRun, Owner: OwnerEngine, Edition: EditionTeam, Wait: true,
		Finishes: []FinishCondition{FinishRunEnded}, newWith: newOf[WaitRunWith](),
	},
	KindWaitEffect: {
		Kind: KindWaitEffect, Owner: OwnerEngine, Edition: EditionTeam, Wait: true,
		Finishes: []FinishCondition{FinishEffectConfirmed}, newWith: newOf[WaitEffectWith](),
	},
	KindGate: {
		Kind: KindGate, Owner: OwnerEngine, Edition: EditionTeam, Wait: true, DeciderPermission: permAutomationAppr,
		Templatable: []string{"/summary"}, newWith: newOf[GateWith](),
	},
	KindRevokeGrant: {
		Kind: KindRevokeGrant, Owner: OwnerEngine, Edition: EditionTeam, Effectful: true, Narrowing: true, RetrySafe: true,
		ConfirmerPermissions: []string{permGrantRevoke}, ConfirmAt: ConfirmCeilingAgents, ConfirmRevocable: true,
		Templatable: []string{"/reason"}, Scopes: []string{ScopeExecution, ScopeTriggerGrant, ScopeCeilingAgents},
		Finishes: []FinishCondition{FinishGrantRevoked}, newWith: newOf[RevokeGrantWith](),
	},
	KindNotify: {
		Kind: KindNotify, Owner: OwnerEngine, Edition: EditionTeam, Effectful: true, RetrySafe: true,
		Templatable:         []string{"/message/title", "/message/body"},
		Scopes:              []string{ScopeOwner, ScopeConfirmers, ScopeApprovers, ScopeTriggerOwner},
		DestinationPurposes: []string{"NOTICE"}, newWith: newOf[NotifyWith](),
	},
	KindDeliver: {
		Kind: KindDeliver, Owner: OwnerEngine, Edition: EditionTeam, Effectful: true, RetrySafe: true,
		ConfirmerPermissions: []string{permEvidenceExport}, ConfirmAt: ConfirmOrg,
		DestinationPurposes: []string{"DIGEST", "NOTICE"},
		Finishes:            []FinishCondition{FinishDeliveryConfirmed}, newWith: newOf[DeliverWith](),
	},
	KindWait: {
		Kind: KindWait, Owner: OwnerEngine, Edition: EditionTeam, Wait: true, newWith: newOf[WaitWith](),
	},
	KindContain: {
		Kind: KindContain, Owner: OwnerTemplates, Edition: EditionBusiness, Effectful: true, RetrySafe: true,
		ConfirmerPermissions: []string{permIncidentRespond}, ConfirmAt: ConfirmOrg, ConfirmRevocable: true,
		Templatable: []string{"/reason"}, Scopes: []string{ScopeTriggerRun, ScopeTriggerGrant},
		Finishes: []FinishCondition{FinishContainmentConfirmed}, newWith: newOf[ContainWith](),
	},
	KindOpenCase: {
		Kind: KindOpenCase, Owner: OwnerTemplates, Edition: EditionTeam, Effectful: true, RetrySafe: true,
		ConfirmerPermissions: []string{permCaseManage}, ConfirmAt: ConfirmOrg,
		Templatable: []string{"/title", "/questions/*"}, Scopes: []string{ScopeTriggerSubjects},
		Finishes: []FinishCondition{FinishCaseOpened}, newWith: newOf[OpenCaseWith](),
	},
	KindPauseLaunches: {
		Kind: KindPauseLaunches, Owner: OwnerTemplates, Edition: EditionTeam, Effectful: true, RetrySafe: true,
		ConfirmerPermissions: []string{permAutomationPub}, ConfirmAt: ConfirmOrg,
		Scopes: []string{ScopeAffected, ScopeList}, newWith: newOf[PauseLaunchesWith](),
	},
	KindResumeLaunches: {
		Kind: KindResumeLaunches, Owner: OwnerTemplates, Edition: EditionTeam, Effectful: true, RetrySafe: true,
		ConfirmerPermissions: []string{permAutomationPub}, ConfirmAt: ConfirmOrg,
		Scopes: []string{ScopeAffected, ScopeList}, newWith: newOf[ResumeLaunchesWith](),
	},
	KindWaitCoverage: {
		Kind: KindWaitCoverage, Owner: OwnerTemplates, Edition: EditionTeam, Wait: true,
		ConfirmerPermissions: []string{permCoverageRead}, ConfirmAt: ConfirmOrg,
		Scopes:   []string{ScopeTriggerScope},
		Finishes: []FinishCondition{FinishCoverageRestored}, newWith: newOf[WaitCoverageWith](),
	},
	KindAssignOwner: {
		Kind: KindAssignOwner, Owner: OwnerTemplates, Edition: EditionTeam, Effectful: true, RetrySafe: true,
		Templatable: []string{"/summary", "/next_step"},
		Scopes:      []string{ScopeAgentOwner, ScopeConnectionOwner, ScopeOwner}, newWith: newOf[AssignOwnerWith](),
	},
	KindRemindApprovers: {
		Kind: KindRemindApprovers, Owner: OwnerTemplates, Edition: EditionTeam, Effectful: true, RetrySafe: true,
		Scopes: []string{ScopeTriggerRequest}, newWith: newOf[ApprovalRequestWith](),
	},
	KindEscalateApproval: {
		Kind: KindEscalateApproval, Owner: OwnerTemplates, Edition: EditionTeam, Effectful: true, RetrySafe: true,
		Scopes: []string{ScopeTriggerRequest}, newWith: newOf[ApprovalRequestWith](),
	},
	KindWaitResolution: {
		Kind: KindWaitResolution, Owner: OwnerTemplates, Edition: EditionTeam, Wait: true, RetrySafe: true,
		Scopes:   []string{ScopeTriggerRequest},
		Finishes: []FinishCondition{FinishApprovalResolved}, newWith: newOf[ApprovalRequestWith](),
	},
	KindProposeOwner:  intake(KindProposeOwner, false, []FinishCondition{FinishProposalRecorded}, newOf[IntakeWith]()),
	KindInspectRoutes: intake(KindInspectRoutes, false, nil, newOf[IntakeWith]()),
	KindDraftBaseline: intake(KindDraftBaseline, false, []FinishCondition{FinishProposalRecorded}, newOf[DraftBaselineWith]()),
	KindRunSafeTests:  intake(KindRunSafeTests, false, []FinishCondition{FinishProposalRecorded}, newOf[IntakeWith]()),
	KindWaitClaim:     intake(KindWaitClaim, true, []FinishCondition{FinishAgentClaimed}, newOf[WaitClaimWith]()),
	KindDraftRestriction: {
		Kind: KindDraftRestriction, Owner: OwnerTemplates, Edition: EditionTeam, ProposalOnly: true, RetrySafe: true,
		ConfirmerPermissions: []string{permPolicyAuthor, permPolicySimulate}, ConfirmAt: ConfirmOrg,
		Scopes:   []string{ScopeOrg},
		Finishes: []FinishCondition{FinishProposalRecorded}, newWith: newOf[DraftRestrictionWith](),
	},
	KindSimulateRestriction: {
		Kind: KindSimulateRestriction, Owner: OwnerTemplates, Edition: EditionTeam, ProposalOnly: true, Wait: true, RetrySafe: true,
		ConfirmerPermissions: []string{permPolicyAuthor, permPolicySimulate}, ConfirmAt: ConfirmOrg,
		Scopes:   []string{ScopeOrg},
		Finishes: []FinishCondition{FinishSimulationDone}, newWith: newOf[SimulateRestrictionWith](),
	},
	KindBuildDigest: {
		Kind: KindBuildDigest, Owner: OwnerTemplates, Edition: EditionTeam, Effectful: true, RetrySafe: true,
		ConfirmerPermissions: []string{permEvidenceRead, permEvidenceExport}, ConfirmAt: ConfirmEvidence,
		Templatable: []string{"/title"}, Scopes: []string{ScopeTimeRange, ScopeTriggerCase}, newWith: newOf[BuildDigestWith](),
	},
}

// intake is an agent-intake kind (D31): proposals only, on the trigger's
// agent, confirmers hold agent.read and coverage read.
func intake(kind string, wait bool, finishes []FinishCondition, nw func() any) KindSpec {
	return KindSpec{
		Kind: kind, Owner: OwnerTemplates, Edition: EditionTeam, ProposalOnly: !wait, Wait: wait, RetrySafe: true,
		ConfirmerPermissions: []string{permAgentRead, permCoverageRead}, ConfirmAt: ConfirmOrg,
		Scopes: []string{ScopeTriggerAgent}, Finishes: finishes, newWith: nw,
	}
}

// Kinds returns every catalog kind, sorted.
func Kinds() []string {
	out := make([]string, 0, len(Catalog))
	for k := range Catalog {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Satisfies reports whether a DONE step of kind can satisfy c.
func (k KindSpec) Satisfies(c FinishCondition) bool { return slices.Contains(k.Finishes, c) }

// NeedsPlatformScope reports whether the kind must be listed in the
// version's `platform` section: every kind not bounded by the ceiling.
func (k KindSpec) NeedsPlatformScope() bool {
	switch k.Kind {
	case KindLaunchRun, KindWaitRun, KindWaitEffect, KindGate, KindWait:
		return false
	}
	return true
}
