// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package steps holds the engine's generic step kinds (G0 M11 part 2 D25):
// launch_run, wait_run, wait_effect, gate, revoke_grant, notify, deliver
// and wait. Each runs in the driver's transaction as the automation's
// service account and acts only through the dedicated …ForAutomationTx
// functions of the grants, runs and approvals use cases (D8): never an RPC
// handler and never a role check. In SHADOW and TEST modes the engine
// calls Preview, which writes nothing outside the execution's own rows
// (HR-288). The server never dispatches a tool call: a launch hands the
// work to an enrolled agent (F3, HR-279).
package steps

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// LaunchIssue is the grant a launch asks for (D9 AutomationIssue).
type LaunchIssue struct {
	Org            ids.OrgID
	Automation     ids.UUID
	Version        ids.UUID
	Execution      ids.UUID
	Ceiling        ids.UUID
	ServiceAccount ids.UUID
	Agent          ids.UUID
	Instance       *ids.UUID
	Principal      gdomain.Principal
	TaskRef        string
	TTL            time.Duration
	Bounds         gdomain.Bounds
	Requirements   []gdomain.Requirement
	Limits         gdomain.Limits
	DryRun         bool
}

// LaunchStart is the run a launch starts under its grant (D10
// AutomationStart).
type LaunchStart struct {
	Org            ids.OrgID
	Execution      ids.UUID
	ServiceAccount ids.UUID
	Agent          ids.UUID
	Instance       *ids.UUID
	Grant          ids.UUID
	Principal      gdomain.Principal
	TaskRef        string
	TTL            time.Duration
	DryRun         bool
}

// GrantRevoke asks for grants of an execution to be revoked (D9
// AutomationRevoke).
type GrantRevoke struct {
	Org       ids.OrgID
	Execution ids.UUID
	// Grant narrows EXECUTION to one grant of the execution, and names the
	// trigger's grant for TRIGGER_GRANT.
	Grant  *ids.UUID
	Scope  string
	Reason string
	// Revocable is the version's authority.revocable (D65, D84 E10): the
	// agents whose grants TRIGGER_GRANT and CEILING_AGENTS may revoke, or
	// every agent with RevocableAll. The issuer side enforces it.
	Revocable    []ids.UUID
	RevocableAll bool
}

// Grants issues and revokes grants for automations (grants/app, core-B).
type Grants interface {
	// IssueForAutomation returns the grant id; a refusal is an error whose
	// stable code (CEILING_VOID, OUTSIDE_CEILING, USAGE_EXCEEDED,
	// NOT_PROMOTED, CEILING_INACTIVE) becomes the step's reason. DryRun
	// writes nothing.
	IssueForAutomation(ctx context.Context, tx pgx.Tx, in LaunchIssue) (ids.UUID, error)
	RevokeForAutomation(ctx context.Context, tx pgx.Tx, in GrantRevoke) ([]ids.UUID, error)
}

// Runs starts and ends runs for automations (runs/app, core-B).
type Runs interface {
	StartForAutomation(ctx context.Context, tx pgx.Tx, in LaunchStart) (ids.UUID, error)
	EndForAutomation(ctx context.Context, tx pgx.Tx, org ids.OrgID, execution, run ids.UUID, reason string) error
}

// GateRequest asks people to approve one gate (D25, HR-281).
type GateRequest struct {
	Org        ids.OrgID
	Automation ids.UUID
	// AutomationName, ServiceAccount and Params (as text, shown as
	// untrusted) render the approval page.
	AutomationName string
	ServiceAccount ids.UUID
	Params         map[string]string
	Execution      ids.UUID
	StepID         string
	Attempt        int
	ParamsDigest   []byte
	Summary        string
	Roles          []string
	Users          []ids.UUID
	// Exclude are the people who never decide it (owner, confirmers,
	// principal, as the gate declares).
	Exclude      []ids.UUID
	MinApprovals int
	Deadline     time.Duration
	// Agent is the launch's agent when the gate concerns one, else nil
	// (D25a).
	Agent *ids.UUID
}

// GateState is a gate's approval request as the step sees it.
type GateState struct {
	State string // PENDING, EVIDENCE_REQUESTED, APPROVED, CONSUMED, DECLINED, EXPIRED, INVALIDATED, SUPERSEDED
	// Approvers who approved it.
	Approvers []ids.UUID
}

// Gates creates and reads automation gates (approvals/app, D25).
type Gates interface {
	// RequestGate returns the request id and how many people may decide
	// it now; zero eligible people refuses with no request.
	RequestGate(ctx context.Context, tx pgx.Tx, in GateRequest) (request ids.UUID, eligible int, err error)
	// EligibleGate counts the people who could decide such a gate now,
	// writing nothing (SHADOW preview).
	EligibleGate(ctx context.Context, tx pgx.Tx, in GateRequest) (int, error)
	GateStatus(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID) (GateState, error)
	// EndGate ends an open gate of a finished execution.
	EndGate(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID, reason string) error
	// ConsumeGate uses an APPROVED gate once (CONSUMED), closing its entry.
	ConsumeGate(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID) error
}

// Notice is an automation.notice to people (D25 notify).
type Notice struct {
	Org        ids.OrgID
	Automation ids.UUID
	Execution  ids.UUID
	StepID     string
	People     []ids.UUID
	Title      string
	Body       string
	Shadow     bool
}

// Notifier sends notices (notifications/app).
type Notifier interface {
	Notify(ctx context.Context, tx pgx.Tx, n Notice) (ids.UUID, error)
}

// Rollout reports an automation's rollout and its cohort's agents (D55).
type Rollout interface {
	Cohort(ctx context.Context, tx pgx.Tx, org ids.OrgID, automation ids.UUID) (autodomain.Rollout, []ids.UUID, error)
}

// Deps are the steps' ties to the platform. A nil dependency refuses the
// kinds that need it (FAILED UNSUPPORTED_CAPABILITY) rather than pretend.
type Deps struct {
	Grants    Grants
	Runs      Runs
	Gates     Gates
	Notifier  Notifier
	Deliverer autoports.Deliverer
	Rollout   Rollout
	// Recipients resolves notify's OWNER, CONFIRMERS, APPROVERS and
	// TRIGGER_OWNER.
	Recipients Recipients
}

// Recipients resolves the people a notice goes to.
type Recipients interface {
	Resolve(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, scope string) ([]ids.UUID, error)
}

// ErrUnwired reports a dependency that is not wired.
var ErrUnwired = errors.New("steps: dependency not wired")

// Generic returns the engine's step kinds.
func Generic(d Deps) autoports.StepRegistry {
	return autoports.StepRegistry{
		autodomain.KindLaunchRun:   &launchRun{d: d},
		autodomain.KindWaitRun:     &waitRun{},
		autodomain.KindWaitEffect:  &waitEffect{},
		autodomain.KindGate:        &gate{d: d},
		autodomain.KindRevokeGrant: &revokeGrant{d: d},
		autodomain.KindNotify:      &notify{d: d},
		autodomain.KindDeliver:     &deliver{d: d},
		autodomain.KindWait:        &wait{},
	}
}
