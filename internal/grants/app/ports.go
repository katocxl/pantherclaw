// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the grant and guardrail use cases: people issue,
// revise and revoke grants and change guardrails; a workload delegates part
// of its run's grant to a child run (BUILD_GUIDE §8 M4, G0 M4 part 2).
// Persistence, agents and runs (M3), definitions and permission checks are
// behind ports. Every write is conditional on what was read and is audited
// in the same transaction.
package app

import (
	"context"
	"errors"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions of the grant and guardrail use cases (the tenancy catalog's).
const (
	PermGrantRead        = tdomain.PermGrantRead
	PermGrantIssue       = tdomain.PermGrantIssue // human only (decision 7)
	PermGrantRevoke      = tdomain.PermGrantRevoke
	PermGuardrailsRead   = tdomain.PermGuardrailsRead
	PermGuardrailsManage = tdomain.PermGuardrailsManage // human only
)

// Repository errors.
var (
	// ErrNotFound reports a grant, envelope, agent or run that does not
	// exist in the org (another org's ids are not found either).
	ErrNotFound = errors.New("grants: not found")
	// ErrConflict reports that what was read changed before the write (a
	// lost race on a conditional update, HR-004). The caller may retry.
	ErrConflict = errors.New("grants: concurrent change")
)

// Agent is what the use cases need to know about an agent (M3).
type Agent struct {
	ID    ids.UUID
	State string
	// Path is the agent's place in the tenancy hierarchy: org, business
	// unit, team. Permissions are checked there.
	Path           tdomain.Path
	BusinessUnitID ids.UUID
	TeamID         ids.UUID
	EnvironmentID  ids.UUID
}

// Agent states that may receive authority (F020): not discovered,
// suspended or retired.
var grantableAgentStates = []string{"CLAIMED", "VERIFIED", "OBSERVED", "PARTIALLY_PROTECTED", "PROTECTED"}

// Run is what the use cases need to know about a run (M3).
type Run struct {
	ID            ids.UUID
	AgentID       ids.UUID
	InstanceID    ids.UUID
	Principal     domain.Principal
	EnvironmentID ids.UUID
	ParentRunID   ids.UUID
	GrantID       domain.GrantID
	Active        bool
	ExpiresAt     time.Time
}

// Subjects reads agents, runs and principals (implemented over the M3 and
// M2 tables).
type Subjects interface {
	Agent(ctx context.Context, org ids.OrgID, id ids.UUID) (Agent, error)
	Run(ctx context.Context, org ids.OrgID, id ids.UUID) (Run, error)
	// PrincipalActive reports whether the user or service account exists
	// in the org and is active.
	PrincipalActive(ctx context.Context, org ids.OrgID, p domain.Principal) (bool, error)
	// ScopePath returns the tenancy path where guardrail permissions for
	// an envelope scope are checked.
	ScopePath(ctx context.Context, org ids.OrgID, s domain.Scope) (tdomain.Path, error)
}

// Definitions returns an org's active definition of an operation, or nil
// when there is none.
type Definitions interface {
	Active(ctx context.Context, org ids.OrgID, op string) (*defs.Definition, error)
}

// Authorizer checks a caller's permission at a path. The production
// implementation is the caller's tenancy subject (Subject.Require).
type Authorizer interface {
	Require(c tapp.Caller, p tdomain.Permission, path tdomain.Path) error
}

// SubjectAuthorizer checks permissions with the caller's role bindings.
type SubjectAuthorizer struct{}

// Require implements Authorizer.
func (SubjectAuthorizer) Require(c tapp.Caller, p tdomain.Permission, path tdomain.Path) error {
	return c.Require(p, path)
}

// Fanout bounds a parent's children; the repository enforces it while the
// parent's row is locked.
type Fanout struct {
	MaxActive int
	MaxTotal  int
}

// Repository stores grants and envelopes. Writes run in one tenant
// transaction each, which records the audit event. Every write that removes
// authority (revision, revocation, envelope change) takes the org
// containment row FOR UPDATE first and increments the epoch; Delegate takes
// it FOR SHARE first and reads the parent after it (G0 M4 part 2, design
// decision 8).
type Repository interface {
	Grant(ctx context.Context, org ids.OrgID, id domain.GrantID) (domain.Grant, error)
	// Chain returns the grant and its ancestors, root first.
	Chain(ctx context.Context, org ids.OrgID, id domain.GrantID) ([]domain.Grant, error)
	// Envelopes returns the current revisions of the envelopes at the
	// given scopes; scopes without an envelope are skipped.
	Envelopes(ctx context.Context, org ids.OrgID, scopes []domain.Scope) ([]domain.Envelope, error)
	// ChildCounts counts a grant's children: those still active and
	// unexpired at now, and all ever created.
	ChildCounts(ctx context.Context, org ids.OrgID, id domain.GrantID, now time.Time) (active, total int, err error)

	Issue(ctx context.Context, org ids.OrgID, g domain.Grant, ev audit.Event) error
	// Delegate inserts child and binds it to childRun, conditional on the
	// parent's revision being parentRevision and still active, the fan-out
	// limits, and the child run having no grant yet.
	Delegate(ctx context.Context, org ids.OrgID, child domain.Grant, parentRevision int, childRun ids.UUID, f Fanout, ev audit.Event) error
	// Revise stores next, conditional on the current revision being
	// next.Revision-1; widens is recorded on the revision. A non-zero
	// accessRequest is closed as answered, or ErrAccessRequestNotOpen.
	Revise(ctx context.Context, org ids.OrgID, next domain.Grant, widens bool, accessRequest ids.UUID, ev audit.Event) error
	// Revoke revokes the grant and every descendant in one transaction and
	// returns the ids it revoked.
	Revoke(ctx context.Context, org ids.OrgID, id domain.GrantID, ev audit.Event) ([]domain.GrantID, error)
	// PutEnvelope stores e, conditional on the scope's current revision
	// being e.Revision-1 (0: no envelope yet); widens is recorded on the
	// revision.
	PutEnvelope(ctx context.Context, org ids.OrgID, e domain.Envelope, widens bool, ev audit.Event) error
}

// scopesFor returns the envelope scopes that apply to an agent's grant.
func scopesFor(a Agent, env ids.UUID, p domain.Principal) []domain.Scope {
	return []domain.Scope{
		{Kind: domain.ScopeOrg},
		{Kind: domain.ScopeBusinessUnit, ID: a.BusinessUnitID},
		{Kind: domain.ScopeTeam, ID: a.TeamID},
		{Kind: domain.ScopeEnvironment, ID: env},
		{Kind: domain.ScopePrincipal, Principal: p},
	}
}
