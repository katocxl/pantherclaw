// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/automationctx"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Ceiling-bounded issuance (G0 M11 part 2 D9, D54, D56, D57; founder
// decision F1; HR-271). Only the automation engine issues a root grant
// with a service-account grantor, and only inside the automation's ACTIVE,
// unexpired ceiling, for a COHORT or FULL rollout, in a LIVE execution, in
// the engine's transaction, with the same envelope, principal and
// promotion checks as a person's issuance, a lifetime of at most 24 hours
// and within the per-grant and per-day caps. RPC Issue stays human only.
// A failed or dry-run issuance writes nothing: its writes run in a
// savepoint that is rolled back.

// Errors of automation issuance and revocation.
var (
	ErrCeilingInactive = pcerr.New(pcerr.FailedPrecondition, "CEILING_INACTIVE",
		"the automation has no active, unexpired ceiling for a live rollout of this version")
	ErrCeilingVoid = pcerr.New(pcerr.FailedPrecondition, "CEILING_VOID",
		"a person who approved the automation's ceiling no longer may: the ceiling must be voided")
	ErrOutsideCeiling = pcerr.New(pcerr.FailedPrecondition, "OUTSIDE_CEILING",
		"the grant is outside the automation's ceiling")
	ErrUsageExceeded = pcerr.New(pcerr.ResourceExhausted, "USAGE_EXCEEDED",
		"the automation reached its daily grant, run or budget cap")
	ErrAutomationIdentity = pcerr.New(pcerr.FailedPrecondition, "AUTOMATION_IDENTITY",
		"only an automation's own execution identity acts for it")
	// ErrCeilingGrant refuses widening a grant issued under a ceiling (D56):
	// people may narrow or revoke it only.
	ErrCeilingGrant = pcerr.New(pcerr.FailedPrecondition, "CEILING_GRANT",
		"a grant an automation issued can only be narrowed or revoked")
)

// Revocation scopes of RevokeForAutomationTx.
const (
	RevokeScopeExecution     = "EXECUTION"
	RevokeScopeTriggerGrant  = "TRIGGER_GRANT"
	RevokeScopeCeilingAgents = "CEILING_AGENTS"
	// RevokeScopeAutomation is every grant under any of the automation's
	// authority rows, whatever their state (RevokeAuthority, D91 K2).
	RevokeScopeAutomation = "AUTOMATION"
	RevokeScopeCeiling    = "CEILING"
	// RevokeScopeGrant is one grant of the given execution (Grant), for a
	// failed launch's withdraw (D102).
	RevokeScopeGrant = "GRANT"
)

// TxStore is the repository's in-transaction side, for issuance and
// revocation inside another use case's transaction (pgstore.Store).
type TxStore interface {
	ReadTx(ctx context.Context, org ids.OrgID, fn func(ctx context.Context, tx db.TenantTx) error) error
	AgentInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (Agent, error)
	EnvelopesInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, scopes []domain.Scope) ([]domain.Envelope, error)
	PrincipalActiveInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, p domain.Principal) (bool, error)
	GrantInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id domain.GrantID) (domain.Grant, bool, error)
	IssueInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, g domain.Grant, ev audit.Event) error
	RevokeInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id domain.GrantID, ev audit.Event) ([]domain.GrantID, error)
	// AutomationGrantsInTx lists active grants by revocation scope:
	// EXECUTION (in.Execution), CEILING (in.Ceiling), CEILING_AGENTS (the
	// agents' root grants) or AUTOMATION (in.Automation's ceilings).
	AutomationGrantsInTx(ctx context.Context, tx db.TenantTx, in AutomationRevoke, agents []ids.UUID) ([]ids.UUID, error)
}

// AutomationCeiling is what issuance needs of an automation's ACTIVE
// ceiling and enabled version.
type AutomationCeiling struct {
	ID             ids.UUID
	AutomationName string
	ServiceAccount ids.UUID
	Agents         []ids.UUID
	// Principal is the version's declared principal (the automation's
	// identity or a consenting confirmer).
	Principal      domain.Principal
	Bounds         domain.Bounds
	Requirements   []domain.Requirement
	TTL            time.Duration
	Limits         domain.Limits
	MinAttestation int
	Delegation     domain.Delegation
	Approvers      []ids.UUID
}

// Ceilings checks and counts against automation ceilings (the automations
// app implements it).
type Ceilings interface {
	// IssueCeiling checks, in tx and by the database clock, that the
	// ceiling is ACTIVE and before its review date, that the version is
	// the automation's enabled version with a COHORT or FULL rollout, and
	// that every approver still qualifies (CeilingChecker); a preview of a
	// SHADOW or TEST execution skips the enabled-version and rollout rules
	// (D84). It returns ErrCeilingInactive or ErrCeilingVoid otherwise, and
	// writes nothing.
	IssueCeiling(ctx context.Context, tx db.TenantTx, in AutomationIssue) (AutomationCeiling, error)
	// Reserve counts one grant and its per-currency budget against today's
	// caps (ErrUsageExceeded); dryRun only checks.
	Reserve(ctx context.Context, tx db.TenantTx, in AutomationIssue, budgets map[string]money.Decimal, dryRun bool) error
}

// AutomationIssue asks for a grant under an automation's ceiling.
type AutomationIssue struct {
	Org            ids.OrgID
	Automation     ids.UUID
	Version        ids.UUID
	Execution      ids.UUID
	Trigger        ids.UUID
	Ceiling        ids.UUID
	ServiceAccount ids.UUID
	AgentID        ids.UUID
	InstanceID     *ids.UUID
	Principal      domain.Principal
	TaskRef        string
	TTL            time.Duration
	Bounds         domain.Bounds
	Requirements   []domain.Requirement
	Limits         domain.Limits
	// Live is false for SHADOW and TEST executions, which never issue;
	// their DryRun previews still run every check (D84), against the
	// automation's ACTIVE authority row (SHADOW) or, with a zero Ceiling,
	// the version's declared ceiling (TEST of a version never enabled).
	Live bool
	// DryRun runs every check without writing (shadow, previews).
	DryRun bool
}

// IssueForAutomationTx issues a grant under an automation's ceiling in the
// engine's transaction (D9 steps 1–9). It never writes when it fails or
// when in.DryRun is set; on CEILING_VOID the caller voids the ceiling in
// its own transaction (automations app VoidCeiling, D57).
func (s *Service) IssueForAutomationTx(ctx context.Context, tx db.TenantTx, in AutomationIssue) (domain.Grant, error) {
	if s.Store == nil || s.Ceilings == nil {
		return domain.Grant{}, ErrCeilingInactive
	}
	if in.Org != tx.OrgID() || in.ServiceAccount.IsZero() {
		return domain.Grant{}, ErrAutomationIdentity
	}
	if !in.Live && !in.DryRun {
		return domain.Grant{}, ErrCeilingInactive // shadow and test executions never issue (HR-288)
	}
	// (1, 2) ceiling, review date, enabled version, rollout, approvers.
	c, err := s.Ceilings.IssueCeiling(ctx, tx, in)
	if err != nil {
		return domain.Grant{}, err
	}
	if c.ServiceAccount != in.ServiceAccount || c.ID != in.Ceiling {
		return domain.Grant{}, ErrAutomationIdentity
	}
	// (3) the agent is a ceiling agent and can receive authority.
	if !slices.Contains(c.Agents, in.AgentID) {
		return domain.Grant{}, pcerr.Wrap(ErrOutsideCeiling, pcerr.FailedPrecondition, "OUTSIDE_CEILING", "the agent is not one of the ceiling's agents")
	}
	agent, err := s.Store.AgentInTx(ctx, tx, in.Org, in.AgentID)
	if errors.Is(err, ErrNotFound) {
		return domain.Grant{}, ErrAgentNotFound
	} else if err != nil {
		return domain.Grant{}, err
	}
	if !slices.Contains(grantableAgentStates, agent.State) {
		return domain.Grant{}, ErrAgentNotEligible
	}
	// (4) the principal is the version's, and active.
	if in.Principal != c.Principal {
		return domain.Grant{}, pcerr.Wrap(ErrOutsideCeiling, pcerr.FailedPrecondition, "OUTSIDE_CEILING", "the principal is not the version's")
	}
	if ok, err := s.Store.PrincipalActiveInTx(ctx, tx, in.Org, in.Principal); err != nil {
		return domain.Grant{}, err
	} else if !ok {
		return domain.Grant{}, ErrPrincipalUnknown
	}
	// (5) build: lifetime ≤ min(TTL, per-grant TTL, 24h); the ceiling's
	// requirements and per-grant limits always apply; the launch's limits
	// may only narrow the per-grant ones (D84 E7).
	limits, err := domain.NarrowLimits(c.Limits, in.Limits)
	if err != nil {
		return domain.Grant{}, pcerr.Wrap(err, pcerr.FailedPrecondition, "OUTSIDE_CEILING", detail(err, domain.ErrOutside))
	}
	now := s.Clock.Now()
	ttl := min(c.TTL, domain.MaxAutomationLifetime)
	if in.TTL > 0 {
		ttl = min(ttl, in.TTL)
	}
	g := domain.Grant{
		ID: domain.NewGrantID(), Org: in.Org, Revision: 1, State: domain.StateActive,
		AgentID: agent.ID, Principal: in.Principal, EnvironmentID: agent.EnvironmentID, TaskRef: in.TaskRef,
		NotBefore: now.Add(-domain.IssueSkew), ExpiresAt: now.Add(ttl), Bounds: in.Bounds,
		Requirements: append(slices.Clone(c.Requirements), in.Requirements...),
		Limits:       limits,
		Delegation:   c.Delegation, MinAttestation: c.MinAttestation,
		Grantor: domain.Principal{Kind: domain.PrincipalServiceAccount, ID: in.ServiceAccount},
		Basis:   fmt.Sprintf("automation %s ceiling %s", c.AutomationName, c.ID),
		Ceiling: c.ID, Execution: in.Execution,
	}
	if in.InstanceID != nil {
		g.InstanceID = *in.InstanceID
	}
	if g.Bounds.Operations == nil {
		g.Bounds.Operations = c.Bounds.Operations // a grant always lists its operations (D39)
	}
	// (6) every envelope, and the ceiling as one more.
	envs, err := s.Store.EnvelopesInTx(ctx, tx, in.Org, scopesFor(agent, g.EnvironmentID, g.Principal))
	if err != nil {
		return domain.Grant{}, err
	}
	envs = append(envs, domain.Envelope{
		Scope: domain.Scope{Kind: domain.ScopeOrg}, Name: "automation " + c.AutomationName + " ceiling",
		Bounds: c.Bounds, MinAttestation: c.MinAttestation,
	})
	lookup, err := s.lookup(ctx, in.Org, g.Bounds, g.Limits)
	if err != nil {
		return domain.Grant{}, err
	}
	// Every budget-consuming operation needs a per-grant budget covering
	// it (D84 E7); a prefix may cover one, so it needs a budget too.
	if g.Bounds.Operations != nil {
		for _, op := range *g.Bounds.Operations {
			spends := strings.HasSuffix(op, "*")
			if !spends {
				d, err := s.Defs.Active(ctx, in.Org, op)
				if err != nil {
					return domain.Grant{}, err
				}
				spends = d != nil && consumesBudget(d)
			}
			if spends && !g.Limits.CoversBudget(op) {
				return domain.Grant{}, pcerr.Wrap(ErrOutsideCeiling, pcerr.FailedPrecondition, "OUTSIDE_CEILING",
					"operation "+op+" spends money: the grant needs a per-grant budget covering it")
			}
		}
	}
	// A TEST preview of a version never enabled has no authority row; its
	// version stands for the ceiling in a check that writes nothing.
	under := c.ID
	if under.IsZero() && in.DryRun && !in.Live {
		under = in.Version
	}
	if err := g.ValidateIssue(domain.IssueContext{Now: now, Envelopes: envs, Lookup: lookup, Ceiling: under}); err != nil {
		if errors.Is(err, domain.ErrOutside) {
			return domain.Grant{}, pcerr.Wrap(err, pcerr.FailedPrecondition, "OUTSIDE_CEILING", detail(err, domain.ErrOutside))
		}
		return domain.Grant{}, apiError(err)
	}
	// (7) the promotion gate for production environments (D39).
	if s.Promotion != nil {
		var ops domain.Ops
		if g.Bounds.Operations != nil {
			ops = *g.Bounds.Operations
		}
		if err := s.Promotion.Check(ctx, tx.Pgx(), in.Org, agent.ID, agent.EnvironmentID, ops); err != nil {
			return domain.Grant{}, err
		}
	}
	budgets, err := taskBudgets(g.Limits)
	if err != nil {
		return domain.Grant{}, apiError(err)
	}
	if in.DryRun {
		// (8) checked only; nothing is written.
		if err := s.Ceilings.Reserve(ctx, tx, in, budgets, true); err != nil {
			return domain.Grant{}, err
		}
		return g, nil
	}
	// (8, 9) the caps and the grant, in a savepoint: a refusal writes nothing.
	actor := evdomain.Actor{Type: string(domain.PrincipalServiceAccount), ID: in.ServiceAccount.String()}
	ref := automationctx.Ref{Automation: in.Automation, Version: in.Version, Execution: in.Execution, Trigger: in.Trigger}
	ctx = automationctx.With(ctx, ref)
	approvers := make([]string, 0, len(c.Approvers))
	for _, a := range c.Approvers {
		approvers = append(approvers, a.String())
	}
	ev := grantEvent(actor, "grant.issued", g, map[string]string{
		"agent": g.AgentID.String(), "principal": g.Principal.String(), "expires_at": g.ExpiresAt.UTC().Format(time.RFC3339),
		"ceiling": c.ID.String(), "approvers": strings.Join(approvers, ","),
	})
	err = tx.Savepoint(ctx, "automation_issue", func() error {
		if err := s.Ceilings.Reserve(ctx, tx, in, budgets, false); err != nil {
			return err
		}
		return s.Store.IssueInTx(ctx, tx, in.Org, g, ev)
	})
	if err != nil {
		return domain.Grant{}, apiError(err)
	}
	g.RevisedAt = now
	return g, nil
}

// consumesBudget reports whether an operation takes a money parameter.
func consumesBudget(d *defs.Definition) bool {
	for _, p := range d.Params {
		if p.Type == defs.TypeMoney {
			return true
		}
	}
	return false
}

// taskBudgets sums the grant's task budget limits per currency: the most
// the grant can spend, reserved against the per-day budget.
func taskBudgets(l domain.Limits) (map[string]money.Decimal, error) {
	out := map[string]money.Decimal{}
	for _, b := range l.Budgets {
		if b.Limit == "" || b.Currency == "" {
			continue
		}
		d, err := money.Parse(b.Limit)
		if err != nil {
			return nil, fmt.Errorf("%w: budget %s: %w", domain.ErrInvalid, b.ID, err)
		}
		if out[b.Currency], err = out[b.Currency].Add(d); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// errNotRevocable refuses a revocation outside authority.revocable (D65).
var errNotRevocable = pcerr.Wrap(ErrOutsideCeiling, pcerr.FailedPrecondition, "OUTSIDE_CEILING",
	"the grant's agent is not one the version may revoke (authority.revocable)")

// AutomationRevoke revokes grants for an automation's execution.
type AutomationRevoke struct {
	Org            ids.OrgID
	Automation     ids.UUID
	Execution      ids.UUID
	Trigger        ids.UUID
	Ceiling        ids.UUID
	ServiceAccount ids.UUID
	// Agents are the ceiling's agents (CEILING_AGENTS).
	Agents []ids.UUID
	// Revocable is the version's authority.revocable (D65, D84 E10): the
	// agents whose grants TRIGGER_GRANT and CEILING_AGENTS may revoke, or
	// every agent of the org with RevocableAll. Neither set refuses both
	// scopes.
	Revocable    []ids.UUID
	RevocableAll bool
	// Grant is the trigger's grant (TRIGGER_GRANT), or the execution's grant (GRANT).
	Grant  ids.UUID
	Scope  string
	Reason string
}

// RevokeForAutomationTx revokes, in the caller's transaction, the grants
// of the scope and every grant delegated from them (D9): the execution's
// own grants (EXECUTION), the trigger's grant when it is one of a
// revocable agent's (TRIGGER_GRANT), the root grants of the ceiling agents
// that are revocable (CEILING_AGENTS), one grant that belongs to the execution
// (GRANT), every grant under one ceiling
// (CEILING: a void or expired authority row) or under any of the
// automation's ceilings (AUTOMATION, for RevokeAuthority). It returns the
// revoked ids.
func (s *Service) RevokeForAutomationTx(ctx context.Context, tx db.TenantTx, in AutomationRevoke) ([]domain.GrantID, error) {
	if s.Store == nil {
		return nil, ErrGrantNotFound
	}
	if in.Org != tx.OrgID() || in.ServiceAccount.IsZero() {
		return nil, ErrAutomationIdentity
	}
	if err := checkReason(in.Reason); err != nil {
		return nil, err
	}
	var targets []ids.UUID
	var err error
	switch in.Scope {
	case RevokeScopeExecution:
		if in.Execution.IsZero() {
			return nil, ErrGrantNotFound
		}
		targets, err = s.Store.AutomationGrantsInTx(ctx, tx, in, nil)
	case RevokeScopeCeiling:
		if in.Ceiling.IsZero() {
			return nil, ErrGrantNotFound
		}
		targets, err = s.Store.AutomationGrantsInTx(ctx, tx, in, nil)
	case RevokeScopeAutomation:
		if in.Automation.IsZero() {
			return nil, ErrGrantNotFound
		}
		targets, err = s.Store.AutomationGrantsInTx(ctx, tx, in, nil)
	case RevokeScopeCeilingAgents:
		agents := in.Agents
		if !in.RevocableAll {
			agents = slices.DeleteFunc(slices.Clone(in.Agents), func(a ids.UUID) bool { return !slices.Contains(in.Revocable, a) })
		}
		if len(agents) == 0 {
			return nil, errNotRevocable
		}
		targets, err = s.Store.AutomationGrantsInTx(ctx, tx, in, agents)
	case RevokeScopeGrant:
		gid, perr := domain.ParseGrantID(in.Grant.String())
		if perr != nil || in.Execution.IsZero() {
			return nil, ErrGrantNotFound
		}
		g, found, gerr := s.Store.GrantInTx(ctx, tx, in.Org, gid)
		switch {
		case gerr != nil:
			return nil, gerr
		case !found || g.Execution != in.Execution:
			return nil, ErrGrantNotFound
		case g.State != domain.StateActive:
			return nil, nil
		}
		targets = []ids.UUID{g.ID.UUID()}
	case RevokeScopeTriggerGrant:
		gid, perr := domain.ParseGrantID(in.Grant.String())
		if perr != nil {
			return nil, ErrGrantNotFound
		}
		g, found, gerr := s.Store.GrantInTx(ctx, tx, in.Org, gid)
		switch {
		case gerr != nil:
			return nil, gerr
		case !found:
			return nil, ErrGrantNotFound
		case !in.RevocableAll && !slices.Contains(in.Revocable, g.AgentID):
			return nil, errNotRevocable
		case g.State != domain.StateActive:
			return nil, nil
		}
		targets = []ids.UUID{g.ID.UUID()}
	default:
		return nil, pcerr.New(pcerr.InvalidArgument, "INVALID_SCOPE", "unknown revocation scope")
	}
	if err != nil {
		return nil, err
	}
	ctx = automationctx.With(ctx, automationctx.Ref{Automation: in.Automation, Execution: in.Execution, Trigger: in.Trigger})
	actor := evdomain.Actor{Type: string(domain.PrincipalServiceAccount), ID: in.ServiceAccount.String()}
	var out []domain.GrantID
	for _, id := range targets {
		gid, err := domain.ParseGrantID(id.String())
		if err != nil {
			return nil, err
		}
		if slices.Contains(out, gid) {
			continue // revoked with an ancestor already
		}
		g, found, err := s.Store.GrantInTx(ctx, tx, in.Org, gid)
		if err != nil {
			return nil, err
		}
		if !found || g.State != domain.StateActive {
			continue
		}
		ev := grantEvent(actor, "grant.revoked", g, map[string]string{"reason": in.Reason, "scope": in.Scope})
		revoked, err := s.Store.RevokeInTx(ctx, tx, in.Org, gid, ev)
		if err != nil {
			return nil, apiError(err)
		}
		out = append(out, revoked...)
	}
	return out, nil
}
