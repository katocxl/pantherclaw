// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// API errors.
var (
	ErrGrantNotFound    = pcerr.New(pcerr.NotFound, "GRANT_NOT_FOUND", "grant not found")
	ErrAgentNotFound    = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrRunNotFound      = pcerr.New(pcerr.NotFound, "RUN_NOT_FOUND", "run not found")
	ErrEnvelopeNotFound = pcerr.New(pcerr.NotFound, "GUARDRAIL_NOT_FOUND", "guardrail not found")
	ErrHumanOnly        = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrAgentNotEligible = pcerr.New(pcerr.FailedPrecondition, "AGENT_NOT_ELIGIBLE", "the agent cannot receive authority in its current state")
	ErrPrincipalUnknown = pcerr.New(pcerr.FailedPrecondition, "PRINCIPAL_UNKNOWN", "the represented principal is not an active user or service account of the org")
	ErrRevisionChanged  = pcerr.New(pcerr.Aborted, "REVISION_CHANGED", "the grant or guardrail changed; read it again")
	ErrRunNotEligible   = pcerr.New(pcerr.FailedPrecondition, "RUN_NOT_ELIGIBLE", "the run cannot delegate to that child run")
	// ErrAccessRequestNotOpen refuses a revision citing an entry that is
	// not an open access request for the grant (G0 M5 part 2).
	ErrAccessRequestNotOpen = pcerr.New(pcerr.FailedPrecondition, "ACCESS_REQUEST_NOT_OPEN",
		"the access request is not an open request for this grant")
)

// apiError maps domain and repository errors to API errors. Messages from
// the domain describe the request, never stored data of another org.
func apiError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrInvalid):
		return pcerr.Wrap(err, pcerr.InvalidArgument, "GRANT_INVALID", detail(err, domain.ErrInvalid))
	case errors.Is(err, domain.ErrOutside):
		return pcerr.Wrap(err, pcerr.FailedPrecondition, "OUTSIDE_ALLOWED_AUTHORITY", detail(err, domain.ErrOutside))
	case errors.Is(err, ErrConflict):
		return ErrRevisionChanged
	}
	return err
}

// Service runs the grant and guardrail use cases.
type Service struct {
	Repo     Repository
	Subjects Subjects
	Defs     Definitions
	Authz    Authorizer
	Clock    clock.Clock
	// Listing serves the API's list and state reads (optional elsewhere).
	Listing Listing
}

// IssueRequest asks for a new root grant.
type IssueRequest struct {
	AgentID        ids.UUID
	InstanceID     ids.UUID // optional: one instance only
	Principal      domain.Principal
	TaskRef        string
	NotBefore      time.Time // zero: now
	ExpiresAt      time.Time
	Bounds         domain.Bounds
	Requirements   []domain.Requirement
	Limits         domain.Limits
	Delegation     domain.Delegation
	MinAttestation int
}

// Issue issues a root grant. Only a person holding grant.issue on the
// agent's team may (HR-161, decision 7).
func (s *Service) Issue(ctx context.Context, req IssueRequest) (domain.Grant, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return domain.Grant{}, err
	}
	if !c.Human() {
		return domain.Grant{}, ErrHumanOnly
	}
	agent, err := s.grantableAgent(ctx, c, req.AgentID, PermGrantIssue)
	if err != nil {
		return domain.Grant{}, err
	}
	ok, err := s.Subjects.PrincipalActive(ctx, c.Org, req.Principal)
	if err != nil {
		return domain.Grant{}, err
	}
	if !ok {
		return domain.Grant{}, ErrPrincipalUnknown
	}
	now := s.Clock.Now()
	g := domain.Grant{
		ID: domain.NewGrantID(), Org: c.Org, Revision: 1, State: domain.StateActive,
		AgentID: agent.ID, InstanceID: req.InstanceID, Principal: req.Principal, EnvironmentID: agent.EnvironmentID,
		TaskRef: req.TaskRef, NotBefore: req.NotBefore, ExpiresAt: req.ExpiresAt,
		Bounds: req.Bounds, Requirements: req.Requirements, Limits: req.Limits, Delegation: req.Delegation, MinAttestation: req.MinAttestation,
		Grantor: domain.Principal{Kind: domain.PrincipalUser, ID: c.Principal.ID},
		Basis:   fmt.Sprintf("%s on team %s", PermGrantIssue, agent.TeamID),
	}
	if g.NotBefore.IsZero() {
		g.NotBefore = now.Add(-domain.IssueSkew)
	}
	envs, err := s.Repo.Envelopes(ctx, c.Org, scopesFor(agent, g.EnvironmentID, g.Principal))
	if err != nil {
		return domain.Grant{}, err
	}
	lookup, err := s.lookup(ctx, c.Org, g.Bounds)
	if err != nil {
		return domain.Grant{}, err
	}
	if err := g.ValidateIssue(domain.IssueContext{Now: now, Envelopes: envs, Lookup: lookup}); err != nil {
		return domain.Grant{}, apiError(err)
	}
	ev := grantEvent(c.Actor(), "grant.issued", g, map[string]string{
		"agent": g.AgentID.String(), "principal": g.Principal.String(), "expires_at": g.ExpiresAt.UTC().Format(time.RFC3339),
	})
	if err := s.Repo.Issue(ctx, c.Org, g, ev); err != nil {
		return domain.Grant{}, apiError(err)
	}
	g.RevisedAt = now
	return g, nil
}

// ReviseRequest replaces the changeable fields of a grant.
type ReviseRequest struct {
	ID       domain.GrantID
	Revision int // the revision the change is based on
	TaskRef  string
	// ExpiresAt zero keeps the current expiry.
	ExpiresAt      time.Time
	Bounds         domain.Bounds
	Requirements   []domain.Requirement
	Limits         domain.Limits
	Delegation     domain.Delegation
	MinAttestation int
	// AccessRequest, when set, is the open access request of this grant
	// the revision answers: it is closed in the same transaction (HR-176).
	AccessRequest ids.UUID
}

// Revise stores a new revision of a grant. Only a person holding
// grant.issue on the agent's team may. Narrowing takes effect at once
// (the repository increments the containment epoch); widening is checked
// like an issuance and audited as such. A revision citing an access
// request closes it, or fails when it is not open for this grant.
func (s *Service) Revise(ctx context.Context, req ReviseRequest) (domain.Grant, domain.Revision, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return domain.Grant{}, domain.Revision{}, err
	}
	if !c.Human() {
		return domain.Grant{}, domain.Revision{}, ErrHumanOnly
	}
	cur, err := s.grant(ctx, c.Org, req.ID)
	if err != nil {
		return domain.Grant{}, domain.Revision{}, err
	}
	agent, err := s.grantableAgent(ctx, c, cur.AgentID, PermGrantIssue)
	if err != nil {
		return domain.Grant{}, domain.Revision{}, err
	}
	if cur.Revision != req.Revision {
		return domain.Grant{}, domain.Revision{}, ErrRevisionChanged
	}
	next := cur
	next.Revision++
	next.TaskRef, next.Bounds, next.Requirements, next.Limits = req.TaskRef, req.Bounds, req.Requirements, req.Limits
	next.Delegation, next.MinAttestation = req.Delegation, req.MinAttestation
	if !req.ExpiresAt.IsZero() {
		next.ExpiresAt = req.ExpiresAt
	}
	rev, err := domain.CompareRevision(cur, next)
	if err != nil {
		return domain.Grant{}, domain.Revision{}, apiError(err)
	}
	ic := domain.IssueContext{Now: s.Clock.Now()}
	if ic.Envelopes, err = s.Repo.Envelopes(ctx, c.Org, scopesFor(agent, next.EnvironmentID, next.Principal)); err != nil {
		return domain.Grant{}, domain.Revision{}, err
	}
	if ic.Lookup, err = s.lookup(ctx, c.Org, next.Bounds); err != nil {
		return domain.Grant{}, domain.Revision{}, err
	}
	if !next.IsRoot() {
		parent, err := s.grant(ctx, c.Org, next.Parent)
		if err != nil {
			return domain.Grant{}, domain.Revision{}, err
		}
		ic.Parent = &parent // a revision adds no child, so the counts stay 0
	}
	if err := next.ValidateIssue(ic); err != nil {
		return domain.Grant{}, domain.Revision{}, apiError(err)
	}
	ev := grantEvent(c.Actor(), "grant.revised", next, map[string]string{
		"revision": strconv.Itoa(next.Revision), "widens": strconv.FormatBool(rev.Widens), "change": rev.Detail,
	})
	if !req.AccessRequest.IsZero() {
		ev.Details["access_request"] = req.AccessRequest.String()
	}
	if err := s.Repo.Revise(ctx, c.Org, next, rev.Widens, req.AccessRequest, ev); err != nil {
		return domain.Grant{}, domain.Revision{}, apiError(err)
	}
	next.RevisedAt = ic.Now
	return next, rev, nil
}

// Revoke revokes a grant and every grant delegated from it, in one
// transaction (HR-047). The issuing person, or a person or service account
// holding grant.revoke on the agent's team, may.
func (s *Service) Revoke(ctx context.Context, id domain.GrantID, reason string) ([]domain.GrantID, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkReason(reason); err != nil {
		return nil, err
	}
	g, err := s.grant(ctx, c.Org, id)
	if err != nil {
		return nil, err
	}
	agent, err := s.agent(ctx, c.Org, g.AgentID)
	if err != nil {
		return nil, err
	}
	issuer := g.IsRoot() && g.Grantor.Kind == domain.PrincipalUser && c.Human() && g.Grantor.ID == c.Principal.ID
	if !issuer {
		if err := s.Authz.Require(c, PermGrantRevoke, agent.Path); err != nil {
			return nil, err
		}
	}
	ev := grantEvent(c.Actor(), "grant.revoked", g, map[string]string{"reason": reason})
	revoked, err := s.Repo.Revoke(ctx, c.Org, id, ev)
	return revoked, apiError(err)
}

// View is a grant with its lineage and what the run can use now.
type View struct {
	Grant domain.Grant
	// Lineage is the grant's chain, root first (F062, F063).
	Lineage   []domain.Grant
	Envelopes []domain.Envelope
	// Effective is the intersection of every level (F046).
	Effective domain.Bounds
	Caps      domain.Caps
}

// Get returns a grant with its lineage and effective authority.
func (s *Service) Get(ctx context.Context, id domain.GrantID) (View, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return View{}, err
	}
	chain, err := s.Repo.Chain(ctx, c.Org, id)
	if errors.Is(err, ErrNotFound) || (err == nil && len(chain) == 0) {
		return View{}, ErrGrantNotFound
	}
	if err != nil {
		return View{}, err
	}
	leaf := chain[len(chain)-1]
	agent, err := s.agent(ctx, c.Org, leaf.AgentID)
	if err != nil {
		return View{}, err
	}
	if err := s.Authz.Require(c, PermGrantRead, agent.Path); err != nil {
		return View{}, err
	}
	envs, err := s.Repo.Envelopes(ctx, c.Org, scopesFor(agent, leaf.EnvironmentID, leaf.Principal))
	if err != nil {
		return View{}, err
	}
	ch := domain.Chain{Envelopes: envs, Grants: chain}
	return View{Grant: leaf, Lineage: chain, Envelopes: envs, Effective: ch.Effective(), Caps: domain.EffectiveCaps(envs)}, nil
}

// RunBinding is the run a grant is about to be bound to at StartRun.
type RunBinding struct {
	AgentID       ids.UUID
	InstanceID    ids.UUID
	Principal     domain.Principal
	EnvironmentID ids.UUID
}

// CheckRunGrant checks that a root grant may be bound to a new run (HR-022,
// PN-002.5) and returns its expiry, which caps the run's. A delegated grant
// reaches a run only through Delegate.
func (s *Service) CheckRunGrant(ctx context.Context, org ids.OrgID, id domain.GrantID, run RunBinding) (time.Time, error) {
	g, err := s.grant(ctx, org, id)
	if err != nil {
		return time.Time{}, err
	}
	if !g.IsRoot() {
		return time.Time{}, pcerr.New(pcerr.FailedPrecondition, domain.ReasonGrantMismatch, "a delegated grant is bound to its child run by delegation")
	}
	if code, ok := g.Usable(s.Clock.Now()); !ok {
		return time.Time{}, pcerr.New(pcerr.FailedPrecondition, code, "the grant cannot be used now")
	}
	if !g.Covers(run.AgentID, run.InstanceID, run.Principal, run.EnvironmentID) {
		return time.Time{}, pcerr.New(pcerr.FailedPrecondition, domain.ReasonGrantMismatch, "the grant is for another agent, instance, principal or environment")
	}
	return g.ExpiresAt, nil
}

func (s *Service) grant(ctx context.Context, org ids.OrgID, id domain.GrantID) (domain.Grant, error) {
	g, err := s.Repo.Grant(ctx, org, id)
	if errors.Is(err, ErrNotFound) {
		return domain.Grant{}, ErrGrantNotFound
	}
	return g, err
}

func (s *Service) agent(ctx context.Context, org ids.OrgID, id ids.UUID) (Agent, error) {
	a, err := s.Subjects.Agent(ctx, org, id)
	if errors.Is(err, ErrNotFound) {
		return Agent{}, ErrAgentNotFound
	}
	return a, err
}

// grantableAgent loads the agent, checks the caller's permission on its
// team, then its state. The permission is checked before the state so the
// state of an agent the caller cannot see is not revealed.
func (s *Service) grantableAgent(ctx context.Context, c tapp.Caller, id ids.UUID, p tdomain.Permission) (Agent, error) {
	a, err := s.agent(ctx, c.Org, id)
	if err != nil {
		return Agent{}, err
	}
	if err := s.Authz.Require(c, p, a.Path); err != nil {
		return Agent{}, err
	}
	if !slices.Contains(grantableAgentStates, a.State) {
		return Agent{}, ErrAgentNotEligible
	}
	return a, nil
}

// lookup preloads the active definitions of the operations whose
// parameters the bounds limit.
func (s *Service) lookup(ctx context.Context, org ids.OrgID, b domain.Bounds) (func(string) *defs.Definition, error) {
	found := map[string]*defs.Definition{}
	for _, op := range slices.Sorted(maps.Keys(b.Params)) {
		d, err := s.Defs.Active(ctx, org, op)
		if err != nil {
			return nil, err
		}
		found[op] = d
	}
	return func(op string) *defs.Definition { return found[op] }, nil
}

func checkReason(reason string) error {
	if reason == "" || len(reason) > 256 {
		return pcerr.New(pcerr.InvalidArgument, "REASON_REQUIRED", "give a reason of 1..256 bytes")
	}
	for _, r := range reason {
		if r < 0x20 || r == 0x7f || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return pcerr.New(pcerr.InvalidArgument, "REASON_INVALID", "the reason contains a control or bidi character")
		}
	}
	return nil
}

func grantEvent(actor evdomain.Actor, name string, g domain.Grant, details map[string]string) audit.Event {
	return audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "grant", ID: g.ID.String()}, Details: details,
	}
}

// detail returns the domain's explanation without the sentinel's prefix.
func detail(err, sentinel error) string {
	return strings.TrimPrefix(err.Error(), sentinel.Error()+": ")
}
