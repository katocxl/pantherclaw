// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the agent inventory use cases (Badge; F016, F017,
// F020, F022–F024, F035, F574, F624; G0 M3). Every use case reads the
// caller from the context, runs in a tenant transaction for the caller's
// org, checks the permission at the agent's place in the hierarchy (team,
// and environment when it belongs to that team), writes the agent's
// append-only history and the platform audit in the same transaction, and
// moves the lifecycle only through conditional updates (HR-004). Nothing
// here grants authority.
package app

import (
	"context"
	"encoding/json/v2"
	"errors"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors returned to clients.
var (
	ErrAgentNotFound = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrPlacement     = pcerr.New(pcerr.InvalidArgument, "AGENT_PLACEMENT",
		"the team and environment must be active, and the environment must belong to the org or to that team")
	ErrOwner      = pcerr.New(pcerr.InvalidArgument, "AGENT_OWNER", "owners must be active users of the org")
	ErrAgentLimit = pcerr.New(pcerr.FailedPrecondition, "AGENT_LIMIT", "the edition's agent limit is reached")
	// ErrRangeAgentLimit: an org has at most MaxRangeAgents live range agents in every edition (D1).
	ErrRangeAgentLimit = pcerr.New(pcerr.FailedPrecondition, "RANGE_AGENT_LIMIT", "an organization has at most 5 range agents")
	ErrState           = pcerr.New(pcerr.FailedPrecondition, "AGENT_STATE", "the agent's state does not allow this change")
	ErrLostRace        = pcerr.New(pcerr.Aborted, "AGENT_CHANGED", "the agent changed concurrently; read it again")
)

// MaxRangeAgents is the number of live range agents an org may have (G0 M12 D1).
const MaxRangeAgents = 5

// Entitlements reports the current edition (billing.Service).
type Entitlements interface {
	Current(context.Context) (billing.Entitlements, error)
}

// Inventory serves the agent use cases.
type Inventory struct {
	pool *db.Pool
	ents Entitlements
}

// NewInventory returns the inventory use cases.
func NewInventory(pool *db.Pool, ents Entitlements) *Inventory {
	return &Inventory{pool: pool, ents: ents}
}

// inOrg runs fn in a tenant transaction of the caller's org.
func inOrg(ctx context.Context, pool *db.Pool, fn func(context.Context, tenancy.Caller, *dbq.Queries, db.TenantTx) error, opts ...db.TxOption) error {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	return pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, c, dbq.New(tx), tx)
	}, opts...)
}

// actor names the caller in the agent history.
func actor(c tenancy.Caller) domain.Actor {
	if c.Principal.Kind == td.KindServiceAccount {
		return domain.ServiceAccountActor(c.Principal.ID)
	}
	return domain.UserActor(c.Principal.ID)
}

// Placement is where an agent sits in the hierarchy.
type placement struct {
	team, env ids.UUID
	path      td.Path
}

// place checks that team and environment are active and compatible, and
// returns the path permissions are checked at: the team, and below it the
// environment when the environment belongs to that team.
func place(ctx context.Context, q *dbq.Queries, org ids.OrgID, team, env ids.UUID) (placement, error) {
	t, err := q.GetTeamPlacement(ctx, org, team)
	if err != nil {
		return placement{}, notFound(err, ErrPlacement)
	}
	e, err := q.GetEnvironmentPlacement(ctx, org, env)
	if err != nil {
		return placement{}, notFound(err, ErrPlacement)
	}
	if t.State != string(td.Active) || e.State != string(td.Active) || (e.TeamID != nil && *e.TeamID != team) {
		return placement{}, ErrPlacement
	}
	path := td.OrgPath(org)
	if t.BusinessUnitID != nil {
		path = path.Child(td.ScopeBusinessUnit, *t.BusinessUnitID)
	}
	path = path.Child(td.ScopeTeam, team)
	if e.TeamID != nil {
		path = path.Child(td.ScopeEnvironment, env)
	}
	return placement{team: team, env: env, path: path}, nil
}

// PathOf returns where an existing agent's permissions are checked: its
// placement once claimed, the org for a discovered agent.
func PathOf(ctx context.Context, q *dbq.Queries, r dbq.PcAgent) (td.Path, error) {
	if r.TeamID == nil || r.EnvironmentID == nil {
		return td.OrgPath(r.OrgID), nil
	}
	p, err := place(ctx, q, r.OrgID, *r.TeamID, *r.EnvironmentID)
	if errors.Is(err, ErrPlacement) {
		// An archived team or environment still scopes its agents.
		return archivedPath(ctx, q, r)
	}
	return p.path, err
}

func archivedPath(ctx context.Context, q *dbq.Queries, r dbq.PcAgent) (td.Path, error) {
	path := td.OrgPath(r.OrgID)
	t, err := q.GetTeamPlacement(ctx, r.OrgID, *r.TeamID)
	if err != nil {
		return nil, err
	}
	if t.BusinessUnitID != nil {
		path = path.Child(td.ScopeBusinessUnit, *t.BusinessUnitID)
	}
	return path.Child(td.ScopeTeam, *r.TeamID), nil
}

// load reads an agent and checks p at its place.
func load(ctx context.Context, c tenancy.Caller, q *dbq.Queries, id ids.UUID, p td.Permission, lock bool) (dbq.PcAgent, error) {
	get := q.GetAgent
	if lock {
		get = q.LockAgent
	}
	r, err := get(ctx, c.Org, id)
	if err != nil {
		return r, notFound(err, ErrAgentNotFound)
	}
	path, err := PathOf(ctx, q, r)
	if err != nil {
		return r, err
	}
	return r, c.Require(p, path)
}

// checkOwners requires owner (and backup, when set) to be active users.
func checkOwners(ctx context.Context, q *dbq.Queries, org ids.OrgID, owner, backup ids.UUID) error {
	for _, u := range []ids.UUID{owner, backup} {
		if u.IsZero() {
			continue
		}
		state, err := q.GetUserState(ctx, org, u)
		if err != nil {
			return notFound(err, ErrOwner)
		}
		if state != string(td.Enabled) {
			return ErrOwner
		}
	}
	return nil
}

// checkLimit enforces the edition's agent limit; it takes the org's agent
// limit lock so concurrent creates and claims cannot both pass.
func (inv *Inventory) checkLimit(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	if err := q.LockAgentLimit(ctx, org.String()); err != nil {
		return err
	}
	n, err := q.CountGovernedAgents(ctx, org)
	if err != nil {
		return err
	}
	ent, err := inv.ents.Current(ctx)
	if err != nil {
		return err
	}
	if err := ent.CheckAgents(int(n)); errors.Is(err, billing.ErrLimitReached) {
		return pcerr.Wrap(err, pcerr.FailedPrecondition, "AGENT_LIMIT", err.Error())
	} else if err != nil {
		return err
	}
	return nil
}

// checkRangeLimit enforces the cap on range agents. They do not count toward
// the edition's limit. It takes the same lock as checkLimit.
func (inv *Inventory) checkRangeLimit(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	if err := q.LockAgentLimit(ctx, org.String()); err != nil {
		return err
	}
	n, err := q.CountRangeAgents(ctx, org)
	if err != nil {
		return err
	}
	if n >= MaxRangeAgents {
		return ErrRangeAgentLimit
	}
	return nil
}

// RecordChange appends one entry to an agent's history, in the caller's
// transaction. Other modules (identity, runs) use it for the agent events
// they cause.
func RecordChange(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent ids.UUID, ch domain.Change) error {
	if err := ch.Validate(); err != nil {
		return err
	}
	details := ch.Details
	if details == nil {
		details = map[string]string{}
	}
	raw, err := json.Marshal(details, json.Deterministic(true))
	if err != nil {
		return err
	}
	return q.InsertAgentChange(ctx, dbq.InsertAgentChangeParams{
		OrgID: org, ID: ids.NewV7(), AgentID: agent, Kind: string(ch.Kind), Actor: string(ch.Actor),
		Reason: ch.Reason, Details: raw,
	})
}

// record audits a change made by c (F585).
func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, agent ids.UUID, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	if c.Credential != "" {
		details["via"] = string(c.Credential)
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "agent", ID: agent.String()}, Details: details,
	})
	return err
}

func notFound(err, nf error) error {
	if db.IsNoRows(err) {
		return nf
	}
	return err
}

func optUUID(u ids.UUID) *ids.UUID {
	if u.IsZero() {
		return nil
	}
	return &u
}

func ptr[T any](v T) *T { return &v }
