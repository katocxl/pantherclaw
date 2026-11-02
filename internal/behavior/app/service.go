// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"slices"

	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	bdomain "github.com/katocxl/pantherclaw/internal/behavior/domain"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// API errors of the service.
var (
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"behavior analytics need the Business edition or above")
	// ErrNotFound answers for what the viewer can't read as well as for what
	// doesn't exist.
	ErrNotFound = pcerr.New(pcerr.NotFound, "NOT_FOUND", "no such record")
)

// Service serves BehaviorService (HR-646).
type Service struct {
	Pool *db.Pool
	Ents Entitlements
}

func (s *Service) entitled(ctx context.Context) error {
	if s.Ents == nil {
		return ErrEdition
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return err
	}
	if !e.BehaviorAnalytics() {
		return ErrEdition
	}
	return nil
}

func (s *Service) caller(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.CanAnywhere(td.PermBehaviorRead) {
		return c, td.ErrPermissionDenied(td.PermBehaviorRead)
	}
	return c, s.entitled(ctx)
}

// visible reports whether c may read agent's behavior.
func visible(ctx context.Context, c tenancy.Caller, q *dbq.Queries, agent ids.UUID) (bool, error) {
	v, err := exapp.VisibleAgents(ctx, c, q, td.PermBehaviorRead)
	if err != nil {
		return false, err
	}
	return v.All || slices.Contains(v.IDs, agent), nil
}

// Profile is an agent's profile, or a NOT_COLLECTED one (HR-643).
func (s *Service) Profile(ctx context.Context, agent ids.UUID, origin bdomain.Origin) (bdomain.BehaviorProfile, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return bdomain.BehaviorProfile{}, err
	}
	var out bdomain.BehaviorProfile
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		ok, err := visible(ctx, c, q, agent)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		out, err = stored(ctx, q, c.Org, agent, origin)
		return err
	}, db.ReadOnly())
	return out, err
}

// stored reads a profile; a missing one is NOT_COLLECTED.
func stored(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent ids.UUID, origin bdomain.Origin) (bdomain.BehaviorProfile, error) {
	r, err := q.GetBehaviorProfile(ctx, org, agent, string(origin))
	if db.IsNoRows(err) {
		return bdomain.BehaviorProfile{Agent: agent, Origin: origin, State: bdomain.StateNotCollected}, nil
	}
	if err != nil {
		return bdomain.BehaviorProfile{}, err
	}
	p := bdomain.BehaviorProfile{
		Agent: r.AgentID, Origin: bdomain.Origin(r.Origin), State: bdomain.State(r.State), Start: r.WindowStart, End: r.WindowEnd,
		Actions: r.Actions, ActiveDays: int(r.ActiveDays), Truncated: r.Truncated, AsOf: r.ComputedAt,
	}
	if err := json.Unmarshal(r.Body, &p.Body); err != nil {
		return bdomain.BehaviorProfile{}, err
	}
	return p, nil
}

// ApprovalContext is what stands out about a held action (D501).
type ApprovalContext struct {
	Agent   ids.UUID
	Profile bdomain.BehaviorProfile
	Lines   []bdomain.Deviation
}

// Context reads what stands out about the action behind an approval request,
// against a baseline of the agent's actions that were allowed and ran
// before it (D526). It never writes, and nothing the approval binds or
// decides reads it (HR-645). The caller must be able to read the approval
// itself. A simulated action is set against simulated activity (HR-642).
func (s *Service) Context(ctx context.Context, approval ids.UUID) (ApprovalContext, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return ApprovalContext{}, err
	}
	var out ApprovalContext
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		// The approval itself must be one the caller may read (D526 P5).
		if ok, err := apapp.Readable(ctx, q, c, approval); err != nil || !ok {
			if err != nil {
				return err
			}
			return ErrNotFound
		}
		r, err := q.BehaviorApprovalAction(ctx, c.Org, approval)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		ok, err := visible(ctx, c, q, r.AgentID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		origin := bdomain.OriginReal
		if r.Simulated {
			origin = bdomain.OriginSimulated
		}
		// The baseline is the agent's known actions before the held one, not
		// the stored profile: a hold, its retries or a later rollup never
		// make the held action look usual (D526).
		p, _, err := baseline(ctx, q, c.Org, r.AgentID, origin, r.CreatedAt.Add(-bdomain.Window), r.CreatedAt, MaxBaseline)
		if err != nil {
			return err
		}
		p.AsOf = r.CreatedAt
		a := bdomain.Action{ID: r.ID, Agent: r.AgentID, Run: r.RunID, Operation: r.Operation, DestClass: r.DestinationClass, At: r.CreatedAt}
		if r.ConnectionID != nil {
			a.Connection = *r.ConnectionID
		}
		out = ApprovalContext{Agent: r.AgentID, Profile: p, Lines: bdomain.Context(p, a)}
		return nil
	}, db.ReadOnly())
	return out, err
}
