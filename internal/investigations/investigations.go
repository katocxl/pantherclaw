// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package investigations assembles the run investigation views (G0 M10
// D20): what actually happened to one action (F239), a run's timeline with
// its gaps, lanes and inferred phases (F284, F232), the context that came
// before an action or a run (F241, F248), and how a run compares with the
// agent's typical runs (F234).
//
// Every view reads in the caller's tenant transaction and passes each row
// through the viewer's Scope before it is assembled or counted (HR-247,
// D8): rows of an agent the viewer may not read are left out, counts never
// include them, and a note about omitted data comes from the scope, never
// from whether hidden rows exist. Nothing here asserts causation: context
// and comparison items carry their Basis, and a comparison never labels a
// run malicious.
package investigations

import (
	"context"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Bounds of the views.
const (
	MaxTimelineActions = 2000
	MaxApprovals       = 1000
	MaxChildren        = 200
	MaxReferenceRuns   = 200
	MaxContextWindow   = 30 * 24 * time.Hour
	DefaultContext     = 24 * time.Hour
	DefaultReference   = 30 * 24 * time.Hour
)

// Errors of the views. NOT_FOUND is also what an agent outside the
// viewer's scope looks like.
var (
	ErrTransactionNotFound = pcerr.New(pcerr.NotFound, "TRANSACTION_NOT_FOUND", "transaction not found")
	ErrRunNotFound         = pcerr.New(pcerr.NotFound, "RUN_NOT_FOUND", "run not found")
	ErrBadRange            = pcerr.New(pcerr.InvalidArgument, "INVALID_RANGE",
		"the range must end after it starts and span at most 30 days")
)

// Scope is the viewer's read scope (HR-247). Visible reports whether the
// viewer may read an agent's runs and evidence; Limited reports whether
// the viewer's scope is narrower than the org, so a view can say that some
// data may be outside it.
type Scope interface {
	Visible(ctx context.Context, agent ids.UUID) (bool, error)
	Limited() bool
}

// Basis says how an item is known (reflexdomain.Basis, F648).
type Basis string

// Bases.
const (
	BasisObserved Basis = "OBSERVED"
	BasisInferred Basis = "INFERRED"
)

// Range is a time window [Start, End).
type Range struct {
	Start, End time.Time
}

func (r Range) check() error {
	if !r.End.After(r.Start) || r.End.Sub(r.Start) > MaxContextWindow {
		return ErrBadRange
	}
	return nil
}

// Party is a launcher, principal or grantor.
type Party struct {
	Kind string // user, service_account, instance
	ID   ids.UUID
}

func party(user, sa, instance *ids.UUID) *Party {
	switch {
	case user != nil:
		return &Party{"user", *user}
	case sa != nil:
		return &Party{"service_account", *sa}
	case instance != nil:
		return &Party{"instance", *instance}
	}
	return nil
}

// Approval is a hold on an action.
type Approval struct {
	ID          ids.UUID
	Transaction *ids.UUID
	Operation   string
	State       string
	EndReason   string
	Created     time.Time
	Deadline    time.Time
	Approved    *time.Time
	Ended       *time.Time
}

func approval(r dbq.InvApprovalsRow) Approval {
	a := Approval{
		ID: r.ID, Transaction: r.TransactionID, Operation: r.Operation, State: r.State, Created: r.CreatedAt,
		Deadline: r.DeadlineAt, Approved: r.ApprovedAt, Ended: r.EndedAt,
	}
	if r.EndReason != nil {
		a.EndReason = *r.EndReason
	}
	return a
}

// Grantor is one link of the grant chain, nearest first.
type Grantor struct {
	Grant     ids.UUID
	Agent     ids.UUID
	Grantor   Party
	Principal *Party
	Depth     int
	State     string
	Created   time.Time
	Revoked   *time.Time
}

// Delegation is one parent run of the delegation chain, nearest first.
type Delegation struct {
	Run       ids.UUID
	Agent     ids.UUID
	Launcher  *Party
	Principal *Party
	Grant     *ids.UUID
	Depth     int
}

// Happened is what actually happened to one action (F239).
type Happened struct {
	Transaction, Run, Agent ids.UUID
	Operation               string
	Decision, Reason        string
	// Stages, each from recorded evidence.
	Allowed, Held, Denied, Observed, Dispatched, EffectConfirmed bool
	Outcome                                                      string
	Effect                                                       string
	Connection                                                   *ids.UUID
	DestinationClass                                             string
	Simulated                                                    bool
	Created                                                      time.Time
	Dispatching, OutcomeAt                                       *time.Time
	Launcher, Principal                                          *Party
	Grantors                                                     []Grantor
	Delegation                                                   []Delegation
	Approvals                                                    []Approval
	// ScopeLimited: the viewer's scope is narrower than the org, so the
	// grantor or delegation chain may stop at its edge.
	ScopeLimited bool
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// WhatHappened assembles F239 for transaction id (Community).
func WhatHappened(ctx context.Context, tx db.TenantTx, s Scope, id ids.UUID) (Happened, error) {
	q := dbq.New(tx)
	t, err := q.InvTransaction(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return Happened{}, ErrTransactionNotFound
	} else if err != nil {
		return Happened{}, err
	}
	if ok, err := s.Visible(ctx, t.AgentID); err != nil {
		return Happened{}, err
	} else if !ok {
		return Happened{}, ErrTransactionNotFound
	}
	h := Happened{
		Transaction: t.ID, Run: t.RunID, Agent: t.AgentID, Operation: t.Operation, Decision: t.Decision,
		Reason: t.ReasonCode, Outcome: str(t.Outcome), Effect: str(t.EffectState), Connection: t.ConnectionID,
		DestinationClass: str(t.DestinationClass), Simulated: t.Simulated, Created: t.CreatedAt,
		Dispatching: t.DispatchingAt, OutcomeAt: t.OutcomeAt, ScopeLimited: s.Limited(),
	}
	switch t.Decision {
	case "ALLOW", "ALLOW_WITH_OBLIGATIONS":
		h.Allowed = true
	case "REQUIRE_APPROVAL", "REQUIRE_STEP_UP":
		h.Held = true
	case "DENY", "CANNOT_AUTHORIZE":
		h.Denied = true
	}
	h.Observed = t.Mode == "monitor"
	h.Dispatched = t.Outcome != nil || (t.PermitState != nil && slices.Contains([]string{"DISPATCHING", "DISPATCHED", "UNKNOWN"}, *t.PermitState))
	h.EffectConfirmed = t.EffectState != nil && *t.EffectState == "CONFIRMED"

	aps, err := q.InvApprovals(ctx, dbq.InvApprovalsParams{OrgID: tx.OrgID(), TransactionID: &t.ID, MaxRows: MaxApprovals})
	if err != nil {
		return Happened{}, err
	}
	for _, a := range aps {
		h.Approvals = append(h.Approvals, approval(a))
	}
	// An approved hold is still a hold on the record.
	h.Held = h.Held || len(h.Approvals) > 0

	r, err := q.InvRun(ctx, tx.OrgID(), t.RunID)
	if err != nil {
		return Happened{}, err
	}
	h.Launcher = party(r.LauncherUserID, r.LauncherSaID, r.LauncherInstanceID)
	h.Principal = party(r.PrincipalUserID, r.PrincipalSaID, nil)

	grant := t.GrantID
	if grant == nil {
		grant = r.GrantID
	}
	if grant != nil {
		if h.Grantors, err = grantors(ctx, q, tx.OrgID(), s, *grant); err != nil {
			return Happened{}, err
		}
	}
	if h.Delegation, err = delegation(ctx, q, tx.OrgID(), s, t.RunID); err != nil {
		return Happened{}, err
	}
	return h, nil
}

// grantors returns the grant chain up to the first grant of an agent the
// viewer may not read.
func grantors(ctx context.Context, q *dbq.Queries, org ids.OrgID, s Scope, grant ids.UUID) ([]Grantor, error) {
	rows, err := q.InvGrantChain(ctx, org, grant)
	if err != nil {
		return nil, err
	}
	var out []Grantor
	for _, g := range rows {
		ok, err := s.Visible(ctx, g.AgentID)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		out = append(out, Grantor{
			Grant: g.ID, Agent: g.AgentID, Grantor: Party{g.GrantorKind, g.GrantorID},
			Principal: party(g.PrincipalUserID, g.PrincipalSaID, nil), Depth: int(g.Depth), State: g.State,
			Created: g.CreatedAt, Revoked: g.RevokedAt,
		})
	}
	return out, nil
}

// delegation returns the parent runs up to the first run of an agent the
// viewer may not read.
func delegation(ctx context.Context, q *dbq.Queries, org ids.OrgID, s Scope, run ids.UUID) ([]Delegation, error) {
	rows, err := q.InvRunAncestors(ctx, org, run)
	if err != nil {
		return nil, err
	}
	var out []Delegation
	for _, r := range rows {
		ok, err := s.Visible(ctx, r.AgentID)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		out = append(out, Delegation{
			Run: r.ID, Agent: r.AgentID, Launcher: party(r.LauncherUserID, r.LauncherSaID, r.LauncherInstanceID),
			Principal: party(r.PrincipalUserID, r.PrincipalSaID, nil), Grant: r.GrantID, Depth: int(r.Depth),
		})
	}
	return out, nil
}
