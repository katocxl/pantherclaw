// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"slices"
	"time"

	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ListFilter narrows List.
type ListFilter struct {
	// States are stored states; empty means PENDING and EVIDENCE_REQUESTED.
	States       []apdomain.State
	Agent, Run   ids.UUID
	WaitingForMe bool
}

// RequestPage is one page of requests the caller may see.
type RequestPage struct {
	Items []Request
	Next  string
	// Scopes are the caller's bindings of roles that read or decide
	// approvals: what the list covers besides the caller's own runs and
	// step-ups (F626).
	Scopes []td.Binding
}

// List lists the requests the caller may see, newest first (ApprovalService
// ListApprovalRequests): those they may decide, their own runs' requests,
// and with approval.read those of agents in its scope (T-037). A page is
// filled before visibility is checked, so it may hold fewer than its size.
// WaitingForMe keeps the requests the caller may decide now and has not
// approved.
func (s *Service) List(ctx context.Context, pr page.Request, f ListFilter) (RequestPage, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return RequestPage{}, err
	}
	states := []string{string(apdomain.StatePending), string(apdomain.StateEvidenceRequested)}
	if len(f.States) > 0 {
		states = states[:0]
		for _, st := range f.States {
			states = append(states, string(st))
		}
	}
	p := dbq.ListApprovalRequestsParams{OrgID: c.Org, States: states, Lim: pr.Limit()}
	if !pr.After.IsZero() {
		p.Before = &pr.After
	}
	if !f.Agent.IsZero() {
		p.AgentID = &f.Agent
	}
	if !f.Run.IsZero() {
		p.RunID = &f.Run
	}
	out := RequestPage{Scopes: approvalScopes(c)}
	var users []ids.UUID
	if c.Human() {
		users = []ids.UUID{c.Principal.ID}
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListApprovalRequests(ctx, p)
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcApprovalRequest) ids.UUID { return r.ID })
		var approved []ids.UUID
		if f.WaitingForMe && c.Human() {
			list := make([]ids.UUID, len(rows))
			for i, r := range rows {
				list[i] = r.ID
			}
			if approved, err = q.RespondedRequests(ctx, c.Org, c.Principal.ID, list); err != nil {
				return err
			}
		}
		for _, r := range rows {
			e, err := pgapprovals.LoadEligibility(ctx, q, c.Org, r.ID, users)
			if err != nil {
				return err
			}
			l := locked{row: r, elig: e}
			if f.WaitingForMe {
				if !c.Human() || slices.Contains(approved, r.ID) || !l.mayRespond(c.Principal.ID) ||
					!waiting(r, e.Context.Now, apdomain.StatePending, apdomain.StateEvidenceRequested) {
					continue
				}
			} else if ok, err := visible(ctx, q, c, l); err != nil {
				return err
			} else if !ok {
				continue
			}
			out.Items = append(out.Items, r)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// approvalScopes are the caller's bindings of roles that read or decide
// approvals.
func approvalScopes(c tenancy.Caller) []td.Binding {
	var out []td.Binding
	for _, b := range c.Bindings {
		if r, ok := td.LookupRole(b.Role); ok && (r.Has(td.PermApprovalRespond) || r.Has(td.PermApprovalRead)) {
			out = append(out, b)
		}
	}
	return out
}

// Variant is an earlier request for the same grant, operation and target
// (HR-037).
type Variant struct {
	Request   ids.UUID
	State     string
	CreatedAt time.Time
}

// Eligibility says whether the caller may decide a request now: approve
// (CanApprove), or decline, ask for evidence and propose (CanRespond); the
// requirements a response of theirs would count toward; and, when they may
// not approve, a stable code saying why.
type Eligibility struct {
	CanApprove, CanRespond bool
	Requirements           []int
	Reason                 string
}

// eligibility computes the caller's eligibility for a request.
func eligibility(ctx context.Context, q *dbq.Queries, c tenancy.Caller, l locked, state apdomain.State) (Eligibility, error) {
	var out Eligibility
	if !c.Human() {
		out.Reason = "HUMAN_SESSION_REQUIRED"
		return out, nil
	}
	me := l.elig.People[c.Principal.ID]
	out.CanRespond = l.mayRespond(c.Principal.ID) && (state == apdomain.StatePending || state == apdomain.StateEvidenceRequested)
	for i, r := range l.elig.Requirements {
		ok, code := apdomain.Check(r, me, l.elig.Context, ids.UUID{})
		if ok {
			out.Requirements = append(out.Requirements, i)
		} else if out.Reason == "" {
			out.Reason = code
		}
	}
	err := approvable(ctx, q, c.Org, l.row, c.Principal.ID)
	switch {
	case err == nil:
		out.CanApprove, out.Reason = true, ""
	case !errors.Is(err, ErrNotWaiting) && !errors.Is(err, ErrNotEligible):
		return out, err
	case out.Reason == "":
		out.Reason = "ALREADY_RESPONDED"
		if errors.Is(err, ErrNotWaiting) {
			out.Reason = "NOT_WAITING"
		}
	}
	return out, nil
}
