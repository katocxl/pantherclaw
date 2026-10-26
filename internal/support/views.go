// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package support

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Request states as read (EXPIRED is a pending request past its expiry).
const (
	StatePending  = "PENDING"
	StateApproved = "APPROVED"
	StateDenied   = "DENIED"
	StateExpired  = "EXPIRED"
)

// Grant states as read.
const (
	GrantActive  = "ACTIVE"
	GrantExpired = "EXPIRED"
	GrantRevoked = "REVOKED"
)

// Request is a support request as an org reads it.
type Request struct {
	ID, Account           ids.UUID
	Email, Name           string
	Task, Scope, State    string
	Hours                 int
	CreatedAt, ExpiresAt  time.Time
	DecidedBy             *ids.UUID
	DecidedAt             *time.Time
	Grant                 *ids.UUID
	StaffOrg, StaffUserID ids.UUID
}

// Grant is a support grant as an org reads it.
type Grant struct {
	ID, Request, Account ids.UUID
	Email, Name, Task    string
	Scope, State         string
	ApprovedBy           ids.UUID
	StartsAt, ExpiresAt  time.Time
	RevokedAt            *time.Time
	RevokedBy            string
	Sessions             int
}

func requestRow(r dbq.GetSupportRequestRow) dbq.PcSupportAccessRequest {
	return dbq.PcSupportAccessRequest{
		OrgID: r.OrgID, ID: r.ID, RequesterAccount: r.RequesterAccount, RequesterIssuer: r.RequesterIssuer,
		RequesterSubject: r.RequesterSubject, RequesterEmail: r.RequesterEmail, RequesterName: r.RequesterName,
		StaffOrg: r.StaffOrg, StaffUser: r.StaffUser, StaffCredential: r.StaffCredential, Task: r.Task, Scope: r.Scope,
		DurationHours: r.DurationHours, State: r.State, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
		DecidedBy: r.DecidedBy, DecidedCredential: r.DecidedCredential, DecidedAt: r.DecidedAt,
	}
}

func requestOf(r dbq.PcSupportAccessRequest, expired bool, grant *ids.UUID) Request {
	state := r.State
	if expired && state == StatePending {
		state = StateExpired
	}
	return Request{
		ID: r.ID, Account: r.RequesterAccount, Email: r.RequesterEmail, Name: r.RequesterName, Task: r.Task, Scope: r.Scope,
		State: state, Hours: int(r.DurationHours), CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, DecidedBy: r.DecidedBy,
		DecidedAt: r.DecidedAt, Grant: grant, StaffOrg: r.StaffOrg, StaffUserID: r.StaffUser,
	}
}

func grantRow(g dbq.GetSupportGrantRow) dbq.PcSupportAccessGrant {
	return dbq.PcSupportAccessGrant{
		OrgID: g.OrgID, ID: g.ID, RequestID: g.RequestID, AccountID: g.AccountID, Scope: g.Scope, ApprovedBy: g.ApprovedBy,
		ApprovedCredential: g.ApprovedCredential, StartsAt: g.StartsAt, ExpiresAt: g.ExpiresAt, RevokedAt: g.RevokedAt,
		RevokedByType: g.RevokedByType, RevokedByID: g.RevokedByID,
	}
}

func grantOf(g dbq.PcSupportAccessGrant, email, name, task string, sessions int32, expired bool) Grant {
	state := GrantActive
	switch {
	case g.RevokedAt != nil:
		state = GrantRevoked
	case expired:
		state = GrantExpired
	}
	out := Grant{
		ID: g.ID, Request: g.RequestID, Account: g.AccountID, Email: email, Name: name, Task: task, Scope: g.Scope,
		State: state, ApprovedBy: g.ApprovedBy, StartsAt: g.StartsAt, ExpiresAt: g.ExpiresAt, RevokedAt: g.RevokedAt,
		Sessions: int(sessions),
	}
	if g.RevokedByType != nil && g.RevokedByID != nil {
		out.RevokedBy = *g.RevokedByType + ":" + *g.RevokedByID
	}
	return out
}

// RequestPage is one page of requests, newest first.
type RequestPage struct {
	Items []Request
	Next  string
}

// ListRequests lists the org's requests, newest first; state filters on
// the state as read ("" for all).
func (s *Service) ListRequests(ctx context.Context, state string, size int32, token string) (RequestPage, error) {
	c, err := caller(ctx, td.PermSupportRead)
	if err != nil {
		return RequestPage{}, err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return RequestPage{}, err
	}
	var st *string
	if state != "" {
		st = &state
	}
	var before *ids.UUID
	if !pr.After.IsZero() {
		before = &pr.After
	}
	var out RequestPage
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListSupportRequests(ctx, dbq.ListSupportRequestsParams{
			OrgID: c.Org, State: st, Before: before, MaxRows: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListSupportRequestsRow) ids.UUID { return r.ID })
		for _, r := range rows {
			out.Items = append(out.Items, requestOf(requestRow(dbq.GetSupportRequestRow(r)), r.Expired, r.GrantID))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// GetRequest returns one request and its grant, if approved.
func (s *Service) GetRequest(ctx context.Context, id ids.UUID) (Request, *Grant, error) {
	c, err := caller(ctx, td.PermSupportRead)
	if err != nil {
		return Request{}, nil, err
	}
	var out Request
	var grant *Grant
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetSupportRequest(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrRequestNotFound
		} else if err != nil {
			return err
		}
		out = requestOf(requestRow(r), r.Expired, r.GrantID)
		if r.GrantID != nil {
			g, err := q.GetSupportGrant(ctx, c.Org, *r.GrantID)
			if err != nil {
				return err
			}
			v := grantOf(grantRow(g), g.RequesterEmail, g.RequesterName, g.Task, g.SessionsOpened, g.Expired)
			grant = &v
		}
		return nil
	}, db.ReadOnly())
	return out, grant, err
}

// GrantPage is one page of grants, newest first.
type GrantPage struct {
	Items []Grant
	Next  string
}

// ListGrants lists the org's grants, newest first.
func (s *Service) ListGrants(ctx context.Context, activeOnly bool, size int32, token string) (GrantPage, error) {
	c, err := caller(ctx, td.PermSupportRead)
	if err != nil {
		return GrantPage{}, err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return GrantPage{}, err
	}
	var before *ids.UUID
	if !pr.After.IsZero() {
		before = &pr.After
	}
	var out GrantPage
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListSupportGrants(ctx, dbq.ListSupportGrantsParams{
			OrgID: c.Org, ActiveOnly: activeOnly, Before: before, MaxRows: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListSupportGrantsRow) ids.UUID { return r.ID })
		for _, g := range rows {
			out.Items = append(out.Items, grantOf(grantRow(dbq.GetSupportGrantRow(g)), g.RequesterEmail, g.RequesterName,
				g.Task, g.SessionsOpened, g.Expired))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
