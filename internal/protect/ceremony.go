// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package protect

import (
	"context"
	"regexp"

	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Ceremony is internal/changes as the Gate's Requests (D6): protected
// changes and clearings are its requests, confirmed with security keys on
// /changes/{id}.
type Ceremony struct {
	Changes *changes.Service
}

// Open implements Requests.
func (c Ceremony) Open(ctx context.Context, tx db.TenantTx, r Request) (ids.UUID, error) {
	var content [32]byte
	copy(content[:], r.Digest)
	req, err := c.Changes.RequestTx(ctx, tx, r.By, changes.Requested{
		Domain: r.Domain, Kind: r.Kind, Subject: r.Subject, Content: content, Summary: r.Summary, Required: r.Required,
	})
	return req.ID, err
}

// Void implements Requests: it voids the pending request id (every pending
// request of its domain about its subject, which is the one request: a
// protected change or a compromise has its own subject).
func (c Ceremony) Void(ctx context.Context, tx db.TenantTx, id ids.UUID, reason string) error {
	r, err := dbq.New(tx).GetChangeRequest(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	if r.State != changes.StatePending {
		return nil
	}
	actor, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	_, err = c.Changes.Void(ctx, tx, actor, r.Domain, r.SubjectID, reason)
	return err
}

// Pending implements Requests.
func (c Ceremony) Pending(ctx context.Context, tx db.TenantTx, id ids.UUID) (bool, error) {
	r, err := dbq.New(tx).GetChangeRequest(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return r.State == changes.StatePending && !r.Expired, nil
}

// Register registers protect's change kinds with the ceremony: every
// category and SETTINGS (one distinct publisher), EMERGENCY_REVIEW (up to
// 72 hours, D74), and the CLEAR of a compromise (two other people). A
// protected change follows its request when the request ends unapplied
// (DECLINED, EXPIRED, VOIDED; D72 P2).
func Register(svc *changes.Service, g *Gate, p *Publishers) {
	one := func(context.Context, db.TenantTx, changes.Request) (int, error) { return 1, nil }
	h := changes.Handler{
		Permission:         td.PermProtectedChangeManage,
		DeclinePermissions: []td.Permission{td.PermProtectedChangeManage},
		Required:           one,
		Eligible: func(ctx context.Context, tx db.TenantTx, r changes.Request, user ids.UUID) (bool, string, error) {
			return g.Eligible(ctx, tx, r.ID, user)
		},
		Apply: func(ctx context.Context, tx db.TenantTx, r changes.Request, confirmers []ids.UUID) error {
			return g.Apply(ctx, tx, r.ID, confirmers)
		},
		Closed: func(ctx context.Context, tx db.TenantTx, r changes.Request, state string) error {
			return g.Closed(ctx, tx, r.ID, state, r.DecidedReason)
		},
	}
	for _, k := range append(categoryKinds(), KindSettings) {
		svc.Register(DomainProtected, k, h)
	}
	review := h
	review.Closed, review.TTL = nil, changes.MaxTTL
	svc.Register(DomainProtected, KindEmergencyReview, review)
	svc.Register(DomainPublisher, KindClear, changes.Handler{
		Permission:         td.PermPublisherCompromise,
		DeclinePermissions: []td.Permission{td.PermPublisherCompromise},
		Required:           func(context.Context, db.TenantTx, changes.Request) (int, error) { return 2, nil },
		Eligible: func(ctx context.Context, tx db.TenantTx, r changes.Request, user ids.UUID) (bool, string, error) {
			return p.EligibleClear(ctx, tx, r.ID, user)
		},
		Apply: func(ctx context.Context, tx db.TenantTx, r changes.Request, confirmers []ids.UUID) error {
			return p.ApplyClear(ctx, tx, r.ID, confirmers)
		},
	})
}

func categoryKinds() []string {
	out := make([]string, 0, 4)
	for _, c := range Categories() {
		out = append(out, string(c))
	}
	return out
}

var reasonPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Closed moves a pending protected change to its request's end state
// (D72 P2): a declined, expired or voided request applies nothing, and its
// change can no longer be applied in an emergency.
func (g *Gate) Closed(ctx context.Context, tx db.TenantTx, request ids.UUID, state, reason string) error {
	switch state {
	case changes.StateDeclined, changes.StateExpired, changes.StateVoided:
	default:
		return nil
	}
	q := dbq.New(tx)
	row, err := q.GetProtectedChangeByRequest(ctx, tx.OrgID(), request)
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	if row.State != StatePending || row.ChangeRequestID == nil || *row.ChangeRequestID != request {
		return nil
	}
	if !reasonPattern.MatchString(reason) {
		reason = state
	}
	_, err = q.DecideProtectedChange(ctx, dbq.DecideProtectedChangeParams{State: state, Reason: &reason, OrgID: tx.OrgID(), ID: row.ID})
	if db.IsNoRows(err) {
		return nil
	}
	return err
}
