// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/ticketsync/domain"
)

// Field ownership changes (G0 M20 D264). Giving a field to the ticket
// system is a protected change (surface ticket.field_owner, category
// COVERAGE_EXCLUSION): with the category on it waits for a second person
// holding connection.manage. Taking a field back for PantherClaw applies
// at once. Containment and restoration never go to the ticket system.

// fieldOwnerPayload is a stored field-owner change.
type fieldOwnerPayload struct {
	Field domain.Field `json:"field"`
	Owner domain.Owner `json:"owner"`
}

// RegisterProtected registers the field-owner surface with g.
func (s *Service) RegisterProtected(g *protect.Gate) {
	s.Gate = g
	if g != nil {
		g.Register(protect.SurfaceTicketFieldOwner, s.ApplyProtectedFieldOwner, s.ProtectedFieldOwnerState)
	}
}

// SetFieldOwner sets field's owner for the caller's organization. Giving a
// field to the ticket system may return a *protect.PendingError (ErrPending)
// after the change was stored for a second person.
//
// permission: connection.manage
func (s *Service) SetFieldOwner(ctx context.Context, field domain.Field, owner domain.Owner) error {
	c, err := person(ctx, td.PermConnectionManage)
	if err != nil {
		return err
	}
	if err := s.business(ctx); err != nil {
		return err
	}
	var held *protect.PendingError
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		held, err = s.setFieldOwner(ctx, tx, c, field, owner)
		return err
	})
	if err == nil && held != nil {
		return held
	}
	return err
}

func (s *Service) setFieldOwner(ctx context.Context, tx db.TenantTx, c tenancy.Caller, field domain.Field, owner domain.Owner) (*protect.PendingError, error) {
	if !field.Valid() || !owner.Valid() {
		return nil, ErrInvalid
	}
	if field.Locked() && owner != domain.OwnerPantherClaw {
		return nil, ErrLockedField
	}
	q := dbq.New(tx)
	own, err := owners(ctx, q, c.Org)
	if err != nil {
		return nil, err
	}
	from := own.Of(field)
	write := func(ctx context.Context) error {
		if err := q.SetTicketFieldOwner(ctx, dbq.SetTicketFieldOwnerParams{
			OrgID: c.Org, Field: string(field), Owner: string(owner), ChangedBy: c.Principal.String(),
		}); err != nil {
			return err
		}
		return s.audit(ctx, tx, c.Actor(), "ticket.field_owner_changed", "ticket_field", protect.SubjectID(protect.SurfaceTicketFieldOwner, "field:"+string(field)), map[string]string{
			"field": string(field), "from": string(from), "to": string(owner),
		})
	}
	if from == owner {
		return nil, nil
	}
	if owner == domain.OwnerPantherClaw {
		return nil, write(ctx)
	}
	return s.Gate.Hold(ctx, tx, c, protect.Change{
		Category: protect.CoverageExclusion, Surface: protect.SurfaceTicketFieldOwner, Subject: "field:" + string(field),
		Summary:  map[string]string{"field": string(field), "from": string(from), "to": string(owner)},
		Widening: []string{string(field)}, Payload: fieldOwnerPayload{Field: field, Owner: owner},
	}, write)
}

// ApplyProtectedFieldOwner re-runs a confirmed field-owner change as its
// author.
func (s *Service) ApplyProtectedFieldOwner(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var in fieldOwnerPayload
	if err := json.Unmarshal(payload, &in); err != nil {
		return ErrInvalid
	}
	if err := author.Require(td.PermConnectionManage, td.OrgPath(author.Org)); err != nil {
		return err
	}
	held, err := s.setFieldOwner(ctx, tx, author, in.Field, in.Owner)
	if err == nil && held != nil {
		return held
	}
	return err
}

// ProtectedFieldOwnerState is the state a confirmed re-run must still
// find: the field's owner when the change was stored.
func (s *Service) ProtectedFieldOwnerState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	var in fieldOwnerPayload
	if err := json.Unmarshal(payload, &in); err != nil {
		return nil, ErrInvalid
	}
	own, err := owners(ctx, dbq.New(tx), tx.OrgID())
	if err != nil {
		return nil, err
	}
	return []byte(own.Of(in.Field)), nil
}
