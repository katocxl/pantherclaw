// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves the org's owned accounts (G0 M30 D933; HR-708). Adding
// an account loosens the share step (D935), so it files a protected change
// that applies only when a second person confirms it with a security key;
// removing one applies at once.
package app

import (
	"context"
	"encoding/json/v2"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/ownedaccounts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	ErrKind = pcerr.New(pcerr.InvalidArgument, "OWNED_ACCOUNT_KIND_INVALID",
		"the kind is not one of aws_account, github_org, email_domain, gcp_project, azure_tenant")
	ErrValue   = pcerr.New(pcerr.InvalidArgument, "OWNED_ACCOUNT_VALUE_INVALID", "the value is not well formed for its kind")
	ErrReason  = pcerr.New(pcerr.InvalidArgument, "OWNED_ACCOUNT_REASON_INVALID", "a reason of 1 to 500 characters is required")
	ErrHuman   = pcerr.New(pcerr.PermissionDenied, "OWNED_ACCOUNT_HUMAN_ONLY", "only a person may change the owned accounts")
	ErrListed  = pcerr.New(pcerr.AlreadyExists, "OWNED_ACCOUNT_LISTED", "the account is already on the owned list")
	ErrMissing = pcerr.New(pcerr.NotFound, "OWNED_ACCOUNT_NOT_FOUND", "owned account not found")
)

// Service serves the owned accounts.
type Service struct {
	Pool *db.Pool
	// Protect holds every addition (RegisterProtect); nil refuses it.
	Protect *protect.Gate
}

// addPayload is a held addition.
type addPayload struct {
	Kind   domain.Kind `json:"kind"`
	Value  string      `json:"value"`
	Reason string      `json:"reason"`
}

// RegisterProtect sets the Gate's applier for additions.
func (s *Service) RegisterProtect(g *protect.Gate) {
	s.Protect = g
	if g != nil {
		g.Register(protect.SurfaceOwnedAccountAdd, s.ApplyAdd, s.addState)
	}
}

func caller(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

func validReason(reason string) error {
	if n := utf8.RuneCountInString(reason); !utf8.ValidString(reason) || n < 1 || n > 500 {
		return ErrReason
	}
	return nil
}

// List reads the org's owned accounts.
func (s *Service) List(ctx context.Context) ([]dbq.PcOwnedAccount, error) {
	c, err := caller(ctx, td.PermOwnedAccountsRead)
	if err != nil {
		return nil, err
	}
	var out []dbq.PcOwnedAccount
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = dbq.New(tx).ListOwnedAccounts(ctx, c.Org)
		return err
	})
	return out, err
}

// Add files the protected change that adds an account, a person holding
// org.owned_accounts.manage (HR-708). It never applies here: a second
// person decides it with a security key.
func (s *Service) Add(ctx context.Context, kind domain.Kind, value, reason string) (*protect.PendingError, error) {
	if !kind.Valid() {
		return nil, ErrKind
	}
	if !domain.ValidValue(kind, value) {
		return nil, ErrValue
	}
	if err := validReason(reason); err != nil {
		return nil, err
	}
	c, err := caller(ctx, td.PermOwnedAccountsManage)
	if err != nil {
		return nil, err
	}
	if !c.Human() {
		return nil, ErrHuman
	}
	if s.Protect == nil {
		return nil, protect.ErrUnavailable
	}
	var held *protect.PendingError
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		switch _, err := dbq.New(tx).GetOwnedAccountByValue(ctx, c.Org, string(kind), value); {
		case err == nil:
			return ErrListed
		case !db.IsNoRows(err):
			return err
		}
		key := string(kind) + ":" + value
		held, err = s.Protect.Hold(ctx, tx, c, protect.Change{
			Category: protect.ConsequenceRules, Surface: protect.SurfaceOwnedAccountAdd, Subject: key,
			SubjectID: protect.SubjectID(protect.SurfaceOwnedAccountAdd, key),
			Summary:   map[string]string{"kind": string(kind), "value": value, "reason": reason},
			Widening:  []string{"owned_account"},
			Payload:   addPayload{Kind: kind, Value: value, Reason: reason},
		}, func(context.Context) error { return protect.ErrUnavailable })
		if err != nil {
			return err
		}
		if held == nil {
			return protect.ErrUnavailable // never applied without a second person
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return held, nil
}

// ApplyAdd is the confirmed re-run of a held addition (a protect.Applier),
// as its requester, in the confirming transaction.
func (s *Service) ApplyAdd(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p addPayload
	if err := json.Unmarshal(payload, &p); err != nil || !p.Kind.Valid() || !domain.ValidValue(p.Kind, p.Value) {
		return protect.ErrInvalid
	}
	if err := author.Require(td.PermOwnedAccountsManage, td.OrgPath(author.Org)); err != nil {
		return err
	}
	q := dbq.New(tx)
	org := tx.OrgID()
	switch _, err := q.GetOwnedAccountByValue(ctx, org, string(p.Kind), p.Value); {
	case err == nil:
		return ErrListed
	case !db.IsNoRows(err):
		return err
	}
	row, err := q.InsertOwnedAccount(ctx, dbq.InsertOwnedAccountParams{
		OrgID: org, ID: ids.NewV7(), Kind: string(p.Kind), Value: p.Value, AddedBy: author.Principal.String(),
	})
	if err != nil {
		return err
	}
	details := map[string]string{"kind": row.Kind, "value": row.Value, "reason": p.Reason}
	if publisher, ok := protect.Publisher(ctx); ok {
		details["confirmed_by"] = publisher.String()
	}
	return record(ctx, tx, author, auditkind.OrgOwnedAccountAdded, row, details)
}

// addState is what a confirmed re-run must still find: the account still
// absent from the list.
func (s *Service) addState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	var p addPayload
	if err := json.Unmarshal(payload, &p); err != nil || !p.Kind.Valid() {
		return nil, protect.ErrInvalid
	}
	switch _, err := dbq.New(tx).GetOwnedAccountByValue(ctx, tx.OrgID(), string(p.Kind), p.Value); {
	case err == nil:
		return []byte("listed"), nil
	case db.IsNoRows(err):
		return []byte("absent"), nil
	default:
		return nil, err
	}
}

// Remove takes an account off the list at once, a person holding
// org.owned_accounts.manage: shares to it hold again.
func (s *Service) Remove(ctx context.Context, id ids.UUID, reason string) error {
	if err := validReason(reason); err != nil {
		return err
	}
	c, err := caller(ctx, td.PermOwnedAccountsManage)
	if err != nil {
		return err
	}
	if !c.Human() {
		return ErrHuman
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).DeleteOwnedAccount(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrMissing
		} else if err != nil {
			return err
		}
		return record(ctx, tx, c, auditkind.OrgOwnedAccountRemoved, row, map[string]string{
			"kind": row.Kind, "value": row.Value, "reason": reason,
		})
	})
}

func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, row dbq.PcOwnedAccount, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "owned_account", ID: row.ID.String()},
		Details: details,
	})
	return err
}
