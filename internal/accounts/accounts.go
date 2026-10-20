// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package accounts holds hosted accounts and self-serve organizations
// (G0 UI D8, D41; PN-026; HR-348..353).
//
// An account is one OIDC identity (issuer, subject) across orgs, never
// linked to another issuer's identity by email (HR-348). Its rows are read
// and written only in the restricted global purpose "accounts" or in the
// account's own context (D41); its memberships are found only through the
// audited cross-org lister (HR-349). An account session belongs to no org:
// it may call only the allow-listed procedures (HR-350, AllowedProcedure),
// and the org-scoped use cases refuse it because it carries no org caller.
package accounts

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Account is a hosted account.
type Account struct {
	ID              ids.UUID
	Issuer, Subject string
	Email           string
	EmailVerified   bool
	DisplayName     string
	CreatedAt       time.Time
}

// Identity is what a provider's ID token says about the person.
type Identity struct {
	Issuer, Subject string
	Email           string
	EmailVerified   bool
	Name            string
}

// Membership is one org the account is an active user of.
type Membership struct {
	Org        ids.OrgID
	User       ids.UUID
	Name, Slug string
}

// Errors.
var (
	ErrNoAccount       = pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "an account session is required")
	ErrAccountNotFound = pcerr.New(pcerr.NotFound, "ACCOUNT_NOT_FOUND", "unknown account")
)

// Caller is an account browser session's caller (no org).
type Caller struct {
	Account  ids.UUID
	Session  ids.UUID
	Provider string
	// AuthTime is when the provider last authenticated the person.
	AuthTime time.Time
	// IP is the client address the request came from (rate limits).
	IP string
}

type callerKey struct{}

// WithCaller returns ctx carrying the account caller. Only the
// authentication layer (and tests) call it.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the account caller of ctx.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok && !c.Account.IsZero()
}

// allowed are the only procedures an account session may call (HR-350,
// D8): who am I, the account's own orgs and invitations, and its account
// page. Everything org-scoped needs an org session.
var allowed = []string{
	"/pantherclaw.v1.AccessService/WhoAmI",
	"/pantherclaw.v1.AccessService/AcceptInvitation",
	"/pantherclaw.v1.TenancyService/CreateOrg",
	"/pantherclaw.v1.TenancyService/ListMyOrgs",
}

// AllowedProcedure reports whether an account session may call procedure.
// AccountService's procedures are allowed by D8; they need an org user and
// refuse an account caller themselves.
func AllowedProcedure(procedure string) bool {
	return slices.Contains(allowed, procedure) || strings.HasPrefix(procedure, "/pantherclaw.v1.AccountService/")
}

// Store reads and writes accounts.
type Store struct {
	pool *db.Pool
}

// NewStore returns the account store.
func NewStore(pool *db.Pool) *Store { return &Store{pool: pool} }

func view(a dbq.PcAccount) Account {
	return Account{
		ID: a.ID, Issuer: a.Issuer, Subject: a.Subject, Email: a.Email, EmailVerified: a.EmailVerified,
		DisplayName: a.DisplayName, CreatedAt: a.CreatedAt,
	}
}

// Resolve returns the account of id, creating it at its first sign-in and
// refreshing its email and name from the ID token (HR-348: by issuer and
// subject only). The sign-in is recorded as an account event.
func (s *Store) Resolve(ctx context.Context, id Identity, clientIP string) (Account, error) {
	if id.Issuer == "" || id.Subject == "" || len(id.Issuer) > 512 || len(id.Subject) > 255 {
		return Account{}, errors.New("accounts: identity needs an issuer and a subject")
	}
	email := td.NormalizeEmail(td.SanitizeClaim(id.Email, td.MaxEmailLen))
	verified := id.EmailVerified && email != ""
	var out Account
	err := s.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		a, err := q.UpsertAccount(ctx, dbq.UpsertAccountParams{
			ID: ids.NewV7(), Issuer: id.Issuer, Subject: id.Subject, Email: email, EmailVerified: verified,
			DisplayName: td.SanitizeClaim(id.Name, td.MaxNameLen),
		})
		if err != nil {
			return err
		}
		out = view(a)
		return q.InsertAccountEvent(ctx, dbq.InsertAccountEventParams{AccountID: a.ID, Kind: "SIGNED_IN", ClientIp: trim(clientIP, 64)})
	})
	if err != nil {
		return Account{}, fmt.Errorf("accounts: resolve: %w", err)
	}
	return out, nil
}

// Get returns the account of id.
func (s *Store) Get(ctx context.Context, id ids.UUID) (Account, error) {
	var out Account
	err := s.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		a, err := dbq.New(tx).GetAccount(ctx, id)
		if db.IsNoRows(err) {
			return ErrAccountNotFound
		} else if err != nil {
			return err
		}
		out = view(a)
		return nil
	}, db.ReadOnly())
	return out, err
}

// event records one account event (best effort is not acceptable: refusals
// count toward the rate limits).
func (s *Store) event(ctx context.Context, account ids.UUID, kind string, org *ids.OrgID, ip, detail string) error {
	return s.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		p := dbq.InsertAccountEventParams{AccountID: account, Kind: kind, ClientIp: trim(ip, 64), Detail: trim(detail, 256)}
		if org != nil {
			p.OrgID = *org
		}
		return dbq.New(tx).InsertAccountEvent(ctx, p)
	})
}

// maxMemberships bounds the orgs listed for one account.
const maxMemberships = 100

// Memberships lists the account's active memberships through the audited
// cross-org lister (HR-349), by org name.
func (s *Store) Memberships(ctx context.Context, account ids.UUID) ([]Membership, error) {
	refs, err := s.pool.CrossOrgListWith(ctx, db.ListAccountMemberships, maxMemberships, db.ListerParams{AccountID: account})
	if err != nil {
		return nil, err
	}
	out := make([]Membership, 0, len(refs))
	for _, r := range refs {
		err := s.pool.InTenantTx(ctx, r.Org, func(ctx context.Context, tx db.TenantTx) error {
			o, err := dbq.New(tx).OrgSummary(ctx, r.Org)
			if err != nil || o.State != "ACTIVE" {
				return err
			}
			out = append(out, Membership{Org: r.Org, User: r.ID, Name: o.Name, Slug: o.Slug})
			return nil
		}, db.ReadOnly())
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, func(a, b Membership) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.Org.String(), b.Org.String())
	})
	return out, nil
}

// LinkUser links org's user to the account (in tx, the org's tenant
// transaction), once; the trigger refuses another identity's account
// (HR-348).
func LinkUser(ctx context.Context, tx db.TenantTx, account, user ids.UUID) error {
	if err := db.SetAccountContext(ctx, tx, account); err != nil {
		return err
	}
	_, err := dbq.New(tx).LinkUserAccount(ctx, &account, tx.OrgID(), user)
	return err
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
