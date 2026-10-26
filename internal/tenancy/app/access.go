// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the access use cases.
var (
	ErrInvitationNotFound     = pcerr.New(pcerr.NotFound, "INVITATION_NOT_FOUND", "invitation not found")
	ErrInvitationClosed       = pcerr.New(pcerr.FailedPrecondition, "INVITATION_CLOSED", "invitation is no longer pending")
	ErrServiceAccountNotFound = pcerr.New(pcerr.NotFound, "SERVICE_ACCOUNT_NOT_FOUND", "service account not found")
	ErrBindingNotFound        = pcerr.New(pcerr.NotFound, "ROLE_BINDING_NOT_FOUND", "role binding not found")
	ErrBindingExists          = pcerr.New(pcerr.AlreadyExists, "ROLE_BINDING_EXISTS", "the principal already has this role at this scope")
	ErrPrincipalDisabled      = pcerr.New(pcerr.FailedPrecondition, "PRINCIPAL_DISABLED", "the principal is disabled")
	ErrInvalidTTL             = pcerr.New(pcerr.InvalidArgument, "INVALID_TTL", "validity is out of range")
)

// Invitation validity (G0 brief item 9).
const (
	DefaultInvitationTTL = 7 * 24 * time.Hour
	MaxInvitationTTL     = 30 * 24 * time.Hour
	BootstrapTTL         = 24 * time.Hour
)

// Access implements the AccessService use cases.
type Access struct {
	pool *db.Pool
	log  *slog.Logger
	// ents counts invitations against the plan's member limit (nil: none).
	ents Entitlements
}

// NewAccess returns the access use cases. log receives security events
// (self-grants) in addition to the audit ledger.
func NewAccess(pool *db.Pool, log *slog.Logger) *Access {
	if log == nil {
		log = pclog.Discard()
	}
	return &Access{pool: pool, log: log}
}

// User is a user of the org.
type User struct {
	ID                   td.UserID
	Issuer, Subject      string
	Email, DisplayName   string
	State                td.AccountState
	CreatedAt, UpdatedAt time.Time
	LastLoginAt          *time.Time
}

// InvitationState is the effective state of an invitation (EXPIRED is a
// pending invitation past its expiry).
type InvitationState string

// Invitation states.
const (
	InvitationPending  InvitationState = "PENDING"
	InvitationAccepted InvitationState = "ACCEPTED"
	InvitationRevoked  InvitationState = "REVOKED"
	InvitationExpired  InvitationState = "EXPIRED"
)

// Invitation is an invitation to join the org.
type Invitation struct {
	ID                   td.InvitationID
	Email                string
	Roles                []td.RoleName
	State                InvitationState
	Bootstrap            bool
	CreatedBy            string
	CreatedAt, ExpiresAt time.Time
	AcceptedAt           *time.Time
	AcceptedUser         td.UserID
}

// RoleBinding is a stored role binding.
type RoleBinding struct {
	ID        td.RoleBindingID
	Role      td.RoleName
	Principal td.PrincipalRef
	Scope     td.Scope
	CreatedBy string
	CreatedAt time.Time
}

// Identity answers "who am I".
type Identity struct {
	Caller
	OrgName     string
	DisplayName string
	Bindings    []RoleBinding
}

func userView(r dbq.PcUser) User {
	return User{
		ID: idOf[td.User](r.ID), Issuer: r.Issuer, Subject: r.Subject, Email: r.Email, DisplayName: r.DisplayName,
		State: td.AccountState(r.State), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLoginAt: r.LastLoginAt,
	}
}

func invitationView(r dbq.ListInvitationsRow) Invitation {
	roles := make([]td.RoleName, len(r.Roles))
	for i, s := range r.Roles {
		roles[i] = td.RoleName(s)
	}
	return Invitation{
		ID: idOf[td.Invitation](r.ID), Email: r.Email, Roles: roles, State: InvitationState(r.EffectiveState),
		Bootstrap: r.Kind == "BOOTSTRAP", CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
		AcceptedAt: r.AcceptedAt, AcceptedUser: optID[td.User](r.AcceptedUserID),
	}
}

func bindingView(org ids.OrgID, r dbq.PcRoleBinding) RoleBinding {
	return RoleBinding{
		ID: idOf[td.RoleBinding](r.ID), Role: td.RoleName(r.Role), Principal: bindingPrincipal(r),
		Scope: bindingScope(org, r), CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
	}
}

func bindingPrincipal(r dbq.PcRoleBinding) td.PrincipalRef {
	if r.UserID != nil {
		return td.PrincipalRef{Kind: td.KindUser, ID: *r.UserID}
	}
	if r.ServiceAccountID != nil {
		return td.PrincipalRef{Kind: td.KindServiceAccount, ID: *r.ServiceAccountID}
	}
	return td.PrincipalRef{}
}

func bindingScope(org ids.OrgID, r dbq.PcRoleBinding) td.Scope {
	s := td.Scope{Type: td.ScopeType(r.ScopeType), ID: org.UUID()}
	for _, id := range []*ids.UUID{r.BusinessUnitID, r.TeamID, r.EnvironmentID} {
		if id != nil {
			s.ID = *id
		}
	}
	return s
}

// Bindings loads the role bindings of p, for the authentication interceptor
// to build the caller's Subject (nothing is cached between requests).
func Bindings(ctx context.Context, q *dbq.Queries, org ids.OrgID, p td.PrincipalRef) ([]td.Binding, error) {
	var rows []dbq.PcRoleBinding
	var err error
	switch p.Kind {
	case td.KindUser:
		rows, err = q.BindingsOfUser(ctx, org, &p.ID)
	case td.KindServiceAccount:
		rows, err = q.BindingsOfServiceAccount(ctx, org, &p.ID)
	case td.KindSupport:
		return SupportBindings(ctx, q, org, p.ID)
	default:
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]td.Binding, len(rows))
	for i, r := range rows {
		out[i] = td.Binding{Role: td.RoleName(r.Role), Scope: bindingScope(org, r)}
	}
	return out, nil
}

// WhoAmI describes the caller.
func (a *Access) WhoAmI(ctx context.Context) (Identity, error) {
	var out Identity
	err := inOrg(ctx, a.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		out.Caller = c
		o, err := q.GetOrg(ctx, c.Org)
		if err != nil {
			return notFound(err, ErrOrgNotFound)
		}
		out.OrgName = o.Name
		var rows []dbq.PcRoleBinding
		switch c.Principal.Kind {
		case td.KindUser:
			u, err := q.GetUser(ctx, c.Org, c.Principal.ID)
			if err != nil {
				return notFound(err, ErrUserNotFound)
			}
			out.DisplayName = u.Email
			rows, err = q.BindingsOfUser(ctx, c.Org, &c.Principal.ID)
			if err != nil {
				return err
			}
		case td.KindServiceAccount:
			sa, err := q.GetServiceAccount(ctx, c.Org, c.Principal.ID)
			if err != nil {
				return notFound(err, ErrServiceAccountNotFound)
			}
			out.DisplayName = sa.Name
			rows, err = q.BindingsOfServiceAccount(ctx, c.Org, &c.Principal.ID)
			if err != nil {
				return err
			}
		}
		for _, r := range rows {
			out.Bindings = append(out.Bindings, bindingView(c.Org, r))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// ListUsers lists the org's users.
func (a *Access) ListUsers(ctx context.Context, pr page.Request) (Page[User], error) {
	var out Page[User]
	err := inOrg(ctx, a.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		if err := c.Require(td.PermUserRead, td.OrgPath(c.Org)); err != nil {
			return err
		}
		rows, err := q.ListUsers(ctx, c.Org, pr.After, pr.Limit())
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcUser) ids.UUID { return r.ID })
		for _, r := range rows {
			out.Items = append(out.Items, userView(r))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// GetUser returns one user.
func (a *Access) GetUser(ctx context.Context, id td.UserID) (User, error) {
	var out User
	err := inOrg(ctx, a.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		if err := c.Require(td.PermUserRead, td.OrgPath(c.Org)); err != nil {
			return err
		}
		r, err := q.GetUser(ctx, c.Org, id.UUID())
		if err != nil {
			return notFound(err, ErrUserNotFound)
		}
		out = userView(r)
		return nil
	}, db.ReadOnly())
	return out, err
}

// SetUserState disables or re-enables a user. Disabling revokes the user's
// CLI sessions in the same transaction, and is refused if it would leave the
// org without an active Org Admin.
func (a *Access) SetUserState(ctx context.Context, id td.UserID, state td.AccountState) (User, error) {
	if state != td.Enabled && state != td.Disabled {
		return User{}, pcerr.New(pcerr.InvalidArgument, "INVALID_STATE", "state must be ACTIVE or DISABLED")
	}
	var out User
	err := inOrg(ctx, a.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermUserManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		guard, err := guardAdmins(ctx, q, c.Org)
		if err != nil {
			return err
		}
		r, err := q.SetUserState(ctx, string(state), c.Org, id.UUID())
		if err != nil {
			return notFound(err, ErrUserNotFound)
		}
		details := map[string]string{}
		event := "access.user_enabled"
		if state == td.Disabled {
			event = "access.user_disabled"
			reason := "USER_DISABLED"
			n, err := q.RevokeUserSessions(ctx, &reason, c.Org, r.ID)
			if err != nil {
				return err
			}
			details["sessions_revoked"] = strconv.FormatInt(n, 10)
		}
		if err := guard(ctx); err != nil {
			return err
		}
		out = userView(r)
		return record(ctx, tx, c, event, "user", r.ID, details)
	})
	return out, err
}

// guardAdmins protects the last Org Admin. It serializes admin-changing
// transactions (LockOrgAdmins) and counts the active Org Admin users; the
// returned check, called after the change, fails if the change took the
// count from at least one to zero, which rolls the change back. An org that
// has no admin yet (bootstrap pending) is not blocked.
func guardAdmins(ctx context.Context, q *dbq.Queries, org ids.OrgID) (func(context.Context) error, error) {
	if err := q.LockOrgAdmins(ctx, org); err != nil {
		return nil, err
	}
	before, err := q.CountActiveOrgAdmins(ctx, org)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) error {
		after, err := q.CountActiveOrgAdmins(ctx, org)
		if err != nil {
			return err
		}
		if before > 0 && after == 0 {
			return td.ErrLastOrgAdmin
		}
		return nil
	}, nil
}

// CreateInvitation invites a person by email, optionally with org-scope
// roles (which also requires role.bind). The token is returned once.
func (a *Access) CreateInvitation(ctx context.Context, email string, roles []td.RoleName, ttl time.Duration) (Invitation, credential.Token, error) {
	email, err := td.CheckEmail(email)
	if err != nil {
		return Invitation{}, credential.Token{}, err
	}
	if ttl == 0 {
		ttl = DefaultInvitationTTL
	}
	if ttl < time.Hour || ttl > MaxInvitationTTL {
		return Invitation{}, credential.Token{}, ErrInvalidTTL
	}
	if len(roles) > 16 || len(slices.Compact(slices.Sorted(slices.Values(roles)))) != len(roles) {
		return Invitation{}, credential.Token{}, pcerr.New(pcerr.InvalidArgument, "INVALID_ROLES", "at most 16 distinct roles")
	}
	for _, r := range roles {
		if _, err := td.CheckBindable(r, td.KindUser, td.ScopeOrg); err != nil {
			return Invitation{}, credential.Token{}, err
		}
	}
	var out Invitation
	var tok credential.Token
	err = inOrg(ctx, a.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermInvitationManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		if len(roles) > 0 {
			if err := c.Require(td.PermRoleBind, td.OrgPath(c.Org)); err != nil {
				return err
			}
		}
		if err := checkMemberLimit(ctx, a.ents, q, c.Org); err != nil {
			return err
		}
		var err error
		if tok, err = credential.New(credential.Invitation, "", c.Org); err != nil {
			return err
		}
		out, err = insertInvitation(ctx, q, c.Org, "MEMBER", email, roles, tok, c.Principal.String(), ttl)
		if err != nil {
			return err
		}
		return record(ctx, tx, c, "access.invitation_created", "invitation", out.ID.UUID(),
			map[string]string{"roles": joinRoles(roles)})
	})
	return out, tok, err
}

func insertInvitation(ctx context.Context, q *dbq.Queries, org ids.OrgID, kind, email string, roles []td.RoleName,
	tok credential.Token, createdBy string, ttl time.Duration,
) (Invitation, error) {
	rs := make([]string, len(roles))
	for i, r := range roles {
		rs[i] = string(r)
	}
	r, err := q.InsertInvitation(ctx, dbq.InsertInvitationParams{
		OrgID: org, ID: ids.NewV7(), Kind: kind, Email: email, Roles: rs, TokenHash: tok.Hash(),
		CreatedBy: createdBy, TtlHours: int32(ttl / time.Hour), //nolint:gosec // G115: ttl ≤ 30 days
	})
	if err != nil {
		return Invitation{}, err
	}
	return invitationView(dbq.ListInvitationsRow(r)), nil
}

func joinRoles(roles []td.RoleName) string {
	s := make([]string, len(roles))
	for i, r := range roles {
		s[i] = string(r)
	}
	return strings.Join(s, ",")
}

// ListInvitations lists invitations (pending only unless includeClosed).
func (a *Access) ListInvitations(ctx context.Context, pr page.Request, includeClosed bool) (Page[Invitation], error) {
	var out Page[Invitation]
	err := inOrg(ctx, a.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		if err := c.Require(td.PermInvitationRead, td.OrgPath(c.Org)); err != nil {
			return err
		}
		rows, err := q.ListInvitations(ctx, dbq.ListInvitationsParams{
			OrgID: c.Org, After: pr.After, IncludeClosed: includeClosed, PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListInvitationsRow) ids.UUID { return r.ID })
		for _, r := range rows {
			out.Items = append(out.Items, invitationView(r))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// RevokeInvitation revokes a pending (or expired) invitation.
func (a *Access) RevokeInvitation(ctx context.Context, id td.InvitationID) (Invitation, error) {
	var out Invitation
	err := inOrg(ctx, a.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermInvitationManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		r, err := q.RevokeInvitation(ctx, c.Org, id.UUID())
		if db.IsNoRows(err) {
			if ok, err := q.InvitationExists(ctx, c.Org, id.UUID()); err != nil {
				return err
			} else if ok {
				return ErrInvitationClosed
			}
			return ErrInvitationNotFound
		} else if err != nil {
			return err
		}
		out = invitationView(dbq.ListInvitationsRow(r))
		return record(ctx, tx, c, "access.invitation_revoked", "invitation", r.ID, nil)
	})
	return out, err
}
