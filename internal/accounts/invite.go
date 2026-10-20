// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package accounts

import (
	"context"
	"errors"
	"strings"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Invitation errors (HR-352).
var (
	ErrInvitationInvalid = pcerr.New(pcerr.NotFound, "INVITATION_INVALID", "this invitation is invalid, used or expired")
	ErrEmailMismatch     = pcerr.New(pcerr.PermissionDenied, "INVITATION_EMAIL_MISMATCH",
		"this invitation is for another email address; sign in with the account your identity provider verified for it")
	ErrAlreadyMember = pcerr.New(pcerr.AlreadyExists, "ALREADY_MEMBER", "your account is already a member of this organization")
	ErrMemberLimit   = pcerr.New(pcerr.FailedPrecondition, "PLAN_LIMIT", "the organization's plan allows no more members")
)

// Entitlements reads an org's entitlements (entitlements.Service.For).
type Entitlements interface {
	For(ctx context.Context, org ids.OrgID) (billing.Entitlements, error)
}

// Invitations accepts invitations in the browser.
type Invitations struct {
	store *Store
	ents  Entitlements
}

// NewInvitations returns the browser invitation use case.
func NewInvitations(store *Store, ents Entitlements) *Invitations {
	return &Invitations{store: store, ents: ents}
}

// Accepted is an accepted invitation: the org joined and the new user.
type Accepted struct {
	Org  ids.OrgID
	User ids.UUID
}

// Accept accepts the invitation token for account (HR-352): once, before
// it expires, and only when the provider-verified email of the account
// equals the invitation's email; a bootstrap invitation without an email
// is accepted only through pclaw. The new user is linked to the account,
// gets the invitation's roles, and counts against the plan's member limit
// (HR-360). Every outcome is recorded.
func (iv *Invitations) Accept(ctx context.Context, account ids.UUID, token, clientIP string) (Accepted, error) {
	tok, err := credential.Parse(credential.Invitation, strings.TrimSpace(token))
	if err != nil {
		return Accepted{}, ErrInvitationInvalid
	}
	return iv.AcceptHash(ctx, account, tok.Org(), tok.Hash(), clientIP)
}

// AcceptHash is Accept for an invitation known by its org and token hash
// (the browser sign-in that carried it keeps only the hash).
func (iv *Invitations) AcceptHash(ctx context.Context, account ids.UUID, org ids.OrgID, hash []byte, clientIP string) (Accepted, error) {
	if org.IsZero() || len(hash) != 32 {
		return Accepted{}, ErrInvitationInvalid
	}
	acct, err := iv.store.Get(ctx, account)
	if err != nil {
		return Accepted{}, err
	}
	var out Accepted
	var invID ids.UUID
	err = iv.store.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, org); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return ErrInvitationInvalid
		} else if err != nil {
			return err
		}
		inv, err := q.LockInvitationByHash(ctx, org, hash)
		if db.IsNoRows(err) {
			return ErrInvitationInvalid
		} else if err != nil {
			return err
		}
		invID = inv.ID
		if inv.State != "PENDING" || !inv.Live {
			return ErrInvitationInvalid
		}
		if inv.Email == "" || !acct.EmailVerified || td.NormalizeEmail(acct.Email) != inv.Email {
			return ErrEmailMismatch
		}
		if _, err := q.UserByIdentity(ctx, org, acct.Issuer, acct.Subject); err == nil {
			return ErrAlreadyMember
		} else if !db.IsNoRows(err) {
			return err
		}
		ent, err := iv.ents.For(ctx, org)
		if err != nil {
			return err
		}
		members, err := q.CountActiveMembers(ctx, org)
		if err != nil {
			return err
		}
		if err := ent.CheckMembers(int(members)); errors.Is(err, billing.ErrLimitReached) {
			return ErrMemberLimit
		} else if err != nil {
			return err
		}
		if err := db.SetAccountContext(ctx, tx, account); err != nil {
			return err
		}
		u, err := q.InsertAccountUser(ctx, dbq.InsertAccountUserParams{
			OrgID: org, ID: ids.NewV7(), Issuer: acct.Issuer, Subject: acct.Subject, Email: td.NormalizeEmail(acct.Email),
			DisplayName: acct.DisplayName, AccountID: &account,
		})
		if err != nil {
			return err
		}
		for _, r := range inv.Roles {
			if _, err := td.CheckBindable(td.RoleName(r), td.KindUser, td.ScopeOrg); err != nil {
				return err
			}
			if _, err := q.InsertRoleBinding(ctx, dbq.InsertRoleBindingParams{
				OrgID: org, ID: ids.NewV7(), Role: r, UserID: &u.ID, ScopeType: string(td.ScopeOrg),
				CreatedBy: "invitation:" + inv.ID.String(),
			}); err != nil {
				return err
			}
		}
		if n, err := q.AcceptInvitationInBrowser(ctx, dbq.AcceptInvitationInBrowserParams{
			UserID: &u.ID, AccountID: &account, OrgID: org, ID: inv.ID,
		}); err != nil {
			return err
		} else if n == 0 {
			return ErrInvitationInvalid
		}
		out = Accepted{Org: org, User: u.ID}
		actor := evdomain.Actor{Type: string(td.KindUser), ID: u.ID.String()}
		for _, ev := range []audit.Event{
			{Name: "access.user_created", Object: &audit.Object{Type: "user", ID: u.ID.String()}, Details: map[string]string{"via": "browser"}},
			{
				Name: "access.invitation_accepted", Object: &audit.Object{Type: "invitation", ID: inv.ID.String()},
				Details: map[string]string{"kind": inv.Kind, "roles": strings.Join(inv.Roles, ","), "via": "browser"},
			},
		} {
			ev.Actor, ev.Outcome = actor, audit.Success
			if _, err := audit.Record(ctx, tx, ev); err != nil {
				return err
			}
		}
		return nil
	})
	kind, detail := "INVITATION_ACCEPTED", ""
	if err != nil {
		kind = "INVITATION_REFUSED"
		var pe *pcerr.Error
		if errors.As(err, &pe) {
			detail = pe.Reason()
		}
		if errors.Is(err, ErrEmailMismatch) && !invID.IsZero() {
			iv.recordMismatch(ctx, org, invID, account)
		}
	}
	orgRef := &org
	if errors.Is(err, ErrInvitationInvalid) {
		orgRef = nil // no org-existence trail for a bad token
	}
	if rerr := iv.store.event(context.WithoutCancel(ctx), account, kind, orgRef, clientIP, detail); rerr != nil && err == nil {
		err = rerr
	}
	return out, err
}

// recordMismatch writes the refused acceptance into the org's ledger, so
// its admins see someone tried an invitation with another account (T-165).
func (iv *Invitations) recordMismatch(ctx context.Context, org ids.OrgID, inv, account ids.UUID) {
	_ = iv.store.pool.InTenantTx(context.WithoutCancel(ctx), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "access.invitation_refused", Actor: evdomain.Actor{Type: "account", ID: account.String()},
			Outcome: audit.Denied, ReasonCode: "INVITATION_EMAIL_MISMATCH",
			Object: &audit.Object{Type: "invitation", ID: inv.String()},
		})
		return err
	})
}
