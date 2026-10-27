// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"

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

// ErrOrgLimit reports that the licence allows no more organizations.
var ErrOrgLimit = pcerr.New(pcerr.FailedPrecondition, "ORG_LIMIT", "the licence allows no more organizations")

// Bootstrap holds the operator-only tenancy actions. They are reachable
// from the pantherclaw-server command line (database access), never from
// the API: creating an organization and issuing its bootstrap admin token.
type Bootstrap struct {
	pool *db.Pool
	ents Entitlements
}

// NewBootstrap returns the operator actions.
func NewBootstrap(pool *db.Pool, ents Entitlements) *Bootstrap {
	return &Bootstrap{pool: pool, ents: ents}
}

func operator(action string) evdomain.Actor { return evdomain.Actor{Type: "operator", ID: action} }

// CreateOrg creates an organization (within the licence's org limit), its
// containment row and a bootstrap invitation granting Org Admin to the first
// person who signs in with it within 24 hours (optionally bound to an
// email). The token is returned once.
func (b *Bootstrap) CreateOrg(ctx context.Context, name, adminEmail string) (ids.OrgID, credential.Token, error) {
	name, err := td.CheckName("name", name)
	if err != nil {
		return ids.OrgID{}, credential.Token{}, err
	}
	if adminEmail != "" {
		if adminEmail, err = td.CheckEmail(adminEmail); err != nil {
			return ids.OrgID{}, credential.Token{}, err
		}
	}
	refs, err := b.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil {
		return ids.OrgID{}, credential.Token{}, err
	}
	tenants := 0
	for _, r := range refs {
		if r.Org != ids.PlatformOrg {
			tenants++
		}
	}
	ent, err := b.ents.Current(ctx)
	if err != nil {
		return ids.OrgID{}, credential.Token{}, err
	}
	if err := ent.CheckOrgs(tenants); errors.Is(err, billing.ErrLimitReached) {
		return ids.OrgID{}, credential.Token{}, pcerr.Wrap(err, pcerr.FailedPrecondition, "ORG_LIMIT", err.Error())
	} else if err != nil {
		return ids.OrgID{}, credential.Token{}, err
	}
	org := ids.New[ids.Org]()
	var tok credential.Token
	err = b.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.InsertOrg(ctx, org, name); err != nil {
			return err
		}
		if err := q.InsertContainment(ctx, org); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "tenancy.org_created", Actor: operator("org-create"), Outcome: audit.Success,
			Object: &audit.Object{Type: "org", ID: org.String()}, Details: map[string]string{"edition": string(ent.Edition)},
		}); err != nil {
			return err
		}
		tok, err = b.bootstrapInvitation(ctx, tx, q, org, adminEmail, "org-create")
		return err
	})
	return org, tok, err
}

// AdminInvitation issues a new bootstrap invitation for an existing org
// (recovery when no administrator can sign in) and revokes earlier pending
// ones.
func (b *Bootstrap) AdminInvitation(ctx context.Context, org ids.OrgID, adminEmail string) (credential.Token, error) {
	if adminEmail != "" {
		var err error
		if adminEmail, err = td.CheckEmail(adminEmail); err != nil {
			return credential.Token{}, err
		}
	}
	var tok credential.Token
	err := b.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		o, err := q.GetOrg(ctx, org)
		if err != nil {
			return notFound(err, ErrOrgNotFound)
		}
		if o.State != "ACTIVE" {
			return ErrArchived
		}
		if _, err := q.RevokeBootstrapInvitations(ctx, org); err != nil {
			return err
		}
		tok, err = b.bootstrapInvitation(ctx, tx, q, org, adminEmail, "org-admin-invite")
		return err
	})
	return tok, err
}

func (b *Bootstrap) bootstrapInvitation(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, email, action string) (credential.Token, error) {
	tok, err := credential.New(credential.Invitation, "", org)
	if err != nil {
		return credential.Token{}, err
	}
	inv, err := insertInvitation(ctx, q, org, "BOOTSTRAP", email, []td.RoleName{td.RoleOrgAdmin}, tok, "operator:"+action, BootstrapTTL)
	if err != nil {
		return credential.Token{}, err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "access.bootstrap_invitation_created", Actor: operator(action), Outcome: audit.Success,
		Object:  &audit.Object{Type: "invitation", ID: inv.ID.String()},
		Details: map[string]string{"email_bound": boolString(email != "")},
	})
	return tok, err
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
