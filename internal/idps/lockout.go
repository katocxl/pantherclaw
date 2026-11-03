// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package idps

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// guardLockOut checks a change for lock-out (HR-484, D162): without is the
// provider the change disables (zero for none) and ownOnly the "own
// providers only" setting after it. An active org admin (an enabled
// person holding org_admin at the org) signs in through a provider whose
// issuer is the one of their identity: the org's ACTIVE providers, and
// the deployment's unless the org uses its own only.
//
// It returns ErrLockOut when no active admin would have a provider left,
// and otherwise the admins who would lose their last one, for the change
// request and its notification. An org without active admins has nobody
// to lock out.
func (s *Store) guardLockOut(ctx context.Context, tx db.TenantTx, without ids.UUID, ownOnly bool) ([]ids.UUID, error) {
	q := dbq.New(tx)
	admins, err := q.OrgAdminIdentities(ctx, tx.OrgID())
	if err != nil || len(admins) == 0 {
		return nil, err
	}
	own, err := q.ActiveOrgIdentityProviders(ctx, tx.OrgID())
	if err != nil {
		return nil, err
	}
	nowOnly, err := s.OwnOnly(ctx, tx)
	if err != nil {
		return nil, err
	}
	before, after := map[string]bool{}, map[string]bool{}
	for _, d := range s.Deployment {
		before[d.Issuer] = !nowOnly
		after[d.Issuer] = !ownOnly
	}
	for _, p := range own {
		before[p.Issuer] = true
		after[p.Issuer] = after[p.Issuer] || p.ID != without
	}
	// A SAML connection is one of the org's own providers (G0 M26 D409).
	saml, err := q.ActiveSAMLIssuers(ctx, tx.OrgID())
	if err != nil {
		return nil, err
	}
	for _, c := range saml {
		if c.Issuer == nil {
			continue
		}
		before[*c.Issuer] = true
		after[*c.Issuer] = after[*c.Issuer] || c.ID != without
	}
	return lockOut(admins, before, after)
}

// CheckSignInPath is ErrLockOut when no active org admin has a way to sign
// in. A change that takes an admin away calls it after the change (HR-484).
func (s *Store) CheckSignInPath(ctx context.Context, tx db.TenantTx) error {
	own, err := s.OwnOnly(ctx, tx)
	if err != nil {
		return err
	}
	_, err = s.guardLockOut(ctx, tx, ids.UUID{}, own)
	return err
}

// lockOut is ErrLockOut when no admin's issuer is available after the
// change, else the admins who had one before and have none after.
func lockOut(admins []dbq.OrgAdminIdentitiesRow, before, after map[string]bool) ([]ids.UUID, error) {
	var stranded []ids.UUID
	left := false
	for _, a := range admins {
		switch {
		case after[a.Issuer]:
			left = true
		case before[a.Issuer]:
			stranded = append(stranded, a.ID)
		}
	}
	if !left {
		return nil, ErrLockOut
	}
	return stranded, nil
}
