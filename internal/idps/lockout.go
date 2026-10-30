// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package idps

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// guardLockOut refuses a change after which no active org admin has a
// provider to sign in with (HR-484): without is the provider the change
// disables (zero for none) and ownOnly the "own providers only" setting
// after it. An admin signs in through a provider whose issuer is the one
// of their identity: the org's ACTIVE providers, and the deployment's
// unless the org uses its own only. An org without active admins has
// nobody to lock out.
func (s *Store) guardLockOut(ctx context.Context, tx db.TenantTx, without ids.UUID, ownOnly bool) error {
	q := dbq.New(tx)
	admins, err := q.OrgAdminIssuers(ctx, tx.OrgID())
	if err != nil {
		return err
	}
	if len(admins) == 0 {
		return nil
	}
	issuers := map[string]bool{}
	if !ownOnly {
		for _, d := range s.Deployment {
			issuers[d.Issuer] = true
		}
	}
	own, err := q.ActiveOrgIdentityProviders(ctx, tx.OrgID())
	if err != nil {
		return err
	}
	for _, p := range own {
		if p.ID != without {
			issuers[p.Issuer] = true
		}
	}
	return lockOut(admins, issuers)
}

// lockOut is ErrLockOut unless some admin's issuer is available.
func lockOut(admins []dbq.OrgAdminIssuersRow, available map[string]bool) error {
	for _, a := range admins {
		if a.Admins > 0 && available[a.Issuer] {
			return nil
		}
	}
	return ErrLockOut
}
