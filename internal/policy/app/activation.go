// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// ReasonPackageBreaksPolicy refuses a package activation after which the
// org's published policy would no longer compile.
const ReasonPackageBreaksPolicy = "PACKAGE_BREAKS_POLICY"

// PublishedTx reads the org's published bundle in tx (nil when none).
type PublishedTx interface {
	PublishedInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) (*domain.Bundle, error)
}

// CatalogTx reads the org's fact catalog in tx.
type CatalogTx interface {
	CatalogInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) (map[string]fdomain.Type, error)
}

// ActivationCheck compiles the org's published policy against the active
// definitions as they are after a package activation, as the Authority
// does for a decision (G0 M4, policy compilation). A rule written for an
// operation no package defined yet compiled without its definition; if
// the activated version makes it fail to compile, the activation is
// refused instead of every later decision failing closed.
type ActivationCheck struct {
	Policies PublishedTx
	Facts    CatalogTx
	Limits   celenv.Limits
}

// CheckActivation implements definitions/app.ActivationCheck.
func (a ActivationCheck) CheckActivation(ctx context.Context, tx db.TenantTx, active []*defs.Definition) error {
	org := tx.OrgID()
	b, err := a.Policies.PublishedInTx(ctx, tx, org)
	if err != nil || b == nil {
		return err
	}
	catalog, err := a.Facts.CatalogInTx(ctx, tx, org)
	if err != nil {
		return err
	}
	if _, err := (&Engine{Limits: a.Limits, Facts: catalog}).Compile(b, active); err != nil {
		return pcerr.Wrap(err, pcerr.FailedPrecondition, ReasonPackageBreaksPolicy,
			fmt.Sprintf("the published policy %s@%d would no longer compile with this version active: %v; publish a policy that compiles first", b.ID, b.Version, err))
	}
	return nil
}
