// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app reads supply-chain flags (G0 M24 D212; HR-582). Flags are
// written by the checks where a listing or an import arrives; nothing here
// writes one, and nothing anywhere acts on one.
package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Service reads flags.
type Service struct{ Pool *db.Pool }

// Filter narrows a list; a nil field keeps everything.
type Filter struct {
	Connection, Item, Version *ids.UUID
	States                    []string
}

// List lists flags, oldest first. A flag on a listed entry needs
// connection.read at the org. One on a package tool also needs package.read,
// as reading the version directly would: asking for a version without it is
// refused, and an unfiltered list leaves those flags out.
func (s *Service) List(ctx context.Context, f Filter, size int32, token string) ([]dbq.PcSupplychainFlag, string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := c.Require(td.PermConnectionRead, td.OrgPath(c.Org)); err != nil {
		return nil, "", err
	}
	pkgErr := c.Require(td.PermPackageRead, td.OrgPath(c.Org))
	if f.Version != nil && pkgErr != nil {
		return nil, "", pkgErr
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	states := f.States
	if states == nil {
		states = []string{}
	}
	var out []dbq.PcSupplychainFlag
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListSupplyChainFlags(ctx, dbq.ListSupplyChainFlagsParams{
			OrgID: c.Org, ConnectionID: f.Connection, InventoryID: f.Item, PackageVersionID: f.Version, States: states,
			Packages: pkgErr == nil, AfterID: pr.After, MaxRows: pr.Limit(),
		})
		if err != nil {
			return err
		}
		out, next = page.Finish(pr, rows, func(r dbq.PcSupplychainFlag) ids.UUID { return r.ID })
		return nil
	}, db.ReadOnly())
	return out, next, err
}
