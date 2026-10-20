// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package entitlements

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Usage is what an org uses now.
type Usage struct {
	Agents, Environments, Members int
}

// View is an org's plan and usage (EntitlementService.GetEntitlements).
type View struct {
	Plan  Plan
	Usage Usage
}

// Get returns the caller's org's plan and usage (entitlements.read).
func (s *Service) Get(ctx context.Context) (View, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return View{}, err
	}
	if !c.CanAnywhere(td.PermEntitlementsRead) {
		return View{}, td.ErrPermissionDenied(td.PermEntitlementsRead)
	}
	p, err := s.Plan(ctx, c.Org)
	if err != nil {
		return View{}, err
	}
	out := View{Plan: p}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		u, err := dbq.New(tx).EntitlementUsage(ctx, c.Org)
		if err != nil {
			return err
		}
		out.Usage = Usage{Agents: int(u.Agents), Environments: int(u.Environments), Members: int(u.Members)}
		return nil
	}, db.ReadOnly())
	return out, err
}
