// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package idps

import (
	"context"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Shadow is an org's ACTIVE provider whose name a deployment provider also
// has: the deployment's wins, so the org's no longer signs anyone in under
// that name (D169).
type Shadow struct {
	Org  ids.OrgID
	ID   ids.UUID
	Name string
}

// Shadowed lists every active org's ACTIVE providers shadowed by a
// deployment provider of the same name. Org names are refused against the
// deployment's at filing, so a shadow means the operator added the
// deployment provider later.
func Shadowed(ctx context.Context, pool *db.Pool, deployment []Deployment) ([]Shadow, error) {
	names := map[string]bool{}
	for _, d := range deployment {
		names[d.Name] = true
	}
	if len(names) == 0 {
		return nil, nil
	}
	var out []Shadow
	err := pool.CrossOrgPages(ctx, db.ListActiveOrgs, db.ListerPageSize, func(page []db.OrgRef) error {
		for _, r := range page {
			if err := pool.InTenantTx(ctx, r.Org, func(ctx context.Context, tx db.TenantTx) error {
				rows, err := dbq.New(tx).ActiveOrgIdentityProviders(ctx, r.Org)
				for _, p := range rows {
					if names[p.Name] {
						out = append(out, Shadow{Org: r.Org, ID: p.ID, Name: p.Name})
					}
				}
				return err
			}, db.ReadOnly()); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// WarnShadowed logs a start-up warning for each shadowed provider (D169).
func WarnShadowed(ctx context.Context, pool *db.Pool, deployment []Deployment, log *slog.Logger) {
	shadows, err := Shadowed(ctx, pool, deployment)
	if err != nil {
		log.WarnContext(ctx, "idps.shadow_check_failed", pclog.Err(err))
		return
	}
	for _, s := range shadows {
		log.WarnContext(ctx, "idps.provider_shadowed", slog.String("org", s.Org.String()), slog.String("provider", s.ID.String()),
			slog.String("name", s.Name), slog.String("note",
				"a deployment provider in auth.oidc_providers has this organization provider's name, so sign-ins under it "+
					"go to the deployment's provider; rename one of them"))
	}
}
