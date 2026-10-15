// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stream

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/search"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// PoolScoper scopes viewers like the evidence explorer: the agents where
// they hold evidence.read (D8).
type PoolScoper struct {
	Pool *db.Pool
}

// Scope implements Scoper.
func (p PoolScoper) Scope(ctx context.Context, c tenancy.Caller) (Scope, error) {
	var out Scope
	err := p.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		sc, err := search.AgentScope(ctx, c, dbq.New(tx), td.PermEvidenceRead)
		if err != nil {
			return err
		}
		out = Scope{All: sc.All, Agents: make(map[ids.UUID]bool, len(sc.Agents))}
		for _, a := range sc.Agents {
			out.Agents[a] = true
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
