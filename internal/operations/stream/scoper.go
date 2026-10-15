// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stream

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	"github.com/katocxl/pantherclaw/internal/search"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// PoolScoper scopes viewers by operations.read where each agent lives
// (D4, D8): the same agent scope search filters with.
type PoolScoper struct {
	Pool *db.Pool
}

// Scope implements Scoper.
func (p PoolScoper) Scope(ctx context.Context, c tenancy.Caller) (Scope, error) {
	var out Scope
	err := p.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		sc, err := search.AgentScope(ctx, c, dbq.New(tx), PermOperations)
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

// PoolFeed reads the feed (internal/reflex/feed) in a read-only tenant
// transaction per call.
type PoolFeed struct {
	Pool *db.Pool
}

// After implements Feed.
func (p PoolFeed) After(ctx context.Context, org ids.OrgID, after int64, limit int) ([]Event, error) {
	var out []Event
	err := p.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = feed.Reader{}.After(ctx, tx, after, limit)
		return err
	}, db.ReadOnly())
	return out, err
}

// Head implements Feed.
func (p PoolFeed) Head(ctx context.Context, org ids.OrgID) (int64, error) {
	var out int64
	err := p.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = feed.Reader{}.Head(ctx, tx)
		return err
	}, db.ReadOnly())
	return out, err
}
